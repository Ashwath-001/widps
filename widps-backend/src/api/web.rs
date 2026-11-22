// HTTP layer (axum): login, sessions, CSRF and roles; typed /api/v1 routes plus the legacy /api handlers.
use crate::api::legacy::{self, ApiCtx};
use crate::api::auth::{self, AuthConfig, LoginError, Role, Session, SessionCheck, COOKIE_NAME};
use crate::store::db::{AckResult, AlertQuery};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Path, Request, State};
use axum::http::{header, request::Parts, HeaderMap, HeaderValue, Method, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub const MAX_BODY_BYTES: usize = 10 * 1024;
const BACKGROUND_HEADER: &str = "x-widps-background";
const CSRF_HEADER: &str = "x-csrf-token";
const MAX_PAGE: u32 = 500;

#[derive(Clone)]
pub struct AppState {
    pub ctx: ApiCtx,
    pub auth: Arc<AuthConfig>,
}

#[derive(Clone)]
struct RequestId(String);

/// Binds `bind` (default 127.0.0.1:8787) on a dedicated thread with its own tokio runtime.
pub fn spawn(bind: String, ctx: ApiCtx, auth: AuthConfig) {
    std::thread::spawn(move || {
        let rt = match tokio::runtime::Builder::new_multi_thread().worker_threads(2).enable_all().build() {
            Ok(rt) => rt,
            Err(e) => {
                eprintln!("[api] cannot start runtime: {}", e);
                return;
            }
        };
        rt.block_on(async move {
            let listener = match tokio::net::TcpListener::bind(&bind).await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("[api] COULD NOT BIND {}: {}", bind, e);
                    return;
                }
            };
            println!("[api] listening on http://{} (expects TLS termination by nginx)", bind);
            let app = router(AppState { ctx, auth: Arc::new(auth) });
            if let Err(e) = axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>()).await {
                eprintln!("[api] server stopped: {}", e);
            }
        });
    });
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(|| async { "ok" }))
        .route("/api/auth/login", post(login))
        .route("/api/auth/logout", post(logout))
        .route("/api/auth/session", get(session_info))
        .route("/api/stream", get(stream))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/session", get(session_info))
        .route("/api/v1/stream", get(stream))
        .route("/api/v1/openapi.json", get(openapi))
        .route("/api/v1/alerts", get(v1_alerts))
        .route("/api/v1/alerts/archive", post(v1_archive))
        .route("/api/v1/alerts/{id}", get(v1_alert))
        .route("/api/v1/alerts/{id}/ack", post(v1_ack))
        .route("/api/v1/alerts/{id}/verdict", post(v1_verdict))
        .route("/api/v1/audit/verify", get(v1_audit_verify))
        .route("/api/v1/audit/log", get(v1_audit_log))
        .route("/api/v1/logs", get(v1_logs))
        .fallback(legacy)
        .layer(axum::middleware::map_response(security_headers))
        .layer(axum::middleware::from_fn(request_id))
        .with_state(state)
}

async fn request_id(mut req: Request, next: Next) -> Response {
    use argon2::password_hash::rand_core::{OsRng, RngCore};
    let id = format!("{:016x}", OsRng.next_u64());
    req.extensions_mut().insert(RequestId(id.clone()));
    let mut res = next.run(req).await;
    if let Ok(v) = HeaderValue::from_str(&id) {
        res.headers_mut().insert("x-request-id", v);
    }
    res
}

async fn security_headers(mut res: Response) -> Response {
    let h = res.headers_mut();
    h.insert("x-content-type-options", HeaderValue::from_static("nosniff"));
    h.insert("x-frame-options", HeaderValue::from_static("DENY"));
    h.insert("referrer-policy", HeaderValue::from_static("no-referrer"));
    if !h.contains_key(header::CACHE_CONTROL) {
        h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    }
    res
}

/// One error type, rendered as {"error": "...", ...} on /api and {"error": {code, message, request_id}} on /api/v1.
#[derive(Debug)]
struct ApiError {
    status: StatusCode,
    code: &'static str,
    message: String,
    reason: Option<&'static str>,
    retry_after: Option<i64>,
}

impl ApiError {
    fn new(status: StatusCode, code: &'static str, message: impl Into<String>) -> Self {
        Self { status, code, message: message.into(), reason: None, retry_after: None }
    }
    fn unauthenticated(reason: &'static str) -> Self {
        Self { reason: Some(reason), ..Self::new(StatusCode::UNAUTHORIZED, "unauthenticated", "sign in required") }
    }
    fn bad_request(code: &'static str, message: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, code, message)
    }
    fn not_found(message: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, "not_found", message)
    }
    fn internal() -> Self {
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal", "internal error")
    }

    fn render(self, v1: bool, request_id: &str) -> Response {
        let body = if v1 {
            let mut e = serde_json::json!({ "code": self.code, "message": self.message, "request_id": request_id });
            if let Some(r) = self.reason {
                e["reason"] = r.into();
            }
            serde_json::json!({ "error": e })
        } else {
            let legacy = if self.code == "unauthenticated" { "unauthenticated".to_string() } else { self.message.clone() };
            let mut e = serde_json::json!({ "error": legacy });
            if let Some(r) = self.reason {
                e["reason"] = r.into();
            }
            e
        };
        let mut res = (self.status, [(header::CONTENT_TYPE, "application/json")], body.to_string()).into_response();
        if let Some(s) = self.retry_after {
            res.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(s.max(1) as u64));
        }
        res
    }
}

struct Ctx {
    v1: bool,
    rid: String,
}

impl Ctx {
    fn of(parts_path: &str, ext: &axum::http::Extensions) -> Self {
        Self {
            v1: parts_path.starts_with("/api/v1/"),
            rid: ext.get::<RequestId>().map(|r| r.0.clone()).unwrap_or_default(),
        }
    }
    fn err(&self, e: ApiError) -> Response {
        e.render(self.v1, &self.rid)
    }
}

fn json_ok(status: StatusCode, body: String) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn header_str<'a>(h: &'a HeaderMap, name: impl header::AsHeaderName) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Peer address; X-Real-IP is trusted only when the peer is the local proxy.
fn client_ip(ext: &axum::http::Extensions, h: &HeaderMap) -> String {
    let peer = ext.get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let forwarded = header_str(h, "x-real-ip").trim().parse::<std::net::IpAddr>().ok();
    match (peer, forwarded) {
        (Some(p), Some(f)) if p.is_loopback() => f.to_string(),
        (Some(p), _) => p.to_string(),
        (None, Some(f)) => f.to_string(),
        (None, None) => "unknown".into(),
    }
}

fn session_cookie(h: &HeaderMap) -> Option<String> {
    h.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).flat_map(|v| v.split(';')).find_map(|kv| {
        let (k, v) = kv.trim().split_once('=')?;
        (k == COOKIE_NAME).then(|| v.to_string())
    })
}

fn set_cookie_header(raw: &str, max_age: i64) -> HeaderValue {
    HeaderValue::from_str(&format!("{}={}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age={}", COOKIE_NAME, raw, max_age))
        .expect("cookie value is hex")
}

fn clear_cookie_header() -> HeaderValue {
    HeaderValue::from_str(&format!("{}=; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=0", COOKIE_NAME)).unwrap()
}

/// The Origin must be this host (any scheme) or listed in WIDPS_ALLOWED_ORIGINS.
fn origin_ok(h: &HeaderMap, cfg: &AuthConfig) -> bool {
    let origin = header_str(h, header::ORIGIN).trim_end_matches('/');
    if origin.is_empty() || origin == "null" {
        return false;
    }
    if cfg.allowed_origins.iter().any(|o| o == origin) {
        return true;
    }
    let host = header_str(h, header::HOST);
    let origin_host = origin.split_once("://").map(|(_, rest)| rest).unwrap_or("");
    !host.is_empty() && origin_host.eq_ignore_ascii_case(host)
}

fn json_body_ok(h: &HeaderMap, body: &[u8]) -> bool {
    body.is_empty() || header_str(h, header::CONTENT_TYPE).to_ascii_lowercase().starts_with("application/json")
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f).await.map_err(|_| ApiError::internal())
}

/// Resolves the session cookie, records anomalies (audit + alert), and returns the session.
async fn authenticate(st: &AppState, h: &HeaderMap, ip: &str) -> Result<Session, ApiError> {
    let Some(raw) = session_cookie(h) else { return Err(ApiError::unauthenticated("missing")) };
    let touch = header_str(h, BACKGROUND_HEADER) != "1";
    let ua = header_str(h, header::USER_AGENT).to_string();
    let (db, cfg, ip_s) = (st.ctx.database.clone(), st.auth.clone(), ip.to_string());
    let check = blocking(move || {
        let db = db.lock().unwrap_or_else(|e| e.into_inner());
        auth::validate(&db, &cfg, &raw, &ip_s, &ua, touch, now())
    })
    .await?;
    match check {
        SessionCheck::Valid(s) => Ok(s),
        SessionCheck::Expired => Err(ApiError::unauthenticated("expired")),
        SessionCheck::Invalid => Err(ApiError::unauthenticated("invalid")),
        SessionCheck::Anomalous { session, reason, revoked } => {
            let (db, actor, user) = (st.ctx.database.clone(), format!("{}@{}", session.username, ip), session.username.clone());
            let policy = if revoked { "force_relogin" } else { "alert_only" };
            let detail = format!("{} (policy: {})", reason, policy);
            let _ = blocking(move || {
                db.lock().unwrap_or_else(|e| e.into_inner()).record_audit(&actor, "session_anomaly", &user, &detail);
                crate::store::alert::fire_from("auth", None, crate::store::alert::Severity::Medium, "Session Anomaly",
                    &format!("Session of '{}' used from a different client: {}. Policy: {}.", user, reason, policy));
            })
            .await;
            if revoked { Err(ApiError::unauthenticated("anomaly")) } else { Ok(session) }
        }
    }
}

/// CSRF and role checks for anything that is not GET/HEAD.
fn check_write(h: &HeaderMap, method: &Method, session: &Session, cfg: &AuthConfig, body: &[u8]) -> Result<(), ApiError> {
    if method == Method::GET || method == Method::HEAD {
        return Ok(());
    }
    if !origin_ok(h, cfg) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "origin_not_allowed", "origin not allowed"));
    }
    if !crate::store::audit::digest_eq(header_str(h, CSRF_HEADER), &session.csrf_token) {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "csrf", "missing or invalid CSRF token"));
    }
    if session.role != Role::Admin {
        return Err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "admin role required"));
    }
    if !json_body_ok(h, body) {
        return Err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", "Content-Type must be application/json"));
    }
    Ok(())
}

async fn read_body(body: Body) -> Result<Bytes, ApiError> {
    to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::new(StatusCode::PAYLOAD_TOO_LARGE, "payload_too_large", "request body too large"))
}

/// A request that passed authentication, CSRF and role checks.
struct Authed {
    session: Session,
    actor: String,
    parts: Parts,
    body: Bytes,
    ctx: Ctx,
}

async fn guard(st: &AppState, req: Request) -> Result<Authed, Response> {
    let (parts, body) = req.into_parts();
    let ctx = Ctx::of(parts.uri.path(), &parts.extensions);
    let ip = client_ip(&parts.extensions, &parts.headers);
    let session = authenticate(st, &parts.headers, &ip).await.map_err(|e| ctx.err(e))?;
    let body = read_body(body).await.map_err(|e| ctx.err(e))?;
    check_write(&parts.headers, &parts.method, &session, &st.auth, &body).map_err(|e| ctx.err(e))?;
    Ok(Authed { actor: format!("{}@{}", session.username, ip), session, parts, body, ctx })
}

fn query_map(parts: &Parts) -> HashMap<String, String> {
    parts.uri.query().unwrap_or("").split('&').filter_map(|kv| {
        let (k, v) = kv.split_once('=')?;
        Some((k.to_string(), v.replace('+', " ")))
    }).collect()
}

fn session_json(s: &Session) -> String {
    serde_json::json!({
        "username": s.username,
        "role": s.role,
        "csrf_token": s.csrf_token,
        "idle_expires_at": s.idle_expires_at,
        "absolute_expires_at": s.absolute_expires_at,
    })
    .to_string()
}

async fn login(State(st): State<AppState>, req: Request) -> Response {
    let (parts, body) = req.into_parts();
    let c = Ctx::of(parts.uri.path(), &parts.extensions);
    let ip = client_ip(&parts.extensions, &parts.headers);
    let h = parts.headers;
    let body = match read_body(body).await {
        Ok(b) => b,
        Err(e) => return c.err(e),
    };
    if !origin_ok(&h, &st.auth) {
        return c.err(ApiError::new(StatusCode::FORBIDDEN, "origin_not_allowed", "origin not allowed"));
    }
    if body.is_empty() || !json_body_ok(&h, &body) {
        return c.err(ApiError::new(StatusCode::UNSUPPORTED_MEDIA_TYPE, "unsupported_media_type", "Content-Type must be application/json"));
    }
    let creds: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let (Some(user), Some(pass)) = (creds["username"].as_str(), creds["password"].as_str()) else {
        return c.err(ApiError::bad_request("bad_request", "username and password required"));
    };
    let invalid = || ApiError::new(StatusCode::UNAUTHORIZED, "invalid_credentials", "invalid credentials");
    if user.len() > 64 || pass.len() > auth::MAX_PASSWORD_LEN {
        return c.err(invalid());
    }
    let (user, pass, ua, prev) = (user.to_string(), pass.to_string(), header_str(&h, header::USER_AGENT).to_string(), session_cookie(&h));
    let (db, cfg) = (st.ctx.database.clone(), st.auth.clone());
    let result = match blocking(move || {
        let db = db.lock().unwrap_or_else(|e| e.into_inner());
        auth::login(&db, &cfg, &user, &pass, &ip, &ua, prev.as_deref(), now())
    })
    .await
    {
        Ok(r) => r,
        Err(e) => return c.err(e),
    };
    match result {
        Ok((raw, session)) => {
            let mut res = json_ok(StatusCode::OK, session_json(&session));
            res.headers_mut().insert(header::SET_COOKIE, set_cookie_header(&raw, st.auth.absolute_secs));
            res
        }
        Err(LoginError::Locked { retry_after }) => c.err(ApiError {
            retry_after: Some(retry_after),
            ..ApiError::new(StatusCode::TOO_MANY_REQUESTS, "locked", "too many failed attempts; try again later")
        }),
        Err(LoginError::Invalid) => c.err(invalid()),
        Err(LoginError::Internal(e)) => {
            eprintln!("[auth] login error: {}", e);
            c.err(ApiError::internal())
        }
    }
}

async fn logout(State(st): State<AppState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let c = Ctx::of(parts.uri.path(), &parts.extensions);
    let ip = client_ip(&parts.extensions, &parts.headers);
    let h = parts.headers;
    let session = match authenticate(&st, &h, &ip).await {
        Ok(s) => s,
        Err(e) => return c.err(e),
    };
    if !origin_ok(&h, &st.auth) || !crate::store::audit::digest_eq(header_str(&h, CSRF_HEADER), &session.csrf_token) {
        return c.err(ApiError::new(StatusCode::FORBIDDEN, "csrf", "missing or invalid CSRF token"));
    }
    let raw = session_cookie(&h).unwrap_or_default();
    let (db, actor, user) = (st.ctx.database.clone(), format!("{}@{}", session.username, ip), session.username.clone());
    let _ = blocking(move || {
        let db = db.lock().unwrap_or_else(|e| e.into_inner());
        auth::logout(&db, &raw);
        db.record_audit(&actor, "logout", &user, "");
    })
    .await;
    let mut res = json_ok(StatusCode::OK, r#"{"status":"logged_out"}"#.into());
    res.headers_mut().insert(header::SET_COOKIE, clear_cookie_header());
    res
}

async fn session_info(State(st): State<AppState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let c = Ctx::of(parts.uri.path(), &parts.extensions);
    let ip = client_ip(&parts.extensions, &parts.headers);
    match authenticate(&st, &parts.headers, &ip).await {
        Ok(s) => json_ok(StatusCode::OK, session_json(&s)),
        Err(e) => c.err(e),
    }
}

/// SSE: requires a session; the stream ends when the session expires or is revoked.
async fn stream(State(st): State<AppState>, req: Request) -> Response {
    let (parts, _) = req.into_parts();
    let c = Ctx::of(parts.uri.path(), &parts.extensions);
    let ip = client_ip(&parts.extensions, &parts.headers);
    let h = parts.headers;
    if let Err(e) = authenticate(&st, &h, &ip).await {
        return c.err(e);
    }
    let raw = session_cookie(&h).unwrap_or_default();
    let ua = header_str(&h, header::USER_AGENT).to_string();
    let last_id: u64 = header_str(&h, "last-event-id").parse().unwrap_or(0);
    let (catch_up, rx) = {
        let mut b = st.ctx.sse_broadcaster.lock().unwrap_or_else(|e| e.into_inner());
        (b.catch_up_since(last_id), b.subscribe())
    };
    let (tx, out) = tokio::sync::mpsc::channel::<Result<Bytes, Infallible>>(64);
    let (db, cfg) = (st.ctx.database.clone(), st.auth.clone());
    std::thread::spawn(move || {
        let send = |s: String| tx.blocking_send(Ok(Bytes::from(s))).is_ok();
        if (!catch_up.is_empty() && !send(catch_up)) || !send("event: connected\ndata: {\"status\":\"ok\"}\n\n".into()) {
            return;
        }
        loop {
            match rx.recv_timeout(Duration::from_secs(15)) {
                Ok(msg) => {
                    if !send(msg) {
                        return;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    let still_valid = {
                        let db = db.lock().unwrap_or_else(|e| e.into_inner());
                        matches!(auth::validate(&db, &cfg, &raw, &ip, &ua, false, now()), SessionCheck::Valid(_))
                    };
                    if !still_valid {
                        let _ = send("event: session_ended\ndata: {}\n\n".into());
                        return;
                    }
                    if !send(": keepalive\n\n".into()) {
                        return;
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
    let body = Body::from_stream(tokio_stream::wrappers::ReceiverStream::new(out));
    Response::builder()
        .status(StatusCode::OK)
        .header(header::CONTENT_TYPE, "text/event-stream")
        .header(header::CACHE_CONTROL, "no-cache")
        .header("x-accel-buffering", "no")
        .body(body)
        .unwrap()
}

// ---------------------------------------------------------------- /api/v1 typed routes

fn parse_id(c: &Ctx, raw: &str) -> Result<i64, Response> {
    raw.parse::<i64>().ok().filter(|v| *v > 0).ok_or_else(|| c.err(ApiError::bad_request("invalid_id", "alert id must be a positive integer")))
}

fn parse_limit(c: &Ctx, q: &HashMap<String, String>, default: u32) -> Result<u32, Response> {
    match q.get("limit") {
        None => Ok(default),
        Some(v) => v.parse::<u32>().ok().filter(|n| (1..=MAX_PAGE).contains(n))
            .ok_or_else(|| c.err(ApiError::bad_request("invalid_limit", format!("limit must be 1-{}", MAX_PAGE)))),
    }
}

fn parse_body(c: &Ctx, body: &Bytes) -> Result<serde_json::Value, Response> {
    if body.is_empty() {
        return Ok(serde_json::json!({}));
    }
    serde_json::from_slice(body).map_err(|_| c.err(ApiError::bad_request("invalid_json", "body is not valid JSON")))
}

async fn db_call<T: Send + 'static>(st: &AppState, f: impl FnOnce(&crate::store::db::Database) -> T + Send + 'static) -> Result<T, ApiError> {
    let db = st.ctx.database.clone();
    blocking(move || f(&db.lock().unwrap_or_else(|e| e.into_inner()))).await
}

/// GET /api/v1/alerts?limit=&before_id=&severity=&detector=&acknowledged=&include_archived=
async fn v1_alerts(State(st): State<AppState>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let q = query_map(&a.parts);
    let limit = match parse_limit(&a.ctx, &q, 100) { Ok(v) => v, Err(r) => return r };
    let before_id = match q.get("before_id").map(|v| parse_id(&a.ctx, v)).transpose() { Ok(v) => v, Err(r) => return r };
    let severity = q.get("severity").cloned();
    if let Some(s) = &severity {
        if !matches!(s.as_str(), "Low" | "Medium" | "High" | "Critical") {
            return a.ctx.err(ApiError::bad_request("invalid_severity", "severity must be Low, Medium, High or Critical"));
        }
    }
    let acknowledged = match q.get("acknowledged").map(String::as_str) {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return a.ctx.err(ApiError::bad_request("invalid_acknowledged", "acknowledged must be true or false")),
    };
    let detector = q.get("detector").filter(|d| d.len() <= 40).cloned();
    let query = AlertQuery { before_id, limit, severity, detector, acknowledged, include_archived: q.get("include_archived").map(String::as_str) == Some("true") };
    match db_call(&st, move |db| db.list_alerts(&query)).await {
        Ok(items) => {
            let next = (items.len() as u32 == limit).then(|| items.last().map(|a| a.id)).flatten();
            json_ok(StatusCode::OK, serde_json::json!({ "items": items, "next_before_id": next }).to_string())
        }
        Err(e) => a.ctx.err(e),
    }
}

async fn v1_alert(State(st): State<AppState>, Path(id): Path<String>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let id = match parse_id(&a.ctx, &id) { Ok(v) => v, Err(r) => return r };
    match db_call(&st, move |db| db.get_alert(id)).await {
        Ok(Some(alert)) => json_ok(StatusCode::OK, serde_json::to_string(&alert).unwrap_or_default()),
        Ok(None) => a.ctx.err(ApiError::not_found("alert not found")),
        Err(e) => a.ctx.err(e),
    }
}

async fn v1_ack(State(st): State<AppState>, Path(id): Path<String>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let id = match parse_id(&a.ctx, &id) { Ok(v) => v, Err(r) => return r };
    let actor = a.actor.clone();
    let result = db_call(&st, move |db| {
        let r = db.ack_alert(id, &actor);
        if r == AckResult::Done {
            db.record_audit(&actor, "alert_ack", &id.to_string(), "");
        }
        (r, db.get_alert(id))
    })
    .await;
    match result {
        Ok((AckResult::NotFound, _)) | Ok((_, None)) => a.ctx.err(ApiError::not_found("alert not found")),
        Ok((r, Some(alert))) => json_ok(StatusCode::OK, serde_json::json!({ "status": if r == AckResult::Done { "acknowledged" } else { "already_acknowledged" }, "alert": alert }).to_string()),
        Err(e) => a.ctx.err(e),
    }
}

/// POST /api/v1/alerts/{id}/verdict {"verdict": "true_positive"|"false_positive"|"benign", "label"?: "Deauth_Flood"}
async fn v1_verdict(State(st): State<AppState>, Path(id): Path<String>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let id = match parse_id(&a.ctx, &id) { Ok(v) => v, Err(r) => return r };
    let body = match parse_body(&a.ctx, &a.body) { Ok(v) => v, Err(r) => return r };
    let verdict = body["verdict"].as_str().unwrap_or("").to_string();
    if !matches!(verdict.as_str(), "true_positive" | "false_positive" | "benign") {
        return a.ctx.err(ApiError::bad_request("invalid_verdict", "verdict must be true_positive, false_positive or benign"));
    }
    let label = body["label"].as_str().map(str::to_string);
    if let Some(l) = &label {
        if l.is_empty() || l.len() > 40 || !l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
            return a.ctx.err(ApiError::bad_request("invalid_label", "label must be 1-40 characters: letters, digits, '_'"));
        }
    }
    let actor = a.actor.clone();
    let result = db_call(&st, move |db| {
        if !db.set_verdict(id, &verdict, label.as_deref(), &actor) {
            return None;
        }
        db.record_audit(&actor, "alert_verdict", &id.to_string(), &format!("{} {}", verdict, label.as_deref().unwrap_or("")).trim().to_string());
        db.get_alert(id)
    })
    .await;
    match result {
        Ok(Some(alert)) => json_ok(StatusCode::OK, serde_json::json!({ "status": "recorded", "alert": alert }).to_string()),
        Ok(None) => a.ctx.err(ApiError::not_found("alert not found")),
        Err(e) => a.ctx.err(e),
    }
}

/// POST /api/v1/alerts/archive {"confirm": "CLEAR"}
async fn v1_archive(State(st): State<AppState>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let body = match parse_body(&a.ctx, &a.body) { Ok(v) => v, Err(r) => return r };
    if body["confirm"] != "CLEAR" {
        return a.ctx.err(ApiError::bad_request("confirmation_required", r#"send {"confirm":"CLEAR"} to archive all alerts"#));
    }
    let (db, actor) = (st.ctx.database.clone(), a.actor.clone());
    match blocking(move || legacy::archive_alerts(&db, &actor)).await {
        Ok(Ok((n, file))) => json_ok(StatusCode::OK, serde_json::json!({ "status": "archived", "archived": n, "archive_file": file }).to_string()),
        Ok(Err(e)) => {
            eprintln!("[api] archive failed: {}", e);
            a.ctx.err(ApiError::internal())
        }
        Err(e) => a.ctx.err(e),
    }
}

async fn v1_audit_verify(State(st): State<AppState>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    match db_call(&st, |db| (db.verify_alert_chain(), db.verify_audit_chain())).await {
        Ok((alerts, audit_log)) => {
            let clean = alerts.is_clean() && audit_log.is_clean();
            json_ok(StatusCode::OK, serde_json::json!({ "status": if clean { "clean" } else { "tampered" }, "alerts": alerts, "audit_log": audit_log }).to_string())
        }
        Err(e) => a.ctx.err(e),
    }
}

async fn v1_audit_log(State(st): State<AppState>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    if a.session.role != Role::Admin {
        return a.ctx.err(ApiError::new(StatusCode::FORBIDDEN, "forbidden", "admin role required"));
    }
    let q = query_map(&a.parts);
    let limit = match parse_limit(&a.ctx, &q, 100) { Ok(v) => v, Err(r) => return r };
    let before_id = match q.get("before_id").map(|v| parse_id(&a.ctx, v)).transpose() { Ok(v) => v, Err(r) => return r };
    match db_call(&st, move |db| db.audit_page(before_id, limit)).await {
        Ok(items) => {
            let next = (items.len() as u32 == limit).then(|| items.last().map(|e| e.id)).flatten();
            json_ok(StatusCode::OK, serde_json::json!({ "items": items, "next_before_id": next }).to_string())
        }
        Err(e) => a.ctx.err(e),
    }
}

/// GET /api/v1/logs?level=&service=&limit=&offset= ; newest first, invalid lines are skipped.
async fn v1_logs(State(st): State<AppState>, req: Request) -> Response {
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    let q = query_map(&a.parts);
    let limit = match parse_limit(&a.ctx, &q, 100) { Ok(v) => v as usize, Err(r) => return r };
    let offset: usize = match q.get("offset").map(|v| v.parse::<usize>()) {
        None => 0,
        Some(Ok(v)) => v,
        Some(Err(_)) => return a.ctx.err(ApiError::bad_request("invalid_offset", "offset must be a non-negative integer")),
    };
    let level = q.get("level").map(|l| l.to_ascii_uppercase());
    let service = q.get("service").cloned();
    let path = format!("data/logs/widps-{}.jsonl", chrono::Local::now().format("%Y-%m-%d"));
    let res = blocking(move || {
        let text = read_tail(&path, 4 * 1024 * 1024);
        let mut matched = text.lines().rev().filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok()).filter(|v| {
            level.as_deref().is_none_or(|lv| v["level"].as_str() == Some(lv)) && service.as_deref().is_none_or(|s| v["service"].as_str() == Some(s))
        });
        let items: Vec<serde_json::Value> = matched.by_ref().skip(offset).take(limit).collect();
        let more = matched.next().is_some();
        serde_json::json!({ "items": items, "next_offset": more.then_some(offset + limit) })
    })
    .await;
    match res {
        Ok(v) => json_ok(StatusCode::OK, v.to_string()),
        Err(e) => a.ctx.err(e),
    }
}

/// Last `max` bytes of a file, starting at a line boundary.
fn read_tail(path: &str, max: u64) -> String {
    use std::io::{Read, Seek, SeekFrom};
    let Ok(mut f) = std::fs::File::open(path) else { return String::new() };
    let len = f.metadata().map(|m| m.len()).unwrap_or(0);
    let start = len.saturating_sub(max);
    if f.seek(SeekFrom::Start(start)).is_err() {
        return String::new();
    }
    let mut buf = Vec::new();
    let _ = f.read_to_end(&mut buf);
    let text = String::from_utf8_lossy(&buf).into_owned();
    if start > 0 { text.split_once('\n').map(|(_, rest)| rest.to_string()).unwrap_or_default() } else { text }
}

async fn openapi(State(st): State<AppState>, req: Request) -> Response {
    if let Err(r) = guard(&st, req).await {
        return r;
    }
    json_ok(StatusCode::OK, openapi_doc().to_string())
}

pub fn openapi_doc() -> serde_json::Value {
    let op = |summary: &str| serde_json::json!({ "summary": summary, "responses": { "200": { "description": "OK" } } });
    serde_json::json!({
        "openapi": "3.0.3",
        "info": { "title": "WIDPS sensor API", "version": "1" },
        "components": {
            "securitySchemes": {
                "session": { "type": "apiKey", "in": "cookie", "name": COOKIE_NAME },
                "csrf": { "type": "apiKey", "in": "header", "name": "X-CSRF-Token", "description": "required on every non-GET request, with a same-origin Origin header" }
            }
        },
        "security": [{ "session": [] }],
        "x-error-shape": { "error": { "code": "string", "message": "string", "request_id": "string", "reason": "string (401 only)" } },
        "paths": {
            "/api/v1/auth/login": { "post": op("Sign in with {username, password}; sets the session cookie and returns the CSRF token") },
            "/api/v1/auth/logout": { "post": op("End the session") },
            "/api/v1/auth/session": { "get": op("Current user, role, CSRF token and expiry") },
            "/api/v1/stream": { "get": op("Server-sent events: alert, ml_prediction, connected, session_ended") },
            "/api/v1/alerts": { "get": op("Alerts newest first; query: limit (1-500), before_id, severity, detector, acknowledged, include_archived") },
            "/api/v1/alerts/{id}": { "get": op("One alert") },
            "/api/v1/alerts/{id}/ack": { "post": op("Acknowledge (admin)") },
            "/api/v1/alerts/{id}/verdict": { "post": op("Record analyst verdict {verdict: true_positive|false_positive|benign, label?} (admin)") },
            "/api/v1/alerts/archive": { "post": op("Archive all visible alerts {confirm: \"CLEAR\"} (admin)") },
            "/api/v1/audit/verify": { "get": op("Verify the alert and audit hash chains") },
            "/api/v1/audit/log": { "get": op("Audit log newest first; query: limit, before_id (admin)") },
            "/api/v1/logs": { "get": op("Structured logs for today; query: level, service, limit, offset") },
            "/api/v1/openapi.json": { "get": op("This document") },
            "/api/v1/{legacy}": { "get": op("Every other /api/<path> route is also served as /api/v1/<path> with v1 error bodies; these keep their legacy response shapes until ported") }
        }
    })
}

/// Every other /api route: session, CSRF and role checks, then the unchanged handler in api_server.rs.
async fn legacy(State(st): State<AppState>, req: Request) -> Response {
    let path = req.uri().path().to_string();
    let c = Ctx::of(&path, req.extensions());
    if !path.starts_with("/api/") {
        return c.err(ApiError::not_found("not found"));
    }
    let a = match guard(&st, req).await { Ok(a) => a, Err(r) => return r };
    if a.parts.method != Method::GET && a.parts.method != Method::HEAD && a.parts.method != Method::POST {
        return a.ctx.err(ApiError::new(StatusCode::METHOD_NOT_ALLOWED, "method_not_allowed", "method not allowed"));
    }
    let method = if a.parts.method == Method::HEAD { "GET".to_string() } else { a.parts.method.as_str().to_string() };
    let mut url = a.parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    if let Some(rest) = url.strip_prefix("/api/v1/") {
        url = format!("/api/{}", rest);
    }
    let body = String::from_utf8_lossy(&a.body).to_string();
    let (ctx, actor) = (st.ctx.clone(), a.actor.clone());
    match blocking(move || legacy::handle(&ctx, &method, &url, &body, &actor)).await {
        Ok(r) if r.status == 404 && a.ctx.v1 => a.ctx.err(ApiError::not_found("not found")),
        Ok(r) => (
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [(header::CONTENT_TYPE, r.content_type)],
            r.body,
        )
            .into_response(),
        Err(e) => a.ctx.err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api::legacy::ApiCtx;
    use crate::store::db::Database;
    use axum::http::Request as HttpRequest;
    use http_body_util::BodyExt;
    use std::collections::HashMap;
    use std::sync::atomic::{AtomicU32, AtomicU8};
    use std::sync::Mutex;
    use tower::ServiceExt;

    const PW: &str = "correct horse battery";
    const HOST: &str = "widps.local";
    const ORIGIN: &str = "https://widps.local";
    const UA: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";

    fn state_with(cfg: AuthConfig) -> AppState {
        crate::store::audit::init_for_tests();
        let dir = std::env::temp_dir().join(format!("widps-web-{}-{}", std::process::id(), auth_rand()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(&dir.join("w.db").display().to_string());
        auth::create_user(&db, "admin", PW, Role::Admin, 0).unwrap();
        auth::create_user(&db, "viewer", PW, Role::Viewer, 0).unwrap();
        let ctx = ApiCtx {
            runtime: Arc::new(crate::api::legacy::RuntimeState::new("wlan1mon")),
            ap_store: Arc::new(Mutex::new(HashMap::new())),
            current_channel: Arc::new(AtomicU8::new(1)),
            client_tracker: Arc::new(Mutex::new(crate::detect::client_tracker::ClientTracker::new())),
            packets_per_second: Arc::new(AtomicU32::new(0)),
            traffic_history: Arc::new(Mutex::new(Default::default())),
            ml_prediction: Arc::new(Mutex::new(None)),
            threat_scorer: Arc::new(Mutex::new(crate::detect::threat_scorer::ThreatScorer::new())),
            sse_broadcaster: Arc::new(Mutex::new(crate::api::sse::SseBroadcaster::new())),
            config_flags: Arc::new(crate::app::config::ConfigFlags::new()),
            database: Arc::new(Mutex::new(db)),
        };
        AppState { ctx, auth: Arc::new(cfg) }
    }

    fn auth_rand() -> String {
        use argon2::password_hash::rand_core::{OsRng, RngCore};
        format!("{:x}", OsRng.next_u64())
    }

    fn state() -> AppState {
        state_with(AuthConfig::default())
    }

    fn req(method: &str, uri: &str) -> axum::http::request::Builder {
        HttpRequest::builder().method(method).uri(uri).header(header::HOST, HOST).header(header::USER_AGENT, UA)
    }

    async fn send(st: &AppState, r: HttpRequest<Body>) -> (StatusCode, HeaderMap, String) {
        let res = router(st.clone()).oneshot(r).await.unwrap();
        let (p, b) = res.into_parts();
        let bytes = b.collect().await.unwrap().to_bytes();
        (p.status, p.headers, String::from_utf8_lossy(&bytes).to_string())
    }

    struct Login {
        cookie: String,
        csrf: String,
        set_cookie: String,
    }

    async fn login_as(st: &AppState, user: &str) -> Login {
        let body = serde_json::json!({"username": user, "password": PW}).to_string();
        let r = req("POST", "/api/auth/login").header(header::ORIGIN, ORIGIN).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)).unwrap();
        let (status, headers, body) = send(st, r).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let set_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().to_string();
        let cookie = set_cookie.split(';').next().unwrap().to_string();
        let csrf = serde_json::from_str::<serde_json::Value>(&body).unwrap()["csrf_token"].as_str().unwrap().to_string();
        Login { cookie, csrf, set_cookie }
    }

    fn authed(method: &str, uri: &str, l: &Login) -> axum::http::request::Builder {
        req(method, uri).header(header::COOKIE, &l.cookie)
    }

    fn write(uri: &str, l: &Login, body: &str) -> HttpRequest<Body> {
        authed("POST", uri, l).header(header::ORIGIN, ORIGIN).header(CSRF_HEADER, &l.csrf)
            .header(header::CONTENT_TYPE, "application/json").body(Body::from(body.to_string())).unwrap()
    }

    const ROUTES: &[&str] = &[
        "/api/alerts", "/api/networks", "/api/aps", "/api/status", "/api/traffic", "/api/clients", "/api/ai/predict",
        "/api/ai/shap", "/api/ai/history", "/api/ai/accuracy", "/api/threats", "/api/events", "/api/audit/integrity",
        "/api/audit/log", "/api/profiles", "/api/honeypot/status", "/api/siem/status", "/api/report", "/api/logs",
        "/api/logs/services", "/api/config", "/api/online-learning/status", "/api/intel", "/api/intel/threats",
        "/api/intel/feed", "/api/whitelist", "/api/stream", "/api/auth/session", "/api/alerts/1/ack",
        "/api/alerts/1/confirm", "/api/intel/AA-BB-CC-DD-EE-FF/blacklist", "/api/nope",
    ];

    #[tokio::test]
    async fn a3_every_route_requires_a_session() {
        let st = state();
        for path in ROUTES {
            for m in ["GET", "POST"] {
                let (status, headers, body) = send(&st, req(m, path).body(Body::empty()).unwrap()).await;
                // GET-only routes answer a POST with 405 before authentication, without any data.
                let get_only = matches!(*path, "/api/stream" | "/api/auth/session");
                if m == "POST" && get_only {
                    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED, "{} {}", m, path);
                    assert!(body.is_empty());
                    continue;
                }
                assert_eq!(status, StatusCode::UNAUTHORIZED, "{} {} -> {}", m, path, body);
                assert!(headers.get("access-control-allow-origin").is_none());
            }
        }
        let (status, _, _) = send(&st, req("GET", "/healthz").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::OK);
    }

    #[tokio::test]
    async fn a1_a2_cookie_flags_and_no_secret_in_body() {
        let st = state();
        let l = login_as(&st, "admin").await;
        let sc = &l.set_cookie;
        assert!(sc.starts_with("__Host-widps_sid="), "{}", sc);
        for flag in ["HttpOnly", "Secure", "SameSite=Strict", "Path=/"] {
            assert!(sc.contains(flag), "missing {} in {}", flag, sc);
        }
        assert!(!sc.to_ascii_lowercase().contains("domain="));
        let raw = l.cookie.split_once('=').unwrap().1;
        let (_, _, body) = send(&st, authed("GET", "/api/auth/session", &l).body(Body::empty()).unwrap()).await;
        assert!(!body.contains(raw), "session id must never appear in a response body");
    }

    #[tokio::test]
    async fn legacy_routes_work_with_a_session() {
        let st = state();
        let l = login_as(&st, "viewer").await;
        for path in ["/api/status", "/api/networks", "/api/alerts", "/api/audit/integrity", "/api/config", "/api/whitelist"] {
            let (status, headers, body) = send(&st, authed("GET", path, &l).body(Body::empty()).unwrap()).await;
            assert_eq!(status, StatusCode::OK, "{} -> {}", path, body);
            assert_eq!(headers.get(header::CONTENT_TYPE).unwrap(), "application/json");
            assert_eq!(headers.get("x-content-type-options").unwrap(), "nosniff");
            assert_eq!(headers.get(header::CACHE_CONTROL).unwrap(), "no-store");
        }
        let (status, _, _) = send(&st, authed("GET", "/api/nope", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn a8_wrong_password_and_unknown_user_identical_then_lockout() {
        let st = state();
        let mk = |u: &str, p: &str| {
            req("POST", "/api/auth/login").header(header::ORIGIN, ORIGIN).header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(serde_json::json!({"username": u, "password": p}).to_string())).unwrap()
        };
        let a = send(&st, mk("admin", "wrong password!!")).await;
        let b = send(&st, mk("ghost", "wrong password!!")).await;
        assert_eq!((a.0, &a.2), (b.0, &b.2));
        assert_eq!(a.0, StatusCode::UNAUTHORIZED);
        for _ in 0..5 {
            send(&st, mk("admin", "wrong password!!")).await;
        }
        let (status, headers, _) = send(&st, mk("admin", PW)).await;
        assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
        assert!(headers.get(header::RETRY_AFTER).is_some());
    }

    #[tokio::test]
    async fn a9_csrf_origin_and_content_type_are_enforced() {
        let st = state();
        let l = login_as(&st, "admin").await;
        let body = r#"{"action":"clear"}"#;
        let no_token = authed("POST", "/api/alerts", &l).header(header::ORIGIN, ORIGIN).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(body)).unwrap();
        assert_eq!(send(&st, no_token).await.0, StatusCode::FORBIDDEN);
        let bad_token = authed("POST", "/api/alerts", &l).header(header::ORIGIN, ORIGIN).header(CSRF_HEADER, "00".repeat(32))
            .header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap();
        assert_eq!(send(&st, bad_token).await.0, StatusCode::FORBIDDEN);
        let no_origin = authed("POST", "/api/alerts", &l).header(CSRF_HEADER, &l.csrf)
            .header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap();
        assert_eq!(send(&st, no_origin).await.0, StatusCode::FORBIDDEN);
        for evil in ["https://evil.com", "http://localhost.evil.com", "https://widps.local.evil.com", "null"] {
            let r = authed("POST", "/api/alerts", &l).header(header::ORIGIN, evil).header(CSRF_HEADER, &l.csrf)
                .header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap();
            assert_eq!(send(&st, r).await.0, StatusCode::FORBIDDEN, "{}", evil);
        }
        let plain = authed("POST", "/api/alerts", &l).header(header::ORIGIN, ORIGIN).header(CSRF_HEADER, &l.csrf)
            .header(header::CONTENT_TYPE, "text/plain").body(Body::from(body)).unwrap();
        assert_eq!(send(&st, plain).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (status, _, resp) = send(&st, write("/api/alerts", &l, body)).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "reaches the handler, which wants the confirm field: {}", resp);
    }

    #[tokio::test]
    async fn login_csrf_requires_same_origin() {
        let st = state();
        let r = req("POST", "/api/auth/login").header(header::ORIGIN, "https://evil.com").header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({"username": "admin", "password": PW}).to_string())).unwrap();
        assert_eq!(send(&st, r).await.0, StatusCode::FORBIDDEN);
        let form = req("POST", "/api/auth/login").header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded").body(Body::from("username=admin")).unwrap();
        assert_eq!(send(&st, form).await.0, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }

    #[tokio::test]
    async fn viewer_cannot_write_admin_can() {
        let st = state();
        let v = login_as(&st, "viewer").await;
        let (status, _, body) = send(&st, write("/api/config", &v, "{}")).await;
        assert_eq!(status, StatusCode::FORBIDDEN, "{}", body);
        let a = login_as(&st, "admin").await;
        let cfg = r#"{"channel_hopping":false}"#;
        let (status, _, body) = send(&st, write("/api/config", &a, cfg)).await;
        assert_eq!(status, StatusCode::OK, "{}", body);
        let audit = st.ctx.database.lock().unwrap().recent_audit(5);
        assert!(audit.iter().any(|e| e.action == "config_change" && e.actor.starts_with("admin@")));
    }

    #[tokio::test]
    async fn a7_logout_invalidates_cookie() {
        let st = state();
        let l = login_as(&st, "admin").await;
        let r = authed("POST", "/api/auth/logout", &l).header(header::ORIGIN, ORIGIN).header(CSRF_HEADER, &l.csrf).body(Body::empty()).unwrap();
        let (status, headers, _) = send(&st, r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().contains("Max-Age=0"));
        let (status, _, _) = send(&st, authed("GET", "/api/status", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a4_login_rotates_and_revokes_presented_cookie() {
        let st = state();
        let first = login_as(&st, "admin").await;
        let body = serde_json::json!({"username": "admin", "password": PW}).to_string();
        let r = req("POST", "/api/auth/login").header(header::COOKIE, &first.cookie).header(header::ORIGIN, ORIGIN)
            .header(header::CONTENT_TYPE, "application/json").body(Body::from(body)).unwrap();
        let (status, headers, _) = send(&st, r).await;
        assert_eq!(status, StatusCode::OK);
        let new_cookie = headers.get(header::SET_COOKIE).unwrap().to_str().unwrap().split(';').next().unwrap().to_string();
        assert_ne!(new_cookie, first.cookie);
        assert_eq!(send(&st, authed("GET", "/api/status", &first).body(Body::empty()).unwrap()).await.0, StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn a5_idle_expiry_returns_expired() {
        let st = state();
        let l = login_as(&st, "admin").await;
        st.ctx.database.lock().unwrap().conn().execute("UPDATE sessions SET last_seen = last_seen - 100000", []).unwrap();
        let (status, _, body) = send(&st, authed("GET", "/api/status", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("expired"), "{}", body);
    }

    #[tokio::test]
    async fn a11_anomaly_is_audited_and_force_relogin_blocks() {
        let mut cfg = AuthConfig::default();
        cfg.anomaly_policy = auth::AnomalyPolicy::ForceRelogin;
        let st = state_with(cfg);
        let l = login_as(&st, "admin").await;
        let chrome = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";
        let r = HttpRequest::builder().uri("/api/status").header(header::HOST, HOST).header(header::USER_AGENT, chrome)
            .header(header::COOKIE, &l.cookie).body(Body::empty()).unwrap();
        let (status, _, body) = send(&st, r).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        assert!(body.contains("anomaly"));
        let audit = st.ctx.database.lock().unwrap().recent_audit(5);
        assert!(audit.iter().any(|e| e.action == "session_anomaly"));
    }

    #[tokio::test]
    async fn body_limit_is_enforced() {
        let st = state();
        let l = login_as(&st, "admin").await;
        let big = "x".repeat(MAX_BODY_BYTES + 1);
        assert_eq!(send(&st, write("/api/config", &l, &big)).await.0, StatusCode::PAYLOAD_TOO_LARGE);
    }

    #[tokio::test]
    async fn a18_stream_requires_session_and_streams_events() {
        let st = state();
        let (status, _, _) = send(&st, req("GET", "/api/stream").body(Body::empty()).unwrap()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
        let l = login_as(&st, "viewer").await;
        let res = router(st.clone()).oneshot(authed("GET", "/api/stream", &l).body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert_eq!(res.headers().get(header::CONTENT_TYPE).unwrap(), "text/event-stream");
        let mut body = res.into_body();
        let first = tokio::time::timeout(Duration::from_secs(5), body.frame()).await.unwrap().unwrap().unwrap();
        assert!(String::from_utf8_lossy(first.data_ref().unwrap()).contains("event: connected"));
        st.ctx.sse_broadcaster.lock().unwrap().push("alert", "{\"title\":\"t\"}");
        let next = tokio::time::timeout(Duration::from_secs(5), body.frame()).await.unwrap().unwrap().unwrap();
        assert!(String::from_utf8_lossy(next.data_ref().unwrap()).contains("event: alert"));
    }

    #[tokio::test]
    async fn b9_open_stream_does_not_block_other_requests() {
        let st = state();
        let l = login_as(&st, "viewer").await;
        let _stream = router(st.clone()).oneshot(authed("GET", "/api/stream", &l).body(Body::empty()).unwrap()).await.unwrap();
        let mut tasks = Vec::new();
        for _ in 0..20 {
            let (st, cookie) = (st.clone(), l.cookie.clone());
            tasks.push(tokio::spawn(async move {
                let r = req("GET", "/api/status").header(header::COOKIE, cookie).header(BACKGROUND_HEADER, "1").body(Body::empty()).unwrap();
                router(st).oneshot(r).await.unwrap().status()
            }));
        }
        for t in tasks {
            assert_eq!(tokio::time::timeout(Duration::from_secs(10), t).await.unwrap().unwrap(), StatusCode::OK);
        }
    }

    #[test]
    fn origin_matching() {
        let cfg = AuthConfig { allowed_origins: vec!["http://localhost:5173".into()], ..Default::default() };
        let mk = |origin: &str, host: &str| {
            let mut h = HeaderMap::new();
            h.insert(header::ORIGIN, HeaderValue::from_str(origin).unwrap());
            h.insert(header::HOST, HeaderValue::from_str(host).unwrap());
            h
        };
        assert!(origin_ok(&mk("https://widps.local", "widps.local"), &cfg));
        assert!(origin_ok(&mk("http://localhost:5173", "127.0.0.1:8787"), &cfg));
        assert!(!origin_ok(&mk("https://widps.local.evil.com", "widps.local"), &cfg));
        assert!(!origin_ok(&mk("https://evil.com", "widps.local"), &cfg));
    }

    fn seed_alerts(st: &AppState, n: usize) -> Vec<i64> {
        let db = st.ctx.database.lock().unwrap();
        (0..n)
            .map(|i| db.insert_alert("2026-04-01 09:00:00", if i % 2 == 0 { "High" } else { "Critical" }, &format!("t{}", i), "d",
                Some("AA:BB:CC:DD:EE:01"), "deauth_flood").unwrap().id)
            .collect()
    }

    async fn json_of(st: &AppState, r: HttpRequest<Body>) -> (StatusCode, serde_json::Value) {
        let (s, _, b) = send(st, r).await;
        (s, serde_json::from_str(&b).unwrap_or(serde_json::Value::Null))
    }

    #[tokio::test]
    async fn v1_alerts_list_pages_and_filters() {
        let st = state();
        let ids = seed_alerts(&st, 5);
        let l = login_as(&st, "viewer").await;
        let (s, v) = json_of(&st, authed("GET", "/api/v1/alerts?limit=2", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::OK);
        let got: Vec<i64> = v["items"].as_array().unwrap().iter().map(|a| a["id"].as_i64().unwrap()).collect();
        assert_eq!(got, vec![ids[4], ids[3]]);
        assert_eq!(v["items"][0]["detector"], "deauth_flood");
        assert_eq!(v["items"][0]["bssid"], "AA:BB:CC:DD:EE:01");
        let next = v["next_before_id"].as_i64().unwrap();
        let (_, v2) = json_of(&st, authed("GET", &format!("/api/v1/alerts?limit=2&before_id={}", next), &l).body(Body::empty()).unwrap()).await;
        assert_eq!(v2["items"][0]["id"].as_i64(), Some(ids[2]));
        let (_, crit) = json_of(&st, authed("GET", "/api/v1/alerts?severity=Critical", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(crit["items"].as_array().unwrap().len(), 2);
        assert!(crit["next_before_id"].is_null());
        for bad in ["limit=0", "limit=501", "limit=x", "before_id=-1", "severity=Bogus", "acknowledged=maybe"] {
            let (s, e) = json_of(&st, authed("GET", &format!("/api/v1/alerts?{}", bad), &l).body(Body::empty()).unwrap()).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{}", bad);
            assert!(e["error"]["code"].is_string() && e["error"]["request_id"].is_string(), "{}: {}", bad, e);
        }
    }

    #[tokio::test]
    async fn v1_ack_uses_real_ids_and_records_actor() {
        let st = state();
        let ids = seed_alerts(&st, 3);
        let a = login_as(&st, "admin").await;
        let (s, v) = json_of(&st, write(&format!("/api/v1/alerts/{}/ack", ids[1]), &a, "")).await;
        assert_eq!(s, StatusCode::OK, "{}", v);
        assert_eq!(v["status"], "acknowledged");
        assert!(v["alert"]["ack_by"].as_str().unwrap().starts_with("admin@"));
        let (_, v) = json_of(&st, write(&format!("/api/v1/alerts/{}/ack", ids[1]), &a, "")).await;
        assert_eq!(v["status"], "already_acknowledged");
        let (_, one) = json_of(&st, authed("GET", &format!("/api/v1/alerts/{}", ids[0]), &a).body(Body::empty()).unwrap()).await;
        assert_eq!(one["acknowledged"], false, "only the targeted alert changes");
        let (s, e) = json_of(&st, write("/api/v1/alerts/99999/ack", &a, "")).await;
        assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
        let (s, _) = json_of(&st, write("/api/v1/alerts/abc/ack", &a, "")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let audit = st.ctx.database.lock().unwrap().recent_audit(10);
        assert_eq!(audit.iter().filter(|e| e.action == "alert_ack").count(), 1, "repeat ack is not audited twice");
    }

    #[tokio::test]
    async fn v1_verdict_and_viewer_restrictions() {
        let st = state();
        let ids = seed_alerts(&st, 1);
        let v = login_as(&st, "viewer").await;
        let (s, _) = json_of(&st, write(&format!("/api/v1/alerts/{}/verdict", ids[0]), &v, r#"{"verdict":"false_positive"}"#)).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = json_of(&st, authed("GET", "/api/v1/audit/log", &v).body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::FORBIDDEN, "audit log is admin-only");
        let a = login_as(&st, "admin").await;
        let (s, body) = json_of(&st, write(&format!("/api/v1/alerts/{}/verdict", ids[0]), &a, r#"{"verdict":"true_positive","label":"Deauth_Flood"}"#)).await;
        assert_eq!(s, StatusCode::OK, "{}", body);
        assert_eq!(body["alert"]["verdict"], "true_positive");
        assert_eq!(body["alert"]["verdict_label"], "Deauth_Flood");
        for bad in [r#"{"verdict":"maybe"}"#, r#"{"verdict":"benign","label":"x y"}"#, "not json"] {
            let (s, _) = json_of(&st, write(&format!("/api/v1/alerts/{}/verdict", ids[0]), &a, bad)).await;
            assert_eq!(s, StatusCode::BAD_REQUEST, "{}", bad);
        }
        let (_, log) = json_of(&st, authed("GET", "/api/v1/audit/log?limit=5", &a).body(Body::empty()).unwrap()).await;
        assert!(log["items"].as_array().unwrap().iter().any(|e| e["action"] == "alert_verdict"));
    }

    #[tokio::test]
    async fn v1_archive_requires_confirmation_and_hides_alerts() {
        let st = state();
        seed_alerts(&st, 2);
        let a = login_as(&st, "admin").await;
        let (s, e) = json_of(&st, write("/api/v1/alerts/archive", &a, "{}")).await;
        assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::BAD_REQUEST, Some("confirmation_required")));
        let (s, v) = json_of(&st, write("/api/v1/alerts/archive", &a, r#"{"confirm":"CLEAR"}"#)).await;
        assert_eq!(s, StatusCode::OK, "{}", v);
        assert_eq!(v["archived"], 2);
        let file = std::path::PathBuf::from(v["archive_file"].as_str().unwrap());
        assert!(file.exists());
        assert!(file.starts_with(std::env::temp_dir()), "tests must not write into the working copy: {}", file.display());
        let (_, list) = json_of(&st, authed("GET", "/api/v1/alerts", &a).body(Body::empty()).unwrap()).await;
        assert!(list["items"].as_array().unwrap().is_empty());
        let (_, all) = json_of(&st, authed("GET", "/api/v1/alerts?include_archived=true", &a).body(Body::empty()).unwrap()).await;
        assert_eq!(all["items"].as_array().unwrap().len(), 2);
        let (_, verify) = json_of(&st, authed("GET", "/api/v1/audit/verify", &a).body(Body::empty()).unwrap()).await;
        assert_eq!(verify["status"], "clean", "{}", verify);
    }

    #[tokio::test]
    async fn v1_errors_have_shape_and_request_id_header() {
        let st = state();
        let (s, h, b) = send(&st, req("GET", "/api/v1/alerts").body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED);
        let v: serde_json::Value = serde_json::from_str(&b).unwrap();
        assert_eq!(v["error"]["code"], "unauthenticated");
        assert_eq!(v["error"]["reason"], "missing");
        assert_eq!(v["error"]["request_id"].as_str().unwrap(), h.get("x-request-id").unwrap().to_str().unwrap());
        let (_, _, legacy) = send(&st, req("GET", "/api/status").body(Body::empty()).unwrap()).await;
        let lv: serde_json::Value = serde_json::from_str(&legacy).unwrap();
        assert_eq!((lv["error"].as_str(), lv["reason"].as_str()), (Some("unauthenticated"), Some("missing")), "legacy shape unchanged");
    }

    #[tokio::test]
    async fn v1_mirrors_legacy_routes_and_unknown_is_404() {
        let st = state();
        let l = login_as(&st, "viewer").await;
        for p in ["/api/v1/status", "/api/v1/networks", "/api/v1/whitelist", "/api/v1/config"] {
            let (s, _, b) = send(&st, authed("GET", p, &l).body(Body::empty()).unwrap()).await;
            assert_eq!(s, StatusCode::OK, "{} -> {}", p, b);
        }
        let (s, e) = json_of(&st, authed("GET", "/api/v1/nope", &l).body(Body::empty()).unwrap()).await;
        assert_eq!((s, e["error"]["code"].as_str()), (StatusCode::NOT_FOUND, Some("not_found")));
        let (s, v) = json_of(&st, req("POST", "/api/v1/auth/login").header(header::ORIGIN, ORIGIN).header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(serde_json::json!({"username":"viewer","password":PW}).to_string())).unwrap()).await;
        assert_eq!(s, StatusCode::OK);
        assert!(v["csrf_token"].is_string());
    }

    #[tokio::test]
    async fn legacy_intel_and_whitelist_validate_input() {
        let st = state();
        let a = login_as(&st, "admin").await;
        let (s, _, b) = send(&st, write("/api/intel/AA-BB-CC-DD-EE-FG/blacklist", &a, "{}")).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{}", b);
        let (s, _, b) = send(&st, write("/api/whitelist", &a, r#"{"ssid":"Lab","bssid":"not-a-mac"}"#)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{}", b);
        let long = "x".repeat(33);
        let (s, _, _) = send(&st, write("/api/whitelist", &a, &serde_json::json!({"ssid": long, "bssid": "AA:BB:CC:DD:EE:FF"}).to_string())).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
    }

    #[tokio::test]
    async fn openapi_lists_every_typed_v1_route() {
        let st = state();
        let l = login_as(&st, "viewer").await;
        let (s, doc) = json_of(&st, authed("GET", "/api/v1/openapi.json", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::OK);
        let src = include_str!("web.rs");
        let routes: Vec<&str> = src.lines().filter_map(|l| l.trim().strip_prefix(".route(\"/api/v1/")).map(|r| r.split('"').next().unwrap()).collect();
        assert!(routes.len() >= 12);
        for r in routes {
            let p = format!("/api/v1/{}", r);
            assert!(doc["paths"].get(&p).is_some(), "{} missing from openapi.json", p);
        }
    }

    #[tokio::test]
    async fn config_updates_are_partial() {
        let st = state();
        let a = login_as(&st, "admin").await;
        assert_eq!(send(&st, write("/api/config", &a, r#"{"retention_days":30,"auto_archive_hours":24}"#)).await.0, StatusCode::OK);
        let (s, _, b) = send(&st, write("/api/config", &a, r#"{"channel_hopping":false}"#)).await;
        assert_eq!(s, StatusCode::OK, "{}", b);
        let (_, cfg) = json_of(&st, authed("GET", "/api/v1/config", &a).body(Body::empty()).unwrap()).await;
        assert_eq!((cfg["retention_days"].as_u64(), cfg["auto_archive_hours"].as_u64(), cfg["channel_hopping"].as_bool()),
            (Some(30), Some(24), Some(false)), "{}", cfg);
        assert!(cfg.get("passive_scan").is_none() && cfg.get("client_warnings").is_none());
        let (s, _, b) = send(&st, write("/api/config", &a, r#"{"retention_days":"forever"}"#)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{}", b);
        let audit = st.ctx.database.lock().unwrap().recent_audit(10);
        let changes: Vec<&str> = audit.iter().filter(|e| e.action == "config_change").map(|e| e.detail.as_str()).collect();
        assert_eq!(changes, vec!["channel_hopping=false", "auto_archive_hours=24, retention_days=30"]);
    }

    #[tokio::test]
    async fn status_reports_real_mode_not_a_healthy_default() {
        let st = state();
        let l = login_as(&st, "viewer").await;
        let (_, v) = json_of(&st, authed("GET", "/api/status", &l).body(Body::empty()).unwrap()).await;
        assert_eq!((v["monitoringActive"].as_bool(), v["captureMode"].as_str(), v["aiModelStatus"].as_str()),
            (Some(false), Some("starting"), Some("Not running")), "{}", v);
        st.ctx.runtime.set_capture_mode(crate::api::legacy::CaptureMode::Simulated);
        let (_, v) = json_of(&st, authed("GET", "/api/status", &l).body(Body::empty()).unwrap()).await;
        assert_eq!(v["monitoringActive"], false);
        assert!(v["detectionEngineStatus"].as_str().unwrap().starts_with("Simulated"));
        st.ctx.runtime.set_capture_mode(crate::api::legacy::CaptureMode::Live);
        st.ctx.runtime.set_ml_running(true);
        let (_, v) = json_of(&st, authed("GET", "/api/status", &l).body(Body::empty()).unwrap()).await;
        assert_eq!((v["monitoringActive"].as_bool(), v["aiModelStatus"].as_str()), (Some(true), Some("Running (Random Forest)")));
    }
}

