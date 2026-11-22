// HTTP layer (axum): login, sessions, CSRF and roles in front of the unchanged legacy /api routes.
use crate::api_server::{self, ApiCtx};
use crate::auth::{self, AuthConfig, LoginError, Role, Session, SessionCheck, COOKIE_NAME};
use axum::body::{to_bytes, Body, Bytes};
use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, HeaderMap, HeaderValue, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::Router;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

pub const MAX_BODY_BYTES: usize = 10 * 1024;
const BACKGROUND_HEADER: &str = "x-widps-background";
const CSRF_HEADER: &str = "x-csrf-token";

#[derive(Clone)]
pub struct AppState {
    pub ctx: ApiCtx,
    pub auth: Arc<AuthConfig>,
}

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
        .fallback(legacy)
        .layer(axum::middleware::map_response(security_headers))
        .with_state(state)
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

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, [(header::CONTENT_TYPE, "application/json")], serde_json::json!({ "error": msg }).to_string()).into_response()
}

fn unauthenticated(reason: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        [(header::CONTENT_TYPE, "application/json")],
        serde_json::json!({ "error": "unauthenticated", "reason": reason }).to_string(),
    )
        .into_response()
}

fn header_str<'a>(h: &'a HeaderMap, name: impl header::AsHeaderName) -> &'a str {
    h.get(name).and_then(|v| v.to_str().ok()).unwrap_or("")
}

/// Peer address; X-Real-IP is trusted only when the peer is the local proxy.
fn client_ip(req: &Request) -> String {
    let peer = req.extensions().get::<ConnectInfo<SocketAddr>>().map(|c| c.0.ip());
    let forwarded = header_str(req.headers(), "x-real-ip").trim();
    let forwarded = forwarded.parse::<std::net::IpAddr>().ok();
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

async fn blocking<T: Send + 'static>(f: impl FnOnce() -> T + Send + 'static) -> Result<T, Response> {
    tokio::task::spawn_blocking(f).await.map_err(|_| json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error"))
}

/// Resolves the session cookie, records anomalies (audit + alert), and returns the session or a 401.
async fn authenticate(st: &AppState, h: &HeaderMap, ip: &str) -> Result<Session, Response> {
    let Some(raw) = session_cookie(h) else { return Err(unauthenticated("missing")) };
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
        SessionCheck::Expired => Err(unauthenticated("expired")),
        SessionCheck::Invalid => Err(unauthenticated("invalid")),
        SessionCheck::Anomalous { session, reason, revoked } => {
            let (db, actor, user) = (st.ctx.database.clone(), format!("{}@{}", session.username, ip), session.username.clone());
            let policy = if revoked { "force_relogin" } else { "alert_only" };
            let detail = format!("{} (policy: {})", reason, policy);
            let _ = blocking(move || {
                db.lock().unwrap_or_else(|e| e.into_inner()).record_audit(&actor, "session_anomaly", &user, &detail);
                crate::alert::fire(crate::alert::Severity::Medium, "Session Anomaly",
                    &format!("Session of '{}' used from a different client: {}. Policy: {}.", user, reason, policy));
            })
            .await;
            if revoked { Err(unauthenticated("anomaly")) } else { Ok(session) }
        }
    }
}

/// CSRF and role checks for anything that is not GET/HEAD.
fn check_write(h: &HeaderMap, method: &Method, session: &Session, cfg: &AuthConfig, body: &[u8]) -> Result<(), Response> {
    if method == Method::GET || method == Method::HEAD {
        return Ok(());
    }
    if !origin_ok(h, cfg) {
        return Err(json_error(StatusCode::FORBIDDEN, "origin not allowed"));
    }
    if !crate::audit::digest_eq(header_str(h, CSRF_HEADER), &session.csrf_token) {
        return Err(json_error(StatusCode::FORBIDDEN, "missing or invalid CSRF token"));
    }
    if session.role != Role::Admin {
        return Err(json_error(StatusCode::FORBIDDEN, "admin role required"));
    }
    if !json_body_ok(h, body) {
        return Err(json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json"));
    }
    Ok(())
}

async fn read_body(body: Body) -> Result<Bytes, Response> {
    to_bytes(body, MAX_BODY_BYTES).await.map_err(|_| json_error(StatusCode::PAYLOAD_TOO_LARGE, "request body too large"))
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
    let ip = client_ip(&req);
    let (parts, body) = req.into_parts();
    let h = parts.headers;
    let body = match read_body(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if !origin_ok(&h, &st.auth) {
        return json_error(StatusCode::FORBIDDEN, "origin not allowed");
    }
    if body.is_empty() || !json_body_ok(&h, &body) {
        return json_error(StatusCode::UNSUPPORTED_MEDIA_TYPE, "Content-Type must be application/json");
    }
    let creds: serde_json::Value = serde_json::from_slice(&body).unwrap_or_default();
    let (Some(user), Some(pass)) = (creds["username"].as_str(), creds["password"].as_str()) else {
        return json_error(StatusCode::BAD_REQUEST, "username and password required");
    };
    if user.len() > 64 || pass.len() > auth::MAX_PASSWORD_LEN {
        return json_error(StatusCode::UNAUTHORIZED, "invalid credentials");
    }
    let (user, pass, ua, prev) = (user.to_string(), pass.to_string(), header_str(&h, header::USER_AGENT).to_string(), session_cookie(&h));
    let (db, cfg, ip_s) = (st.ctx.database.clone(), st.auth.clone(), ip.clone());
    let result = match blocking(move || {
        let db = db.lock().unwrap_or_else(|e| e.into_inner());
        auth::login(&db, &cfg, &user, &pass, &ip_s, &ua, prev.as_deref(), now())
    })
    .await
    {
        Ok(r) => r,
        Err(r) => return r,
    };
    match result {
        Ok((raw, session)) => {
            let mut res = (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], session_json(&session)).into_response();
            res.headers_mut().insert(header::SET_COOKIE, set_cookie_header(&raw, st.auth.absolute_secs));
            res
        }
        Err(LoginError::Locked { retry_after }) => {
            let mut res = json_error(StatusCode::TOO_MANY_REQUESTS, "too many failed attempts; try again later");
            res.headers_mut().insert(header::RETRY_AFTER, HeaderValue::from(retry_after as u64));
            res
        }
        Err(LoginError::Invalid) => json_error(StatusCode::UNAUTHORIZED, "invalid credentials"),
        Err(LoginError::Internal(e)) => {
            eprintln!("[auth] login error: {}", e);
            json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
        }
    }
}

async fn logout(State(st): State<AppState>, req: Request) -> Response {
    let ip = client_ip(&req);
    let h = req.headers().clone();
    let session = match authenticate(&st, &h, &ip).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    if !origin_ok(&h, &st.auth) || !crate::audit::digest_eq(header_str(&h, CSRF_HEADER), &session.csrf_token) {
        return json_error(StatusCode::FORBIDDEN, "missing or invalid CSRF token");
    }
    let raw = session_cookie(&h).unwrap_or_default();
    let (db, actor, user) = (st.ctx.database.clone(), format!("{}@{}", session.username, ip), session.username.clone());
    let _ = blocking(move || {
        let db = db.lock().unwrap_or_else(|e| e.into_inner());
        auth::logout(&db, &raw);
        db.record_audit(&actor, "logout", &user, "");
    })
    .await;
    let mut res = (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], r#"{"status":"logged_out"}"#).into_response();
    res.headers_mut().insert(header::SET_COOKIE, clear_cookie_header());
    res
}

async fn session_info(State(st): State<AppState>, req: Request) -> Response {
    let ip = client_ip(&req);
    match authenticate(&st, req.headers(), &ip).await {
        Ok(s) => (StatusCode::OK, [(header::CONTENT_TYPE, "application/json")], session_json(&s)).into_response(),
        Err(r) => r,
    }
}

/// SSE: requires a session; the stream ends when the session expires or is revoked.
async fn stream(State(st): State<AppState>, req: Request) -> Response {
    let ip = client_ip(&req);
    let h = req.headers().clone();
    let mut bg = h.clone();
    bg.insert(BACKGROUND_HEADER, HeaderValue::from_static("1"));
    if let Err(r) = authenticate(&st, &h, &ip).await {
        return r;
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

/// Every other /api route: session, CSRF and role checks, then the unchanged handler in api_server.rs.
async fn legacy(State(st): State<AppState>, req: Request) -> Response {
    let ip = client_ip(&req);
    let (parts, body) = req.into_parts();
    if !parts.uri.path().starts_with("/api/") {
        return json_error(StatusCode::NOT_FOUND, "not found");
    }
    let session = match authenticate(&st, &parts.headers, &ip).await {
        Ok(s) => s,
        Err(r) => return r,
    };
    let body = match read_body(body).await {
        Ok(b) => b,
        Err(r) => return r,
    };
    if parts.method != Method::GET && parts.method != Method::HEAD && parts.method != Method::POST {
        return json_error(StatusCode::METHOD_NOT_ALLOWED, "method not allowed");
    }
    if let Err(r) = check_write(&parts.headers, &parts.method, &session, &st.auth, &body) {
        return r;
    }
    let method = if parts.method == Method::HEAD { "GET".to_string() } else { parts.method.as_str().to_string() };
    let url = parts.uri.path_and_query().map(|p| p.as_str().to_string()).unwrap_or_default();
    let body = String::from_utf8_lossy(&body).to_string();
    let actor = format!("{}@{}", session.username, ip);
    let ctx = st.ctx.clone();
    match blocking(move || api_server::handle(&ctx, &method, &url, &body, &actor)).await {
        Ok(r) => (
            StatusCode::from_u16(r.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
            [(header::CONTENT_TYPE, r.content_type)],
            r.body,
        )
            .into_response(),
        Err(r) => r,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::api_server::ApiCtx;
    use crate::db::Database;
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
        crate::audit::init_for_tests();
        let dir = std::env::temp_dir().join(format!("widps-web-{}-{}", std::process::id(), auth_rand()));
        std::fs::create_dir_all(&dir).unwrap();
        let db = Database::open(&dir.join("w.db").display().to_string());
        auth::create_user(&db, "admin", PW, Role::Admin, 0).unwrap();
        auth::create_user(&db, "viewer", PW, Role::Viewer, 0).unwrap();
        let ctx = ApiCtx {
            ap_store: Arc::new(Mutex::new(HashMap::new())),
            current_channel: Arc::new(AtomicU8::new(1)),
            client_tracker: Arc::new(Mutex::new(crate::client_tracker::ClientTracker::new())),
            packets_per_second: Arc::new(AtomicU32::new(0)),
            traffic_history: Arc::new(Mutex::new(Default::default())),
            ml_prediction: Arc::new(Mutex::new(None)),
            threat_scorer: Arc::new(Mutex::new(crate::threat_scorer::ThreatScorer::new())),
            sse_broadcaster: Arc::new(Mutex::new(crate::sse::SseBroadcaster::new())),
            config_flags: Arc::new(crate::config::ConfigFlags::new()),
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
        let cfg = r#"{"channel_hopping":true,"passive_scan":true,"client_tracking":true,"retention_days":0,"auto_archive_hours":0,"passive_blocking":true,"client_warnings":false}"#;
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
}
