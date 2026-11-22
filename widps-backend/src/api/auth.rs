// Users, sessions and login throttling stored in SQLite; all times are unix seconds passed in by the caller.
use crate::store::db::Database;
use argon2::password_hash::rand_core::{OsRng, RngCore};
use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use rusqlite::{params, Connection, OptionalExtension};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

pub const COOKIE_NAME: &str = "__Host-widps_sid";
pub const MIN_PASSWORD_LEN: usize = 12;
pub const MAX_PASSWORD_LEN: usize = 1024;
const TOUCH_INTERVAL_SECS: i64 = 15;

#[derive(Debug, Clone, Copy, PartialEq, serde::Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Admin,
    Viewer,
}

impl Role {
    pub fn parse(s: &str) -> Option<Role> {
        match s {
            "admin" => Some(Role::Admin),
            "viewer" => Some(Role::Viewer),
            _ => None,
        }
    }
    pub fn as_str(self) -> &'static str {
        match self {
            Role::Admin => "admin",
            Role::Viewer => "viewer",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum AnomalyPolicy {
    AlertOnly,
    ForceRelogin,
}

#[derive(Debug, Clone)]
pub struct AuthConfig {
    pub idle_secs: i64,
    pub absolute_secs: i64,
    pub anomaly_policy: AnomalyPolicy,
    pub max_failures: u32,
    pub failure_window_secs: i64,
    pub lockout_base_secs: i64,
    pub lockout_max_secs: i64,
    pub allowed_origins: Vec<String>,
}

impl Default for AuthConfig {
    fn default() -> Self {
        Self {
            idle_secs: 15 * 60,
            absolute_secs: 8 * 3600,
            anomaly_policy: AnomalyPolicy::AlertOnly,
            max_failures: 5,
            failure_window_secs: 15 * 60,
            lockout_base_secs: 30,
            lockout_max_secs: 15 * 60,
            allowed_origins: Vec::new(),
        }
    }
}

impl AuthConfig {
    /// WIDPS_SESSION_IDLE_MIN, WIDPS_SESSION_ABSOLUTE_HOURS, WIDPS_SESSION_ANOMALY_POLICY, WIDPS_ALLOWED_ORIGINS.
    pub fn from_env() -> Self {
        let mut c = Self::default();
        let num = |k: &str| std::env::var(k).ok().and_then(|v| v.trim().parse::<i64>().ok()).filter(|v| *v > 0);
        if let Some(m) = num("WIDPS_SESSION_IDLE_MIN") {
            c.idle_secs = m * 60;
        }
        if let Some(h) = num("WIDPS_SESSION_ABSOLUTE_HOURS") {
            c.absolute_secs = h * 3600;
        }
        if std::env::var("WIDPS_SESSION_ANOMALY_POLICY").as_deref() == Ok("force_relogin") {
            c.anomaly_policy = AnomalyPolicy::ForceRelogin;
        }
        if let Ok(v) = std::env::var("WIDPS_ALLOWED_ORIGINS") {
            c.allowed_origins = v.split(',').map(|s| s.trim().trim_end_matches('/').to_string()).filter(|s| !s.is_empty()).collect();
        }
        c
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct Session {
    #[serde(skip)]
    pub id_hash: String,
    pub username: String,
    pub role: Role,
    pub csrf_token: String,
    pub idle_expires_at: i64,
    pub absolute_expires_at: i64,
}

#[derive(Debug, PartialEq)]
pub enum LoginError {
    Invalid,
    Locked { retry_after: i64 },
    Internal(String),
}

#[derive(Debug)]
pub enum SessionCheck {
    Valid(Session),
    /// The browser family or network changed; `revoked` is true under the force_relogin policy.
    Anomalous { session: Session, reason: String, revoked: bool },
    Expired,
    Invalid,
}

pub fn migrate(conn: &Connection) {
    conn.execute_batch(
        "
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL CHECK (role IN ('admin', 'viewer')),
            created_at INTEGER NOT NULL,
            disabled INTEGER NOT NULL DEFAULT 0
        );
        CREATE TABLE IF NOT EXISTS sessions (
            id_hash TEXT PRIMARY KEY,
            user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
            csrf_token TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            last_seen INTEGER NOT NULL,
            absolute_expires INTEGER NOT NULL,
            ip TEXT NOT NULL,
            ua_family TEXT NOT NULL,
            anomalous INTEGER NOT NULL DEFAULT 0
        );
        CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
        CREATE TABLE IF NOT EXISTS login_attempts (
            key TEXT NOT NULL,
            ts INTEGER NOT NULL,
            success INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_login_attempts ON login_attempts(key, ts);
        ",
    )
    .expect("Failed to create auth tables");
}

fn argon2() -> Argon2<'static> {
    // OWASP minimum for Argon2id: 19 MiB memory, 2 iterations, 1 lane.
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).expect("valid argon2 params"))
}

pub fn hash_password(password: &str) -> Result<String, String> {
    let salt = SaltString::generate(&mut OsRng);
    argon2().hash_password(password.as_bytes(), &salt).map(|h| h.to_string()).map_err(|e| e.to_string())
}

pub fn verify_password(hash: &str, password: &str) -> bool {
    match PasswordHash::new(hash) {
        Ok(parsed) => argon2().verify_password(password.as_bytes(), &parsed).is_ok(),
        Err(_) => false,
    }
}

/// Verified against when the username does not exist, so both cases cost the same time.
fn dummy_hash() -> &'static str {
    static H: OnceLock<String> = OnceLock::new();
    H.get_or_init(|| hash_password("widps-dummy-password-for-timing").expect("dummy hash"))
}

pub fn validate_username(u: &str) -> Result<(), String> {
    let ok_len = (3..=32).contains(&u.len());
    let ok_chars = u.chars().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '_' | '-' | '.'));
    if ok_len && ok_chars {
        Ok(())
    } else {
        Err("username must be 3-32 characters: a-z, 0-9, '_', '-', '.'".into())
    }
}

pub fn validate_password(p: &str) -> Result<(), String> {
    if p.chars().count() < MIN_PASSWORD_LEN {
        return Err(format!("password must be at least {} characters", MIN_PASSWORD_LEN));
    }
    if p.len() > MAX_PASSWORD_LEN {
        return Err(format!("password must be at most {} bytes", MAX_PASSWORD_LEN));
    }
    Ok(())
}

pub fn create_user(db: &Database, username: &str, password: &str, role: Role, now: i64) -> Result<(), String> {
    validate_username(username)?;
    validate_password(password)?;
    let hash = hash_password(password)?;
    db.conn()
        .execute(
            "INSERT INTO users (username, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4)",
            params![username, hash, role.as_str(), now],
        )
        .map_err(|e| if e.to_string().contains("UNIQUE") { format!("user '{}' already exists", username) } else { e.to_string() })?;
    db.record_audit("cli", "user_create", username, role.as_str());
    Ok(())
}

/// Changes the password and revokes every session of that user.
pub fn set_password(db: &Database, username: &str, password: &str) -> Result<(), String> {
    validate_password(password)?;
    let hash = hash_password(password)?;
    let n = db.conn()
        .execute("UPDATE users SET password_hash = ?1 WHERE username = ?2", params![hash, username])
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("no user '{}'", username));
    }
    revoke_user_sessions(db, username)?;
    db.record_audit("cli", "user_password_change", username, "all sessions revoked");
    Ok(())
}

pub fn set_disabled(db: &Database, username: &str, disabled: bool) -> Result<(), String> {
    let n = db.conn()
        .execute("UPDATE users SET disabled = ?1 WHERE username = ?2", params![disabled as i64, username])
        .map_err(|e| e.to_string())?;
    if n == 0 {
        return Err(format!("no user '{}'", username));
    }
    if disabled {
        revoke_user_sessions(db, username)?;
    }
    db.record_audit("cli", if disabled { "user_disable" } else { "user_enable" }, username, "");
    Ok(())
}

pub fn revoke_user_sessions(db: &Database, username: &str) -> Result<usize, String> {
    db.conn()
        .execute("DELETE FROM sessions WHERE user_id = (SELECT id FROM users WHERE username = ?1)", params![username])
        .map_err(|e| e.to_string())
}

pub fn list_users(db: &Database) -> Vec<(String, String, bool)> {
    let Ok(mut st) = db.conn().prepare("SELECT username, role, disabled FROM users ORDER BY username") else {
        return Vec::new();
    };
    st.query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? != 0)))
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
}

pub fn user_count(db: &Database) -> i64 {
    db.conn().query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0)).unwrap_or(0)
}

fn random_hex(bytes: usize) -> String {
    let mut buf = vec![0u8; bytes];
    OsRng.fill_bytes(&mut buf);
    hex::encode(buf)
}

pub fn hash_session_id(raw: &str) -> String {
    hex::encode(Sha256::digest(raw.as_bytes()))
}

fn looks_like_session_id(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Coarse browser family, used to notice a session cookie moving to another client.
pub fn ua_family(ua: &str) -> &'static str {
    if ua.is_empty() {
        "none"
    } else if ua.contains("Firefox/") {
        "firefox"
    } else if ua.contains("Edg/") {
        "edge"
    } else if ua.contains("OPR/") {
        "opera"
    } else if ua.contains("Chrome/") || ua.contains("Chromium/") {
        "chrome"
    } else if ua.contains("Safari/") {
        "safari"
    } else if ua.starts_with("curl/") {
        "curl"
    } else {
        "other"
    }
}

/// IPv4 /24 or IPv6 /64, so normal DHCP churn inside one network is not an anomaly.
pub fn ip_range(ip: &str) -> String {
    match ip.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            let o = v4.octets();
            format!("{}.{}.{}.0/24", o[0], o[1], o[2])
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            let s = v6.segments();
            format!("{:x}:{:x}:{:x}:{:x}::/64", s[0], s[1], s[2], s[3])
        }
        Err(_) => ip.to_string(),
    }
}

/// Seconds until `key` may try again, or 0. Counts failures since the last success inside the window.
fn lockout_remaining(c: &Connection, cfg: &AuthConfig, key: &str, now: i64) -> rusqlite::Result<i64> {
    let since = now - cfg.failure_window_secs;
    let last_success: i64 = c
        .query_row("SELECT COALESCE(MAX(ts), 0) FROM login_attempts WHERE key = ?1 AND success = 1", params![key], |r| r.get(0))?;
    let (count, last_fail): (i64, Option<i64>) = c.query_row(
        "SELECT COUNT(*), MAX(ts) FROM login_attempts WHERE key = ?1 AND success = 0 AND ts > ?2",
        params![key, since.max(last_success)],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    if count < cfg.max_failures as i64 {
        return Ok(0);
    }
    let exp = (count - cfg.max_failures as i64).min(20) as u32;
    let wait = (cfg.lockout_base_secs.saturating_mul(1i64 << exp)).min(cfg.lockout_max_secs);
    Ok((last_fail.unwrap_or(now) + wait - now).max(0))
}

fn record_attempt(c: &Connection, key: &str, now: i64, success: bool) {
    let _ = c.execute("INSERT INTO login_attempts (key, ts, success) VALUES (?1, ?2, ?3)", params![key, now, success as i64]);
    let _ = c.execute("DELETE FROM login_attempts WHERE ts < ?1", params![now - 7 * 86400]);
}

/// Checks the password and creates a new session. `previous_raw` (a cookie sent with the login) is revoked.
pub fn login(
    db: &Database, cfg: &AuthConfig, username: &str, password: &str, ip: &str, ua: &str,
    previous_raw: Option<&str>, now: i64,
) -> Result<(String, Session), LoginError> {
    let c = db.conn();
    let ip_key = format!("ip:{}", ip);
    let user_key = format!("user:{}", username.to_ascii_lowercase());
    let wait = lockout_remaining(c, cfg, &ip_key, now)
        .and_then(|a| lockout_remaining(c, cfg, &user_key, now).map(|b| a.max(b)))
        .map_err(|e| LoginError::Internal(e.to_string()))?;
    if wait > 0 {
        // Attempts during a lockout count too, so a continuing attack keeps growing the backoff (capped).
        record_attempt(c, &ip_key, now, false);
        record_attempt(c, &user_key, now, false);
        return Err(LoginError::Locked { retry_after: wait });
    }

    let user: Option<(i64, String, String, bool)> = c
        .query_row(
            "SELECT id, password_hash, role, disabled FROM users WHERE username = ?1",
            params![username],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get::<_, i64>(3)? != 0)),
        )
        .optional()
        .map_err(|e| LoginError::Internal(e.to_string()))?;

    let password_ok = match &user {
        Some((_, hash, _, _)) => verify_password(hash, password),
        None => {
            let _ = verify_password(dummy_hash(), password);
            false
        }
    };
    let (user_id, role) = match user {
        Some((id, _, role, disabled)) if password_ok && !disabled => (id, Role::parse(&role).unwrap_or(Role::Viewer)),
        _ => {
            record_attempt(c, &ip_key, now, false);
            record_attempt(c, &user_key, now, false);
            db.record_audit(&format!("{}@{}", username, ip), "login_failure", username, "");
            return Err(LoginError::Invalid);
        }
    };
    record_attempt(c, &ip_key, now, true);
    record_attempt(c, &user_key, now, true);

    if let Some(prev) = previous_raw {
        let _ = c.execute("DELETE FROM sessions WHERE id_hash = ?1", params![hash_session_id(prev)]);
    }
    let _ = c.execute("DELETE FROM sessions WHERE absolute_expires < ?1 OR last_seen < ?2", params![now, now - cfg.idle_secs]);

    let raw = random_hex(32);
    let session = Session {
        id_hash: hash_session_id(&raw),
        username: username.to_string(),
        role,
        csrf_token: random_hex(32),
        idle_expires_at: now + cfg.idle_secs,
        absolute_expires_at: now + cfg.absolute_secs,
    };
    c.execute(
        "INSERT INTO sessions (id_hash, user_id, csrf_token, created_at, last_seen, absolute_expires, ip, ua_family)
         VALUES (?1, ?2, ?3, ?4, ?4, ?5, ?6, ?7)",
        params![session.id_hash, user_id, session.csrf_token, now, session.absolute_expires_at, ip, ua_family(ua)],
    )
    .map_err(|e| LoginError::Internal(e.to_string()))?;
    db.record_audit(&format!("{}@{}", username, ip), "login_success", username, ua_family(ua));
    Ok((raw, session))
}

/// Looks up a session. `touch` extends the idle timer (user activity); background polling passes false.
pub fn validate(db: &Database, cfg: &AuthConfig, raw: &str, ip: &str, ua: &str, touch: bool, now: i64) -> SessionCheck {
    if !looks_like_session_id(raw) {
        return SessionCheck::Invalid;
    }
    let c = db.conn();
    let id_hash = hash_session_id(raw);
    let row: Option<(String, String, String, i64, i64, String, String, bool, bool)> = c
        .query_row(
            "SELECT u.username, u.role, s.csrf_token, s.last_seen, s.absolute_expires, s.ip, s.ua_family, s.anomalous, u.disabled
             FROM sessions s JOIN users u ON u.id = s.user_id WHERE s.id_hash = ?1",
            params![id_hash],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?, r.get(6)?,
                    r.get::<_, i64>(7)? != 0, r.get::<_, i64>(8)? != 0)),
        )
        .optional()
        .unwrap_or(None);
    let Some((username, role, csrf, last_seen, abs_exp, s_ip, s_ua, anomalous, disabled)) = row else {
        return SessionCheck::Invalid;
    };
    if disabled {
        let _ = c.execute("DELETE FROM sessions WHERE id_hash = ?1", params![id_hash]);
        return SessionCheck::Invalid;
    }
    if now >= abs_exp || now >= last_seen + cfg.idle_secs {
        let _ = c.execute("DELETE FROM sessions WHERE id_hash = ?1", params![id_hash]);
        return SessionCheck::Expired;
    }
    let mut last_seen = last_seen;
    if touch && now - last_seen >= TOUCH_INTERVAL_SECS {
        let _ = c.execute("UPDATE sessions SET last_seen = ?1 WHERE id_hash = ?2", params![now, id_hash]);
        last_seen = now;
    }
    let session = Session {
        id_hash: id_hash.clone(),
        username,
        role: Role::parse(&role).unwrap_or(Role::Viewer),
        csrf_token: csrf,
        idle_expires_at: (last_seen + cfg.idle_secs).min(abs_exp),
        absolute_expires_at: abs_exp,
    };

    let fam = ua_family(ua);
    let mut reasons = Vec::new();
    if fam != s_ua {
        reasons.push(format!("browser changed from {} to {}", s_ua, fam));
    }
    if ip_range(ip) != ip_range(&s_ip) {
        reasons.push(format!("network changed from {} to {}", ip_range(&s_ip), ip_range(ip)));
    }
    if reasons.is_empty() {
        return SessionCheck::Valid(session);
    }
    let reason = reasons.join("; ");
    match cfg.anomaly_policy {
        AnomalyPolicy::ForceRelogin => {
            let _ = c.execute("DELETE FROM sessions WHERE id_hash = ?1", params![id_hash]);
            SessionCheck::Anomalous { session, reason, revoked: true }
        }
        AnomalyPolicy::AlertOnly if !anomalous => {
            let _ = c.execute("UPDATE sessions SET anomalous = 1 WHERE id_hash = ?1", params![id_hash]);
            SessionCheck::Anomalous { session, reason, revoked: false }
        }
        AnomalyPolicy::AlertOnly => SessionCheck::Valid(session),
    }
}

pub fn logout(db: &Database, raw: &str) -> bool {
    db.conn().execute("DELETE FROM sessions WHERE id_hash = ?1", params![hash_session_id(raw)]).map(|n| n > 0).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub fn test_db() -> Database {
        crate::store::audit::init_for_tests();
        let dir = std::env::temp_dir().join(format!("widps-auth-{}-{}", std::process::id(), random_hex(6)));
        std::fs::create_dir_all(&dir).unwrap();
        Database::open(&dir.join("a.db").display().to_string())
    }

    const PW: &str = "correct horse battery";
    const FF: &str = "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0";
    const CHROME: &str = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0 Safari/537.36";

    fn setup() -> (Database, AuthConfig) {
        let db = test_db();
        create_user(&db, "alice", PW, Role::Admin, 1_000).unwrap();
        (db, AuthConfig::default())
    }

    #[test]
    fn password_hash_is_argon2id_and_verifies() {
        let h = hash_password(PW).unwrap();
        assert!(h.starts_with("$argon2id$"));
        assert!(verify_password(&h, PW));
        assert!(!verify_password(&h, "wrong password here"));
        assert_ne!(h, hash_password(PW).unwrap(), "salts must differ");
    }

    #[test]
    fn user_validation() {
        assert!(validate_username("ops.admin_1").is_ok());
        assert!(validate_username("Al").is_err());
        assert!(validate_username("bad name").is_err());
        assert!(validate_password("short").is_err());
        assert!(validate_password(PW).is_ok());
        let (db, _) = setup();
        assert!(create_user(&db, "alice", PW, Role::Viewer, 0).unwrap_err().contains("exists"));
        let stored: String = db.conn().query_row("SELECT password_hash FROM users WHERE username='alice'", [], |r| r.get(0)).unwrap();
        assert!(!stored.contains(PW));
    }

    #[test]
    fn login_creates_session_with_hashed_id() {
        let (db, cfg) = setup();
        let (raw, s) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 2_000).unwrap();
        assert!(looks_like_session_id(&raw));
        assert_eq!(s.role, Role::Admin);
        let stored: String = db.conn().query_row("SELECT id_hash FROM sessions", [], |r| r.get(0)).unwrap();
        assert_eq!(stored, hash_session_id(&raw));
        assert_ne!(stored, raw);
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, 2_001), SessionCheck::Valid(_)));
    }

    #[test]
    fn wrong_password_and_unknown_user_look_the_same() {
        let (db, cfg) = setup();
        assert_eq!(login(&db, &cfg, "alice", "wrong password!!", "10.0.0.5", FF, None, 2_000).unwrap_err(), LoginError::Invalid);
        assert_eq!(login(&db, &cfg, "mallory", PW, "10.0.0.6", FF, None, 2_000).unwrap_err(), LoginError::Invalid);
    }

    #[test]
    fn lockout_after_repeated_failures_even_with_right_password() {
        let (db, cfg) = setup();
        for i in 0..cfg.max_failures {
            assert_eq!(login(&db, &cfg, "alice", "wrong password!!", "10.0.0.5", FF, None, 2_000 + i as i64).unwrap_err(), LoginError::Invalid);
        }
        match login(&db, &cfg, "alice", PW, "10.0.0.9", FF, None, 2_010) {
            Err(LoginError::Locked { retry_after }) => assert!(retry_after > 0 && retry_after <= cfg.lockout_base_secs),
            other => panic!("expected lockout, got {:?}", other.map(|_| ())),
        }
        let after = 2_010 + lockout_remaining(db.conn(), &cfg, "user:alice", 2_010).unwrap() + 1;
        assert!(login(&db, &cfg, "alice", PW, "10.0.0.9", FF, None, after).is_ok());
    }

    #[test]
    fn lockout_grows_and_is_capped() {
        let (db, cfg) = setup();
        let mut now = 5_000;
        for _ in 0..cfg.max_failures + 3 {
            let _ = login(&db, &cfg, "alice", "wrong password!!", "10.0.0.5", FF, None, now);
            now += 1;
        }
        let rem = lockout_remaining(db.conn(), &cfg, "user:alice", now).unwrap();
        assert!(rem > cfg.lockout_base_secs * 4, "{}", rem);
        assert!(rem <= cfg.lockout_max_secs);
    }

    #[test]
    fn idle_and_absolute_timeouts() {
        let (db, cfg) = setup();
        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 10_000).unwrap();
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, false, 10_000 + cfg.idle_secs), SessionCheck::Expired));
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, false, 10_001), SessionCheck::Invalid), "expired session is deleted");

        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 20_000).unwrap();
        let mut t = 20_000;
        while t + cfg.idle_secs / 2 < 20_000 + cfg.absolute_secs {
            t += cfg.idle_secs / 2;
            assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, t), SessionCheck::Valid(_)), "t={}", t);
        }
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, 20_000 + cfg.absolute_secs), SessionCheck::Expired));
    }

    #[test]
    fn background_requests_do_not_extend_idle() {
        let (db, cfg) = setup();
        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 10_000).unwrap();
        for t in (10_030..10_000 + cfg.idle_secs).step_by(30) {
            assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, false, t), SessionCheck::Valid(_)));
        }
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, false, 10_000 + cfg.idle_secs), SessionCheck::Expired));
    }

    #[test]
    fn login_revokes_a_cookie_sent_with_it() {
        let (db, cfg) = setup();
        let (old, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 2_000).unwrap();
        let (new, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, Some(&old), 2_100).unwrap();
        assert_ne!(old, new);
        assert!(matches!(validate(&db, &cfg, &old, "10.0.0.5", FF, true, 2_101), SessionCheck::Invalid));
        assert!(matches!(validate(&db, &cfg, &new, "10.0.0.5", FF, true, 2_101), SessionCheck::Valid(_)));
    }

    #[test]
    fn anomaly_alert_only_flags_once() {
        let (db, cfg) = setup();
        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 2_000).unwrap();
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.77", FF, true, 2_001), SessionCheck::Valid(_)), "same /24 is fine");
        match validate(&db, &cfg, &raw, "10.0.0.5", CHROME, true, 2_002) {
            SessionCheck::Anomalous { revoked, reason, .. } => {
                assert!(!revoked);
                assert!(reason.contains("firefox to chrome"), "{}", reason);
            }
            other => panic!("{:?}", other),
        }
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", CHROME, true, 2_003), SessionCheck::Valid(_)));
    }

    #[test]
    fn anomaly_force_relogin_revokes() {
        let (db, mut cfg) = setup();
        cfg.anomaly_policy = AnomalyPolicy::ForceRelogin;
        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 2_000).unwrap();
        assert!(matches!(validate(&db, &cfg, &raw, "192.168.9.9", FF, true, 2_001), SessionCheck::Anomalous { revoked: true, .. }));
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, 2_002), SessionCheck::Invalid));
    }

    #[test]
    fn password_change_and_disable_revoke_sessions() {
        let (db, cfg) = setup();
        let (raw, _) = login(&db, &cfg, "alice", PW, "10.0.0.5", FF, None, 2_000).unwrap();
        set_password(&db, "alice", "another long password").unwrap();
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, 2_001), SessionCheck::Invalid));
        let (raw, _) = login(&db, &cfg, "alice", "another long password", "10.0.0.5", FF, None, 2_002).unwrap();
        set_disabled(&db, "alice", true).unwrap();
        assert!(matches!(validate(&db, &cfg, &raw, "10.0.0.5", FF, true, 2_003), SessionCheck::Invalid));
        assert_eq!(login(&db, &cfg, "alice", "another long password", "10.0.0.5", FF, None, 2_004).unwrap_err(), LoginError::Invalid);
    }

    #[test]
    fn garbage_cookie_is_invalid() {
        let (db, cfg) = setup();
        for raw in ["", "abc", &"z".repeat(64), "' OR 1=1 --"] {
            assert!(matches!(validate(&db, &cfg, raw, "10.0.0.5", FF, true, 1), SessionCheck::Invalid));
        }
    }

    #[test]
    fn helpers() {
        assert_eq!(ua_family(FF), "firefox");
        assert_eq!(ua_family(CHROME), "chrome");
        assert_eq!(ua_family("curl/8.0"), "curl");
        assert_eq!(ip_range("192.168.1.77"), "192.168.1.0/24");
        assert_eq!(ip_range("2001:db8:1:2:3:4:5:6"), "2001:db8:1:2::/64");
    }
}
