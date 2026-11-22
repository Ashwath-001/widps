use crate::audit;
use rusqlite::{params, Connection, OptionalExtension};
use std::io::Write;
use std::sync::{Arc, Mutex};

pub type SharedDb = Arc<Mutex<Database>>;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Self {
        // Ensure parent directory exists
        if let Some(parent) = std::path::Path::new(path).parent() {
            let _ = std::fs::create_dir_all(parent);
        }

        let conn = Connection::open(path).expect("Failed to open SQLite database");

        conn.execute_batch("
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous = NORMAL;
            PRAGMA cache_size = -8000;
            PRAGMA busy_timeout = 5000;
        ").expect("Failed to set PRAGMA");

        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                severity TEXT NOT NULL,
                title TEXT NOT NULL,
                detail TEXT,
                bssid TEXT,
                source TEXT DEFAULT 'rule',
                acknowledged INTEGER DEFAULT 0,
                hmac_signature TEXT
            );

            CREATE TABLE IF NOT EXISTS networks (
                bssid TEXT PRIMARY KEY,
                ssid TEXT,
                channel INTEGER,
                rssi INTEGER,
                vendor TEXT,
                encryption TEXT,
                status TEXT DEFAULT 'Normal',
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS ml_predictions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                label TEXT NOT NULL,
                confidence REAL,
                threat_score INTEGER,
                frame_count INTEGER
            );

            CREATE TABLE IF NOT EXISTS shap_explanations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                prediction_label TEXT NOT NULL,
                confidence REAL,
                top_features TEXT NOT NULL,
                shap_values TEXT NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_ml_time ON ml_predictions(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_shap_time ON shap_explanations(timestamp DESC);

            CREATE TABLE IF NOT EXISTS confirmed_samples (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                label TEXT NOT NULL,
                confirmed_by TEXT DEFAULT 'admin',
                features TEXT NOT NULL,
                used_in_retrain INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_confirmed_label ON confirmed_samples(label);
        ").expect("Failed to create tables");

        // Migration: add hmac_signature column if missing (existing DBs)
        let _ = conn.execute("ALTER TABLE alerts ADD COLUMN hmac_signature TEXT", []);
        // Hash-chain columns; rows written before this migration stay unchained ("legacy").
        let _ = conn.execute("ALTER TABLE alerts ADD COLUMN prev_hash TEXT", []);
        let _ = conn.execute("ALTER TABLE alerts ADD COLUMN record_hash TEXT", []);
        let _ = conn.execute("ALTER TABLE alerts ADD COLUMN archived INTEGER NOT NULL DEFAULT 0", []);
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS audit_log (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                actor TEXT NOT NULL,
                action TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT '',
                detail TEXT NOT NULL DEFAULT '',
                prev_hash TEXT NOT NULL,
                record_hash TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS chain_anchor (
                chain TEXT PRIMARY KEY,
                last_hash TEXT NOT NULL,
                last_id INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            );
        ").expect("Failed to create audit tables");
        // Migration: add shap_explanations table if not already created above (handled by CREATE TABLE IF NOT...

        crate::auth::migrate(&conn);

        Self { conn }
    }

    pub(crate) fn conn(&self) -> &Connection {
        &self.conn
    }

    /// Runs `f` inside BEGIN IMMEDIATE, so reading the chain tip and appending are atomic across connections.
    fn immediate<T>(&self, f: impl FnOnce(&Connection) -> rusqlite::Result<T>) -> rusqlite::Result<T> {
        self.conn.execute_batch("BEGIN IMMEDIATE")?;
        match f(&self.conn) {
            Ok(v) => match self.conn.execute_batch("COMMIT") {
                Ok(()) => Ok(v),
                Err(e) => {
                    let _ = self.conn.execute_batch("ROLLBACK");
                    Err(e)
                }
            },
            Err(e) => {
                let _ = self.conn.execute_batch("ROLLBACK");
                Err(e)
            }
        }
    }

    /// Appends a hash-chained alert using the caller's timestamp; returns its id and record hash.
    pub fn insert_alert(&self, ts: &str, severity: &str, title: &str, detail: &str, bssid: Option<&str>, source: &str) -> Option<ChainedRecord> {
        let bssid = bssid.unwrap_or("");
        let res = self.immediate(|c| {
            let prev = chain_tip(c, "alerts")?;
            let hash = audit::alert_record_hash(&prev, ts, severity, title, detail, bssid, source);
            c.execute(
                "INSERT INTO alerts (timestamp, severity, title, detail, bssid, source, hmac_signature, prev_hash, record_hash)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?7)",
                params![ts, severity, title, detail, bssid, source, hash, prev],
            )?;
            Ok(ChainedRecord { id: c.last_insert_rowid(), record_hash: hash })
        });
        match res {
            Ok(r) => Some(r),
            Err(e) => {
                eprintln!("[db] alert insert failed: {}", e);
                None
            }
        }
    }

    /// Appends a hash-chained entry to audit_log.
    pub fn record_audit(&self, actor: &str, action: &str, target: &str, detail: &str) -> bool {
        match self.immediate(|c| append_audit(c, actor, action, target, detail)) {
            Ok(_) => true,
            Err(e) => {
                eprintln!("[db] audit insert failed: {}", e);
                false
            }
        }
    }

    /// Exports every visible alert to `archive_file` (JSONL, fsynced), then hides them; nothing is deleted.
    pub fn archive_all_alerts(&self, archive_file: &std::path::Path, actor: &str) -> Result<u32, String> {
        if let Some(parent) = archive_file.parent() {
            std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        self.immediate(|c| {
            let mut stmt = c.prepare(
                "SELECT id, timestamp, severity, title, COALESCE(detail,''), COALESCE(bssid,''), COALESCE(source,''),
                        acknowledged, COALESCE(prev_hash,''), COALESCE(record_hash,'')
                 FROM alerts WHERE archived = 0 ORDER BY id",
            )?;
            let rows: Vec<serde_json::Value> = stmt
                .query_map([], |r| {
                    Ok(serde_json::json!({
                        "id": r.get::<_, i64>(0)?, "timestamp": r.get::<_, String>(1)?,
                        "severity": r.get::<_, String>(2)?, "title": r.get::<_, String>(3)?,
                        "detail": r.get::<_, String>(4)?, "bssid": r.get::<_, String>(5)?,
                        "source": r.get::<_, String>(6)?, "acknowledged": r.get::<_, i64>(7)? != 0,
                        "prev_hash": r.get::<_, String>(8)?, "record_hash": r.get::<_, String>(9)?,
                    }))
                })?
                .collect::<Result<_, _>>()?;
            let io = |e: std::io::Error| rusqlite::Error::ToSqlConversionFailure(Box::new(e));
            let mut f = std::fs::OpenOptions::new().create_new(true).write(true).open(archive_file).map_err(io)?;
            for row in &rows {
                writeln!(f, "{}", row).map_err(io)?;
            }
            f.sync_all().map_err(io)?;
            let n = c.execute("UPDATE alerts SET archived = 1 WHERE archived = 0", [])?;
            append_audit(c, actor, "alerts_archive", &archive_file.display().to_string(), &format!("{} alerts archived", n))?;
            Ok(n as u32)
        })
        .map_err(|e| e.to_string())
    }

    /// Verifies the alert chain from its anchor (or genesis) to the newest record.
    pub fn verify_alert_chain(&self) -> ChainReport {
        let legacy: u32 = self.conn
            .query_row("SELECT COUNT(*) FROM alerts WHERE record_hash IS NULL OR record_hash = ''", [], |r| r.get(0))
            .unwrap_or(0);
        let rows = self.conn.prepare(
            "SELECT id, timestamp, severity, title, COALESCE(detail,''), COALESCE(bssid,''), COALESCE(source,''), COALESCE(prev_hash,''), record_hash
             FROM alerts WHERE record_hash IS NOT NULL AND record_hash != '' ORDER BY id",
        ).and_then(|mut st| {
            st.query_map([], |r| {
                let f: Vec<String> = (1..=6).map(|i| r.get::<_, String>(i)).collect::<Result<_, _>>()?;
                let expected = audit::alert_record_hash(&r.get::<_, String>(7)?, &f[0], &f[1], &f[2], &f[3], &f[4], &f[5]);
                Ok(ChainRow { id: r.get(0)?, prev: r.get(7)?, stored: r.get(8)?, recomputed: expected })
            })?.collect::<Result<Vec<_>, _>>()
        });
        let mut report = walk_chain(rows, anchor(&self.conn, "alerts"));
        report.legacy_unchained = legacy;
        report
    }

    pub fn verify_audit_chain(&self) -> ChainReport {
        let rows = self.conn.prepare(
            "SELECT id, timestamp, actor, action, target, detail, prev_hash, record_hash FROM audit_log ORDER BY id",
        ).and_then(|mut st| {
            st.query_map([], |r| {
                let f: Vec<String> = (1..=5).map(|i| r.get::<_, String>(i)).collect::<Result<_, _>>()?;
                let expected = audit::audit_record_hash(&r.get::<_, String>(6)?, &f[0], &f[1], &f[2], &f[3], &f[4]);
                Ok(ChainRow { id: r.get(0)?, prev: r.get(6)?, stored: r.get(7)?, recomputed: expected })
            })?.collect::<Result<Vec<_>, _>>()
        });
        walk_chain(rows, anchor(&self.conn, "audit_log"))
    }

    pub fn recent_audit(&self, limit: u32) -> Vec<AuditRow> {
        let Ok(mut stmt) = self.conn.prepare(
            "SELECT id, timestamp, actor, action, target, detail, record_hash FROM audit_log ORDER BY id DESC LIMIT ?1",
        ) else {
            return Vec::new();
        };
        stmt.query_map(params![limit], |r| {
            Ok(AuditRow {
                id: r.get(0)?, timestamp: r.get(1)?, actor: r.get(2)?, action: r.get(3)?,
                target: r.get(4)?, detail: r.get(5)?, record_hash: r.get(6)?,
            })
        })
        .map(|it| it.filter_map(|r| r.ok()).collect())
        .unwrap_or_default()
    }

    pub fn insert_network(&self, bssid: &str, ssid: &str, channel: u8, rssi: i8, vendor: &str, encryption: &str, status: &str) {
        let ts = chrono::Local::now().format("%H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT OR REPLACE INTO networks (bssid, ssid, channel, rssi, vendor, encryption, status, first_seen, last_seen)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7,
                     COALESCE((SELECT first_seen FROM networks WHERE bssid = ?1), ?8), ?8)",
            params![bssid, ssid, channel, rssi as i32, vendor, encryption, status, ts],
        );
    }

    pub fn insert_ml_prediction(&self, label: &str, confidence: f64, threat_score: u32, frame_count: u32) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT INTO ml_predictions (timestamp, label, confidence, threat_score, frame_count) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, label, confidence, threat_score as i32, frame_count as i32],
        );
    }

    pub fn insert_shap_explanation(&self, label: &str, confidence: f64, top_features_json: &str, shap_values_json: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT INTO shap_explanations (timestamp, prediction_label, confidence, top_features, shap_values) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts, label, confidence, top_features_json, shap_values_json],
        );
    }

    pub fn insert_confirmed_sample(&self, label: &str, features_json: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT INTO confirmed_samples (timestamp, label, features) VALUES (?1, ?2, ?3)",
            params![ts, label, features_json],
        );
    }

    pub fn get_unretrained_samples(&self) -> Vec<ConfirmedSampleRow> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, label, features FROM confirmed_samples WHERE used_in_retrain = 0"
        ).unwrap();

        stmt.query_map([], |row| {
            Ok(ConfirmedSampleRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                label: row.get(2)?,
                features: row.get(3)?,
            })
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    pub fn mark_samples_retrained(&self, ids: &[i64]) {
        for id in ids {
            let _ = self.conn.execute(
                "UPDATE confirmed_samples SET used_in_retrain = 1 WHERE id = ?1",
                params![id],
            );
        }
    }

    pub fn get_confirmed_sample_count(&self) -> (u32, u32) {
        let total: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM confirmed_samples", [], |row| row.get(0)
        ).unwrap_or(0);
        let pending: u32 = self.conn.query_row(
            "SELECT COUNT(*) FROM confirmed_samples WHERE used_in_retrain = 0", [], |row| row.get(0)
        ).unwrap_or(0);
        (total, pending)
    }

    pub fn get_recent_alerts(&self, limit: u32) -> Vec<AlertRow> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, severity, title, COALESCE(detail,''), acknowledged, COALESCE(hmac_signature,'') FROM alerts WHERE archived = 0 ORDER BY id DESC LIMIT ?1"
        ).unwrap();

        stmt.query_map(params![limit], |row| {
            Ok(AlertRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                detail: row.get(4)?,
                acknowledged: row.get::<_, i32>(5)? != 0,
                hmac_signature: row.get::<_, String>(6).unwrap_or_default(),
            })
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    pub fn acknowledge_alert(&self, alert_id: i64) -> bool {
        let affected = self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE id = ?1",
            params![alert_id],
        ).unwrap_or(0);
        affected > 0
    }

    pub fn get_alert_count(&self) -> u32 {
        self.conn.query_row("SELECT COUNT(*) FROM alerts", [], |row| row.get(0)).unwrap_or(0)
    }

    pub fn get_ml_predictions(&self, limit: u32) -> Vec<MlPredRow> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, label, confidence, threat_score, frame_count FROM ml_predictions ORDER BY id DESC LIMIT ?1"
        ).unwrap();

        stmt.query_map(params![limit], |row| {
            Ok(MlPredRow {
                timestamp: row.get(0)?,
                label: row.get(1)?,
                confidence: row.get(2)?,
                threat_score: row.get(3)?,
                frame_count: row.get(4)?,
            })
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    pub fn get_recent_shap(&self, limit: u32) -> Vec<ShapRow> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, prediction_label, confidence, top_features, shap_values FROM shap_explanations ORDER BY id DESC LIMIT ?1"
        ).unwrap();

        stmt.query_map(params![limit], |row| {
            Ok(ShapRow {
                timestamp: row.get(0)?,
                prediction_label: row.get(1)?,
                confidence: row.get(2)?,
                top_features: row.get(3)?,
                shap_values: row.get(4)?,
            })
        }).unwrap().filter_map(|r| r.ok()).collect()
    }

    /// Prune alerts older than N days
    /// Deletes a prefix of the chain (ids up to the newest expired alert) and moves the anchor forward.
    pub fn prune_alerts_older_than(&self, days: u32) -> u32 {
        let cutoff = chrono::Local::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        self.prune_alerts_before(&cutoff_str)
    }

    fn prune_alerts_before(&self, cutoff_str: &str) -> u32 {
        self.immediate(|c| {
            let max_id: Option<i64> = c.query_row("SELECT MAX(id) FROM alerts WHERE timestamp < ?1", params![cutoff_str], |r| r.get(0))?;
            let Some(max_id) = max_id else { return Ok(0) };
            let last: Option<(i64, String)> = c.query_row(
                "SELECT id, record_hash FROM alerts WHERE id <= ?1 AND record_hash IS NOT NULL AND record_hash != '' ORDER BY id DESC LIMIT 1",
                params![max_id],
                |r| Ok((r.get(0)?, r.get(1)?)),
            ).optional()?;
            let n = c.execute("DELETE FROM alerts WHERE id <= ?1", params![max_id])?;
            if let Some((id, hash)) = &last {
                set_anchor(c, "alerts", hash, *id)?;
            }
            append_audit(c, "system", "retention_prune", "alerts",
                &format!("deleted {} alerts with id <= {} (timestamp < {})", n, max_id, cutoff_str))?;
            Ok(n as u32)
        })
        .unwrap_or(0)
    }

    /// Prune ML predictions older than N days
    pub fn prune_predictions_older_than(&self, days: u32) -> u32 {
        let cutoff = chrono::Local::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "DELETE FROM ml_predictions WHERE timestamp < ?1",
            params![cutoff_str],
        ).unwrap_or(0) as u32
    }

    /// Auto-archive: mark alerts older than N hours as acknowledged
    pub fn auto_archive_older_than(&self, hours: u32) -> u32 {
        let cutoff = chrono::Local::now() - chrono::Duration::hours(hours as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "UPDATE alerts SET acknowledged = 1 WHERE acknowledged = 0 AND timestamp < ?1",
            params![cutoff_str],
        ).unwrap_or(0) as u32
    }


    /// (chained records, valid, broken) for the report; see verify_alert_chain for details.
    pub fn audit_alert_integrity(&self) -> (u32, u32, u32) {
        let r = self.verify_alert_chain();
        (r.chained, r.valid, r.broken)
    }

}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub acknowledged: bool,
    pub hmac_signature: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MlPredRow {
    pub timestamp: String,
    pub label: String,
    pub confidence: f64,
    pub threat_score: i32,
    pub frame_count: i32,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ShapRow {
    pub timestamp: String,
    pub prediction_label: String,
    pub confidence: f64,
    pub top_features: String,
    pub shap_values: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ConfirmedSampleRow {
    pub id: i64,
    pub timestamp: String,
    pub label: String,
    pub features: String,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct ChainedRecord {
    pub id: i64,
    pub record_hash: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, PartialEq)]
pub struct ChainReport {
    pub chained: u32,
    pub valid: u32,
    pub broken: u32,
    pub first_broken_id: Option<i64>,
    pub legacy_unchained: u32,
    pub anchor: String,
    pub head_hash: Option<String>,
    pub error: Option<String>,
}

impl ChainReport {
    pub fn is_clean(&self) -> bool {
        self.broken == 0 && self.error.is_none()
    }
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AuditRow {
    pub id: i64,
    pub timestamp: String,
    pub actor: String,
    pub action: String,
    pub target: String,
    pub detail: String,
    pub record_hash: String,
}

struct ChainRow {
    id: i64,
    prev: String,
    stored: String,
    recomputed: String,
}

fn now_ts() -> String {
    chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string()
}

fn anchor(c: &Connection, chain: &str) -> rusqlite::Result<Option<String>> {
    c.query_row("SELECT last_hash FROM chain_anchor WHERE chain = ?1", params![chain], |r| r.get(0)).optional()
}

fn set_anchor(c: &Connection, chain: &str, hash: &str, id: i64) -> rusqlite::Result<()> {
    c.execute(
        "INSERT INTO chain_anchor (chain, last_hash, last_id, updated_at) VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(chain) DO UPDATE SET last_hash = excluded.last_hash, last_id = excluded.last_id, updated_at = excluded.updated_at",
        params![chain, hash, id, now_ts()],
    )?;
    Ok(())
}

/// Hash of the newest chained record, else the anchor left by pruning, else genesis.
fn chain_tip(c: &Connection, table: &str) -> rusqlite::Result<String> {
    let sql = match table {
        "alerts" => "SELECT record_hash FROM alerts WHERE record_hash IS NOT NULL AND record_hash != '' ORDER BY id DESC LIMIT 1",
        "audit_log" => "SELECT record_hash FROM audit_log ORDER BY id DESC LIMIT 1",
        _ => unreachable!("unknown chain table"),
    };
    if let Some(h) = c.query_row(sql, [], |r| r.get::<_, String>(0)).optional()? {
        return Ok(h);
    }
    Ok(anchor(c, table)?.unwrap_or_else(|| audit::GENESIS.to_string()))
}

fn append_audit(c: &Connection, actor: &str, action: &str, target: &str, detail: &str) -> rusqlite::Result<i64> {
    let ts = now_ts();
    let prev = chain_tip(c, "audit_log")?;
    let hash = audit::audit_record_hash(&prev, &ts, actor, action, target, detail);
    c.execute(
        "INSERT INTO audit_log (timestamp, actor, action, target, detail, prev_hash, record_hash) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        params![ts, actor, action, target, detail, prev, hash],
    )?;
    Ok(c.last_insert_rowid())
}

/// Each record must hash correctly and point at the previous record (or the anchor/genesis for the first).
fn walk_chain(rows: rusqlite::Result<Vec<ChainRow>>, anchor: rusqlite::Result<Option<String>>) -> ChainReport {
    let mut report = ChainReport::default();
    let (rows, anchor) = match (rows, anchor) {
        (Ok(r), Ok(a)) => (r, a),
        (Err(e), _) | (_, Err(e)) => {
            report.error = Some(e.to_string());
            return report;
        }
    };
    report.anchor = anchor.clone().unwrap_or_else(|| audit::GENESIS.to_string());
    let mut expected_prev = report.anchor.clone();
    for row in rows {
        report.chained += 1;
        let ok = audit::digest_eq(&row.stored, &row.recomputed) && audit::digest_eq(&row.prev, &expected_prev);
        if ok {
            report.valid += 1;
        } else {
            report.broken += 1;
            report.first_broken_id.get_or_insert(row.id);
        }
        expected_prev = row.stored.clone();
        report.head_hash = Some(row.stored);
    }
    report
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::thread;

    static N: AtomicUsize = AtomicUsize::new(0);

    fn temp_db_path() -> String {
        let n = N.fetch_add(1, Ordering::SeqCst);
        let dir = std::env::temp_dir().join(format!("widps-db-test-{}-{}", std::process::id(), n));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("t.db").display().to_string()
    }

    fn db() -> Database {
        audit::init_for_tests();
        Database::open(&temp_db_path())
    }

    fn add(db: &Database, n: usize) -> Vec<ChainedRecord> {
        (0..n)
            .map(|i| db.insert_alert("2026-01-01 10:00:00", "High", &format!("t{}", i), "d", Some("AA:BB"), "rule").unwrap())
            .collect()
    }

    #[test]
    fn empty_chain_is_clean() {
        let d = db();
        let r = d.verify_alert_chain();
        assert!(r.is_clean());
        assert_eq!((r.chained, r.anchor.as_str()), (0, audit::GENESIS));
    }

    #[test]
    fn appended_records_link_and_verify() {
        let d = db();
        let recs = add(&d, 5);
        let r = d.verify_alert_chain();
        assert_eq!((r.chained, r.valid, r.broken), (5, 5, 0));
        assert_eq!(r.head_hash.as_deref(), Some(recs[4].record_hash.as_str()));
        let prev: String = d.conn.query_row("SELECT prev_hash FROM alerts WHERE id = ?1", params![recs[1].id], |r| r.get(0)).unwrap();
        assert_eq!(prev, recs[0].record_hash);
    }

    #[test]
    fn same_timestamp_is_stored_and_hashed() {
        let d = db();
        let rec = d.insert_alert("2026-05-05 05:05:05", "Critical", "x", "y", None, "rule").unwrap();
        let ts: String = d.conn.query_row("SELECT timestamp FROM alerts WHERE id = ?1", params![rec.id], |r| r.get(0)).unwrap();
        assert_eq!(ts, "2026-05-05 05:05:05");
        assert!(d.verify_alert_chain().is_clean());
    }

    #[test]
    fn edited_field_is_detected() {
        let d = db();
        let recs = add(&d, 4);
        d.conn.execute("UPDATE alerts SET severity = 'Medium' WHERE id = ?1", params![recs[2].id]).unwrap();
        let r = d.verify_alert_chain();
        assert_eq!((r.broken, r.first_broken_id), (1, Some(recs[2].id)));
    }

    #[test]
    fn deleted_middle_record_is_detected() {
        let d = db();
        let recs = add(&d, 4);
        d.conn.execute("DELETE FROM alerts WHERE id = ?1", params![recs[1].id]).unwrap();
        let r = d.verify_alert_chain();
        assert_eq!(r.first_broken_id, Some(recs[2].id));
        assert!(!r.is_clean());
    }

    #[test]
    fn swapped_records_are_detected() {
        let d = db();
        let recs = add(&d, 3);
        let (a, b) = (recs[0].id, recs[1].id);
        d.conn.execute_batch(&format!(
            "UPDATE alerts SET id = -1 WHERE id = {a}; UPDATE alerts SET id = {a} WHERE id = {b}; UPDATE alerts SET id = {b} WHERE id = -1;"
        )).unwrap();
        assert!(!d.verify_alert_chain().is_clean());
    }

    #[test]
    fn forged_hash_without_key_is_detected() {
        let d = db();
        let recs = add(&d, 2);
        d.conn.execute("UPDATE alerts SET title = 'fake', record_hash = ?1 WHERE id = ?2",
            params!["00".repeat(32), recs[1].id]).unwrap();
        assert_eq!(d.verify_alert_chain().first_broken_id, Some(recs[1].id));
    }

    #[test]
    fn acknowledging_does_not_break_the_chain() {
        let d = db();
        let recs = add(&d, 3);
        assert!(d.acknowledge_alert(recs[1].id));
        assert!(d.verify_alert_chain().is_clean());
    }

    #[test]
    fn legacy_rows_are_counted_not_verified() {
        let d = db();
        d.conn.execute("INSERT INTO alerts (timestamp, severity, title) VALUES ('2025-01-01 00:00:00','High','old')", []).unwrap();
        add(&d, 2);
        let r = d.verify_alert_chain();
        assert_eq!((r.legacy_unchained, r.chained, r.broken), (1, 2, 0));
    }

    #[test]
    fn prune_moves_anchor_and_chain_stays_valid() {
        let d = db();
        for i in 0..3 {
            d.insert_alert("2020-01-01 00:00:00", "High", &format!("old{}", i), "", None, "rule").unwrap();
        }
        let keep = add(&d, 2);
        assert_eq!(d.prune_alerts_before("2021-01-01 00:00:00"), 3);
        let r = d.verify_alert_chain();
        assert!(r.is_clean(), "{:?}", r);
        assert_eq!(r.chained, 2);
        assert_ne!(r.anchor, audit::GENESIS);
        let next = d.insert_alert("2026-01-02 00:00:00", "High", "new", "", None, "rule").unwrap();
        assert!(d.verify_alert_chain().is_clean());
        assert!(next.id > keep[1].id);
        assert!(d.recent_audit(10).iter().any(|a| a.action == "retention_prune"));
        assert!(d.verify_audit_chain().is_clean());
    }

    #[test]
    fn prune_of_everything_then_append_links_to_anchor() {
        let d = db();
        for _ in 0..2 {
            d.insert_alert("2020-01-01 00:00:00", "High", "old", "", None, "rule").unwrap();
        }
        assert_eq!(d.prune_alerts_before("2021-01-01 00:00:00"), 2);
        add(&d, 1);
        assert!(d.verify_alert_chain().is_clean());
    }

    #[test]
    fn tampered_anchor_is_detected() {
        let d = db();
        d.insert_alert("2020-01-01 00:00:00", "High", "old", "", None, "rule").unwrap();
        add(&d, 2);
        d.prune_alerts_before("2021-01-01 00:00:00");
        d.conn.execute("UPDATE chain_anchor SET last_hash = 'x' WHERE chain = 'alerts'", []).unwrap();
        assert!(!d.verify_alert_chain().is_clean());
    }

    #[test]
    fn archive_exports_hides_and_keeps_chain() {
        let d = db();
        add(&d, 3);
        let path = std::path::PathBuf::from(temp_db_path()).with_file_name("archive/a.jsonl");
        assert_eq!(d.archive_all_alerts(&path, "tester").unwrap(), 3);
        assert_eq!(std::fs::read_to_string(&path).unwrap().lines().count(), 3);
        assert!(d.get_recent_alerts(10).is_empty());
        assert_eq!(d.get_alert_count(), 3);
        assert!(d.verify_alert_chain().is_clean());
        let audit = d.recent_audit(5);
        assert_eq!((audit[0].action.as_str(), audit[0].actor.as_str()), ("alerts_archive", "tester"));
        assert!(d.archive_all_alerts(&path, "tester").is_err(), "existing archive file must not be overwritten");
    }

    #[test]
    fn audit_chain_detects_edit() {
        let d = db();
        for i in 0..3 {
            assert!(d.record_audit("anon@127.0.0.1", "config_change", "cfg", &i.to_string()));
        }
        assert!(d.verify_audit_chain().is_clean());
        d.conn.execute("UPDATE audit_log SET actor = 'someone-else' WHERE id = 2", []).unwrap();
        assert_eq!(d.verify_audit_chain().first_broken_id, Some(2));
    }

    /// B8b: concurrent alert and audit writers on two separate connections to the same file.
    #[test]
    fn concurrent_writers_on_two_connections_keep_both_chains_valid() {
        audit::init_for_tests();
        let path = temp_db_path();
        let a = Arc::new(Mutex::new(Database::open(&path)));
        let b = Arc::new(Mutex::new(Database::open(&path)));
        let mut handles = Vec::new();
        for t in 0..8 {
            let (da, db_) = (Arc::clone(&a), Arc::clone(&b));
            handles.push(thread::spawn(move || {
                for i in 0..25 {
                    let target = if i % 2 == 0 { &da } else { &db_ };
                    assert!(target.lock().unwrap()
                        .insert_alert("2026-01-01 00:00:00", "High", &format!("w{}-{}", t, i), "", None, "rule").is_some());
                }
            }));
            let (da, db_) = (Arc::clone(&a), Arc::clone(&b));
            handles.push(thread::spawn(move || {
                for i in 0..25 {
                    let target = if i % 2 == 0 { &db_ } else { &da };
                    assert!(target.lock().unwrap().record_audit("api", "alert_ack", &format!("{}-{}", t, i), ""));
                }
            }));
        }
        for h in handles {
            h.join().unwrap();
        }
        let d = a.lock().unwrap();
        let alerts = d.verify_alert_chain();
        let audit_log = d.verify_audit_chain();
        assert_eq!((alerts.chained, alerts.broken), (200, 0), "{:?}", alerts);
        assert_eq!((audit_log.chained, audit_log.broken), (200, 0), "{:?}", audit_log);
    }
}
