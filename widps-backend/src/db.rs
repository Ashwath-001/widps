use rusqlite::{Connection, params};
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
        // Migration: add shap_explanations table if not already created above
        // (handled by CREATE TABLE IF NOT EXISTS)

        Self { conn }
    }

    pub fn clear_all_alerts(&self) {
        let _ = self.conn.execute("DELETE FROM alerts", []);
    }

    pub fn insert_alert(&self, severity: &str, title: &str, detail: &str, bssid: Option<&str>, source: &str, hmac_sig: Option<&str>) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT INTO alerts (timestamp, severity, title, detail, bssid, source, hmac_signature) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
            params![ts, severity, title, detail, bssid.unwrap_or(""), source, hmac_sig.unwrap_or("")],
        );
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
            "SELECT id, timestamp, severity, title, detail, acknowledged, hmac_signature FROM alerts ORDER BY id DESC LIMIT ?1"
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
    pub fn prune_alerts_older_than(&self, days: u32) -> u32 {
        let cutoff = chrono::Local::now() - chrono::Duration::days(days as i64);
        let cutoff_str = cutoff.format("%Y-%m-%d %H:%M:%S").to_string();
        self.conn.execute(
            "DELETE FROM alerts WHERE timestamp < ?1",
            params![cutoff_str],
        ).unwrap_or(0) as u32
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


    pub fn audit_alert_integrity(&self) -> (u32, u32, u32) {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, severity, title, detail, hmac_signature FROM alerts WHERE hmac_signature IS NOT NULL AND hmac_signature != ''"
        ).unwrap();

        let mut total: u32 = 0;
        let mut valid: u32 = 0;
        let mut tampered: u32 = 0;

        let rows = stmt.query_map([], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
            ))
        }).unwrap();

        for row in rows.flatten() {
            total += 1;
            let (ts, sev, title, detail, sig) = row;
            if crate::alert::verify_alert_signature(&ts, &sev, &title, &detail, &sig) {
                valid += 1;
            } else {
                tampered += 1;
            }
        }

        (total, valid, tampered)
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
