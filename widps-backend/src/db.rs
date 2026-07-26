use rusqlite::{Connection, params};
use std::sync::{Arc, Mutex};

pub type SharedDb = Arc<Mutex<Database>>;

pub struct Database {
    conn: Connection,
}

impl Database {
    pub fn open(path: &str) -> Self {
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
                acknowledged INTEGER DEFAULT 0
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

            CREATE INDEX IF NOT EXISTS idx_alerts_time ON alerts(timestamp DESC);
            CREATE INDEX IF NOT EXISTS idx_alerts_severity ON alerts(severity);
            CREATE INDEX IF NOT EXISTS idx_ml_time ON ml_predictions(timestamp DESC);
        ").expect("Failed to create tables");

        Self { conn }
    }

    pub fn insert_alert(&self, severity: &str, title: &str, detail: &str, bssid: Option<&str>, source: &str) {
        let ts = chrono::Local::now().format("%Y-%m-%d %H:%M:%S").to_string();
        let _ = self.conn.execute(
            "INSERT INTO alerts (timestamp, severity, title, detail, bssid, source) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![ts, severity, title, detail, bssid.unwrap_or(""), source],
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

    pub fn get_recent_alerts(&self, limit: u32) -> Vec<AlertRow> {
        let mut stmt = self.conn.prepare(
            "SELECT id, timestamp, severity, title, detail, acknowledged FROM alerts ORDER BY id DESC LIMIT ?1"
        ).unwrap();

        stmt.query_map(params![limit], |row| {
            Ok(AlertRow {
                id: row.get(0)?,
                timestamp: row.get(1)?,
                severity: row.get(2)?,
                title: row.get(3)?,
                detail: row.get(4)?,
                acknowledged: row.get::<_, i32>(5)? != 0,
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
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct AlertRow {
    pub id: i64,
    pub timestamp: String,
    pub severity: String,
    pub title: String,
    pub detail: String,
    pub acknowledged: bool,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct MlPredRow {
    pub timestamp: String,
    pub label: String,
    pub confidence: f64,
    pub threat_score: i32,
    pub frame_count: i32,
}
