// Periodic, atomic snapshot of the AP table (was rewritten on every beacon from the capture loop).
use crate::api_server::{ScannedAp, SharedApStore};
use std::path::Path;
use std::time::Duration;

pub fn spawn(store: SharedApStore, path: &'static str, every: Duration) {
    let _ = std::thread::Builder::new().name("widps-snapshot".into()).spawn(move || {
        let mut last = String::new();
        loop {
            std::thread::sleep(every);
            let list: Vec<ScannedAp> = store.lock().unwrap_or_else(|e| e.into_inner()).values().cloned().collect();
            let Ok(json) = serde_json::to_string(&list) else { continue };
            if json != last {
                if let Err(e) = write_atomic(Path::new(path), json.as_bytes()) {
                    eprintln!("[snapshot] {}: {}", path, e);
                }
                last = json;
            }
        }
    });
}

/// Write to a temp file, fsync, then rename, so a reader or a power cut never sees a half-written file.
pub fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    let tmp = path.with_extension("json.tmp");
    {
        let mut f = std::fs::File::create(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_write_replaces_whole_file() {
        let dir = std::env::temp_dir().join(format!("widps-snap-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("n.json");
        write_atomic(&p, b"[1,2,3]").unwrap();
        write_atomic(&p, b"[]").unwrap();
        assert_eq!(std::fs::read_to_string(&p).unwrap(), "[]");
        assert!(!p.with_extension("json.tmp").exists());
    }
}
