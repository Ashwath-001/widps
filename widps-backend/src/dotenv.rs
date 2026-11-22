// Loads KEY=VALUE pairs from a .env file into the process environment; existing variables always win.
use std::path::Path;

/// Parses .env text: `#` comments, optional `export `, optional single or double quotes around the value.
pub fn parse(text: &str) -> Vec<(String, String)> {
    text.lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            let line = line.strip_prefix("export ").unwrap_or(line);
            let (k, v) = line.split_once('=')?;
            let k = k.trim();
            if k.is_empty() || !k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_') {
                return None;
            }
            let v = v.trim();
            let v = if v.len() >= 2 && ((v.starts_with('"') && v.ends_with('"')) || (v.starts_with('\'') && v.ends_with('\''))) {
                &v[1..v.len() - 1]
            } else {
                v.split(" #").next().unwrap_or(v).trim_end()
            };
            Some((k.to_string(), v.to_string()))
        })
        .collect()
}

/// Reads `WIDPS_ENV_FILE` (default `.env`). Must run before any thread starts. Returns the keys it set.
pub fn load() -> Vec<String> {
    let path = std::env::var("WIDPS_ENV_FILE").unwrap_or_else(|_| ".env".into());
    let Ok(text) = std::fs::read_to_string(Path::new(&path)) else { return Vec::new() };
    let mut set = Vec::new();
    for (k, v) in parse(&text) {
        // Empty values are skipped so an unfilled template does not hide a missing setting.
        if v.is_empty() || std::env::var_os(&k).is_some() {
            continue;
        }
        std::env::set_var(&k, &v);
        set.push(k);
    }
    set
}

#[cfg(test)]
mod tests {
    use super::parse;

    #[test]
    fn parses_common_forms() {
        let text = "# comment\n\nWIDPS_BIND=127.0.0.1:8787\nexport WIDPS_DB=\"data/x.db\"\nA='quoted # not a comment'\nB=value # trailing comment\nEMPTY=\nbad key=1\n=novalue\nNO_EQUALS\n";
        let got = parse(text);
        assert_eq!(got, vec![
            ("WIDPS_BIND".into(), "127.0.0.1:8787".into()),
            ("WIDPS_DB".into(), "data/x.db".into()),
            ("A".into(), "quoted # not a comment".into()),
            ("B".into(), "value".into()),
            ("EMPTY".into(), "".into()),
        ]);
    }
}
