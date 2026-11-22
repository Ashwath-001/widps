// `widps admin ...`: manage dashboard users from the sensor's shell.
use crate::api::auth::{self, Role};
use crate::store::db::Database;
use std::io::{BufRead, IsTerminal, Write};

const USAGE: &str = "usage:
  widps admin create <username> [--role admin|viewer]   (default role: admin)
  widps admin passwd <username>                         (revokes the user's sessions)
  widps admin disable <username> | enable <username>
  widps admin revoke-sessions <username>
  widps admin list
The password is read from stdin (prompted without echo on a terminal).";

pub fn run(args: &[String], db_path: &str) -> i32 {
    let cmd = args.first().map(String::as_str).unwrap_or("");
    let user = args.get(1).map(String::as_str);
    let db = Database::open(db_path);
    let result = match (cmd, user) {
        ("list", _) => {
            for (name, role, disabled) in auth::list_users(&db) {
                println!("{:<32} {:<7} {}", name, role, if disabled { "disabled" } else { "active" });
            }
            Ok(())
        }
        ("create", Some(u)) => {
            let role = match args.iter().position(|a| a == "--role").and_then(|i| args.get(i + 1)) {
                None => Ok(Role::Admin),
                Some(r) => Role::parse(r).ok_or_else(|| format!("unknown role '{}'", r)),
            };
            role.and_then(|role| {
                let pw = read_new_password()?;
                auth::create_user(&db, u, &pw, role, chrono::Utc::now().timestamp())?;
                println!("created {} ({})", u, role.as_str());
                Ok(())
            })
        }
        ("passwd", Some(u)) => read_new_password().and_then(|pw| auth::set_password(&db, u, &pw)).map(|_| println!("password changed; sessions revoked")),
        ("disable", Some(u)) => auth::set_disabled(&db, u, true).map(|_| println!("disabled {}", u)),
        ("enable", Some(u)) => auth::set_disabled(&db, u, false).map(|_| println!("enabled {}", u)),
        ("revoke-sessions", Some(u)) => auth::revoke_user_sessions(&db, u).map(|n| println!("revoked {} session(s)", n)),
        _ => Err(USAGE.to_string()),
    };
    match result {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("{}", e);
            1
        }
    }
}

fn read_new_password() -> Result<String, String> {
    let stdin = std::io::stdin();
    if !stdin.is_terminal() {
        let mut line = String::new();
        stdin.lock().read_line(&mut line).map_err(|e| e.to_string())?;
        let pw = line.trim_end_matches(['\n', '\r']).to_string();
        auth::validate_password(&pw)?;
        return Ok(pw);
    }
    let first = prompt_hidden("New password: ")?;
    auth::validate_password(&first)?;
    if prompt_hidden("Repeat password: ")? != first {
        return Err("passwords do not match".into());
    }
    Ok(first)
}

fn prompt_hidden(label: &str) -> Result<String, String> {
    print!("{}", label);
    let _ = std::io::stdout().flush();
    let stty = |arg: &str| {
        std::process::Command::new("stty").arg(arg).stdin(std::process::Stdio::inherit()).status().map(|s| s.success()).unwrap_or(false)
    };
    let hidden = stty("-echo");
    let mut line = String::new();
    let res = std::io::stdin().lock().read_line(&mut line);
    if hidden {
        stty("echo");
    }
    println!();
    res.map_err(|e| e.to_string())?;
    Ok(line.trim_end_matches(['\n', '\r']).to_string())
}
