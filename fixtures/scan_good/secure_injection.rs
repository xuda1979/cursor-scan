// Injection-safe Rust patterns — must produce zero findings.
use std::process::Command;
use rusqlite::Connection;

fn find_user(conn: &Connection, name: &str) {
    conn.execute("SELECT * FROM users WHERE name = ?", [name])
        .unwrap();
}

fn apply_fix(conn: &Connection, id: u32) {
    conn.execute("UPDATE t SET status = 'ok' WHERE id = ?", [id])
        .unwrap();
}

fn list_dir(dir: &str) {
    // Argument-list form: no shell involved.
    Command::new("ls").arg(dir).spawn().unwrap();
}
