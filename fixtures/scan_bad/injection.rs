// Deliberately unsafe Rust SQL string interpolation/concatenation and shell
// execution (CWE-89 / CWE-78): user-controlled values are spliced into query
// strings via format!() verbs or `+` concatenation, and shell commands are
// run through sh -c / cmd /C with a formatted command string, instead of
// parameterized placeholders (?) / argument-list forms.
use std::process::Command;
use rusqlite::Connection;

fn find_user(conn: &Connection, name: &str) {
    conn.execute(&format!("SELECT * FROM users WHERE name = '{name}'"), [])
        .unwrap();
}

fn wipe_logs(conn: &Connection, id: &str) {
    let q = format!("DELETE FROM logs WHERE id = {}", id);
    conn.execute(&q, []).unwrap();
}

fn wipe_dir(dir: &str) {
    Command::new("sh").arg("-c").arg(format!("rm -rf {}", dir)).output().unwrap();
}

fn touch_rows(conn: &Connection, cols: &str) {
    let q = "UPDATE t SET ".to_string() + cols + " WHERE id = 1";
    conn.execute(&q, []).ok();
}

// NOT findings: parameterized placeholders and argument-list / static forms.
fn safe_query(conn: &Connection, name: &str) {
    conn.execute("SELECT * FROM users WHERE name = ?", [name]).ok();
    Command::new("ls").arg(name).output().unwrap();
    Command::new("sh").arg("-c").arg("true").output().unwrap();
    Command::new("npm").arg("run").arg("build").status().ok();
}
