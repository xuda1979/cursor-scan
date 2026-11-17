// Deliberately unsafe Swift SQL string concatenation / interpolation and
// shell execution (CWE-89 / CWE-78): user-controlled values are spliced
// into query strings via `+` concatenation or `\(...)` string interpolation,
// and shell commands are run through Process (-c /bin/sh) or system() with a
// concatenated / interpolated command, instead of parameterized `?`
// placeholders / argument-list forms.

import Foundation
import SQLite3

let db = try Connection("app.db")

func findUser(_ name: String) {
    // SQLite.swift receiver with `+` concatenation: dynamic user input.
    let rows = try db.execute("SELECT * FROM users WHERE name = '" + name + "'")
}

func findAccount(_ owner: String) throws {
    // SQLite.swift receiver with `\(...)` string interpolation.
    try db.execute("SELECT id FROM accounts WHERE owner = \(owner)")
}

func touchRow(_ id: Int) throws {
    // FMDB-style executeUpdate with `+` concatenation.
    try database.executeUpdate("UPDATE logs SET status = 'ok' WHERE id = " + id,
                               withArgumentsIn: [])
}

func queryColumns(_ cols: String) throws {
    // Chained `.prepare` with interpolation.
    let stmt = try db.prepare("SELECT " + cols + " FROM reports")
}

func wipeTable(_ tbl: String) {
    // C SQLite API with `+` concatenation.
    sqlite3_exec(db, "DROP TABLE " + tbl, nil, nil, nil)
}

func dumpBackup(_ dir: String) {
    // Process launches /bin/sh -c with a `+`-concatenated command.
    let process = Process()
    process.executableURL = URL(fileURLWithPath: "/bin/sh")
    process.arguments = ["/bin/sh", "-c", "tar czf /tmp/backup.tgz " + dir]
}

func greet(_ user: String) {
    // Process launches sh -c with an interpolated command string.
    let p = Process()
    p.arguments = ["sh", "-c", "echo hello \(user)"]
}

func deleteCache(_ path: String) {
    // C system() with a concatenated command.
    system("rm -rf /tmp/" + path)
}

func updateStatus(_ who: String) {
    // system() with an interpolated command.
    system("chown \(who) /var/log/app")
}

// NOT findings: parameterized placeholders, argument-list Process launches
// and static commands.
func safePath() -> String {
    return "/usr/bin"
}
