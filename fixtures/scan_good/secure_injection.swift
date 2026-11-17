// Injection-safe Swift patterns — must produce zero findings.
// Parameterized `?` placeholders, argument-list Process launches and static
// commands only.

import Foundation
import SQLite3

let db = try Connection("app.db")

func getByID(_ id: Int) throws -> Row? {
    // Parameterized placeholder: no string concatenation or interpolation.
    let rows = try db.prepare("SELECT * FROM users WHERE id = ?")
    for row in rows {
        return row
    }
    return nil
}

func insertLog(_ msg: String) throws {
    // Argument list via withArgumentsIn: values are bound, not spliced.
    try database.executeUpdate("INSERT INTO logs (msg) VALUES (?)", withArgumentsIn: [msg])
}

func runQuery(_ id: Int) throws {
    // SQLite.swift run with bindings array.
    try db.run("UPDATE accounts SET bal = ? WHERE id = ?", id * 2)
}

func pingHost() {
    // Argument-list Process launch: no shell -c involvement.
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/ping")
    p.arguments = ["-c", "1", "127.0.0.1"]
    try p.run()
}

func listDir(_ dir: String) {
    // Direct binary invocation: argument passed as a separate array element.
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/ls")
    p.arguments = ["-la", dir]
    try p.run()
}

func staticShell() {
    // Static shell command with nothing to interpolate stays quiet.
    let p = Process()
    p.executableURL = URL(fileURLWithPath: "/bin/sh")
    p.arguments = ["/bin/sh", "-c", "echo hello"]
    try p.run()
}

func staticSystem() {
    // Static command for system() with no runtime value stays quiet.
    system("true")
}

func noSQLAssignment() {
    // A plain string interpolation into a local variable is not a query.
    let s = "SELECT * FROM users WHERE name = \(getUser())"
}
