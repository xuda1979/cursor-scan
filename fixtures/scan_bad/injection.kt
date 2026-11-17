// Deliberately unsafe Kotlin SQL string concatenation and shell execution
// (CWE-89 / CWE-78): user-controlled values are spliced into query strings
// via `+` concatenation, and shell commands are launched through
// Runtime.exec / ProcessBuilder sh -c, instead of parameterized placeholders
// (?) / argument-list forms.

import java.sql.Statement

fun findUser(stmt: Statement, id: String) {
    val rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id)
    rs.close()
}

fun touchRow(stmt: Statement, id: String) {
    stmt.executeUpdate("UPDATE logs SET status = 'ok' WHERE id = " + id)
}

fun dropTable(db: android.database.sqlite.SQLiteDatabase, name: String) {
    db.execSQL("DROP TABLE " + name)
}

fun queryByOwner(db: android.database.sqlite.SQLiteDatabase, owner: String) {
    db.rawQuery("SELECT id FROM accounts WHERE owner = '" + owner + "'", null)
}

fun wipeDir(path: String) {
    Runtime.getRuntime().exec("rm -rf " + path)
}

fun listFiles(dir: String) {
    ProcessBuilder("/bin/sh", "-c", "ls " + dir).start()
}

// NOT findings: parameterized placeholders and argument-list / static forms.
fun safeQuery(stmt: Statement, id: Int) {
    stmt.executeQuery("SELECT * FROM users WHERE id = ?")
    Runtime.getRuntime().exec(arrayOf("ls", "-la"))
}
