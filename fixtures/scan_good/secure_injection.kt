// Injection-safe Kotlin patterns — must produce zero findings.
import java.sql.Statement

fun getById(stmt: Statement, id: Int) {
    // Parameterized placeholder: no string concatenation.
    stmt.executeQuery("SELECT * FROM users WHERE id = ?")
}

fun listFiles(dir: String) {
    // Argument-list form: no shell involvement.
    ProcessBuilder("ls", "-la", dir).start()
}

fun showHelp() {
    // Static command line: no concatenation.
    Runtime.getRuntime().exec("which java")
}
