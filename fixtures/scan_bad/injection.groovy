// Bad: user input spliced into JDBC SQL strings (concatenation / GString
// interpolation) and into shell command strings.

import java.sql.*

class BadDao {
    def stmt = null

    void findUsers(Connection conn, String uid) {
        stmt = conn.createStatement()
        // rule: injection.sql_concat
        stmt.executeQuery("SELECT * FROM users WHERE id = " + uid)
        stmt = conn.createStatement()
        // rule: injection.sql_concat
        stmt.executeUpdate("DELETE FROM logs WHERE id = " + lid)
        stmt = conn.prepareStatement("UPDATE accounts SET owner = '" + owner + "'")
        stmt = conn.createStatement()
        // rule: injection.sql_concat
        stmt.execute("UPDATE t SET v = '$value' WHERE id = $value")
        stmt = conn.createStatement()
        // rule: injection.sql_concat
        stmt.executeQuery("SELECT * FROM t WHERE id = ${uid}")
    }

    void buildQuery() {
        def q = "SELECT * FROM books WHERE isbn = " + isbn
        stmt.executeQuery(q)
        def q2 = "SELECT * FROM users WHERE name = $name"
        stmt.executeQuery(q2)
    }

    void ping(String host) {
        "ping -c 1 ${host}".execute()
        "cmd /c $cmd".execute()
        ("cmd /c " + cmd).execute()
        Runtime.getRuntime().exec("cmd /c " + cmd)
    }
}
