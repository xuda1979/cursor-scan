// Good: parameterized queries and argument-list commands leave injection
// scanners quiet.

import java.sql.*

class SafeDao {
    ResultSet findUser(Connection conn, long id) {
        def stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
        stmt.setLong(1, id)
        stmt.executeQuery()
    }

    ResultSet findByName(Connection conn, String name) {
        def stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
        stmt.setString(1, name)
        stmt.executeQuery()
    }

    int ageByName(Connection conn, String name) {
        def stmt = conn.prepareStatement("UPDATE t SET v = ? WHERE name = ?")
        stmt.setString(1, v)
        stmt.setString(2, name)
        stmt.executeUpdate()
    }

    long count(Connection conn) {
        def stmt = conn.createStatement()
        def rs = stmt.executeQuery("SELECT COUNT(*) FROM users")
        rs.getLong(1)
    }

    void ping(String host) {
        ["ping", "-c", "1", host].execute()
        ["cmd", "/c", "echo", "hi"].execute()
        "git status".execute()
    }
}
