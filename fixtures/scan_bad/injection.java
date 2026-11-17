// Deliberately unsafe Java SQL string concatenation and shell execution
// (CWE-89 / CWE-78): user input is spliced into Statement queries and
// Runtime.exec commands instead of PreparedStatement binds / argument lists.

import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class UnsafeInjection {
  ResultSet findUser(Statement stmt, String username) throws Exception {
    return stmt.executeQuery("SELECT * FROM users WHERE name = " + username);
  }

  void deleteRow(Connection conn, String id) throws Exception {
    conn.createStatement().executeUpdate("DELETE FROM t WHERE id = " + id);
  }

  void runSnapshot(Statement statement, String owner) throws Exception {
    statement.execute("SELECT * FROM accounts WHERE owner='" + owner + "'");
  }

  void wipeLogs(String dir) throws Exception {
    Runtime.getRuntime().exec("rm -rf " + dir);
  }

  void runNode(String cmd) throws Exception {
    Runtime.getRuntime().exec("node -e " + cmd);
  }
}
