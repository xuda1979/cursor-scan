// Deliberately injected Scala — must produce findings.
import java.sql.{Connection, PreparedStatement, ResultSet}
import scala.sys.process.Process

object UnsafeQueries {
  def byId(conn: Connection, uid: String): ResultSet = {
    val stmt = conn.createStatement()
    // `+` concatenation into a JDBC receiver.
    stmt.executeQuery("SELECT * FROM users WHERE id = " + uid)
  }

  def deleteLog(conn: Connection, lid: String): Unit = {
    val stmt = conn.createStatement()
    // `+` concatenation into executeUpdate.
    stmt.executeUpdate("DELETE FROM logs WHERE id = " + lid)
  }

  def updateOwner(conn: Connection, owner: String): Unit = {
    // `+` concatenation into prepareStatement.
    val stmt = conn.prepareStatement("UPDATE accounts SET owner = '" + owner + "'")
    stmt.executeUpdate()
  }

  def interpolated(conn: Connection, value: String): Unit = {
    val stmt = conn.createStatement()
    // s"..." interpolation with a runtime $var expanded into execute().
    stmt.execute(s"UPDATE t SET v = '$value' WHERE id = $value")
  }

  def assignBuild(conn: Connection, isbn: String): Unit = {
    // Assignment form: query built on this line, consumed by a later
    // `stmt.executeQuery(q)` the line scanner never sees.
    val q = "SELECT * FROM books WHERE isbn = " + isbn
    val stmt = conn.createStatement()
    stmt.executeQuery(q)
  }

  def runPing(host: String): Unit = {
    // scala.sys.process Process with s"..." interpolation.
    Process(s"ping -c 1 $host").!
  }

  def runCmd(cmd: String): Unit = {
    // Process with `+` concatenation.
    Process("cmd /c " + cmd).!
  }

  def javaExec(cmd: String): Unit = {
    // Java interop Runtime exec with `+`.
    Runtime.getRuntime().exec("cmd /c " + cmd)
  }
}
