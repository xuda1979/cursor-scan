// Injection-safe Scala patterns — must produce zero findings.
import java.sql.{Connection, PreparedStatement, ResultSet}
import scala.sys.process.Process

object SafeQueries {
  def byId(conn: Connection, id: Int): ResultSet = {
    // Bound ? placeholder: no string concatenation.
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setInt(1, id)
    stmt.executeQuery()
  }

  def byName(conn: Connection, name: String): ResultSet = {
    // Bound ? placeholder.
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE name = ?")
    stmt.setString(1, name)
    stmt.executeQuery()
  }

  def count(conn: Connection): Long = {
    // Static literal query, no splice.
    val stmt = conn.createStatement()
    val rs = stmt.executeQuery("SELECT COUNT(*) FROM users")
    rs.next()
    rs.getLong(1)
  }

  def ping(host: String): Unit = {
    // Argument-list Process launch: quiet (no shell string).
    Process("ping", Seq("-c", "1", host)).!
  }

  def gitStatus(): Unit = {
    // Static command line.
    Process("git status").!
  }

  def slick(conn: Connection, id: Int): Unit = {
    // Slick's sql"..." interpolator is parameterized — quiet.
    val q = sql"SELECT * FROM users WHERE id = $id"
  }
}
