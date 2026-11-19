import pgo
import sqlight
import gleam/erlang

const sql = "
"

pub fn query_users(conn, id) {
  // 7 SQL positives
  pgo.query(conn, "SELECT * FROM users WHERE id = " <> id)
  pgo.query(conn, "SELECT * FROM users WHERE id = {id}")
  pgo.execute(conn, "UPDATE accounts SET balance = balance - " <> amount)
  sqlight.execute(conn, "DELETE FROM sessions WHERE sid = " <> sid)
  sqlight.query(conn, "SELECT * FROM payments WHERE name = {name}")
  aga.query(conn, "DROP TABLE " <> tbl)
  let sql = "SELECT count(*) FROM items WHERE owner = " <> owner
  // 3 shell positives
  erlang.system_cmd("ls -la " <> dir)
  erlang.system_cmd("ping -c 1 {host}")
  erlang.system_cmd("cat " <> path <> " | grep " <> needle)
}
