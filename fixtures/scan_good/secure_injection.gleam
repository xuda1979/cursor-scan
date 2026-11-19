import pgo
import sqlight
import gleam/erlang

const sql = "
"

pub fn query_users(conn, id) {
  pgo.query(conn, "SELECT * FROM users WHERE id = $1", [id])
  pgo.query(conn, "SELECT count(*) FROM users")
  sqlight.query(conn, "SELECT name FROM items WHERE id = ?", [id])
  sqlight.execute(conn, "SELECT 1")
  aga.query(conn, "SELECT id FROM accounts")
  let greeting = "hello, {name}"
  erlang.system_cmd("echo ok")
  erlang.system_cmd("ping 127.0.0.1")
  erlang.system_cmd("ls", ["-la", dir])
  let full = built_cmd(user_input)
}
