import std/[db_sqlite, osproc, strutils]

# Nim injection sink fixture: `&`-concatenated SQL into the db_sqlite /
# db_mysql / db_postgres family, and `&`-concatenated commands into the
# osproc shell executors.

proc build_query(id: string): string =
  # SELECT through db.exec
  db.exec(dbConn, "SELECT * FROM orders WHERE uid = " & id)

proc build_insert(user: string): string =
  # INSERT through the free-function form
  exec(dbConn, "INSERT INTO accounts (name) VALUES ('" & user & "')")

proc build_update(amount: string): string =
  # UPDATE through db.execAffectedRows
  discard db.execAffectedRows(dbConn, "UPDATE accounts SET balance = " & amount)

proc build_delete(sid: string): string =
  # DELETE through db.getAllRows
  let rows = db.getAllRows(dbConn, "DELETE FROM sessions WHERE sid = " & sid)

proc build_alter(col: string): string =
  # ALTER through db.tryExec
  db.tryExec(dbConn, "ALTER TABLE users ADD COLUMN " & col)

proc build_select_id_user(k: string): string =
  let sql = "SELECT * FROM users WHERE name = '" & k & "'"
  db.getRow(dbConn, sql)

proc run_filters(q: string): string =
  # execShellCmd fed a concatenated command string
  execShellCmd("grep " & q & " /var/log/messages")

proc run_cmd(cmd: string): string =
  # execCmdEx fed a concatenated command string
  let (outp, code) = execCmdEx("ls -la " & cmd)

proc run_proc(p: string): int =
  # execProcess fed a concatenated filter string
  execProcess("cat " & p & " | wc -l")
