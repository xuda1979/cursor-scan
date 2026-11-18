import std/[db_sqlite, osproc]

# Nim secure pattern fixture: parameterized queries and static command
# strings only.  Nothing here should be flagged.

proc param_ok(id: string): string =
  # parameterized statement: the user value is passed as a bound argument
  db.exec(dbConn, "SELECT * FROM orders WHERE uid = ?", id)

proc param_ok2(name: string): string =
  # free-function form with a bound placeholder for the user value
  getRow(dbConn, "SELECT * FROM users WHERE name = ?", name)

proc static_sql_ok(): string =
  # fully static SQL literal, no concatenation
  db.getAllRows(dbConn, "SELECT * FROM users")

proc built_from_var_ok(folder: string): string =
  # the `&` operand is a variable, not a string literal: not in-line taint
  execShellCmd(folder & " -al /tmp")

proc static_cmd_ok(): string =
  # static command string into execShellCmd
  execShellCmd("grep -c error /var/log/messages")
