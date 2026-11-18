using LibPQ, DBInterface, MySQL, SQLite

# $var-interpolated query string fed to LibPQ.execute
conn = LibPQ.Connection("dbname=app")
id = readline()
LibPQ.execute(conn, "SELECT * FROM users WHERE id = $id")

# $(expr)-interpolated query string fed to DBInterface.execute
amt = readline()
conn2 = DBInterface.connect(LibPQ.Connection, "dbname=app")
DBInterface.execute(conn2, "UPDATE accounts SET balance = balance - $(amt)")

# *-concatenated query string fed to MySQL.execute
uid = readline()
MySQL.execute(conn3, "SELECT * FROM orders WHERE user_id = " * uid)

# *-concatenated query string fed to SQLite.query
lid = readline()
db = SQLite.DB("app.db")
SQLite.query(db, "DELETE FROM sessions WHERE lid = " * lid)

# $var-interpolated backtick command fed to run()
dir = readline()
run(`ls $dir`)

# $(expr)-interpolated backtick command fed to readchomp()
file = readline()
readchomp(`cat $(file)`)

# *-concatenated command string fed to run(Cmd(...))
host = readline()
run(Cmd("ping " * host))
