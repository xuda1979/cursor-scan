require "db"

conn = DB.open("sqlite3://./app.db")

DB.exec conn, "SELECT * FROM orders WHERE uid = ?", uid
DB.exec conn, "SELECT * FROM users", params
DB.exec conn, "SELECT * FROM users"

system("ls -la /tmp")
`uname -a`
Process.run("sh", ["-c", "uname -a"])
