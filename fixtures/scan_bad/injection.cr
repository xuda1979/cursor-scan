require "db"

conn = DB.open("sqlite3://./app.db")

DB.exec conn, "SELECT * FROM orders WHERE uid = " + uid
DB.query conn, "INSERT INTO accounts (name) VALUES ('" + user_name + "')"
conn.query_all "UPDATE accounts SET balance = " + amount
DB.query_one conn, "DELETE FROM sessions WHERE sid = " + sid
DB.query_each conn, "ALTER TABLE users ADD COLUMN " + col do |rs|
end

sql : String = "SELECT * FROM users WHERE name = '#{k}'"
DB.exec conn, sql

system("rm -rf #{dir}")
`ls -la #{folder}`
Process.run("cat " + p + " | wc -l")
