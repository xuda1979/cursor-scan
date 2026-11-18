using LibPQ, DBInterface, MySQL, SQLite

# Parameterized query with \$1-style bound parameter (LibPQ)
conn = LibPQ.Connection("dbname=app")
id = parse(Int, readline())
LibPQ.execute(conn, "SELECT * FROM users WHERE id = \$1", [id])

# Parameterized query with ? placeholders (DBInterface)
conn2 = DBInterface.connect(LibPQ.Connection, "dbname=app")
name = readline()
DBInterface.execute(conn2, "UPDATE accounts SET owner = ? WHERE id = ?", [name, 7])

# Static SQL literal with no interpolation (MySQL)
MySQL.execute(conn3, "SELECT COUNT(*) FROM orders")

# Static backtick command with no interpolation (run)
run(`ls -la /tmp`)

# Static Cmd string with no interpolation (run)
run(Cmd("mkdir -p /tmp/app"))

# read() with a static backtick command
out = read(`echo ok`)
