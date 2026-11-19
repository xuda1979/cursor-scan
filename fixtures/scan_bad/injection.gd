# Bad GDScript (Godot): dynamic SQL and shell commands built with +
# concatenation / % formatting, fed to the SQLite facade and OS.execute.

# +-concatenated query fed to the db.query sink
func run_query(id):
	db.query("SELECT * FROM users WHERE id = " + id)

# +-concatenated UPDATE fed to db.query
func update_balance(amt):
	db.query("UPDATE accounts SET balance = " + amt)

# +-concatenated DELETE with an embedded quote literal
func delete_session(sid):
	db.query("DELETE FROM sessions WHERE sid = '" + sid + "'")

# +-concatenated DROP fed to db.query_bind_row
func drop_table(tbl):
	db.query_bind_row("DROP TABLE " + tbl)

# % -formatted INSERT fed to db.query
func insert_log(msg):
	db.query("INSERT INTO log VALUES ('%s')" % msg)

# % -formatted SELECT fed to db.query_with_params
func query_type(typ):
	db.query_with_params("SELECT * FROM log WHERE type = %s" % typ)

# +-concatenated assignment consumed by a DB call on a later line
func get_orders(uid):
	var sql = "SELECT * FROM orders WHERE uid = " + uid

# shell-joined command fed to OS.execute with "sh" and -c
func list_dir(dir):
	OS.execute("sh", ["-c", "ls -la " + dir])

# +-concatenated command fed to OS.execute with "bash" and -c
func ping_host(host):
	OS.execute("bash", ["-c", "ping -c 1 " + host])

# % -formatted command fed to OS.execute with "zsh" and -c
func backup(src):
	OS.execute("zsh", ["-c", "tar czf /tmp/backup.tgz %s" % src])
