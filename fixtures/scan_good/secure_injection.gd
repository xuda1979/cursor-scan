# Good GDScript (Godot): parameterized queries and static commands only.

# Parameterized query with a ? placeholder and a params array
func get_user(id):
	db.query_with_params("SELECT * FROM users WHERE id = ?", [id])

# Static SQL string, no concatenation
func count_users():
	db.query("SELECT count(*) FROM users")

# Parameterized DELETE with a ? placeholder
func clear_session(sid):
	db.query_with_params("DELETE FROM sessions WHERE sid = ?", [sid])

# Parameterized INSERT with a params array
func add_log(m):
	db.query_with_params("INSERT INTO log (msg) VALUES (?)", [m])

# %s in the literal but no % operator applied to it
func lookup(a):
	db.query("SELECT * FROM t WHERE a = %s", [a])

# Non-shell command execution: no shell binary, no -c
func list_tmp():
	OS.execute("ls", ["-la", "/tmp"])

# Shell invoked but the command is a static string
func echo_ok():
	OS.execute("sh", ["-c", "echo ok"])

# Inert assignment, no SQL keyword, never fed to a DB call
func unused():
	var sql = "hello"
