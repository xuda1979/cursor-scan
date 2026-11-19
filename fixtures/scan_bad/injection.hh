# Bad Hack: dynamic SQL and shell commands built with .-concatenation
# or $var double-quote interpolation, fed to MySQLi/AsyncMysql receivers
# and shell_exec/system.

# .-concatenated query fed to the object-query sink
$conn->query("SELECT * FROM users WHERE id = " . $id)

# $var-interpolated query fed to the object-query sink
$conn->query("SELECT * FROM users WHERE id = $id")

# .-concatenated UPDATE fed to .prepare
$db->prepare("UPDATE accounts SET balance = balance - " . $amt)

# $var-interpolated DELETE fed to the function-query sink
mysqli_query($conn, "DELETE FROM sessions WHERE sid = $sid")

# .-concatenated DROP fed to .exec
$dbh->exec("DROP TABLE " . $tbl)

# .-concatenated assignment consumed by a DB call on a later line
$sql = "SELECT * FROM t WHERE uname = " . $name;

# $var-interpolated assignment consumed by a DB call on a later line
$stmt = "SELECT count(*) FROM items WHERE owner = $owner";

# .-joined command fed to shell_exec()
shell_exec("ls -la " . $dir)

# $var-interpolated command fed to system()
system("ping -c 1 $host")

# .-joined command fed to proc-open()
proc_open("tar czf /tmp/backup.tgz " . $src, $descriptors, $pipes)
