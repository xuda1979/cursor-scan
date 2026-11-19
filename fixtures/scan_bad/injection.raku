# Bad Raku: dynamic SQL and shell commands built with ~-concatenation
# or $var double-quote interpolation, fed to DBIish handles and shell().

# ~-concatenated query fed to the .query sink
$dbh.query("SELECT * FROM users WHERE id = " ~ $id)

# $-interpolated query fed to the .query sink
$dbh.query("SELECT * FROM users WHERE id = $id")

# ~-concatenated UPDATE fed to .prepare
$db.prepare("UPDATE accounts SET balance = balance - " ~ $amt)

# $-interpolated DELETE fed to the .query sink
$conn.query("DELETE FROM sessions WHERE sid = $sid")

# ~-concatenated DROP fed to the .do sink
$dbh.do("DROP TABLE " ~ $tbl)

# ~-concatenated assignment consumed by a DB call on a later line
my $sql = "SELECT * FROM t WHERE uname = " ~ $name;

# $-interpolated assignment consumed by a DB call on a later line
my $stmt = "SELECT count(*) FROM items WHERE owner = $owner";

# ~-joined command fed to shell()
shell("ls -la " ~ $dir)

# $-interpolated command fed to shell()
shell("ping -c 1 $host")

# ~-joined command fed to proc-open()
proc-open("tar czf /tmp/backup.tgz " ~ $src, :w)
