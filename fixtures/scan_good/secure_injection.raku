# Good Raku: parameterized queries, static SQL/commands, arg-list execution.

# Parameterized query with a ? placeholder and a params array
$dbh.query("SELECT * FROM users WHERE id = ?", [$id])

# Parameterized prepare with a ? placeholder
my $sth = $dbh.prepare("SELECT * FROM users WHERE name = ?");

# Static SQL string, no interpolation or concat
$dbh.query("SELECT count(*) FROM users")

# Static do() call before execute
$sth.execute("SELECT 1")

# $var double-quote interpolation without any SQL keyword
my $s = "hello $name";

# Query call without a DBIish handle sink
query("SELECT * FROM users WHERE id = " ~ $id)

# Static command string, no concat or interpolation
shell("echo ok")

# Argument-list execution, no shell string built at all
run("ls", "-la", $dir)

# proc-open with an argument array, no string build
proc-open(["ls", "-la", $dir], :w)

# Variable-only shell call, nothing spliced into the string
shell($cmd)
