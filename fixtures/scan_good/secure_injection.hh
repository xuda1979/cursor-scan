# Good Hack: parameterized queries, static SQL/commands, arg-array shells.

# Parameterized query with a ? placeholder
$conn->query("SELECT * FROM users WHERE id = ?", $params)

# Parameterized prepare with a ? placeholder
$stmt = $db->prepare("SELECT * FROM users WHERE name = ?");

# Static SQL string, no interpolation or concat
$conn->query("SELECT count(*) FROM users")

# Static queryf() without a printf verb
$conn->queryf("SELECT name FROM users WHERE id = %d", $id)

# $var double-quote interpolation without any SQL keyword
$s = "hello $name";

# Function-query call with a static literal
mysqli_query($conn, "SELECT 1")

# Static command string, no concat or interpolation
shell_exec("echo ok")

# $var fully inside the double-quoted literal is static-safe here
system("ping 127.0.0.1")

# proc-open with an argument array, no string build
proc_open(["ls", "-la", $dir], $descriptors, $pipes)

# Variable-only shell call, nothing spliced into the string
shell_exec($cmd)
