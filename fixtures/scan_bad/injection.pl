# Deliberately unsafe Perl DBI SQL string interpolation and shell execution
# (CWE-89 / CWE-78): user-controlled values are spliced into query strings
# through double-quoted `$var` interpolation or the `.` concatenation operator,
# and shell commands are run through the single-string system() form or
# backticks with an interpolated variable, instead of parameterized `?`
# placeholders / argument-list forms.
use strict;
use warnings;
use DBI;

my $dbh = DBI->connect("dbi:SQLite:dbname=t.db");

# FINDING 1: double-quoted $name interpolation into SQL.
my $sth = $dbh->prepare("SELECT * FROM users WHERE name = '$name'");
$sth->execute();

# FINDING 2: double-quoted $id interpolation into SQL.
$dbh->do("DELETE FROM logs WHERE id = $id");

# FINDING 3: single-string system() routes the command through the shell.
system("rm -rf $dir");

# FINDING 4: backtick operator interpolates $dir into the command.
`rm -rf $dir`;

# NOT findings: parameterized ? placeholders and argument-list / static forms.
# Double-quoted strings with $var are flagged; ?-placeholder queries bound
# separately through execute()/do() stay quiet, and single-quoted strings never
# interpolate.  system("ls", $dir) uses the argument-list form (no shell), a
# static single-string command has nothing to interpolate, and static
# backtick / qx{} commands with no $var are unchanged.
my $ok = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$ok->execute($name);
$dbh->do("DELETE FROM logs WHERE id = ?", {}, $id);
my $row = $dbh->selectrow_array("SELECT COUNT(*) FROM logs WHERE id = ?", {}, $id);
system("ls", $dir);
exec("npm", "run", "build");
my $when = `date`;
qx{git log --oneline};
