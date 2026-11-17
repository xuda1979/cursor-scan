# Secure Perl DBI usage (no findings): every query uses parameterized `?`
# placeholders bound separately through execute()/do()/selectrow_*(), and every
# shell invocation uses the argument-list form or a static command string with
# nothing to interpolate.  Single-quoted strings never interpolate in Perl, so
# the `$var` below is literal, not a runtime splice.
use strict;
use warnings;
use DBI;

my $dbh = DBI->connect("dbi:SQLite:dbname=secure.db");

my $sth = $dbh->prepare("SELECT * FROM users WHERE name = ?");
$sth->execute($name);

$dbh->do("DELETE FROM logs WHERE id = ?", {}, $id);

my $row = $dbh->selectrow_array("SELECT COUNT(*) FROM logs WHERE id = ?", {}, $id);
my $rows = $dbh->selectall_arrayref("SELECT * FROM logs WHERE id = ?", {}, $id);
my $ids = $dbh->selectcol_arrayref("SELECT id FROM logs WHERE user = ?", {}, $user);

system("ls", $dir);
exec("npm", "run", "build");
my $when = `date`;
qx{git log --oneline};
my $literal = 'INSERT INTO t VALUES ($name)';
