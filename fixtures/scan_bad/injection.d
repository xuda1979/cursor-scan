// Deliberately unsafe D (DLang) SQL concatenation and shell execution
// (CWE-89 / CWE-78): user-controlled values are spliced into vibe.d /
// mysql-native queries with the `~` operator, and commands are launched
// through std.process with concatenated arguments, instead of parameterized
// queries / static command lines.

import std.process;
import std.stdio;
import vibe.data.serialization;

void badQueries(Connection conn, string userId, string cols)
{
    // String concatenation into SQL, executed via a db.query sink.
    db.query("SELECT * FROM users WHERE id = " ~ userId);

    // conn.execute with a concatenated UPDATE.
    conn.execute("UPDATE logs SET status = '" ~ status ~ "' WHERE id = " ~ id);

    // mysql-native db.exec with a concatenated SELECT.
    db.exec("SELECT id FROM accounts WHERE owner = '" ~ owner ~ "'");

    // conn.prepare with a concatenated DELETE.
    conn.prepare("DELETE FROM orders WHERE id > " ~ minId);

    // Assignment build fed to a query later.
    auto sql = "SELECT * FROM users WHERE id = " ~ userId;
    string query = "SELECT name FROM t WHERE id = " ~ userInput;
    db.query(sql);
}

void badShell(string dir, string target, string host)
{
    // executeShell with a concatenated argument.
    executeShell("ls -l " ~ dir);

    // spawnShell with a concatenated command.
    spawnShell("tar czf /tmp/out.tgz " ~ target);

    // system with a concatenated command.
    system("mkdir " ~ dirName);
}
