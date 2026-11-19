// Secure D usage: parameterized queries, static SQL, static command lines,
// argument lists, and unrelated `~` string concatenation -- none tainted.

import std.process;
import std.stdio;

void goodQueries(Connection conn, int id)
{
    // Static SQL literal, no concatenation.
    db.query("SELECT * FROM users WHERE id = 1");

    // Parameterized query with a placeholder value.
    db.query("SELECT * FROM users WHERE id = ?", id);

    // Already-bound statement, no keyword-bearing fragment fed to ~.
    conn.execute("UPDATE logs SET status = 'ok'");

    // Non-SQL ~ concatenation into a variable.
    auto msg = name ~ " is here";
    writeln(msg);
}

void goodShell(string cmd)
{
    // Static command, no concatenation.
    executeShell("ls -l");
    spawnShell(["echo", "hi"]);
    auto r = system("date");

    // Variable-only command line; no spliced literal fragment.
    executeShell(cmd);
}
