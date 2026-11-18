"""Injection rules: SQL string concatenation, shell concatenation (no params),
eval/exec on non-literal input (Python), dangerous child_process/no-shell usage.

AST-level for Python/JS via tree-sitter, regex fallback elsewhere.
"""

from __future__ import annotations

import re
from typing import List

from ..models import Evidence
from .helpers import code_lines

# Regex fallbacks ------------------------------------------------------------
RE_SQL_CONCAT_PY = re.compile(
    r"\b(execute|executemany|executescript|text|cursor\.execute|db\.query|db\.execute|query_all|query_one|run_query|cursor3\.execute|fetchval|fetchrow|fetch|fetchmany)\s*\(\s*([\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"']*[\"']\s*\+)",
    re.I,
)
# Assignment form: query = f"... {user_input} ..." followed later by execute(query)
RE_SQL_FSTRING_ASSIGN = re.compile(
    r"""^\s*[A-Za-z_]\w*\s*=\s*f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*\{[^}]+}""",
    re.I,
)
# Call form: execute/executemany/cursor.execute/db.query/query_all/query_one
# fed a directly-interpolated f-string literal (no assignment indirection).
# The `{...}` interpolation is required so an inert f-string without
# placeholders (e.g. execute(f"SELECT 1")) stays quiet.
# The quoted f-string section is matched with same-quote closure (a double-
# quoted f-string may legally contain ' and vice-versa, so the classic
# [^"'] class would break on embedded opposite quotes, e.g.
# f"DELETE ... WHERE owner = '{owner}'").
RE_SQL_FSTRING_CALL_PY = re.compile(
    r"\b(?:execute|executemany|executescript|text|query|query_all|query_one|run_query|cursor\.execute|db\.execute|fetchval|fetchrow|fetch|fetchmany)\s*\(\s*(?:"
    r"f\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\{[^}]+\}"
    r"|f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*\{[^}]+\})",
    re.I,
)
# Shared building blocks for the cross-language SQL patterns below: a quoted
# string containing a SQL keyword, matched with the same-quote closure (a
# double-quoted string may legally contain ' and vice-versa, so the classic
# [^"'] class would break on embedded quotes), and the SQL keyword alternation.
_SQL_KW = "(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)"
_SQL_STR = (
    '"(?:[^"]*' + _SQL_KW + '[^"]*)"|'
    "'(?:[^']*" + _SQL_KW + "[^']*)'"
)
RE_SQL_CONCAT_JS = re.compile(
    r"\b(db\.(?:query|run|all|get|prepare|exec|execute)|(?:pg|mysql)\.(?:pool\.)?query|(?:pool|connection|client|conn)\.(?:query|execute)|mysql2\.(?:query|execute)|better-sqlite3\.(?:prepare|exec)|knex\.raw|sequelize\.query|prisma\.\w+)\s*\(\s*(?:"
    + _SQL_STR
    + r")\s*\+|`.*SELECT.*\$\{",
    re.I,
)
# Assignment form: JS `const q = 'SELECT ...' + input` where the SQL literal
# is concatenated with a dynamic value. The DB call (db.run(q)) sits on a
# later line the line-scanner never sees, so the tainted assignment itself is
# the only in-line evidence; Python has the analogous RE_SQL_FSTRING_ASSIGN.
RE_SQL_CONCAT_JS_ASSIGN = re.compile(
    r"""^\s*(?:const|let|var)\s+\w+\s*=\s*["'`][^"'`]*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^"'`]*["'`]\s*\+""",
    re.I,
)
RE_SHELL_CONCAT = re.compile(
    r"\b(subprocess\.(call|run|Popen|check_output|check_call)\s*\(\s*[\"'][^\"']*[\"']\s*\+|os\.system\s*\(\s*\w+.*\+|os\.popen\s*\(\s*[\"'][^\"']*[\"']\s*\+|exec\s*\(\s*[\"'][^\"']*\+|spawn\s*\(\s*[\"']),",
    re.I,
)
RE_DANGEROUS_SHELL = re.compile(
    r"\b(shell\s*=\s*True|shell:\s*true)\b", re.I
)
RE_SHELL_OFF = re.compile(r"\bshell\s*=\s*False\b", re.I)
# Python f-string shell forms: os.system/os.popen/subprocess family called
# directly with an interpolating f-string (os.system(f"rm -rf {dir}")).  The
# `{...}` interpolation is required; static f-strings (os.system(f"echo hi"))
# and plain strings stay quiet.  shell=True lines are already covered by
# RE_DANGEROUS_SHELL, and the two rules share the rule_id, so the f-string
# line keeps its single finding either way.
# Same-quote closure as RE_SQL_FSTRING_CALL_PY, so f-strings with embedded
# opposite quotes (os.system(f"rm -rf '{dir}'")) still flag.
RE_SHELL_FSTRING_PY = re.compile(
    r"\b(?:subprocess\.(?:call|run|Popen|check_output|check_call)|os\.system|os\.popen|system|popen)\s*\(\s*(?:"
    r"f\"[^\"]*\{[^}]+\}"
    r"|f'[^']*\{[^}]+\})",
    re.I,
)
# Python ``str.format()`` and ``%``-style interpolating call forms that are not
# f-strings: ``execute("SELECT ... {}".format(uid))`` and
# ``execute("SELECT ... %s" % uid)`` feed a runtime-substituted SQL literal
# straight into the driver (and os.system/subprocess variants into a shell).
# A `{...}` placeholder plus a non-empty .format(...) argument list, or the
# `` % `` operator right after a ``%s``-style conversion, marks the runtime
# interpolation; an inert ``"".format()`` (no args), parameterized
# ``"%s", (uid,)`` argument tuples and static calls stay quiet.
_RE_PY_SQL_RCV = (
    r"(?:execute|executemany|executescript|text|cursor\.execute|db\.execute|"
    r"db\.query|query_all|query_one|run_query|cursor3\.execute|fetchval|fetchrow|"
    r"fetch|fetchmany)"
)
RE_SQL_FMT_CALL_PY = re.compile(
    r"\b" + _RE_PY_SQL_RCV + r"\s*\(\s*(?:"
    r"\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}\"]*\}[^\"]*\"\s*\.format\s*\(\s*[^)]"
    r"|'[^']*(?:" + _SQL_KW + r")[^']*\{[^}']*\}[^']*'\s*\.format\s*\(\s*[^)]"
    r"|\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%\w[^\"]*\"\s+%\s+"
    r"|'[^']*(?:" + _SQL_KW + r")[^']*%\w[^']*'\s+%\s+"
    r")",
    re.I,
)
# Assignment form: ``query = "SELECT ... {}".format(uid)`` / ``% uid`` where the
# driver call (execute(query)) sits on a later line the line-scanner never sees,
# mirroring RE_SQL_FSTRING_ASSIGN.
RE_SQL_FMT_ASSIGN_PY = re.compile(
    r"""^\s*[A-Za-z_]\w*\s*=\s*(?:
        ["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^"']*\{[^}]*\}[^"']*["']\s*\.format
        |["'][^"']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^"']*%\w[^"']*["']\s+%\s+
        )""",
    re.I | re.VERBOSE,
)
# Shell-family call forms using str.format()/%-style interpolation:
# os.system("rm -rf {}".format(d)) and subprocess.call("ls %s" % d) build the
# command string at runtime then hand it to a shell, exactly like the f-string
# form (RE_SHELL_FSTRING_PY).  The interpolation (`{...}` + non-empty .format
# args, or `%s ... % var`) is required; static commands and parameterized
# subprocess arg tuples stay quiet.
RE_SHELL_FMT_CALL_PY = re.compile(
    r"\b(?:subprocess\.(?:call|run|Popen|check_output|check_call)|os\.system|os\.popen|system|popen)\s*\(\s*(?:"
    r"\"[^\"]*\{[^}\"]*\}[^\"]*\"\s*\.format\s*\(\s*[^)]"
    r"|'[^']*\{[^}']*\}[^']*'\s*\.format\s*\(\s*[^)]"
    r"|\"[^\"]*%\w[^\"]*\"\s+%\s+"
    r"|'[^']*%\w[^']*'\s+%\s+"
    r")",
    re.I,
)
# PHP builds SQL strings with the `.` concatenation operator; the DB entry
# points are mysqli_query($conn, ...) / pg_query($conn, ...) and the
# PDO-style object receivers `$pdo->query/exec/prepare(...)` (variable-ish
# receivers since PHP is untyped).  Static literals without concatenation
# (e.g. mysqli_query($conn, "SELECT 1") or prepare with ? placeholders)
# stay quiet: the `.` concat after the quoted SQL is required.
RE_SQL_CONCAT_PHP = re.compile(
    r"\b(?:mysqli_query|pg_query)\s*\([^;]*?(?:" + _SQL_STR + r")\s*\."
    r"|\$\w+\s*->\s*(?:query|exec|prepare)\s*\([^;]*?(?:" + _SQL_STR + r")\s*\.",
    re.I,
)
# Java uses the `+` concatenation operator on Statement/PreparedStatement
# builders and executors, and String.format with a printf verb inside
# execute(Query|Update) feeds a formatted SQL literal straight to the driver
# (the Go fmt.Sprintf analog).  Spring JdbcTemplate receivers (query/queryForList/
# execute/update) and MyBatis @Select/@Update/@Delete/@Insert annotations
# interpolate SQL too: the ${...} placeholder is textually substituted, unlike
# the safe #{...} bind form.  Static literals, parameterized ../?/#{...}
# placeholders (bound separately) and non-substituted @Select("SELECT 1") stay
# quiet.
RE_SQL_CONCAT_JAVA = re.compile(
    r"\.execute(?:Query|Update)?\s*\(\s*(?:" + _SQL_STR + r")\s*\+"
    r"|\.prepareStatement\s*\(\s*(?:" + _SQL_STR + r")\s*\+"
    r"|\.execute(?:Query|Update)?\s*\(\s*String\.format\s*\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\""
    r"|\.?(?:jdbcTemplate|jdbc)\.(?:query|queryForList|queryForObject|execute|update)\s*\(\s*(?:" + _SQL_STR + r")\s*\+"
    r"|@(?:Select|Update|Delete|Insert)\s*\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\$\{[^}]+\}",
    re.I,
)
# Ruby: ActiveRecord finders/exec helpers taking a concatenated SQL string,
# plus the `#{}` double-quoted string-interpolation form baked into a query
# literal.  The .where() receiver's first argument IS raw SQL, so a `+` or
# `#{}` next to it flags on the receiver alone; single-quoted strings do not
# interpolate in Ruby, so their `#{}` stays literal and quiet.
RE_SQL_CONCAT_RUBY = re.compile(
    r"\.(?:find_by_sql|execute|exec_query)\s*\(?[^;]*?(?:" + _SQL_STR + r")\s*\+"
    r"|\.where\s*\([^)]*?(?:\"[^\"]*\"\s*\+|'[^']*'\s*\+|\"[^\"]*#\{[^}]+\})"
    r"|(?:\"[^\"]*" + _SQL_KW + r"[^\"]*#\{[^}]+\})",
    re.I,
)
# Cross-language shell concatenation.
#
# PHP function form with `.` (system/exec/shell_exec/passthru/proc_open
# taking the command as first argument); a receiver `->exec` is a method
# dispatch (SQL executor, etc.), never a shell call, so bare exec is guarded
# with a -> lookbehind.  Ruby Kernel system/exec, backtick literals and
# IO.popen/Open3 with `+` concatenation or double-quoted `#{}`
# interpolation; Java Runtime.exec with `+`.  Static commands with no
# concatenation / no interpolation stay quiet.
RE_SHELL_CONCAT_PHP = re.compile(
    r"(?:\b(?:system|shell_exec|passthru|proc_open)\s*\(|(?<!->)\bexec\s*\()"
    r"\s*(?:\"[^\"]*\"|'[^']*')\s*\.",
    re.I,
)
RE_SHELL_CONCAT_RUBY = re.compile(
    r"\b(?:system|exec)\s*\(\s*"
    r"(?:\"[^\"]*\"\s*\+|'[^']*'\s*\+|\"[^\"]*#\{[^}]+\})"
    r"|`[^`]*#\{[^}]+\}[^`]*`"
    r"|IO\.popen\s*\(\s*(?:\"[^\"]*\"\s*\+|'[^']*'\s*\+|\"[^\"]*#\{[^}]+\})"
    r"|Open3\.\w+\s*\(\s*(?:\"[^\"]*\"\s*\+|'[^']*'\s*\+)",
)
RE_SHELL_CONCAT_JAVA = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'][^\"']*[\"']\s*\+",
    re.I,
)
# Go (database/sql): receivers with `+` concatenation, or a fmt.Sprintf
# format string containing a printf verb (db.Query(fmt.Sprintf("...%s", x))
# feeds the formatted SQL straight into the driver).  Parameterized `?`
# placeholders and arg lists stay quiet.  exec.Command shell forms require
# the explicit `-c` shell invocation (exec.Command("ping", "-c", host) is
# ping's count flag, not a shell) PLUS a concatenated/`+` or interpolating
# Sprintf command string; exec.Command("ping", host) arg-list forms stay
# quiet.  The Windows cmd shell is covered by the `cmd`/`cmd.exe` + `/C`
# (also `/c`, `-c`) invocation with the same dynamic command-string demand;
# `cmd /C` with a static command stays quiet.  CommandContext shifts the
# context-first argument, skipped by the optional ``[^,]+,\s*`` group.
RE_SQL_CONCAT_GO = re.compile(
    r"\.(?:Raw|Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:[^,]+,\s*)?(?:" + _SQL_STR + r")\s*\+"
    r"|\.(?:Raw|Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:[^,]+,\s*)?fmt\.Sprintf\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\""
    r"|\.(?:Where|Joins|Having)\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*\+",
    re.I,
)
RE_SHELL_CONCAT_GO = re.compile(
    r"exec\.Command(?:Context)?\s*\(\s*(?:[^,]+,\s*)?"
    r"(?:"
    r"[\"'](?:sh|bash|zsh|dash|/bin/sh|/bin/bash|/bin/zsh|/bin/dash)[\"']\s*,\s*[\"']-c[\"']\s*,\s*(?:"
    r"\"[^\"]*\"\s*\+|'[^']*'\s*\+|fmt\.Sprintf\(\s*\"[^\"]*%[a-zA-Z][^\"]*\"\s*,"
    r")"
    r"|[\"'](?:cmd|cmd\.exe)[\"']\s*,\s*[\"']/?-?c[\"']\s*,\s*(?:"
    r"\"[^\"]*\"\s*\+|'[^']*'\s*\+|fmt\.Sprintf\(\s*\"[^\"]*%[a-zA-Z][^\"]*\"\s*,"
    r")"
    r")",
    re.I,
)
# C# (.cs): System.Data/System.Data.SqlClient command constructors
# (new SqlCommand("SELECT ... " + x, conn)), CommandText assignment with `+`
# concatenation or interpolated-string ($"...{x}") templates; .NET
# Process.Start / ProcessStartInfo commands built with `+` concatenation or
# interpolated Arguments.  Parameterized @id / ? placeholders and static
# Process.Start invocations stay quiet.
RE_SQL_CONCAT_CS = re.compile(
    r"new\s+\w*Command\s*\(\s*(?:" + _SQL_STR + r")\s*\+"
    r"|new\s+\w*Command\s*\(\s*\$\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]+\}"
    r"|\.CommandText\s*=\s*(?:" + _SQL_STR + r")\s*\+"
    r"|\.CommandText\s*=\s*\$\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]+\}",
    re.I,
)
# A dynamic shell-command argument: a quoted string followed by `+`
# concatenation, or a `$`-interpolated quoted string containing a `{...}`
# template (interpolated strings are the only braces that expand at runtime).
# Static literals, @-strings and format-less quotes stay quiet.  The group
# keeps the inner `|` contained so a bare interpolated string elsewhere on the
# line cannot satisfy the shell rule on its own.
_CS_DYN_ARG = r'(?:\"[^\"]*\"\s*\+|\$\"[^\"]*\{[^}]+\})'
RE_SHELL_CONCAT_CS = re.compile(
    (r"(?:System\.Diagnostics\.)?Process\.Start\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*\+"
     r"|(?:System\.Diagnostics\.)?Process\.Start\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*,\s*"
     + _CS_DYN_ARG
     + r"|(?:ProcessStartInfo|Process)\s*\(?\)?\s*\{\s*[^}]*\.?Arguments\s*=\s*"
     + _CS_DYN_ARG
     + r"|StartInfo\s*=\s*\{[^}]*\.?Arguments\s*=\s*"
     + _CS_DYN_ARG
     + r"|new\s+\w*StartInfo\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*,\s*"
     + _CS_DYN_ARG
     + r"|\.Arguments\s*=\s*"
     + _CS_DYN_ARG),
    re.I,
)
# Kotlin (.kt): JDBC/Android SQL receivers (executeQuery/executeUpdate/
# execute/rawQuery/execSQL) with `+` concatenation, mirroring the Java rule
# shape (execSQL is Android SQLite), plus the Spring JdbcTemplate receivers
# (query/queryForList/execute/update) taking a concatenated SQL literal.
# Shell forms: Runtime.getRuntime().exec with `+` (Java interop) and
# ProcessBuilder launching a shell -c with a concatenated command string.
# Parameterized ? / rawQuery selectionArgs and ProcessBuilder arg lists stay
# quiet.
RE_SQL_CONCAT_KT = re.compile(
    r"\.(?:executeQuery|executeUpdate|execute|execSQL|rawQuery)\s*\(\s*(?:" + _SQL_STR + r")\s*\+"
    r"|\.?(?:jdbcTemplate|jdbc)\.(?:query|queryForList|queryForObject|execute|update)\s*\(\s*(?:" + _SQL_STR + r")\s*\+",
    re.I,
)
RE_SHELL_CONCAT_KT = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'][^\"']*[\"']\s*\+"
    r"|ProcessBuilder\s*\(\s*[\"'](?:/bin/sh|/bin/bash|/bin/zsh|sh|bash)[\"']\s*,\s*[\"']-c[\"']\s*,\s*(?:\"[^\"]*\"|'[^']*')\s*\+",
    re.I,
)
# Rust: rusqlite / sqlx / tokio-postgres execute/query receivers interpolating
# a string literal with `format!`/`format_args!` verbs (db.execute(&format!(
# "SELECT .. {}", id)) feeds the formatted SQL straight into the driver), the
# `+` string-concat form into the same receivers, and the `println!`-style
# bare `format!` assignment (`let q = format!("SELECT ... {}", id);` followed
# on a later line by a driver call the line-scanner never sees, mirroring
# RE_SQL_FSTRING_ASSIGN / RE_SQL_FMT_ASSIGN_PY).  Static literals,
# parameterized `?` placeholders and `.bind(...)`/`(?,).bind()` arg lists stay
# quiet.  Shell forms: std::process::Command launching an explicit
# `sh`/`cmd` + `-c` with a concatenated or format!-built command string; the
# `-c` requirement mirrors the Go rule (Command::new("sh") without `-c` is an
# argv file, never a shell).  Command/Child arg-list forms and the `-c`
# flag of non-shell binaries stay quiet.
RE_SQL_CONCAT_RS = re.compile(
    r"(?:\.|::)(?:execute|query|query_one|query_row|query_map|query_as|"
    r"query_scalar|fetch_one|fetch_optional|fetch_all)\s*\(\s*(?:&?\s*\(?\s*)?(?:"
    r"format!\s*\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]*\}"
    r"|fmt::format\s*\(\s*(?:format_args!\s*\(\s*&?\s*)?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]*\}"
    r"|format_args!\s*\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]*\}"
    r"|(?:" + _SQL_STR + r")\s*\+"
    r"|(?:" + _SQL_STR + r")\s*\.to_string\s*\(\s*\)\s*\+"
    r")",
    re.I,
)
RE_SQL_FMT_ASSIGN_RS = re.compile(
    r"^\s*(?:let|let mut)\s+[A-Za-z_]\w*\s*=\s*("
    r"format!\s*\(\s*\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\{[^}]*\}"
    r'|"[^"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^"]*"\s*\.to_string\s*\(\s*\)\s*\+'
    r"|'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*'\s*\.to_string\s*\(\s*\)\s*\+"
    r")",
    re.I,
)
RE_SHELL_CONCAT_RS = re.compile(
    r"(?:Command::new|Command::from)\s*\(\s*[\"'](?:sh|bash|zsh|dash|/bin/sh|/bin/bash|/bin/zsh|/bin/dash|cmd|cmd\.exe)[\"']\s*\)\s*\.arg\s*\(\s*[\"']/?-?c[\"']\s*\)\s*\.arg\s*\(\s*(?:&?\s*\(?\s*)?(?:"
    r"format!\s*\(\s*\"[^\"]*\{[^}]*\}"
    r"|(?:\"[^\"]*\"|'[^']*')\s*\+"
    r"|(?:\"[^\"]*\"|'[^']*')\s*\.to_string\s*\(\s*\)\s*\+"
    r")",
    re.I,
)
# Perl (.pl): DBI receivers (prepare / do / selectrow_* / selectall_* /
# selectcol_arrayref) handed a double-quoted query literal containing `$var`
# interpolation (double-quoted Perl strings interpolate scalars and arrays at
# runtime), or a query literal built with the `.` concatenation operator
# (single- or double-quoted).  Parameterized `?` placeholders bound through
# execute()/do() stay quiet.  Shell forms: single-string system/exec calls
# (one-argument form routes through the shell), backtick operators and
# qx{...} with an interpolated `$var` command string.  Argument-list
# system("ls", $dir) and static single-string commands stay quiet, and
# single-quoted strings never interpolate in Perl, so their `$var` is literal.
RE_SQL_CONCAT_PL = re.compile(
    r"\$\w+\s*->\s*(?:prepare|do|selectrow_array|selectrow_hashref|"
    r"selectall_arrayref|selectall_hashref|selectcol_arrayref)\s*\(\s*"
    r"(?:"
    r'"[^"]*' + _SQL_KW + r'[^"]*\$'
    r"|(?:" + _SQL_STR + r")\s*\."
    r")",
    re.I,
)
RE_SHELL_CONCAT_PL = re.compile(
    r"\b(?:system|exec)\s*\(?\s*\"[^\"$]*\$[a-zA-Z_{@]"
    r"|`[^`]*\$[a-zA-Z_{@]"
    r"|\bqx\s*[^a-zA-Z0-9_']\s*[^$]*?\$[a-zA-Z_{@]",
    re.I,
)
# Lua (.lua): LuaSQL receivers (conn:execute / db:execute / db.exec) and
# LuaSQLite3 (db:exec / db:execute) handed a query literal spliced together
# with the `..` concatenation operator (Lua's string concat), or built
# through string.format("...%s", v) where the printf verb is baked into a
# SQL-keyword literal (the Go fmt.Sprintf / Java String.format analog);
# both splice runtime values straight into the query sent to the driver.
# Static literals, parameterized ? placeholders and non-receiver assignments
# stay quiet.  Shell forms: os.execute / io.popen with a `..`-concatenated
# or string.format-built command string; static commands with nothing to
# interpolate stay quiet.
RE_SQL_CONCAT_LUA = re.compile(
    r"\b[a-zA-Z_]\w*\s*[:.]\s*exec(?:ute)?\s*\(\s*(?:"
    + _SQL_STR
    + r")\s*\.\.\s*"
    r"|\b[a-zA-Z_]\w*\s*[:.]\s*exec(?:ute)?\s*\(\s*string\.format\s*\(\s*(?:"
    r"\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\""
    r"|'[^']*(?:" + _SQL_KW + r")[^']*%[a-zA-Z][^']*'"
    r")",
    re.I,
)
RE_SHELL_CONCAT_LUA = re.compile(
    r"\b(?:os\.execute|io\.popen)\s*\(\s*(?:"
    r"\"[^\"]*\"\s*\.\.\s*"
    r"|'[^']*'\s*\.\.\s*"
    r"|string\.format\s*\(\s*(?:\"[^\"]*%[a-zA-Z][^\"]*\"|'[^']*%[a-zA-Z][^']*')"
    r")",
    re.I,
)
# C/C++ (.c/.h/.cpp/.hpp/.cc/.cxx): C SQLite (sqlite3_exec) and MySQL
# (mysql_query / mysql_real_query) receivers handed a query literal spliced
# with the `+` operator (C++ std::string, possibly wrapped in `.c_str()`),
# or a query string built through sprintf()/snprintf() with a printf verb
# baked into a SQL-keyword literal.  Prepared statements (sqlite3_prepare_v2
# / mysql_stmt_*) and static literals stay quiet.  Shell forms: a command
# string built with sprintf()/snprintf() using a printf verb and then handed
# to system()/popen() on the same line, or a std::string `+` concat passed
# straight into system()/popen(); static command strings stay quiet.
RE_SQL_CONCAT_CPP = re.compile(
    r"\b(?:sqlite3_exec|mysql_query|mysql_real_query)\s*\(\s*[^,]+,\s*"
    r"(?:std::string\s*\(|\(|)\s*(?:" + _SQL_STR + r")\s*"
    r"(?:\)\s*)?(?:\.\s*c_str\s*\(\s*\)\s*)?\+"
    r"|\b(?:snprintf|sprintf)\s*\(\s*[^,]+,?\s*(?:[^,]+,\s*)?(?:"
    r"\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\""
    r"|'[^']*(?:" + _SQL_KW + r")[^']*%[a-zA-Z][^']*'"
    r")",
    re.I,
)
RE_SHELL_CONCAT_CPP = re.compile(
    r"(?:system|popen)\s*\(\s*\(\s*(?:std::string\s*\(\s*)?(?:\"[^\"]*\"|'[^']*')\s*\)?\s*\+"
    r"|\b(?:snprintf|sprintf)\s*\(\s*[^,]+,?\s*(?:[^,]+,\s*)?"
    r"(?:\"[^\"]*%[a-zA-Z][^\"]*\"|'[^']*%[a-zA-Z][^']*')[^)]*\)"
    r"\s*;\s*(?:system|popen)\s*\(",
    re.I,
)
# Swift (.swift): SQLite.swift / FMDB receivers (execute / prepare / run /
# scalar / executeUpdate / executeQuery / executeStatements) handed a query
# literal spliced with the `+` operator or built with `\(...)` string
# interpolation, plus the C API sqlite3_exec with a `+`-concatenated query.
# Parameterized `?` placeholders, selection args and static literals stay
# quiet.  Shell forms: Process / NSTask `arguments` arrays launching a shell
# with `-c` as the first element and a `+`-concatenated / `\(...)`-interpolated
# command string, plus the C `system()` function taking a concatenated /
# interpolated command; static command strings stay quiet.
RE_SQL_CONCAT_SWIFT = re.compile(
    r"\b[a-zA-Z_]\w*\s*[.:]\s*(?:execute|prepare|run|scalar|executeUpdate|"
    r"executeQuery|executeStatements)\s*\(\s*"
    r"(?:"
    r"(?:" + _SQL_STR + r")\s*\+"
    + r'|"[^"]*(?:' + _SQL_KW + r')[^"]*\\\([^"]*"'
    + r")"
    + r"|\bsqlite3_exec\s*\(\s*[^,]+,\s*"
    + r"(?:" + _SQL_STR + r")\s*\+",
    re.I,
)
# A dynamic shell command argument: a quoted string spliced with `+`, or a
# double-quoted string containing a `\(...)` interpolation (the only braces
# that expand at runtime in Swift).  Static literals stay quiet.
_SWIFT_DYN_ARG = r'(?:"[^"]*"\s*\+|"[^"]*\\\([^"]*")'
RE_SHELL_CONCAT_SWIFT = re.compile(
    r"\barguments\s*(?::\s*|\s*=\s*)\s*\[\s*(?:"
    r"[\"']-c[\"']\s*,\s*" + _SWIFT_DYN_ARG
    + r"|[\"'](?:/bin/)?(?:sh|bash|zsh|dash)[\"']\s*,\s*[\"']-c[\"']\s*,\s*"
    + _SWIFT_DYN_ARG
    + r")"
    + r"|\bsystem\s*\(\s*"
    + _SWIFT_DYN_ARG,
    re.I,
)
# Shell (.sh/.bash/.zsh): SQL passed to a CLI database client (sqlite3 / mysql /
# psql / mysqlsh) as a double-quoted literal that interpolates a shell `$var`
# at line-splice time (the SQL argument is a double-quoted string containing a
# shell-variable reference, so runtime input reaches the parser unescaped).
# Static literals and parameterized placeholder strings stay quiet.  Shell
# forms: `eval "$cmd"` / `eval $cmd` and a shell interpreter launched with
# `-c` (sh / bash / zsh / dash) taking a command argument that is a `$var`
# reference; static command strings stay quiet, and `$#`/`$?`/`$$`/`$0` are
# positional/runtime values, not tainted string variables.
RE_SQL_CONCAT_SH = re.compile(
    r"\b(?:sqlite3|mysql|psql|mysqlsh)\s+[^\"'\n]*\"[^\"]*"
    + _SQL_KW
    + r"[^\"]*\$[a-zA-Z_{@*]",
    re.I,
)
RE_SHELL_CONCAT_SH = re.compile(
    r"\beval\s+(?:\$[a-zA-Z_{@*]|\"[^\"]*\$[a-zA-Z_{@*])"
    r"|\b(?:sh|bash|zsh|dash)\s+-c\s+(?:\$[a-zA-Z_{@*]|\"[^\"]*\$[a-zA-Z_{@*])",
    re.I,
)
# R (.r): DBI receivers (dbGetQuery / dbSendQuery / dbExecute / dbSendStatement /
# dbGetStatement) handed a query string spliced through paste0() / paste()
# (comma-joined runtime value), sprintf() with a printf verb baked into a
# SQL-keyword literal (the Go fmt.Sprintf analog), or the glue package's
# glue() / glue_sql() `{var}` interpolation (the R f-string analog — glue_sql
# is the safest idiom yet textually substitutes the brace span straight into
# the query).  A later-line driver call fed a `sql <- paste0(...)` / sprintf /
# glue assignment is caught by the assignment form, mirroring
# RE_SQL_FSTRING_ASSIGN.  Static literals and parameterized params=list(...)
# binding stay quiet.  Shell forms: system() with a paste0/paste-joined,
# sprintf-verb or glue-interpolated command string; static commands and
# argument-list system2() stay quiet.
RE_SQL_CONCAT_R = re.compile(
    r"\b(?:dbGetQuery|dbSendQuery|dbExecute|dbSendStatement|dbGetStatement)\s*\(\s*[^,]+,\s*(?:"
    r"(?:paste0|paste)\s*\(\s*(?:\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\"|'[^']*(?:" + _SQL_KW + r")[^']*')\s*,"
    r"|sprintf\s*\(\s*(?:\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\"|'[^']*(?:" + _SQL_KW + r")[^']*%[a-zA-Z][^']*')"
    r"|(?:glue::)?glue(?:_sql)?\s*\(\s*(?:\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]+\}\"|'[^']*(?:" + _SQL_KW + r")[^']*\{[^}]+\}')"
    r")",
    re.I,
)
RE_SQL_CONCAT_R_ASSIGN = re.compile(
    r"^\s*[A-Za-z_]\w*\s*<-\s*(?:"
    r"(?:paste0|paste)\s*\(\s*(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\"|'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*')\s*,"
    r"|sprintf\s*\(\s*(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*%[a-zA-Z]|'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*%[a-zA-Z])"
    r"|(?:glue::)?glue(?:_sql)?\s*\(\s*(?:\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\{[^}]+\}|'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*\{[^}]+\}')"
    r")",
    re.I,
)
RE_SHELL_CONCAT_R = re.compile(
    r"\bsystem\s*\(\s*(?:"
    r"(?:paste0|paste)\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*,"
    r"|sprintf\s*\(\s*(?:\"[^\"]*%[a-zA-Z][^\"]*\"|'[^']*%[a-zA-Z][^']*')"
    r"|(?:glue::)?glue\s*\(\s*(?:\"[^\"]*\{[^}]+\}|'[^']*\{[^}]+\}')"
    r")",
    re.I,
)
# PowerShell (.ps1): Invoke-Sqlcmd / Invoke-DbaQuery / Invoke-DbaCmd handed a
# double-quoted query string that interpolates a `$var` / `$(...)`
# subexpression or that is `+`-concatenated.  Double-quoted PowerShell strings
# interpolate `$` even without an explicit join operator, so a SQL-keyword
# literal containing `$var` / `$()` counts as concatenation.  Single-quoted
# strings (no interpolation), `@name`/`@id` parameter placeholders, static
# literals and @(...) splatting stay quiet.  A later-line
# `$query = "...SQL..." + $var` assignment fed to `-Query $query` is caught by
# the assignment form (line-anchored), mirroring RE_SQL_CONCAT_R_ASSIGN.
# Shell forms: Invoke-Expression / iex fed an interpolated or
# `+`-concatenated command string.
RE_SQL_CONCAT_PS1 = re.compile(
    r"\b(?:Invoke-Sqlcmd|Invoke-DbaQuery|Invoke-DbaCmd)\b[^\n;]*?(?:"
    r"\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\$[a-zA-Z_{(@*]"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\"\s*\+"
    r"|\"\$\([^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)"
    r")",
    re.I,
)
RE_SQL_CONCAT_PS1_ASSIGN = re.compile(
    r"^\s*\$?[A-Za-z_]\w*\s*=\s*(?:"
    r"\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\$[a-zA-Z_{(@*]"
    r"|\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\"\s*\+"
    r")",
    re.I,
)
RE_SHELL_CONCAT_PS1 = re.compile(
    r"\b(?:Invoke-Expression|iex)\b\s*[(-]?\s*(?:"
    r"\"[^\"]*\$[a-zA-Z_{(@*]"
    r"|\"[^\"]*\"\s*\+"
    r")",
    re.I,
)
# SQL (.sql): dynamic SQL built by concatenation inside the file itself.
# PL/SQL / T-SQL / MySQL stored procedures assemble queries with
# EXECUTE IMMEDIATE / EXEC( / sp_executesql, splicing a runtime value via
# `||` (Oracle/Postgres concatenation), `+` (T-SQL), or CONCAT(...) /
# CONCAT_WS(...) (MySQL, SQL Server 2012+).  Parameterized EXECUTE
# IMMEDIATE ... USING or sp_executesql @sql, N'@p', @p = ... bind forms and
# static literals stay quiet.
RE_SQL_CONCAT_SQL = re.compile(
    r"\b(?:EXECUTE\s+IMMEDIATE|EXEC|sp_executesql)\b[^\n;]*?(?:"
    r"(?:N)?['\"](?:[^'\"]|''|\"\")*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)(?:[^'\"]|''|\"\")*['\"]\s*(?:\|\||\+)"
    r"|@?[A-Za-z_]\w*(?:\s*\+\s*)+@?[A-Za-z_]\w*"
    r"|CONCAT(?:_WS)?\s*\([^\n;]*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)"
    r")",
    re.I,
)
RE_SQL_CONCAT_SQL_ASSIGN = re.compile(
    r"^\s*@?[A-Za-z_]\w*(?:\s+@?\w+)*\s*:?=\s*(?:"
    r"(?:N)?['\"](?:[^'\"]|''|\"\")*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)(?:[^'\"]|''|\"\")*['\"]\s*(?:\|\||\+)"
    r"|@?[A-Za-z_]\w*(?:\s*\+\s*)+@?[A-Za-z_]\w*"
    r"|CONCAT(?:_WS)?\s*\([^\n;]*?(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)"
    r")",
    re.I,
)
# VB.NET (.vb): the `&` operator (VB string concatenation; `+` also joins
# strings) glues a runtime value onto a SQL-keyword literal fed into ADO.NET
# receivers -- New SqlCommand("SELECT ... " & id, conn) or the
# .CommandText assignment form -- before ExecuteNonQuery/ExecuteReader/ExecuteScalar.
# An interpolated string ($"...{x}", VB 14+) assigned to CommandText also
# expands templates at runtime.  Parameterized @id placeholders /
# .AddWithValue(...) and static literals stay quiet.  Shell forms:
# Process.Start / ProcessStartInfo, Shell(...) and CreateObject("WScript.Shell")
# .Run called with a `&`/`+`-concatenated command string.
RE_SQL_CONCAT_VB = re.compile(
    r"New\s+\w*Command\s*\(\s*(?:" + _SQL_STR + r")\s*[&+]"
    r"|\.CommandText\s*=\s*(?:" + _SQL_STR + r")\s*[&+]"
    r"|\.CommandText\s*=\s*\$\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]+\}",
    re.I,
)
# Line-anchored assignment form: `Dim sql As String = "SELECT ... " & id`
# (or `sql = ...`) where the tainted query is built before a CommandText/
# `New SqlCommand(...)` consumer later in the routine.
RE_SQL_CONCAT_VB_ASSIGN = re.compile(
    r"^\s*Dim\s+[A-Za-z_]\w*(?:\s+As\s+\w+)?\s*=\s*(?:"
    r"(?:" + _SQL_STR + r")\s*[&+]"
    r"|\$\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\{[^}]+\}"
    r")",
    re.I,
)
_RE_ARG = r'(?:\"[^\"]*\"|' + "'[^']*')"
RE_SHELL_CONCAT_VB = re.compile(
    r"(?:System\.Diagnostics\.)?Process\.Start\s*\(\s*" + _RE_ARG + r"\s*,\s*" + _RE_ARG + r"\s*[&+]"
    r"|\bShell\s*(?:\(\s*" + _RE_ARG + r"|" + _RE_ARG + r")\s*[&+]"
    r"|CreateObject\s*\(\s*[\"']WScript\.Shell[\"']\s*\)\.Run\s*(?:\(\s*" + _RE_ARG + r"|" + _RE_ARG + r")\s*[&+]"
    r"|\.Arguments\s*=\s*" + _RE_ARG + r"\s*[&+]",
    re.I,
)
# Scala (.scala): the JVM language whose signature taint is string
# interpolation -- s"..." / f"..." templates expanding `$var` / `${expr}` --
# or `+` concatenation feeding JDBC receivers (executeQuery / executeUpdate /
# execute / prepareStatement), plus the `val query = ...` assignment build
# whose driver call sits on a later line (line-anchored).  scala.sys.process
# shell forms: Process("cmd " + arg) / Process(s"cmd $var") and the Java
# interop Runtime.getRuntime().exec("cmd " + arg).  Bound `?`/`@id`
# placeholders, static literals and Seq(...) argument-list Process launches
# stay quiet.
RE_SQL_CONCAT_SCALA = re.compile(
    r"\.(?:execute(?:Query|Update|LargeUpdate)?|prepareStatement|createQuery)\s*\(\s*(?:"
    r"[sf]?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\$[{\w]"
    r"|(?:" + _SQL_STR + r")\s*\+"
    r")",
    re.I,
)
# Line-anchored assignment form: `val query = "SELECT ... " + id` or
# `val q = s"SELECT ... $name"` where a JDBC call consumes it later.
RE_SQL_CONCAT_SCALA_ASSIGN = re.compile(
    r"^\s*(?:val|var)\s+[A-Za-z_]\w*\s*=\s*(?:"
    r"[sf]?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\$[{\w]"
    r"|(?:" + _SQL_STR + r")\s*\+"
    r")",
    re.I,
)
RE_SHELL_CONCAT_SCALA = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*\+"
    r"|\bProcess\s*\(\s*(?:"
    r"(?:s|f|raw)?\"[^\"]*\$[{\w]"
    r"|\"[^\"]*\"\s*\+"
    r"|'[^']*'\s*\+"
    r")",
    re.I,
)
# Groovy (.groovy / .gradle): the JVM scripting language whose signature taint
# is the GString -- double-quoted "..." templates expanding `$var` / `${expr}` --
# or `+` concatenation feeding JDBC receivers (executeQuery / executeUpdate /
# execute / executeInsert / prepareStatement), plus the `def q = ...` assignment
# build.  Groovy shell forms: string templates / `+` concat used through
# `.execute()` (groovy 时 java.lang.Process) or the Java interop
# Runtime.getRuntime().exec("cmd " + arg).  Bound `?` placeholders, static
# literals and list/array argument forms (["ping", host].execute()) stay quiet.
RE_SQL_CONCAT_GROOVY = re.compile(
    r"\.(?:execute(?:Query|Update|Insert)?|prepareStatement)\s*\(\s*(?:"
    r"\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\$[{\w]"
    r"|(?:" + _SQL_STR + r")\s*\+"
    r")",
    re.I,
)
# Line-anchored assignment form: `def q = "SELECT ... " + id` or
# `def q = "SELECT ... WHERE name = $name"` consumed by a JDBC call later.
RE_SQL_CONCAT_GROOVY_ASSIGN = re.compile(
    r"^\s*(?:def|final|var|String)?\s*[A-Za-z_]\w*\s*=\s*(?:"
    r"\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\$[{\w]"
    r"|(?:" + _SQL_STR + r")\s*\+"
    r")",
    re.I,
)
RE_SHELL_CONCAT_GROOVY = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*(?:\"[^\"]*\"|'[^']*')\s*\+"
    r"|\(\s*(?:\"[^\"]*\"|'[^']*')\s*\+[^)]*\)\s*\.execute\s*\("
    r"|\"[^\"]*\$[{\w][^\"]*\"\s*\.execute\s*\(",
    re.I,
)
# Dart (.dart): the Flutter/VM language whose signature taint is string
# interpolation -- "..."/$var and ${expr} templates (no prefix letter, like
# Groovy) -- or `+` concatenation feeding sqflite / postgres-style receivers
# (rawQuery / rawInsert / rawUpdate / rawDelete / execute / query), plus the
# `final q = ...` / `var q = ...` / `String sql = ...` assignment build.
# Dart shell forms: dart:io Process.run / Process.start with an interpolated
# or `+`-concatenated command string.  Bound `?` placeholders, `$1`-style
# positional placeholders, static literals, arg-list Process launches and the
# `db.query(where: ...)` builder form stay quiet.
_LITERAL = r"(?:\"[^\"]*\"|'[^']*')"
_TMPL = r"\$(?:[A-Za-z_]\w*|\{[^}]*\})"
RE_SQL_CONCAT_DART = re.compile(
    r"\.(?:rawQuery|rawInsert|rawUpdate|rawDelete|execute|query)\s*\(\s*(?:"
    + r"[\"'][^\"']*(?:" + _SQL_KW + r")[^\"']*" + _TMPL
    + r"|(?:" + _SQL_STR + r")\s*\+"
    + r")",
    re.I,
)
# Line-anchored assignment form: `final q = "SELECT ... " + id` or
# `var q = "SELECT ... WHERE name = $name"` consumed by a DB call later.
RE_SQL_CONCAT_DART_ASSIGN = re.compile(
    r"^\s*(?:(?:final|var|const)\s+)?(?:String\s+)?[A-Za-z_]\w*\s*=\s*(?:"
    + r"[\"'][^\"']*(?:" + _SQL_KW + r")[^\"']*" + _TMPL
    + r"|(?:" + _SQL_STR + r")\s*\+"
    + r")",
    re.I,
)
RE_SHELL_CONCAT_DART = re.compile(
    r"Process\.(?:run|start)\s*\(\s*(?:"
    + r"" + _LITERAL + r"\s*\+"
    + r"|[\"'][^\"']*" + _TMPL + r"[^\"']*[\"'](?:\s*[,\)])"
    + r")",
    re.I,
)
# Objective-C (.m / .mm): the signature taint is a format string built with
# NSString stringWithFormat: / [[NSString alloc] initWithFormat:] /
# stringByAppendingFormat: carrying a `%@` object placeholder, or FMDB's
# variadic executeQuery:/executeUpdate: receiving a format LITERAL with `%@`
# directly (the format ARGS list, e.g. executeQuery:withArgumentsInArray:,
# is the parameterized bind and stays quiet) -- or
# [@"..." stringByAppendingString:] concatenation -- feeding FMDB / sqlite3
# receivers.  Shell forms: system() / popen() with a format-built command,
# and NSTask @"-c" launch args built through a format call.  Static
# literals, `?` placeholders, `%d` numeric formats and stringWithFormat:
# without a SQL keyword stay quiet.
_M_FMT_SQL = (
    r"\[?(?:\[NSString\s+alloc\]\s*)?(?:NSString\s+)?"
    + r"(?:stringWithFormat:|initWithFormat:|stringByAppendingFormat:)"
    + r"\s*@?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%@"
)
_M_APPEND_SQL = (
    r"\[\s*@?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*\""
    + r"\s+(?:stringByAppendingString|stringByAppendingFormat):"
)
RE_SQL_CONCAT_M = re.compile(
    r"(?:executeQuery|executeUpdate)\s*:\s*@?\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%@"
    + r"|(?:executeQuery|executeUpdate|executeStatement)\s*:\s*"
    + r"(?:" + _M_FMT_SQL + r"|" + _M_APPEND_SQL + r")"
    + r"|\bsqlite3_exec\s*\(\s*[^,]+,\s*\[?"
    + r"(?:" + _M_FMT_SQL + r"|" + _M_APPEND_SQL + r")",
    re.I,
)
# Line-anchored assignment form: `NSString *sql = [NSString stringWithFormat:
# @"SELECT ... %@", x];` (driver call on a later line).
RE_SQL_CONCAT_M_ASSIGN = re.compile(
    r"^\s*(?:NSString\s*\*\s*|NSMutableString\s*\*\s*)?[A-Za-z_]\w*\s*=\s*\[?"
    + r"(?:" + _M_FMT_SQL + r"|" + _M_APPEND_SQL + r")",
    re.I,
)
RE_SHELL_CONCAT_M = re.compile(
    r"\b(?:system|popen)\s*\((?=[^)]*%@)[^)]*?"
    + r"(?:stringWithFormat:|initWithFormat:|stringByAppendingFormat:)"
    + r"|@\"-c\"\s*,\s*\[?\[?(?:NSString\s+)?"
    + r"(?:stringWithFormat:|initWithFormat:)[^\]]*%@",
    re.I,
)


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity="critical", file=source_path,
                        line=line, message=msg, fix=fix, dimension="injection")

    # The regex fallback below runs on every text-extension file, so each
    # language-targeted pattern is gated on the source extension.  Without
    # the gate, patterns collide across languages: Ruby's
    # ``connection.execute("SELECT ... " + id)`` also matches the Python
    # ``\bexecute\s*\(`` pattern, producing a duplicate finding on the line.
    ext = source_path.rsplit(".", 1)[-1].lower() if "." in source_path else ""
    py_ext = ext in ("py", "pyi")
    js_ext = ext in ("js", "jsx", "mjs", "cjs", "ts", "tsx", "mts", "cts")
    cpp_ext = ext in ("c", "h", "cc", "cpp", "cxx", "hpp", "hxx")
    swift_ext = ext == "swift"
    sh_ext = ext in ("sh", "bash", "zsh")
    r_ext = ext == "r"
    ps1_ext = ext == "ps1"
    sql_ext = ext == "sql"
    vb_ext = ext == "vb"
    scala_ext = ext == "scala"
    groovy_ext = ext in ("groovy", "gradle")
    dart_ext = ext == "dart"
    m_ext = ext in ("m", "mm")

    for lineno, raw in code_lines(code):
        if "import " in raw or "from " in raw:
            continue
        line = raw
        if py_ext and (RE_SQL_CONCAT_PY.search(line) or RE_SQL_FSTRING_ASSIGN.match(line)
                       or RE_SQL_FSTRING_CALL_PY.search(line)
                       or RE_SQL_FMT_CALL_PY.search(line)
                       or RE_SQL_FMT_ASSIGN_PY.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if js_ext and (RE_SQL_CONCAT_JS.search(line) or RE_SQL_CONCAT_JS_ASSIGN.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 ($1)"))
        if py_ext and RE_SHELL_CONCAT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if py_ext and (RE_SHELL_FSTRING_PY.search(line)
                       or RE_SHELL_FMT_CALL_PY.search(line)) \
                and not (RE_DANGEROUS_SHELL.search(line) and "subprocess" in line.lower()) \
                and not RE_SHELL_OFF.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # PHP '.', Java '+', Ruby '+' / '#{}' SQL concatenation.
        if ext == "php" and RE_SQL_CONCAT_PHP.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (bind 变量)"))
        if ext == "java" and RE_SQL_CONCAT_JAVA.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (bind 变量)"))
        if ext == "rb" and RE_SQL_CONCAT_RUBY.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (bind 变量)"))
        if ext == "php" and RE_SHELL_CONCAT_PHP.search(line) \
                or ext == "rb" and RE_SHELL_CONCAT_RUBY.search(line) \
                or ext == "java" and RE_SHELL_CONCAT_JAVA.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Go, C#, Kotlin (regex fallback only, no AST scanner).  Same-quote
        # SQL `+` / Sprintf-verb / interpolated-string forms and shell
        # `-c`/Process.Start/Remote-exec forms; parameterized it placeholders
        # (`?`/`@id`/arg lists) and static commands stay quiet.
        if ext == "go" and RE_SQL_CONCAT_GO.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if ext == "cs" and RE_SQL_CONCAT_CS.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (@参数)"))
        if ext == "kt" and RE_SQL_CONCAT_KT.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (bind 变量)"))
        if ext == "rs" and (RE_SQL_CONCAT_RS.search(line)
                            or RE_SQL_FMT_ASSIGN_RS.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if ext == "go" and RE_SHELL_CONCAT_GO.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if ext == "cs" and RE_SHELL_CONCAT_CS.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if ext == "kt" and RE_SHELL_CONCAT_KT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if ext == "rs" and RE_SHELL_CONCAT_RS.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Perl DBI double-quoted `$var` interpolation and `.` concatenation SQL,
        # plus single-string system/exec, backtick and qx{} shell commands.
        if ext == "pl" and RE_SQL_CONCAT_PL.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if ext == "pl" and RE_SHELL_CONCAT_PL.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Lua `..` concatenation / string.format-verb SQL into LuaSQL /
        # LuaSQLite3 receivers, and os.execute / io.popen shell commands.
        if ext == "lua" and RE_SQL_CONCAT_LUA.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if ext == "lua" and RE_SHELL_CONCAT_LUA.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # C/C++ sqlite3_exec / mysql_query / mysql_real_query receivers with
        # `+` concatenation or a sprintf/snprintf format-string SQL literal,
        # plus system()/popen() with a sprintf/snprintf-built command string.
        if cpp_ext and RE_SQL_CONCAT_CPP.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用预编译语句 (sqlite3_prepare / mysql_stmt)"))
        if cpp_ext and RE_SHELL_CONCAT_CPP.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Swift SQLite.swift / FMDB receivers with `+` concatenation or
        # `\(...)` string interpolation, and Process /bin/sh -c / system()
        # shell commands built with a concatenated or interpolated string.
        if swift_ext and RE_SQL_CONCAT_SWIFT.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if swift_ext and RE_SHELL_CONCAT_SWIFT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Shell double-quoted `$var` interpolation into a CLI-database-tool SQL
        # argument, plus eval / sh -c command injection.
        if sh_ext and RE_SQL_CONCAT_SH.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if sh_ext and RE_SHELL_CONCAT_SH.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # R paste0/paste, sprintf-verb and glue-interpolated query strings into
        # DBI receivers (plus the sql <- assignment form), and system() with a
        # paste-joined / sprintf / glue command string.
        if r_ext and (RE_SQL_CONCAT_R.search(line) or RE_SQL_CONCAT_R_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (params=list())"))
        if r_ext and RE_SHELL_CONCAT_R.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # PowerShell interpolated / concatenated -Query strings into
        # Invoke-Sqlcmd / Invoke-DbaQuery, and Invoke-Expression fed an
        # interpolated / concatenated command string.
        if ps1_ext and (RE_SQL_CONCAT_PS1.search(line) or RE_SQL_CONCAT_PS1_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (@参数)"))
        if ps1_ext and RE_SHELL_CONCAT_PS1.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # SQL dynamic-SQL: EXECUTE IMMEDIATE / EXEC / sp_executesql / CONCAT
        # splice forms and `var := '...SQL...' || x` assignment builds.
        if sql_ext and (RE_SQL_CONCAT_SQL.search(line) or RE_SQL_CONCAT_SQL_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用绑定变量 (USING / sp_executesql 参数)"))
        # VB.NET: ADO.NET New SqlCommand / .CommandText with `&`/`+`-concatenated
        # or $-interpolated template SQL (plus the `Dim sql = ...` assignment form),
        # and Process.Start / Shell / WScript.Shell Run with a concatenated command.
        if vb_ext and (RE_SQL_CONCAT_VB.search(line) or RE_SQL_CONCAT_VB_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (@参数)"))
        if vb_ext and RE_SHELL_CONCAT_VB.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Scala: s/f-interpolated ($var / ${expr}) or `+`-concatenated query
        # strings into JDBC / Hibernate receivers (plus the val query =
        # assignment form), and scala.sys.process Process / Java Runtime
        # exec with an interpolated or concatenated command string.
        if scala_ext and (RE_SQL_CONCAT_SCALA.search(line)
                          or RE_SQL_CONCAT_SCALA_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if scala_ext and RE_SHELL_CONCAT_SCALA.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Groovy: GString ($var / ${expr}) or `+`-concatenated query strings into
        # JDBC receivers (plus the `def q = ...` assignment form), and string
        # `.execute()` / Java Runtime exec with an interpolated/concatenated
        # command string.
        if groovy_ext and (RE_SQL_CONCAT_GROOVY.search(line)
                           or RE_SQL_CONCAT_GROOVY_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if groovy_ext and RE_SHELL_CONCAT_GROOVY.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Dart: interpolated ($var / ${expr}) or `+`-concatenated query strings
        # into sqflite / postgres-style receivers (plus the final/var/String
        # assignment form), and dart:io Process.run / Process.start with an
        # interpolated or concatenated command string.
        if dart_ext and (RE_SQL_CONCAT_DART.search(line)
                         or RE_SQL_CONCAT_DART_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if dart_ext and RE_SHELL_CONCAT_DART.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        # Objective-C: FMDB / sqlite3_exec receivers fed a format-built
        # (stringWithFormat: with a %@ place-holder) or stringByAppendingString:
        #-concatenated query string (plus the assignment form), and
        # system()/popen()/NSTask -c with a format-built command string.
        if m_ext and (RE_SQL_CONCAT_M.search(line) or RE_SQL_CONCAT_M_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if m_ext and RE_SHELL_CONCAT_M.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if RE_DANGEROUS_SHELL.search(line) and "subprocess" in line.lower():
            findings.append(hit(lineno, "injection.shell_concat", "shell=True 命令执行",
                                "subprocess 调用开启 shell=True", "传入参数列表并关闭 shell"))
    return findings
