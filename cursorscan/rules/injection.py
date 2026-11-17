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
    r"\b(execute|executemany|executescript|cursor\.execute|db\.query|db\.execute|query_all|query_one|run_query|cursor3\.execute|fetchval|fetchrow|fetch|fetchmany)\s*\(\s*([\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"']*[\"']\s*\+)",
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
    r"\b(?:execute|executemany|executescript|query|query_all|query_one|run_query|cursor\.execute|db\.execute|fetchval|fetchrow|fetch|fetchmany)\s*\(\s*(?:"
    r"f\"[^\"]*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"]*\{[^}]+\}"
    r"|f'[^']*(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^']*\{[^}]+\})",
    re.I,
)
RE_SQL_CONCAT_JS = re.compile(
    r"\b(db\.(query|run|all|get|prepare|exec)|(?:pg|mysql)\.(?:pool\.)?query|(?:pool|connection|client|conn)\.query|better-sqlite3\.(?:prepare|exec)|mysql\.query|knex\.raw|sequelize\.query|prisma\.\w+)\s*\(\s*[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"']*[\"']\s*(\+\s*|`)|`.*SELECT.*\$\{",
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
# Cross-language SQL concatenation.
#
# Shared building blocks: a quoted string containing a SQL keyword, matched
# with the same-quote closure (a double-quoted string may legally contain
# ' and vice-versa, so the classic [^"'] class would break on embedded
# quotes), and the SQL keyword alternation.
_SQL_KW = "(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)"
_SQL_STR = (
    '"(?:[^"]*' + _SQL_KW + '[^"]*)"|'
    "'(?:[^']*" + _SQL_KW + "[^']*)'"
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
# executors.  Static literals and parameterized ../? placeholders (bound
# separately) are not concatenations and stay quiet.
RE_SQL_CONCAT_JAVA = re.compile(
    r"\.execute(?:Query|Update)?\s*\(\s*(?:" + _SQL_STR + r")\s*\+",
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
# quiet.  CommandContext shifts the context-first argument, skipped by the
# optional ``[^,]+,\s*`` group.
RE_SQL_CONCAT_GO = re.compile(
    r"\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:[^,]+,\s*)?(?:" + _SQL_STR + r")\s*\+"
    r"|\.(?:Query|QueryRow|Exec|QueryContext|QueryRowContext|ExecContext)\s*\(\s*(?:[^,]+,\s*)?fmt\.Sprintf\(\s*\"[^\"]*(?:" + _SQL_KW + r")[^\"]*%[a-zA-Z][^\"]*\"",
    re.I,
)
RE_SHELL_CONCAT_GO = re.compile(
    r"exec\.Command(?:Context)?\s*\(\s*(?:[^,]+,\s*)?"
    r"(?:[\"'](?:sh|bash|zsh|dash|/bin/sh|/bin/bash|/bin/zsh|/bin/dash)[\"']\s*,\s*[\"']-c[\"']\s*,\s*(?:"
    r"\"[^\"]*\"\s*\+|'[^']*'\s*\+|fmt\.Sprintf\(\s*\"[^\"]*%[a-zA-Z][^\"]*\"\s*,"
    r"))",
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
# shape (execSQL is Android SQLite); shell forms: Runtime.getRuntime().exec
# with `+` (Java interop) and ProcessBuilder launching a shell -c with a
# concatenated command string.  Parameterized ? / rawQuery selectionArgs and
# ProcessBuilder arg lists stay quiet.
RE_SQL_CONCAT_KT = re.compile(
    r"\.(?:executeQuery|executeUpdate|execute|execSQL|rawQuery)\s*\(\s*(?:" + _SQL_STR + r")\s*\+",
    re.I,
)
RE_SHELL_CONCAT_KT = re.compile(
    r"Runtime\.getRuntime\(\)\.exec\s*\(\s*[\"'][^\"']*[\"']\s*\+"
    r"|ProcessBuilder\s*\(\s*[\"'](?:/bin/sh|/bin/bash|/bin/zsh|sh|bash)[\"']\s*,\s*[\"']-c[\"']\s*,\s*(?:\"[^\"]*\"|'[^']*')\s*\+",
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

    for lineno, raw in code_lines(code):
        if "import " in raw or "from " in raw:
            continue
        line = raw
        if py_ext and (RE_SQL_CONCAT_PY.search(line) or RE_SQL_FSTRING_ASSIGN.match(line)
                       or RE_SQL_FSTRING_CALL_PY.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if js_ext and (RE_SQL_CONCAT_JS.search(line) or RE_SQL_CONCAT_JS_ASSIGN.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 ($1)"))
        if py_ext and RE_SHELL_CONCAT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if py_ext and RE_SHELL_FSTRING_PY.search(line) \
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
        if ext == "go" and RE_SHELL_CONCAT_GO.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if ext == "cs" and RE_SHELL_CONCAT_CS.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if ext == "kt" and RE_SHELL_CONCAT_KT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if RE_DANGEROUS_SHELL.search(line) and "subprocess" in line.lower():
            findings.append(hit(lineno, "injection.shell_concat", "shell=True 命令执行",
                                "subprocess 调用开启 shell=True", "传入参数列表并关闭 shell"))
    return findings
