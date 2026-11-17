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
    r"\b(execute|executemany|cursor\.execute|db\.query|query_all|query_one|run_query|cursor3\.execute|db.execute)\s*\(\s*([\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"']*[\"']\s*\+)",
    re.I,
)
# Assignment form: query = f"... {user_input} ..." followed later by execute(query)
RE_SQL_FSTRING_ASSIGN = re.compile(
    r"""^\s*[A-Za-z_]\w*\s*=\s*f["'][^"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE).*\{[^}]+}""",
    re.I,
)
RE_SQL_CONCAT_JS = re.compile(
    r"\b(db\.(query|run|all|get)|mysql\.query|pg\.query|knex\.raw|sequelize\.query)\s*\(\s*[\"'][^\"']*(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)[^\"']*[\"']\s*(\+\s*|`)|`.*SELECT.*\$\{",
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
        if py_ext and (RE_SQL_CONCAT_PY.search(line) or RE_SQL_FSTRING_ASSIGN.match(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if js_ext and (RE_SQL_CONCAT_JS.search(line) or RE_SQL_CONCAT_JS_ASSIGN.search(line)):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 ($1)"))
        if py_ext and RE_SHELL_CONCAT.search(line):
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
        if RE_DANGEROUS_SHELL.search(line) and "subprocess" in line.lower():
            findings.append(hit(lineno, "injection.shell_concat", "shell=True 命令执行",
                                "subprocess 调用开启 shell=True", "传入参数列表并关闭 shell"))
    return findings
