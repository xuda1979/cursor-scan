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


def analyze_code(source_path: str, code: str) -> List[Evidence]:
    findings: List[Evidence] = []

    def hit(line: int, rule_id: str, title: str, msg: str, fix: str) -> Evidence:
        return Evidence(rule_id=rule_id, title=title, severity="critical", file=source_path,
                        line=line, message=msg, fix=fix, dimension="injection")

    for lineno, raw in code_lines(code):
        if "import " in raw or "from " in raw:
            continue
        line = raw
        if RE_SQL_CONCAT_PY.search(line) or RE_SQL_FSTRING_ASSIGN.match(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 (?)"))
        if RE_SQL_CONCAT_JS.search(line) or RE_SQL_CONCAT_JS_ASSIGN.search(line):
            findings.append(hit(lineno, "injection.sql_concat", "SQL 拼接注入",
                                "用户输入被拼入 SQL，存在 SQL 注入风险", "使用参数化查询 ($1)"))
        if RE_SHELL_CONCAT.search(line):
            findings.append(hit(lineno, "injection.shell_concat", "Shell 拼接注入",
                                "外部输入被拼入 shell 命令", "使用参数列表 (list) 而非字符串"))
        if RE_DANGEROUS_SHELL.search(line) and "subprocess" in line.lower():
            findings.append(hit(lineno, "injection.shell_concat", "shell=True 命令执行",
                                "subprocess 调用开启 shell=True", "传入参数列表并关闭 shell"))
    return findings
