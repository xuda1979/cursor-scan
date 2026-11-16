"""Regression tests for AST-level injection detection of f-string and
template-literal concatenation.

Historically ``_has_concat`` only recognised ``+`` / ``%`` concatenation, so
the most common AI-generated injection idiom -- ``cursor.execute(f"...{x}")``
and JS ``db.query(`...${x}`)`` -- escaped detection. These tests lock in the
direct-call interpolation forms and assert safe parameterized calls stay clean.
"""

from __future__ import annotations

from cursorscan.rules.injection import analyze_code as analyze_injection
from cursorscan.scanners.ast import analyze_jsts, analyze_python


def _py(code: str):
    finds = []
    analyze_python("x.py", code, finds)
    return finds


def _js(code: str):
    finds = []
    analyze_jsts("x.js", code, finds)
    return finds


def _js_regex(code: str):
    return [(f.rule_id, f.line) for f in analyze_injection("x.js", code)]


class TestPythonFstringConcat:
    def test_execute_fstring_flags(self):
        finds = _py('cur.execute(f"SELECT * FROM users WHERE id = {user_id}")\n')
        assert [(f.rule_id, f.severity) for f in finds] == [
            ("injection.sql_concat", "critical")]

    def test_execute_fstring_with_format_spec_flags(self):
        finds = _py('cur.execute(f"SELECT * FROM users WHERE name = {username!r}")\n')
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_os_system_fstring_flags(self):
        finds = _py('os.system(f"grep {host} /etc/passwd")\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_parameterized_execute_is_clean(self):
        finds = _py('cur.execute("SELECT * FROM users WHERE name = %s", (username,))\n')
        assert finds == []

    def test_constant_query_is_clean(self):
        finds = _py('cur.execute("SELECT * FROM users WHERE id = ?")\n')
        assert finds == []

    def test_constant_fstring_escaped_braces_is_clean(self):
        # {{literal}} is not interpolation; no findings.
        finds = _py('cur.execute(f"SELECT * FROM users WHERE name = {{literal}}")\n')
        assert finds == []

    def test_fstring_without_sql_keyword_is_clean(self):
        finds = _py('cur.execute(f"SET x = {n}")\n')
        assert finds == []

    def test_subprocess_list_form_is_clean(self):
        finds = _py('subprocess.run(["grep", host])\n')
        assert finds == []


class TestPythonShellConcatGaps:
    def test_os_popen_concat_flags(self):
        finds = _py("out = os.popen('ls ' + user_dir)\n")
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_os_popen_static_is_clean(self):
        finds = _py("out = os.popen('ls /tmp')\n")
        assert finds == []

    def test_os_popen_list_form_is_clean(self):
        finds = _py("out = os.popen(['ls', d])\n")
        assert finds == []


class TestJSTemplateLiteralConcat:
    def test_db_query_template_literal_flags(self):
        finds = _js("db.query(`SELECT * FROM users WHERE id = ${id}`);\n")
        assert [(f.rule_id, f.severity) for f in finds] == [
            ("injection.sql_concat", "critical")]

    def test_parameterized_query_clean(self):
        finds = _js('db.query("SELECT * FROM users WHERE id = ?", [id]);\n')
        assert finds == []

    def test_constant_template_literal_clean(self):
        finds = _js("db.query(`SELECT * FROM users WHERE id = ?`);\n")
        assert finds == []


class TestJSCrossLineSqlConcat:
    """JS `const q = 'SELECT ...' + input` built on one line and handed to a
    DB driver on a later line.  The AST call-walker only sees the bare
    identifier ``q`` at ``db.run(q)``, and the line-scanner never sees the
    tainted assignment -- so the assignment itself is the detection point
    (regex fallback, same as the Python RE_SQL_FSTRING_ASSIGN form)."""

    def _reg(self, code: str):
        return _js_regex(code)

    def test_concat_assignment_flags(self):
        found = analyze_injection(
            "x.js", "const q = 'SELECT * FROM users WHERE id = ' + req.query.id;\n")
        assert [(f.rule_id, f.severity) for f in found] == [
            ("injection.sql_concat", "critical")]

    def test_concat_assignment_let_flags(self):
        assert self._reg("let q = 'SELECT * FROM users WHERE id = ' + user_id;\n") == [
            ("injection.sql_concat", 1)]

    def test_template_assignment_flags(self):
        assert self._reg("const q = `SELECT * FROM orders WHERE total > ${amount}`;\n") == [
            ("injection.sql_concat", 1)]

    def test_static_assignment_is_quiet(self):
        # No concatenation; a constant query string.
        assert self._reg("const q = 'SELECT * FROM users ORDER BY id';\n") == []

    def test_no_sql_keyword_is_quiet(self):
        assert self._reg("const msg = 'hello ' + name;\n") == []

    def test_object_literal_assignment_is_quiet(self):
        # A JS object body is not a SQL string concat.
        assert self._reg("const data = { op: 'SELECT', source: x } + obj;\n") == []

    def test_single_line_db_run_still_flags(self):
        # The direct-call form must keep working alongside the new pass.
        assert self._reg("db.run('SELECT * FROM users WHERE id = ' + req.query.id);\n") == [
            ("injection.sql_concat", 1)]


class TestE2EFixtureLock:
    def test_direct_fstring_form_and_assignment_form_both_found(self, scan_bad_dir):
        from cursorscan.scan import scan_project

        result = scan_project(str(scan_bad_dir))
        lines = {
            f"{f.file.rsplit('/', 1)[-1]}:{f.line}": f.rule_id
            for f in result.findings if f.rule_id == "injection.sql_concat"
        }
        # assignment form (get_user_v2) and direct-call form (get_user_v3)
        assert "injection.py:19" in lines
        assert "injection.py:26" in lines

    def test_good_fixture_stays_injection_clean(self, scan_good_dir):
        from cursorscan.scan import scan_project

        result = scan_project(str(scan_good_dir))
        assert all(f.rule_id != "injection.sql_concat" for f in result.findings)
