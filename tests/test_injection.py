"""Unit tests for the cross-language injection regex fallbacks.

The line-scanner regex rules in cursorscan/rules/injection.py also cover PHP
(`.` concat), Java (`+` concat) and Ruby (`+` concat / `#{}` interpolation)
for both SQL string-concatenation and shell-command concatenation.  These
tests lock in the dynamic forms as findings and the static/parameterized/
argument-list forms as quiet negatives.
"""

from __future__ import annotations

from cursorscan.rules.injection import analyze_code as analyze_injection


def _reg(code: str, path: str = "x.php"):
    return [(f.rule_id, f.line) for f in analyze_injection(path, code)]


class TestPhpSqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.php", code)]

    def test_mysqli_query_dot_concat_flags(self):
        assert self._reg(
            'mysqli_query($conn, "SELECT * FROM users WHERE name = \'" . $name . "\'");\n'
        ) == [("injection.sql_concat", 1)]

    def test_pg_query_embedded_quote_flags(self):
        # The SQL literal contains an embedded single quote; classic [^"']
        # closure would break here.
        assert self._reg(
            "pg_query($conn, \"SELECT id FROM accounts WHERE owner = '\" . $owner . \"'\");\n"
        ) == [("injection.sql_concat", 1)]

    def test_pdo_exec_dot_concat_flags(self):
        # ->exec is PDO method dispatch (SQL), NOT a shell exec.
        assert self._reg(
            '$pdo->exec("DELETE FROM sessions WHERE token = \'" . $t . "\'");\n'
        ) == [("injection.sql_concat", 1)]

    def test_pdo_prepare_dot_concat_flags(self):
        assert self._reg(
            '$db->prepare("INSERT INTO items (name) VALUES (\'" . $n . "\')");\n'
        ) == [("injection.sql_concat", 1)]

    def test_static_query_is_quiet(self):
        assert self._reg('mysqli_query($conn, "SELECT * FROM users");\n') == []

    def test_parameterized_prepare_is_quiet(self):
        assert self._reg('$pdo->prepare("SELECT * FROM t WHERE id = ?");\n') == []


class TestJavaSqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.java", code)]

    def test_execute_query_plus_concat_flags(self):
        assert self._reg(
            'stmt.executeQuery("SELECT * FROM users WHERE name = " + username);\n'
        ) == [("injection.sql_concat", 1)]

    def test_execute_update_plus_concat_flags(self):
        assert self._reg(
            'conn.createStatement().executeUpdate("DELETE FROM t WHERE id = " + id);\n'
        ) == [("injection.sql_concat", 1)]

    def test_execute_with_embedded_quote_flags(self):
        assert self._reg(
            'statement.execute("SELECT * FROM accounts WHERE owner=\'" + owner + "\'");\n'
        ) == [("injection.sql_concat", 1)]

    def test_static_query_is_quiet(self):
        assert self._reg('stmt.executeQuery("SELECT * FROM users");\n') == []

    def test_parameterized_statement_is_quiet(self):
        assert self._reg('ps.executeQuery("SELECT * FROM t WHERE id = ?");\n') == []


class TestRubySqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.rb", code)]

    def test_where_plus_concat_flags(self):
        # .where()'s first argument is raw SQL, so the receiver alone flags.
        assert self._reg('User.where("name = " + params[:name]);\n') == [
            ("injection.sql_concat", 1)]

    def test_connection_execute_plus_concat_flags(self):
        assert self._reg(
            'ActiveRecord::Base.connection.execute("SELECT * FROM t WHERE a = " + id);\n'
        ) == [("injection.sql_concat", 1)]

    def test_find_by_sql_plus_concat_flags(self):
        assert self._reg(
            'User.find_by_sql("SELECT * FROM users WHERE name = \'" + name + "\'");\n'
        ) == [("injection.sql_concat", 1)]

    def test_exec_query_plus_concat_flags(self):
        assert self._reg('Project.exec_query("UPDATE p SET x = " + val);\n') == [
            ("injection.sql_concat", 1)]

    def test_keyword_args_hash_is_quiet(self):
        assert self._reg("User.where(name: params[:name]);\n") == []


class TestPhpShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.php", code)]

    def test_system_dot_concat_flags(self):
        assert self._reg('system("rm -rf " . $dir);\n') == [
            ("injection.shell_concat", 1)]

    def test_exec_dot_concat_flags(self):
        assert self._reg('exec("sh -c " . $cmd);\n') == [
            ("injection.shell_concat", 1)]

    def test_shell_exec_dot_concat_flags(self):
        assert self._reg('shell_exec("ls " . $path);\n') == [
            ("injection.shell_concat", 1)]

    def test_proc_open_dot_concat_flags(self):
        assert self._reg('proc_open("echo " . $cmd, $pipes);\n') == [
            ("injection.shell_concat", 1)]

    def test_static_system_is_quiet(self):
        assert self._reg('system("echo hello");\n') == []


class TestRubyShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.rb", code)]

    def test_system_plus_concat_flags(self):
        assert self._reg('system("rm -rf " + dir);\n') == [
            ("injection.shell_concat", 1)]

    def test_exec_plus_concat_flags(self):
        assert self._reg('exec("sh -c " + cmd);\n') == [
            ("injection.shell_concat", 1)]

    def test_backtick_interpolation_flags(self):
        assert self._reg("`cat #{file}`;\n") == [("injection.shell_concat", 1)]

    def test_io_popen_interpolation_flags(self):
        assert self._reg('IO.popen("grep #{term}");\n') == [
            ("injection.shell_concat", 1)]

    def test_open3_capture_plus_concat_flags(self):
        assert self._reg('Open3.capture2("ls " + dir);\n') == [
            ("injection.shell_concat", 1)]

    def test_static_backtick_is_quiet(self):
        assert self._reg("`ls -la`;\n") == []


class TestJavaShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.java", code)]

    def test_runtime_exec_plus_concat_flags(self):
        assert self._reg('Runtime.getRuntime().exec("sh -c " + cmd);\n') == [
            ("injection.shell_concat", 1)]

    def test_static_runtime_exec_is_quiet(self):
        # Static command, no concatenation.
        assert self._reg('Runtime.getRuntime().exec("ls -la");\n') == []


class TestCrossExtensionSilence:
    """The new regexes must not fire on Python/JS safe forms."""

    def _reg(self, code: str, path: str):
        return [(f.rule_id, f.line) for f in analyze_injection(path, code)]

    def test_python_parameterized_execute_is_quiet(self):
        assert self._reg('cur.execute("SELECT * FROM users WHERE id = %s", (uid,))\n',
                         "x.py") == []

    def test_python_subprocess_list_form_is_quiet(self):
        assert self._reg('subprocess.run(["ls", d])\n', "x.py") == []

    def test_python_static_os_system_is_quiet(self):
        assert self._reg('os.system("echo hi")\n', "x.py") == []

    def test_js_parameterized_query_is_quiet(self):
        assert self._reg('conn.query("SELECT * FROM t WHERE id = ?", [id]);\n',
                         "x.js") == []
