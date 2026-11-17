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


class TestPythonShellSlotAwareConcat:
    """subprocess shell injection is slot-aware (mirror of the JS exec-family
    rule): a concat in a *string* command (os.system/os.popen, or a single
    string argument to subprocess) always reaches a shell and flags;
    shell=True flags; an explicit ``sh -c``/``bash -c`` argv list with a
    concat-built command flags.  But a concat inside the *argv list* of a
    shell-less subprocess call is passed as separate arguments (no
    metacharacter expansion) and stays quiet."""

    def test_list_concat_is_quiet(self):
        finds = _py('subprocess.run(["grep", prefix + suffix, f])\n')
        assert finds == []

    def test_call_list_concat_is_quiet(self):
        finds = _py('subprocess.call(["echo", a + b])\n')
        assert finds == []

    def test_check_output_list_concat_is_quiet(self):
        finds = _py('subprocess.check_output(["git", "log", msg + "x"])\n')
        assert finds == []

    def test_popen_list_concat_is_quiet(self):
        finds = _py('subprocess.Popen(["ls", user_dir + ".csv"])\n')
        assert finds == []

    def test_fstring_inside_list_is_quiet(self):
        finds = _py('subprocess.run([f"ls {d}"])\n')
        assert finds == []

    def test_string_command_concat_flags(self):
        finds = _py('subprocess.run("ls " + path)\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_call_string_concat_flags(self):
        finds = _py('subprocess.call("sudo " + payload)\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_sh_dash_c_dynamic_flags(self):
        finds = _py('subprocess.Popen(["sh", "-c", "ls " + d])\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_bash_dash_c_dynamic_flags(self):
        finds = _py('subprocess.run(["bash", "-c", "sudo " + payload])\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_sh_dash_c_static_is_quiet(self):
        finds = _py('subprocess.Popen(["sh", "-c", "echo hi"])\n')
        assert finds == []

    def test_shell_true_flags_once(self):
        # shell=True + concat: exactly one finding, not the historical double.
        finds = _py('subprocess.run(f"ping {host}", shell=True)\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_shell_true_string_concat_flags(self):
        finds = _py('subprocess.run("apt-get update && apt-get install " + name, shell=True)\n')
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_explicit_shell_false_is_quiet(self):
        # shell=False is a security configuration: no shell is invoked, so a
        # concat-built command string never reaches a shell.
        finds = _py('subprocess.run("ls " + path, shell=False)\n')
        assert finds == []

    def test_explicit_shell_false_fstring_is_quiet(self):
        finds = _py('subprocess.run(f"ping {host}", shell=False)\n')
        assert finds == []

    def test_explicit_shell_false_with_spaces_is_quiet(self):
        finds = _py('subprocess.run("ls " + path, shell = False)\n')
        assert finds == []

    def test_explicit_shell_false_argv_is_quiet(self):
        finds = _py('subprocess.run(["ls", d], shell=False)\n')
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


class TestJSSqlDriverReceivers:
    """DB-driver receiver coverage (node-postgres/mysql2/better-sqlite3):
    ``pool/connection/client/conn.query`` and the ``db.prepare(...)`` chain
    are SQL entry points, so a SQL-keyword literal concat at the call flags
    at both the AST and regex layers.  Express/Fastify data getters
    (``req.query``, ``res.get``, ``app.get``) are not SQL entry points and
    must stay quiet, as must parameterized and static calls."""

    def test_pool_query_concat_flags(self):
        finds = _js("pool.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [(f.rule_id, f.severity) for f in finds] == [
            ("injection.sql_concat", "critical")]

    def test_connection_query_concat_flags(self):
        finds = _js("connection.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_client_query_concat_flags(self):
        finds = _js("client.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_conn_query_concat_flags(self):
        finds = _js("conn.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_await_pool_query_concat_flags(self):
        finds = _js("await pool.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_pg_pool_query_concat_flags(self):
        finds = _js("pg.pool.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_prepare_chain_concat_flags(self):
        # The concat sits in the inner db.prepare(...) call of the chain.
        finds = _js("db.prepare('SELECT * FROM users WHERE id = ' + id).run(id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_db_exec_concat_flags(self):
        finds = _js("db.exec('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_prisma_query_raw_concat_flags(self):
        finds = _js("prisma.$queryRaw('SELECT * FROM users WHERE id = ' + id)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_pool_query_template_concat_flags(self):
        finds = _js("pool.query(`SELECT * FROM users WHERE id = ${id}`)\n")
        assert [f.rule_id for f in finds] == ["injection.sql_concat"]

    def test_pool_query_parameterized_is_quiet(self):
        finds = _js("pool.query('SELECT * FROM users WHERE id = ?', [id])\n")
        assert finds == []

    def test_pool_query_static_is_quiet(self):
        finds = _js("pool.query('SELECT * FROM users')\n")
        assert finds == []

    def test_req_query_is_not_a_sql_sink(self):
        # Express req.query is a URL-query-parameter object, not SQL.
        finds = _js("req.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert finds == []

    def test_request_query_is_not_a_sql_sink(self):
        finds = _js("request.query('SELECT * FROM users WHERE id = ' + id)\n")
        assert finds == []

    def test_res_get_is_not_a_sql_sink(self):
        finds = _js("res.get('X-Frame-Options')\n")
        assert finds == []

    def test_app_get_is_not_a_sql_sink(self):
        finds = _js("app.get('/users', (req, res) => {})\n")
        assert finds == []

    def test_router_all_is_not_a_sql_sink(self):
        finds = _js("router.all('*', handler)\n")
        assert finds == []


class TestJSShellSlotAwareConcat:
    """exec-family shell injection is slot-aware: a concat in the *command
    string* reaches a shell (exec/execSync always; spawn/Promise-based
    spawnSync/fork/execa only with ``shell:`` or an explicit ``sh -c`` style
    command line), while a concat buried in the *argument array* of a plain
    spawn arrives as a separate argv entry and stays quiet."""

    def test_exec_concat_flags(self):
        finds = _js('exec("ping -c 1 " + host)\n')
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_execa_concat_flags(self):
        finds = _js('execa("ls " + dir)\n')
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_exec_file_shell_true_dynamic_flags(self):
        # execFile is the argv-form sibling: a dynamic first-arg command
        # with shell:true reaches a shell and must flag.
        finds = _js("execFile('ls ' + d, [], { shell: true })\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_exec_file_sync_shell_true_dynamic_flags(self):
        finds = _js("execFileSync('ls ' + d, [], { shell: true })\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_exec_file_shell_false_is_quiet(self):
        finds = _js("execFile('ls ' + d, [], { shell: false })\n")
        assert finds == []

    def test_exec_file_sh_dash_c_dynamic_flags(self):
        finds = _js("execFile('sh', ['-c', 'ls ' + dir])\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_exec_file_receiver_flags(self):
        finds = _js("cp.execFile('ls ' + d, [], { shell: true })\n")
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_exec_file_static_is_quiet(self):
        # Static argv with shell:true: no concat-built command, quiet.
        finds = _js("execFile('ping', ['-c', '3', 'h'], { shell: true })\n")
        assert finds == []

    def test_spawn_single_string_command_flags(self):
        # A single string to spawn goes through a shell for parsing.
        finds = _js('spawn("ping " + host)\n')
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_spawn_sh_c_dynamic_flags(self):
        # An explicit sh -c line is shell interpretation even without shell:.
        finds = _js("spawn('/bin/sh', ['-c', 'ls ' + dir])\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_spawn_bash_c_dynamic_flags(self):
        finds = _js("spawn('bash', ['-c', 'sudo ' + payload])\n")
        assert [(f.rule_id, f.line) for f in finds] == [
            ("injection.shell_concat", 1)]

    def test_spawn_sh_c_static_is_quiet(self):
        # Static command line through sh is not an injection.
        finds = _js("spawn('sh', ['-c', 'echo hi'])\n")
        assert finds == []

    def test_spawn_shell_true_with_concat_flags(self):
        finds = _js("cp.spawn('echo ' + msg, [], { shell: true })\n")
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_spawn_shell_true_static_is_quiet(self):
        # Static args with shell on: nothing is concat-built, so quiet.
        finds = _js("spawn('ls', ['-la'], { shell: true })\n")
        assert finds == []

    def test_spawn_arglist_concat_is_quiet(self):
        # Args reach the child as separate argv entries: no metacharacter
        # expansion, even though the array literal contains a concat.
        finds = _js("spawn('tar', ['czf', dir + '.tgz', 'src'])\n")
        assert finds == []

    def test_spawn_static_is_quiet(self):
        finds = _js("spawn('ping', ['-c', '1', '127.0.0.1'])\n")
        assert finds == []

    def test_spawn_sync_arglist_concat_is_quiet(self):
        finds = _js("cp.spawnSync('echo', [prefix + name])\n")
        assert finds == []

    def test_spawn_explicit_shell_false_is_quiet(self):
        # shell:false explicitly disables the shell, so the concat-built
        # command string is never interpreted by a shell.
        finds = _js("spawn('echo ' + msg, [], { shell: false })\n")
        assert finds == []

    def test_exec_explicit_shell_false_is_quiet(self):
        finds = _js("exec('ls ' + dir, { shell: false })\n")
        assert finds == []

    def test_exec_without_shell_option_still_flags(self):
        # exec always interprets its command through a shell; no options.
        finds = _js("exec('ls ' + dir)\n")
        assert [f.rule_id for f in finds] == ["injection.shell_concat"]

    def test_spawn_explicit_shell_true_voice_shell_false_is_quiet(self):
        # The last option wins at runtime; one explicit false among many is
        # enough to quiet the shell-injection line.
        finds = _js("spawn('echo ' + msg, [], { shell: false, detached: true })\n")
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
