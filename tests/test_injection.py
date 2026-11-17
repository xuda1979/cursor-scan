"""Unit tests for the cross-language injection regex fallbacks.

The line-scanner regex rules in cursorscan/rules/injection.py also cover PHP
(`.` concat), Java (`+` concat), Ruby (`+` concat / `#{}` interpolation),
Go (`+` concat / fmt.Sprintf verbs), C# (`+` concat / `$"..."` interpolated
templates), Kotlin (`+` concat), Rust (`format!` / `format_args!` /
`fmt::format` interpolation, `+` concat, `Command::new("sh").arg("-c")`)
and Perl (DBI double-quoted `$var` interpolation / `.` concat,
single-string `system`/`exec`, backticks, `qx{}`) and Lua (`..` concat /
`string.format` verbs into LuaSQL / LuaSQLite3 receivers, `os.execute` /
`io.popen` command strings) and C/C++ (`.c/.h/.cpp/.hpp`: `+` concat /
`sprintf`-verb literals into `sqlite3_exec` / `mysql_query` /
`mysql_real_query`, `sprintf`-built / `+`-concatenated commands into
`system` / `popen`)
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

    def test_prepare_statement_concat_flags(self):
        assert self._reg(
            'PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = " + uid);\n'
        ) == [("injection.sql_concat", 1)]

    def test_execute_query_string_format_flags(self):
        assert self._reg(
            'stmt.executeQuery(String.format("SELECT %s FROM users WHERE id = %d", cols, id));\n'
        ) == [("injection.sql_concat", 1)]

    def test_prepare_statement_embedded_quote_flags(self):
        assert self._reg(
            "ps = conn.prepareStatement(\"UPDATE t SET name = '\" + n + \"' WHERE id = 1\");\n"
        ) == [("injection.sql_concat", 1)]

    def test_prepare_statement_parameterized_is_quiet(self):
        assert self._reg('conn.prepareStatement("SELECT * FROM t WHERE id = ?");\n') == []

    def test_prepare_statement_static_is_quiet(self):
        assert self._reg('conn.prepareStatement("SELECT 1");\n') == []

    def test_string_format_without_sql_keyword_is_quiet(self):
        assert self._reg('stmt.executeQuery(String.format("version %s", v));\n') == []

    def test_jdbc_template_query_concat_flags(self):
        assert self._reg(
            'jdbcTemplate.query("SELECT * FROM u WHERE n = " + name);\n'
        ) == [("injection.sql_concat", 1)]

    def test_jdbc_query_for_list_concat_flags(self):
        assert self._reg(
            'jdbc.queryForList("SELECT * FROM u WHERE id = " + id, args);\n'
        ) == [("injection.sql_concat", 1)]

    def test_jdbc_template_query_for_object_concat_flags(self):
        assert self._reg(
            'jdbcTemplate.queryForObject("SELECT name FROM u WHERE id = " + id, String.class);\n'
        ) == [("injection.sql_concat", 1)]

    def test_jdbc_template_update_concat_flags(self):
        assert self._reg('jdbcTemplate.update("UPDATE t SET x = " + v);\n') == [
            ("injection.sql_concat", 1)]

    def test_mybatis_select_interpolation_flags(self):
        assert self._reg('@Select("SELECT * FROM t WHERE id = ${id}")\n') == [
            ("injection.sql_concat", 1)]

    def test_mybatis_update_interpolation_flags(self):
        assert self._reg('@Update("UPDATE t SET n = ${name} WHERE id = 1")\n') == [
            ("injection.sql_concat", 1)]

    def test_jdbc_template_parameterized_is_quiet(self):
        assert self._reg(
            'jdbcTemplate.query("SELECT * FROM u WHERE n = ?", args);\n') == []

    def test_jdbc_template_static_is_quiet(self):
        assert self._reg('jdbcTemplate.query("SELECT 1");\n') == []

    def test_mybatis_bind_placeholder_is_quiet(self):
        assert self._reg('@Select("SELECT * FROM t WHERE id = #{id}")\n') == []

    def test_mybatis_static_is_quiet(self):
        assert self._reg('@Select("SELECT 1")\n') == []

    def test_dao_query_for_list_is_quiet(self):
        assert self._reg('dao.queryForList("SELECT 1");\n') == []


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


class TestGoSqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.go", code)]

    def test_dot_query_plus_concat_flags(self):
        assert self._reg(
            'rows, err := db.Query("SELECT * FROM users WHERE id = " + userInput)\n'
        ) == [("injection.sql_concat", 1)]

    def test_query_row_plus_concat_flags(self):
        assert self._reg(
            'row := db.QueryRow("SELECT name FROM users WHERE name = " + user.name)\n'
        ) == [("injection.sql_concat", 1)]

    def test_exec_plus_concat_flags(self):
        assert self._reg('db.Exec("UPDATE t SET x = " + input)\n') == [
            ("injection.sql_concat", 1)]

    def test_query_context_ctx_first_flags(self):
        # CommandContext-style receivers shift the ctx argument first.
        assert self._reg(
            'rows, err := db.QueryContext(ctx, "SELECT " + cols + " FROM t")\n'
        ) == [("injection.sql_concat", 1)]

    def test_exec_context_sprintf_flags(self):
        assert self._reg(
            'rows, err := db.QueryContext(ctx, fmt.Sprintf("SELECT %s FROM t", cols))\n'
        ) == [("injection.sql_concat", 1)]

    def test_query_sprintf_format_verb_flags(self):
        assert self._reg(
            'rows, err := db.Query(fmt.Sprintf("SELECT %s FROM users WHERE id = %d", cols, id))\n'
        ) == [("injection.sql_concat", 1)]

    def test_parameterized_placeholder_is_quiet(self):
        assert self._reg(
            'rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)\n') == []

    def test_static_query_is_quiet(self):
        assert self._reg('rows, err := db.Query("SELECT 1")\n') == []

    def test_sprintf_without_sql_keyword_is_quiet(self):
        assert self._reg('db.Query(fmt.Sprintf("version %s", ver))\n') == []

    def test_raw_plus_concat_flags(self):
        assert self._reg(
            'db.Raw("SELECT * FROM users WHERE id = " + uid).Scan(&u)\n'
        ) == [("injection.sql_concat", 1)]

    def test_raw_sprintf_format_verb_flags(self):
        assert self._reg(
            'db.Raw(fmt.Sprintf("SELECT %s FROM accounts", cols)).Scan(&a)\n'
        ) == [("injection.sql_concat", 1)]

    def test_raw_parameterized_is_quiet(self):
        assert self._reg(
            'db.Raw("SELECT * FROM users WHERE id = ?", uid).Scan(&u)\n') == []

    def test_raw_static_is_quiet(self):
        assert self._reg('db.Raw("SELECT 1")\n') == []

    def test_where_concat_flags(self):
        assert self._reg('db.Where("name = " + name).Find(&users)\n') == [
            ("injection.sql_concat", 1)]

    def test_joins_concat_flags(self):
        assert self._reg(
            'db.Table("u").Joins("JOIN orders o ON o.uid = u.id WHERE o.x = " + cond)\n'
        ) == [("injection.sql_concat", 1)]

    def test_having_concat_flags(self):
        assert self._reg('db.Having("COUNT(*) > " + min).Group("cat")\n') == [
            ("injection.sql_concat", 1)]

    def test_where_parameterized_is_quiet(self):
        assert self._reg('db.Where("name = ?", name).First(&u)\n') == []

    def test_where_keyword_args_is_quiet(self):
        # GORM map/struct condition form carries no literal SQL.
        assert self._reg('db.Where(map[string]interface{}{"name": name}).Find(&u)\n') == []


class TestGoShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.go", code)]

    def test_sh_c_concat_flags(self):
        assert self._reg(
            'exec.Command("/bin/sh", "-c", "ping -c 1 " + host).Run()\n'
        ) == [("injection.shell_concat", 1)]

    def test_bash_c_sprintf_flags(self):
        assert self._reg(
            'exec.Command("bash", "-c", fmt.Sprintf("ls %s", dir))\n'
        ) == [("injection.shell_concat", 1)]

    def test_command_context_sh_c_flags(self):
        assert self._reg(
            'exec.CommandContext(ctx, "/bin/sh", "-c", "rm -rf " + path)\n'
        ) == [("injection.shell_concat", 1)]

    def test_arg_list_form_is_quiet(self):
        assert self._reg('exec.Command("ping", host).Run()\n') == []

    def test_ping_count_flag_is_quiet(self):
        # "-c" is ping's count flag here, not a shell invocation.
        assert self._reg('exec.Command("ping", "-c", host).Run()\n') == []

    def test_static_sh_c_is_quiet(self):
        assert self._reg('exec.Command("sh", "-c", "echo hi").Run()\n') == []

    def test_windows_cmd_c_concat_flags(self):
        assert self._reg(
            'exec.Command("cmd", "/C", "del " + path).Run()\n'
        ) == [("injection.shell_concat", 1)]

    def test_windows_cmd_exe_c_sprintf_flags(self):
        assert self._reg(
            'exec.Command("cmd.exe", "/c", fmt.Sprintf("xcopy %s", src)).Run()\n'
        ) == [("injection.shell_concat", 1)]

    def test_windows_cmd_dash_c_concat_flags(self):
        # cmd also accepts the -c spelling of the command switch.
        assert self._reg(
            'exec.Command("cmd", "-c", "type " + file).Run()\n'
        ) == [("injection.shell_concat", 1)]

    def test_static_windows_cmd_c_is_quiet(self):
        assert self._reg('exec.Command("cmd", "/C", "del /q tmp.txt").Run()\n') == []

    def test_static_windows_cmd_exe_is_quiet(self):
        assert self._reg('exec.Command("cmd", "/C", "echo hi").Run()\n') == []


class TestCSharpSqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.cs", code)]

    def test_sql_command_ctor_plus_flags(self):
        assert self._reg(
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + userId, conn);\n'
        ) == [("injection.sql_concat", 1)]

    def test_npgsql_command_ctor_plus_flags(self):
        assert self._reg(
            'var cmd = new NpgsqlCommand("UPDATE t SET x = " + val, conn);\n'
        ) == [("injection.sql_concat", 1)]

    def test_command_text_plus_flags(self):
        assert self._reg(
            'cmd.CommandText = "SELECT name FROM users WHERE name = " + input;\n'
        ) == [("injection.sql_concat", 1)]

    def test_command_text_interpolated_flags(self):
        assert self._reg(
            'cmd.CommandText = $"SELECT * FROM users WHERE id = {userId}";\n'
        ) == [("injection.sql_concat", 1)]

    def test_parameterized_at_id_is_quiet(self):
        assert self._reg(
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);\n'
        ) == []

    def test_static_command_is_quiet(self):
        assert self._reg(
            'var cmd = new SqlCommand("SELECT * FROM Users", conn);\n') == []


class TestCSharpShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.cs", code)]

    def test_process_start_two_arg_plus_flags(self):
        assert self._reg(
            'Process.Start("cmd.exe", "/c " + payload);\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_start_info_object_initializer_flags(self):
        assert self._reg(
            'ProcessStartInfo psi = new ProcessStartInfo() { Arguments = "ls " + dir };\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_start_info_interpolated_flags(self):
        assert self._reg(
            'new ProcessStartInfo { Arguments = $"rm -rf {path}" };\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_start_info_with_filename_flags(self):
        assert self._reg(
            'ProcessStartInfo psi = new ProcessStartInfo { FileName = "sh", Arguments = "-c " + cmd };\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_start_info_nested_initializer_flags(self):
        assert self._reg(
            'new Process { StartInfo = { Arguments = "curl " + url } };\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_start_info_ctor_plus_flags(self):
        assert self._reg(
            'ProcessStartInfo psi = new ProcessStartInfo("ls", "-l " + dir);\n'
        ) == [("injection.shell_concat", 1)]

    def test_start_info_arguments_member_flags(self):
        assert self._reg(
            'var p = new Process(); p.StartInfo.Arguments = "ping " + host;\n'
        ) == [("injection.shell_concat", 1)]

    def test_static_process_start_is_quiet(self):
        assert self._reg('Process.Start("notepad.exe");\n') == []

    def test_static_arguments_assignment_is_quiet(self):
        assert self._reg('psi.Arguments = "--help";\n') == []


class TestKotlinSqlConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.kt", code)]

    def test_execute_query_plus_concat_flags(self):
        assert self._reg(
            'val rs = stmt.executeQuery("SELECT * FROM users WHERE id = " + id)\n'
        ) == [("injection.sql_concat", 1)]

    def test_raw_query_plus_concat_flags(self):
        assert self._reg(
            'db.rawQuery("SELECT * FROM t WHERE x = " + input, null)\n'
        ) == [("injection.sql_concat", 1)]

    def test_exec_sql_plus_concat_flags(self):
        assert self._reg(
            'db.execSQL("DROP TABLE " + tableName)\n'
        ) == [("injection.sql_concat", 1)]

    def test_execute_update_plus_concat_flags(self):
        assert self._reg(
            'stmt.executeUpdate("DELETE FROM t WHERE id = " + id)\n'
        ) == [("injection.sql_concat", 1)]

    def test_parameterized_placeholder_is_quiet(self):
        assert self._reg(
            'stmt.executeQuery("SELECT * FROM users WHERE id = ?")\n') == []

    def test_static_query_is_quiet(self):
        assert self._reg('stmt.executeQuery("SELECT 1")\n') == []

    def test_jdbc_template_query_concat_flags(self):
        assert self._reg(
            'jdbcTemplate.query("SELECT * FROM u WHERE n = " + name)\n'
        ) == [("injection.sql_concat", 1)]

    def test_jdbc_query_for_list_concat_flags(self):
        assert self._reg(
            'jdbc.queryForList("SELECT * FROM u WHERE id = " + id)\n'
        ) == [("injection.sql_concat", 1)]

    def test_jdbc_template_parameterized_is_quiet(self):
        assert self._reg(
            'jdbcTemplate.query("SELECT * FROM u WHERE n = ?", args)\n') == []

    def test_jdbc_template_static_is_quiet(self):
        assert self._reg('jdbcTemplate.query("SELECT 1")\n') == []


class TestKotlinShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.kt", code)]

    def test_runtime_exec_plus_concat_flags(self):
        assert self._reg(
            'Runtime.getRuntime().exec("ping " + host)\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_builder_sh_c_plus_flags(self):
        assert self._reg(
            'ProcessBuilder("/bin/sh", "-c", "ls " + dir).start()\n'
        ) == [("injection.shell_concat", 1)]

    def test_process_builder_arg_list_is_quiet(self):
        assert self._reg(
            'ProcessBuilder("ping", host).start()\n') == []

    def test_static_runtime_exec_is_quiet(self):
        assert self._reg('Runtime.getRuntime().exec("ls -la")\n') == []


class TestRustSqlConcat:
    """Regex-layer lock for the Rust SQL receivers (rusqlite / sqlx /
    tokio-postgres): ``format!`` / ``format_args!`` / ``fmt::format``
    interpolated SQL literals and `+` concatenation flag
    ``injection.sql_concat``; parameterized `?` placeholders and bind/list
    forms stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.rs", code)]

    def test_execute_format_interpolation_flags(self):
        assert self._reg(
            'conn.execute(&format!("SELECT * FROM users WHERE name = \'{name}\'"), [])'
        ) == [("injection.sql_concat", 1)]

    def test_execute_format_braced_interpolation_flags(self):
        assert self._reg(
            'conn.execute(&format!("SELECT id FROM t WHERE a = {}", id))'
        ) == [("injection.sql_concat", 1)]

    def test_query_format_args_flags(self):
        assert self._reg(
            '''sqlx::query(&format_args!("SELECT x FROM t WHERE b = '{b}'")).fetch_all(&pool)'''
        ) == [("injection.sql_concat", 1)]

    def test_fmt_format_module_flags(self):
        assert self._reg(
            '''conn.query(&fmt::format(format_args!("UPDATE t SET y = {}", y)))?'''
        ) == [("injection.sql_concat", 1)]

    def test_query_row_plus_concat_flags(self):
        assert self._reg(
            'conn.query_row("SELECT z FROM t WHERE c = " + field, [], |r| Ok(r))'
        ) == [("injection.sql_concat", 1)]

    def test_assignment_format_flags(self):
        assert self._reg(
            'let q = format!("DELETE FROM logs WHERE id = {}", id);'
        ) == [("injection.sql_concat", 1)]

    def test_assignment_sql_to_string_concat_flags(self):
        assert self._reg(
            'let q = "UPDATE t SET ".to_string() + cols + " WHERE id = 1";'
        ) == [("injection.sql_concat", 1)]

    def test_parameterized_placeholder_is_quiet(self):
        assert self._reg(
            'conn.execute("SELECT * FROM users WHERE name = ?", [name])'
        ) == []

    def test_bind_list_is_quiet(self):
        assert self._reg(
            'sqlx::query("SELECT * FROM t WHERE id = $1").bind(id).fetch_one(&pool)'
        ) == []

    def test_static_query_is_quiet(self):
        assert self._reg('conn.execute("SELECT 1")') == []

    def test_format_without_sql_keyword_is_quiet(self):
        assert self._reg('conn.execute(&format!("hello {}", name))') == []

    def test_non_receiver_format_call_is_quiet(self):
        # Rust output macros like println! / write! never reach a driver.
        assert self._reg('println!("SELECT count FROM x where a = {}", n)') == []


class TestRustShellConcat:
    """Regex-layer lock for Rust ``std::process::Command`` shell launches:
    an explicit `-c` with a format!-built or concatenated command string
    flags ``injection.shell_concat``; argv-list and static `-c` forms stay
    quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.rs", code)]

    def test_sh_c_format_flags(self):
        assert self._reg(
            'Command::new("sh").arg("-c").arg(format!("rm -rf {}", dir)).output()'
        ) == [("injection.shell_concat", 1)]

    def test_bash_c_concat_flags(self):
        assert self._reg(
            r'Command::new("/bin/bash").arg("-c").arg("ls " + dir).status()'
        ) == [("injection.shell_concat", 1)]

    def test_cmd_c_to_string_concat_flags(self):
        assert self._reg(
            r'Command::new("cmd").arg("/C").arg("del " + f + "\\\"").output()'
        ) == [("injection.shell_concat", 1)]

    def test_arg_list_form_is_quiet(self):
        assert self._reg(
            'Command::new("ls").arg(dir).output()'
        ) == []

    def test_static_sh_c_is_quiet(self):
        assert self._reg(
            'Command::new("sh").arg("-c").arg("true").output()'
        ) == []

    def test_sh_without_dash_c_is_quiet(self):
        # ``sh file.sh`` executes a script file, not a shell command line.
        assert self._reg(
            'Command::new("sh").arg("build.sh").status()'
        ) == []

    def test_non_shell_binary_dash_c_is_quiet(self):
        # ``ping -c 1 ...``: the -c is ping's count flag, not a shell.
        assert self._reg(
            'Command::new("ping").arg("-c").arg("1").arg("127.0.0.1").status()'
        ) == []


class TestPerlSqlConcat:
    """Regex-layer lock for the Perl DBI receivers (prepare / do / selectrow_* /
    selectall_* / selectcol_arrayref): a double-quoted query literal with `$var`
    interpolation (double-quoted Perl strings interpolate scalars at runtime) or
    a query literal built with the `.` concatenation operator flags
    ``injection.sql_concat``; parameterized `?` placeholders bound separately
    and single-quoted literals stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.pl", code)]

    def test_prepare_double_quoted_interpolation_flags(self):
        assert self._reg(
            '$dbh->prepare("SELECT * FROM users WHERE name = \'$name\'")\n'
        ) == [("injection.sql_concat", 1)]

    def test_do_double_quoted_interpolation_flags(self):
        assert self._reg(
            '$dbh->do("DELETE FROM logs WHERE id = $id")\n'
        ) == [("injection.sql_concat", 1)]

    def test_selectrow_array_interpolation_flags(self):
        assert self._reg(
            '$dbh->selectrow_array("SELECT password FROM users WHERE name = \'$name\'")\n'
        ) == [("injection.sql_concat", 1)]

    def test_selectall_arrayref_interpolation_flags(self):
        assert self._reg(
            '$dbh->selectall_arrayref("UPDATE accounts SET balance = $amt WHERE id = 1")\n'
        ) == [("injection.sql_concat", 1)]

    def test_do_dot_concat_flags(self):
        assert self._reg(
            '$dbh->do("SELECT * FROM t " . $where)\n'
        ) == [("injection.sql_concat", 1)]

    def test_prepare_dot_concat_flags(self):
        assert self._reg(
            '$dbh->prepare("UPDATE t SET " . $cols . " WHERE id = 1")\n'
        ) == [("injection.sql_concat", 1)]

    def test_selectcol_single_quoted_dot_concat_flags(self):
        # `.` concatenation splices into the query at runtime even when the
        # fragment is single-quoted (the `$v` operand is still interpolated).
        assert self._reg(
            "$dbh->selectcol_arrayref('SELECT id FROM t WHERE x = ' . $v)\n"
        ) == [("injection.sql_concat", 1)]

    def test_placeholder_parameterized_is_quiet(self):
        assert self._reg(
            '$dbh->prepare("SELECT * FROM users WHERE name = ?")->execute($name)\n'
        ) == []

    def test_do_placeholder_is_quiet(self):
        assert self._reg(
            '$dbh->do("DELETE FROM logs WHERE id = ?", {}, $id)\n'
        ) == []

    def test_static_query_is_quiet(self):
        assert self._reg('$dbh->prepare("SELECT 1")\n') == []

    def test_double_quoted_without_interpolation_is_quiet(self):
        # `$name` appears in a comment-like trailing context, not inside the
        # query literal; no runtime splice into the SQL string.
        assert self._reg(
            '$ok = $dbh->prepare("SELECT * FROM users WHERE name = ?");\n'
        ) == []


class TestPerlShellConcat:
    """Regex-layer lock for Perl shell execution: the one-argument
    ``system("...$var...")`` / ``exec "$cmd $var"`` single-string forms,
    backtick operators and ``qx{...}`` with a `$var` command string flag
    ``injection.shell_concat``; argument-list ``system("ls", $dir)``, static
    single-string commands and ``qx`` without interpolation stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.pl", code)]

    def test_system_single_string_interpolation_flags(self):
        assert self._reg(
            'system("rm -rf $dir")\n'
        ) == [("injection.shell_concat", 1)]

    def test_exec_single_string_interpolation_flags(self):
        assert self._reg(
            'exec "ls -la $f"\n'
        ) == [("injection.shell_concat", 1)]

    def test_backtick_interpolation_flags(self):
        assert self._reg(
            '`rm -rf $dir`\n'
        ) == [("injection.shell_concat", 1)]

    def test_qx_braces_interpolation_flags(self):
        assert self._reg(
            'qx{git push origin $branch}\n'
        ) == [("injection.shell_concat", 1)]

    def test_qx_parens_interpolation_flags(self):
        assert self._reg(
            'my $out = qx(ls $dir);\n'
        ) == [("injection.shell_concat", 1)]

    def test_argument_list_form_is_quiet(self):
        assert self._reg(
            'system("ls", $dir)\n'
        ) == []

    def test_exec_argument_list_is_quiet(self):
        assert self._reg(
            'exec("npm", "run", "build")\n'
        ) == []

    def test_static_system_is_quiet(self):
        assert self._reg('system("true")\n') == []

    def test_static_backtick_is_quiet(self):
        assert self._reg("`date`\n") == []

    def test_static_qx_is_quiet(self):
        assert self._reg('qx{git log --oneline}\n') == []


class TestLuaSqlConcat:
    """Regex-layer lock for LuaSQL / LuaSQLite3 receivers (conn:execute /
    db:execute / db:exec): a SQL-keyword literal spliced with Lua's `..`
    concatenation operator or built through string.format() with a printf
    verb flags ``injection.sql_concat``; static literals, parameterized `?`
    placeholders and non-receiver assignments stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.lua", code)]

    def test_colon_execute_concat_flags(self):
        assert self._reg(
            'local res = conn:execute("SELECT * FROM users WHERE name = \'" .. name .. "\'")\n'
        ) == [("injection.sql_concat", 1)]

    def test_dot_exec_exec_string_format_flags(self):
        assert self._reg(
            'db.exec(string.format("DELETE FROM logs WHERE id = %s", id))\n'
        ) == [("injection.sql_concat", 1)]

    def test_colon_exec_string_format_flags(self):
        assert self._reg(
            'conn:execute(string.format("UPDATE accounts SET balance = %d WHERE id = 1", amt))\n'
        ) == [("injection.sql_concat", 1)]

    def test_db_execute_concat_flags(self):
        assert self._reg(
            'db:execute("SELECT * FROM t " .. where)\n'
        ) == [("injection.sql_concat", 1)]

    def test_placeholder_parameterized_is_quiet(self):
        assert self._reg(
            'local res = conn:execute("SELECT * FROM users WHERE name = ?", name)\n'
        ) == []

    def test_db_exec_placeholder_is_quiet(self):
        assert self._reg(
            'db:exec("DELETE FROM logs WHERE id = ?", id)\n'
        ) == []

    def test_static_query_is_quiet(self):
        assert self._reg('conn:execute("SELECT COUNT(*) FROM logs")\n') == []

    def test_static_concat_to_local_is_quiet(self):
        # Concatenating two constants into a local is not a driver call; the
        # rule keys on the receiver argument, not on any `..` on the line.
        assert self._reg('local eq = "SELECT * FROM t WHERE a = " .. "1"\n') == []


class TestLuaShellConcat:
    """Regex-layer lock for Lua shell execution: os.execute / io.popen called
    with a command string spliced together with `..` concatenation or built
    through string.format() with a printf verb flag ``injection.shell_concat``;
    static command strings stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.lua", code)]

    def test_os_execute_concat_flags(self):
        assert self._reg(
            'os.execute("rm -rf /tmp/" .. dir)\n'
        ) == [("injection.shell_concat", 1)]

    def test_io_popen_string_format_flags(self):
        assert self._reg(
            'local out = io.popen(string.format("ls -la %s", dir)):read("*a")\n'
        ) == [("injection.shell_concat", 1)]

    def test_os_execute_string_format_flags(self):
        assert self._reg(
            'os.execute(string.format("ping -c 1 %s", host))\n'
        ) == [("injection.shell_concat", 1)]

    def test_static_os_execute_is_quiet(self):
        assert self._reg('os.execute("true")\n') == []

    def test_static_io_popen_is_quiet(self):
        assert self._reg('local when = io.popen("date"):read("*a")\n') == []


class TestCppSqlConcat:
    """Regex-layer lock for C/C++ SQL receivers: sqlite3_exec / mysql_query /
    mysql_real_query handed a SQL-keyword literal spliced with the `+`
    operator (optionally via std::string or wrapped in `.c_str()`), or a
    query string built through sprintf()/snprintf() with a printf verb baked
    into the SQL literal, flags ``injection.sql_concat``; prepared statements
    (sqlite3_prepare_v2 / mysql_stmt_*) and static literals stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.cpp", code)]

    def test_sqlite3_exec_c_str_concat_flags(self):
        assert self._reg(
            "sqlite3_exec(db, (\"SELECT * FROM users WHERE name = '\" + name + \"'\").c_str(), 0, 0, &err);\n"
        ) == [("injection.sql_concat", 1)]

    def test_sqlite3_exec_string_concat_flags(self):
        assert self._reg(
            'sqlite3_exec(db, std::string("SELECT * FROM users WHERE id = ") + id, 0, 0, 0);\n'
        ) == [("injection.sql_concat", 1)]

    def test_snprintf_format_verb_flags(self):
        assert self._reg(
            'snprintf(query, sizeof query, "DELETE FROM logs WHERE id = %s", id);\n'
        ) == [("injection.sql_concat", 1)]

    def test_sprintf_format_verb_flags(self):
        assert self._reg(
            'sprintf(query, "UPDATE accounts SET bal = %d WHERE id = %s", amt, id);\n'
        ) == [("injection.sql_concat", 1)]

    def test_prepare_v2_is_quiet(self):
        assert self._reg(
            'sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, 0);\n'
        ) == []

    def test_mysql_stmt_prepare_is_quiet(self):
        assert self._reg(
            "mysql_stmt_prepare(stmt, \"UPDATE logs SET status = 'ok' WHERE id = ?\", -1);\n"
        ) == []

    def test_static_query_is_quiet(self):
        assert self._reg(
            'sqlite3_exec(db, "SELECT COUNT(*) FROM logs", 0, 0, 0);\n'
        ) == []

    def test_sprintf_without_sql_keyword_is_quiet(self):
        assert self._reg(
            'sprintf(buf, "%s: %d", tag, n);\n'
        ) == []


class TestCppShellConcat:
    """Regex-layer lock for C/C++ shell execution: a command string built
    with snprintf()/sprintf() and then handed to system()/popen() on the
    same line, or a std::string `+` concat passed straight into system() /
    popen(), flags ``injection.shell_concat``; static command strings stay
    quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.cpp", code)]

    def test_snprintf_then_system_flags(self):
        assert self._reg(
            'snprintf(cmd, sizeof cmd, "ls -la %s", dir); system(cmd);\n'
        ) == [("injection.shell_concat", 1)]

    def test_system_string_concat_flags(self):
        assert self._reg(
            'system(("rm -rf /tmp/" + std::string(path)).c_str());\n'
        ) == [("injection.shell_concat", 1)]

    def test_popen_concat_flags(self):
        assert self._reg(
            'popen(("grep " + pat).c_str(), "r");\n'
        ) == [("injection.shell_concat", 1)]

    def test_static_system_is_quiet(self):
        assert self._reg('system("true");\n') == []

    def test_static_popen_is_quiet(self):
        assert self._reg('popen("date", "r");\n') == []

    def test_snprintf_without_receiver_is_quiet(self):
        assert self._reg(
            'snprintf(cmd, sizeof cmd, "ls -la %s", dir);\n'
        ) == []


class TestJSSqlConcatRegex:
    """Regex-layer lock for the JS DB-driver receivers: node-postgres /
    mysql2 / better-sqlite3 style ``pool/connection/client/conn.query`` and
    chained ``db.prepare(...)``/``db.exec(...)`` with a SQL-keyword literal
    concat flag ``injection.sql_concat``; parameterized, static and
    Express data-getter forms stay quiet."""

    def test_pool_query_concat_flags(self):
        assert _reg("pool.query('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_connection_query_concat_flags(self):
        assert _reg("connection.query('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_client_query_concat_flags(self):
        assert _reg("client.query('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_pg_pool_query_concat_flags(self):
        assert _reg("pg.pool.query('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_prepare_chain_concat_flags(self):
        assert _reg("db.prepare('SELECT * FROM u WHERE id = ' + id).run(id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_parametrized_pool_query_is_quiet(self):
        assert _reg("pool.query('SELECT * FROM users WHERE id = ?', [id])\n",
                    "x.js") == []

    def test_static_pool_query_is_quiet(self):
        assert _reg("pool.query('SELECT * FROM users')\n", "x.js") == []

    def test_req_query_is_quiet(self):
        assert _reg("req.query('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == []

    def test_client_execute_concat_flags(self):
        assert _reg("client.execute('SELECT * FROM users WHERE id = ' + id, [])\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_db_execute_embedded_opposite_quote_flags(self):
        # Double-quoted SQL literal containing an embedded single quote chain,
        # exactly the shape that a naive [^"'] char class would break on.
        assert _reg('db.execute("UPDATE users SET name = \'" + n + "\' WHERE id = 1")\n',
                    "x.js") == [("injection.sql_concat", 1)]

    def test_mysql2_execute_concat_flags(self):
        assert _reg("mysql2.execute('SELECT * FROM orders WHERE id = ' + id, [])\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_pool_execute_concat_flags(self):
        assert _reg("pool.execute('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_mysql2_query_concat_flags(self):
        assert _reg("mysql2.query('INSERT INTO logs (msg) VALUES (' + msg + ')')\n",
                    "x.js") == [("injection.sql_concat", 1)]

    def test_execute_parameterized_is_quiet(self):
        assert _reg("db.execute('SELECT * FROM users WHERE id = ?', [id])\n",
                    "x.js") == []

    def test_execute_static_is_quiet(self):
        assert _reg("db.execute('SELECT * FROM users')\n", "x.js") == []

    def test_router_execute_is_quiet(self):
        # Express router dispatch is not a SQL sink.
        assert _reg("router.execute('SELECT * FROM users WHERE id = ' + id)\n",
                    "x.js") == []


class TestCrossExtensionSilence:
    """The new regexes must not fire on Python/JS safe forms, and the
    Go/C#/Kotlin patterns must not leak onto other languages' files."""

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

    def test_go_parameterized_query_is_quiet(self):
        assert self._reg('db.Query("SELECT * FROM t WHERE id = ?", id)\n',
                         "x.go") == []

    def test_go_arg_list_command_is_quiet(self):
        assert self._reg('exec.Command("ping", "-c", host).Run()\n', "x.go") == []

    def test_csharp_parameterized_command_is_quiet(self):
        assert self._reg(
            'var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);\n',
            "x.cs") == []

    def test_csharp_static_process_start_is_quiet(self):
        assert self._reg('Process.Start("notepad.exe");\n', "x.cs") == []

    def test_kotlin_parameterized_query_is_quiet(self):
        assert self._reg('stmt.executeQuery("SELECT * FROM users WHERE id = ?")\n',
                         "x.kt") == []

    def test_go_query_receiver_silent_on_java_file(self):
        # The .Query("..." + x) receiver only fires for .go extensions.
        assert self._reg('db.Query("SELECT * FROM t WHERE id = " + uid)\n',
                         "x.java") == []

    def test_csharp_process_start_silent_on_java_file(self):
        # Process.Start only fires on .cs; the Java shell rule uses Runtime.exec.
        assert self._reg('Process.Start("cmd", "/c " + payload);\n',
                         "x.cs") == [("injection.shell_concat", 1)]
        assert self._reg('Process.Start("cmd", "/c " + payload);\n',
                         "x.java") == []

    def test_perl_receiver_silent_on_php_file(self):
        # ``$var->prepare(...)`` receiver syntax also appears in PHP, but the
        # `$var` interpolation rule only fires for .pl extensions.
        assert self._reg(
            '$stmt = $conn->prepare("SELECT * FROM users WHERE name = \'$name\'")\n',
            "x.php") == []

    def test_perl_parameterized_query_is_quiet(self):
        assert self._reg(
            '$dbh->prepare("SELECT * FROM users WHERE name = ?")->execute($name)\n',
            "x.pl") == []

    def test_perl_static_system_is_quiet(self):
        assert self._reg('system("true")\n', "x.pl") == []

    def test_lua_receiver_silent_on_go_file(self):
        # LuaSQL's ``conn:execute("..." .. x)`` only fires for .lua files;
        # on .go the SQL-concat rule requires the db.Query-family receivers.
        assert self._reg(
            'local res = conn:execute("SELECT * FROM t WHERE id = " .. id)\n',
            "x.go") == []

    def test_lua_shell_concat_silent_on_pl_file(self):
        # os.execute("..." .. x) is a Lua form; the Perl shell rule keys on
        # `$` interpolation, so a `.lua` line is silent on a .pl path.
        assert self._reg(
            'os.execute("rm -rf /tmp/" .. dir)\n',
            "x.pl") == []

    def test_lua_parameterized_query_is_quiet(self):
        assert self._reg(
            'conn:execute("SELECT * FROM users WHERE name = ?", name)\n',
            "x.lua") == []

    def test_lua_static_os_execute_is_quiet(self):
        assert self._reg('os.execute("true")\n', "x.lua") == []


class TestPythonFStringSqlConcat:
    """AST-blind receivers fed a directly-interpolated f-string literal."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.py", code)]

    def test_db_query_fstring_flags(self):
        assert self._reg('conn.query(f"DELETE FROM invoices WHERE owner = \'{owner}\'")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_run_query_fstring_flags(self):
        assert self._reg('run_query(f"DELETE FROM audit_log WHERE created < {days}")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_query_all_fstring_flags(self):
        assert self._reg('query_all(f"SELECT * FROM products WHERE cat = {category}")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_query_one_fstring_flags(self):
        assert self._reg('query_one(f"SELECT email FROM profiles WHERE id = {u_id}")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_single_quoted_fstring_embedded_double_quote_flags(self):
        # Same-quote closure: an embedded " inside a '...' f-string.
        assert self._reg('cur.execute(f\'SELECT "owner" FROM t WHERE id = {uid}\')\n'
                         ) == [("injection.sql_concat", 1)]

    def test_executemany_fstring_flags(self):
        assert self._reg('cur.executemany(f"INSERT INTO t (id) VALUES ({v})", rows)\n'
                         ) == [("injection.sql_concat", 1)]

    def test_inert_fstring_no_interp_is_quiet(self):
        assert self._reg('execute(f"SELECT 1")\n') == []

    def test_static_fstring_is_quiet(self):
        # Static content, no interpolation: os.system(f"echo hi") style shell
        # line stays quiet too, so a python.cursor.execute(f"SELECT *") line
        # with no placeholder f-string must not fire.
        assert self._reg('cur.execute(f"SELECT * FROM users")\n') == []

    def test_parameterized_execute_is_quiet(self):
        assert self._reg('cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n') == []

    def test_method_receiver_like_getquery_fstring_is_quiet(self):
        # obj.getquery(f"...") must not match the bare \bquery\b boundary.
        assert self._reg('db.getquery(f"SELECT * FROM t WHERE id = {uid}")\n') == []


class TestPythonAsyncSqlRegex:
    """Regex-layer parity for asyncpg / aiosqlite async SQL receivers:
    fetchval/fetchrow/fetch/fetchmany/executescript with `+` concatenation
    or f-string interpolation flag; parameterized and static forms stay
    quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.py", code)]

    def test_fetchval_concat_flags(self):
        assert self._reg("await pool.fetchval('SELECT * FROM users WHERE id = ' + uid)\n"
                         ) == [("injection.sql_concat", 1)]

    def test_fetchrow_concat_flags(self):
        assert self._reg("await pool.fetchrow('SELECT * FROM users WHERE name = ' + name)\n"
                         ) == [("injection.sql_concat", 1)]

    def test_conn_fetch_concat_flags(self):
        assert self._reg("await conn.fetch('SELECT * FROM orders WHERE total > ' + amt)\n"
                         ) == [("injection.sql_concat", 1)]

    def test_executescript_concat_flags(self):
        assert self._reg("db.executescript('DELETE FROM t WHERE id = ' + i)\n"
                         ) == [("injection.sql_concat", 1)]

    def test_fetchval_fstring_flags(self):
        assert self._reg('await pool.fetchval(f"SELECT * FROM users WHERE id = {uid}")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_fetchrow_fstring_flags(self):
        assert self._reg('await conn.fetchrow(f"SELECT * FROM t WHERE id = {i}")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_fetchval_parameterized_is_quiet(self):
        assert self._reg("await pool.fetchval('SELECT * FROM users WHERE id = $1', uid)\n") == []

    def test_fetchval_static_is_quiet(self):
        assert self._reg("await pool.fetchval('SELECT 1')\n") == []

    def test_conn_fetch_static_is_quiet(self):
        assert self._reg("async for r in conn.fetch('SELECT * FROM t'):\n") == []

    def test_non_sql_fetch_is_quiet(self):
        # A json.fetch(...) data read is not a SQL entry point.
        assert self._reg("row = json.fetch('data')\n") == []


class TestPythonFStringShellConcat:
    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.py", code)]

    def test_bare_system_fstring_flags(self):
        assert self._reg('system(f"rm -rf {workdir}")\n') == [
            ("injection.shell_concat", 1)]

    def test_bare_popen_fstring_flags(self):
        assert self._reg('popen(f"tail -n 1 {log_file}")\n') == [
            ("injection.shell_concat", 1)]

    def test_os_popen_fstring_flags(self):
        assert self._reg('os.popen(f"ls {dir}")\n') == [("injection.shell_concat", 1)]

    def test_subprocess_call_executable_fstring_flags(self):
        assert self._reg('subprocess.check_output(f"id {user}")\n') == [
            ("injection.shell_concat", 1)]

    def test_embedded_opposite_quote_flags(self):
        # f-string with an embedded single quote inside double-quoted shell.
        assert self._reg('os.system(f"rm -rf \'{dir}\'")\n') == [
            ("injection.shell_concat", 1)]

    def test_static_os_system_is_quiet(self):
        assert self._reg('os.system("echo hi")\n') == []

    def test_no_interp_fstring_is_quiet(self):
        assert self._reg('os.system(f"echo hello")\n') == []

    def test_subprocess_list_form_is_quiet(self):
        assert self._reg('subprocess.run(["ls", d])\n') == []

    def test_subprocess_shell_true_does_not_double_fire(self):
        # The f-string branch must step aside when the shell=True branch
        # already owns the line (single finding beats the dedup-blindness of
        # the standalone analyzer).
        assert self._reg('subprocess.run(f"ping {host}", shell=True)\n') == [
            ("injection.shell_concat", 1)]

    def test_subprocess_fstring_explicit_shell_false_is_quiet(self):
        # shell=False explicitly disables the shell; the interpolating
        # f-string is never interpreted by a shell.
        assert self._reg('subprocess.run(f"ping {host}", shell=False)\n') == []

    def test_import_line_is_quiet(self):
        assert self._reg('from subprocess import run\n') == []


class TestPythonStrFormatRegex:
    """Regex-layer parity for str.format()/%-style interpolating SQL and shell
    call forms (AST already covers the same lines).  `.format(uid)` with a
    placeholder, and ``"..." % var`` with a %s conversion fed to the execute
    family or a subprocess/os.system shell call flag; inert ``.format()``
    (no args), parameterized %s arg tuples and lone conversions without the
    ``%`` operator stay quiet."""

    def _reg(self, code: str):
        return [(f.rule_id, f.line) for f in analyze_injection("x.py", code)]

    def test_execute_format_flags(self):
        assert self._reg('cursor.execute("SELECT * FROM t WHERE id = {}".format(uid))\n'
                         ) == [("injection.sql_concat", 1)]

    def test_execute_single_quoted_format_flags(self):
        assert self._reg("cur.execute('INSERT INTO t VALUES ({0})'.format(v))\n"
                         ) == [("injection.sql_concat", 1)]

    def test_execute_percent_format_flags(self):
        assert self._reg('db.execute("SELECT * FROM t WHERE key = %s" % key)\n'
                         ) == [("injection.sql_concat", 1)]

    def test_embedded_opposite_quote_format_flags(self):
        assert self._reg('cur.execute(f"DELETE FROM t WHERE owner = \'{owner}\'")\n'
                         ) == [("injection.sql_concat", 1)]

    def test_assignment_format_flags(self):
        assert self._reg('q = "SELECT name FROM u WHERE id = {}".format(uid)\n'
                         ) == [("injection.sql_concat", 1)]

    def test_assignment_percent_format_flags(self):
        assert self._reg('sql = "SELECT * FROM t WHERE n = %s" % name\n'
                         ) == [("injection.sql_concat", 1)]

    def test_os_system_format_flags(self):
        assert self._reg('os.system("rm -rf {}".format(d))\n'
                         ) == [("injection.shell_concat", 1)]

    def test_subprocess_percent_format_flags(self):
        assert self._reg('subprocess.call("ls %s" % d)\n'
                         ) == [("injection.shell_concat", 1)]

    def test_popen_format_flags(self):
        assert self._reg('subprocess.Popen("ping {}".format(host))\n'
                         ) == [("injection.shell_concat", 1)]

    def test_inert_format_no_args_is_quiet(self):
        assert self._reg('cur.execute("SELECT * FROM t".format())\n') == []

    def test_placeholder_without_format_call_is_quiet(self):
        assert self._reg('execute("SELECT {x} FROM t")\n') == []

    def test_parameterized_tuple_is_quiet(self):
        assert self._reg('cur.execute("SELECT * FROM t WHERE id = %s", (uid,))\n') == []

    def test_lone_conversion_without_operator_is_quiet(self):
        assert self._reg('execute("SELECT %s FROM t")\n') == []

    def test_no_sql_keyword_format_is_quiet(self):
        assert self._reg('execute("SET {k}".format(k))\n') == []

    def test_no_sql_keyword_percent_is_quiet(self):
        assert self._reg('execute("SET x = %s" % v)\n') == []

    def test_import_line_is_quiet(self):
        assert self._reg('from subprocess import run\n') == []
