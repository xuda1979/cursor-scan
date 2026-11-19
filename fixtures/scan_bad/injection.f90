! Bad Fortran: dynamic SQL and shell commands built with // concatenation.
program badInjection
  implicit none
  character(len=200) :: sql, query, cmd
  character(len=50) :: userid, val, msg, newval, suffix, uid, folder, path, idv
  integer :: rc
  ! ODBC / derived-type statement runners fed //-concatenated SQL
  rc = SQLExecDirect(hstmt, "SELECT * FROM user WHERE id = " // userid, SQL_NTS)
  call SQLExecDirect(hstmt, 'UPDATE log SET v = ' // val // '', SQL_NTS)
  rc = SQLExecute(hstmt, "DELETE FROM t WHERE x = " // xval)
  call db%execute('INSERT INTO log VALUES(' // msg // ')')
  call conn%execute("CREATE TABLE t (id int) " // suffix)
  rc = SQLPrepare(hstmt, "SELECT name FROM users WHERE id = " // uid)
  rc = execute_immediate(db, "SELECT name FROM users WHERE id = " // uid)
  ! assignment builds then run later
  sql = "SELECT name FROM t WHERE id = " // user_input
  query = 'DELETE FROM t WHERE id = ' // idv
  sql = 'UPDATE t SET v = ' // newval
  ! shell concatenation
  call execute_command_line("dir " // folder)
  call EXECUTE_COMMAND_LINE('rm -rf /tmp/' // name // '')
  call system("ls -la " // path)
end program
