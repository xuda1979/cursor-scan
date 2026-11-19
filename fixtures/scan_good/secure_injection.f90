! Good Fortran: parameterized / static SQL and static shell commands.
program secureInjection
  implicit none
  character(len=200) :: sql, msg, cmd
  character(len=50) :: folder
  integer :: rc
  ! parameterized queries (no // concatenation)
  rc = SQLExecDirect(hstmt, "SELECT * FROM user WHERE id = ?", SQL_NTS)
  call db%execute('INSERT INTO log VALUES(?)')
  call conn%execute(prepstmt)
  sql = "SELECT * FROM t WHERE id = ?"
  ! static SQL strings
  sql = "SELECT count(*) FROM t"
  ! non-SQL // concatenation
  msg = "hello " // folder
  ! static shell commands
  call execute_command_line("dir")
  call system("echo hi")
  call execute_command_line(cmd)
  call system(cmdline)
end program
