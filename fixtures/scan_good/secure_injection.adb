-- Good Ada: parameterized / static SQL and static shell commands.
with GNAT.OS_Lib; use GNAT.OS_Lib;
procedure Secure_Injection is
   User_Id : String := Input_Value;
   Sql : String;
   Cmd : String;
   Folder : String;
   begin
   -- parameterized queries (no & concatenation)
   Sqlite3.Exec ("SELECT * FROM users WHERE id = ?");
   Conn.Execute ("INSERT INTO log VALUES (?)", Args);
   Db.Exec (Prepared_Stmt);
   Sql := "SELECT * FROM t WHERE id = ?";
   -- static SQL strings
   Sql := "SELECT count(*) FROM t";
   -- non-SQL & concatenation (string building, not a statement sink)
   Greeting := "hello " & Folder;
   -- static shell commands
   Spawn_Command ("dir");
   Spawn_Execution ("echo hi");
   system ("ls");
   Spawn_Command (Cmd);
   system (Cmd_Line);
   end Secure_Injection;
