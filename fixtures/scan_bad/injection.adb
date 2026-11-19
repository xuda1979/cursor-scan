-- Bad Ada: dynamic SQL and shell commands built with & concatenation.
with GNAT.OS_Lib; use GNAT.OS_Lib;
procedure Bad_Injection is
   User_Id : String := Input_Value;
   Value, New_Val, Suffix, Msg, Uid, User_Input, Idv : String;
   Folder, Path, Name_Arg, Day_Arg : String;
   Sql, Query : String;
   Db : Connection;
   begin
   -- GNATCOLL.SQL / sqlite3-ada statement runners fed &-concatenated SQL
   Sqlite3.Exec ("SELECT * FROM users WHERE id = " & User_Id);
   sqlite3_exec (Db, "DELETE FROM log WHERE v = " & Value, Null, Null, Error);
   Conn.Execute ("UPDATE t SET x = " & New_Val);
   DB.Exec ("CREATE TABLE t (id int) " & Suffix);
   Connection.Query ("INSERT INTO log VALUES (" & Msg & ")");
   Database.Prepare ("SELECT name FROM users WHERE id = " & Uid);
   Exec ("SELECT count FROM stats WHERE d = " & Day_Arg);
   -- assignment builds then run later
   Sql := "SELECT name FROM t WHERE id = " & User_Input;
   Query := "DELETE FROM t WHERE id = " & Idv;
   Sql := "UPDATE t SET v = " & New_Val;
   -- shell concatenation
   Spawn_Command ("dir " & Folder);
   Spawn_Execution ("rm -rf /tmp/" & Name_Arg);
   system ("ls -la " & Path);
   end Bad_Injection;
