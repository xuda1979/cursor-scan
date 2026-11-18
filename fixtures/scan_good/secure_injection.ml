(* Safe OCaml: static SQL literals, ? placeholders, bound statements and
   static command strings -- no ^-concatenation feeding any sink. *)

let q = "SELECT * FROM users"
;;
Sqlite3.exec db "SELECT * FROM users";;
Sqlite3.exec db "SELECT * FROM orders WHERE uid = ?" [uid];;
let stmt = Sqlite3.prepare db "SELECT * FROM orders WHERE uid = ?"
;;
Sqlite3.bind stmt 1 uid
;;
Sqlite3.step stmt
;;
Sys.command "ls -l /var/log";;
Unix.open_process_in "grep -c error /var/log/messages";;

let dynamic_cmd = "/bin/ls"
;;
Sys.command (dynamic_cmd ^ " -l /var/log");;
