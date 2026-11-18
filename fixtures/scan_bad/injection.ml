(* OCaml injection samples (sqlite3-ocaml / mysql-ocaml / postgres + shell). *)

(* 1. Sqlite3.exec fed a ^-concatenated SQL string. *)
Sqlite3.exec db "SELECT * FROM orders WHERE uid = " ^ uid;;

(* 2. Sqlite3.prepare with a ^-concatenated pattern. *)
Sqlite3.prepare db "SELECT * FROM users WHERE name = '" ^ q ^ "'";;

(* 3. Postgresql.exec with a ^-concatenated UPDATE. *)
Postgresql.exec conn "UPDATE accounts SET balance = " ^ amt;;

(* 4. let sql = "..." ^ x assignment build consumed on a later line. *)
let sql = "DELETE FROM sessions WHERE sid = " ^ sid in
run_db db sql;;

(* 5. Mysql.exec with a ^-concatenated INSERT. *)
Mysql.exec db "INSERT INTO logs VALUES (" ^ payload ^ ")";;

(* 6. Sys.command fed a ^-concatenated command string. *)
Sys.command ("rm -rf /tmp/" ^ folder);;

(* 7. Unix.open_process_in pipe filter with a ^-concatenated pattern. *)
Unix.open_process_in ("grep " ^ pattern ^ " /var/log/messages");;
