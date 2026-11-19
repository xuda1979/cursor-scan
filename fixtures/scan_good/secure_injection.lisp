;; Good Common Lisp: parameterized / static SQL and static shell commands.
(defpackage #:secure-injection
  (:use #:cl #:clsql #:postmodern #:sqlite))

;; parameterized queries (no concatenation)
(defun load-user (conn id)
  (clsql:query conn "SELECT * FROM users WHERE id = ?" :parameters (list id)))

(defun update-balance (conn amt)
  (clsql:execute-command conn "UPDATE accounts SET balance = ?" :parameters (list amt)))

(postmodern:query "SELECT * FROM sessions WHERE sid = $1" sid)
(sqlite:execute-non-query db "INSERT INTO log VALUES (?)" msg)

;; static SQL strings
(defun list-users (conn)
  (clsql:query conn "SELECT count(*) FROM users"))

(defparameter *static-sql* "SELECT * FROM t WHERE id = ?")

;; non-SQL string building (no statement sink on this line)
(defun greeting (name)
  (concatenate 'string "hello " name))

;; static shell commands
(defun list-dir ()
  (uiop:run-program "ls -la" :output t))

(defun ping ()
  (run-shell-command "ping -c 1 localhost"))
