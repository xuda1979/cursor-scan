;; Bad Common Lisp: dynamic SQL and shell commands built with
;; concatenate / format.
(defpackage #:bad-injection
  (:use #:cl #:clsql #:postmodern #:sqlite))

;; (concatenate 'string ...)-built query fed to a CLSQL sink
(defun run-query (conn id)
  (clsql:query conn (concatenate 'string "SELECT * FROM users WHERE id = " id)))

;; (format nil ...)-built query fed to a CLSQL execute-command sink
(defun update-balance (conn amt)
  (clsql:execute-command conn (format nil "UPDATE accounts SET balance = ~a" amt)))

;; concatenate-built query fed to postmodern query
(defun delete-session (conn sid)
  (postmodern:query (concatenate 'string "DELETE FROM sessions WHERE sid = '" sid "'") conn))

;; concatenate-built query fed to postmodern execute
(defun drop-table (conn tbl)
  (postmodern:execute (concatenate 'string "DROP TABLE " tbl) conn))

;; (format nil ...)-built query fed to cl-sqlite execute-non-query
(defun insert-log (db msg)
  (sqlite:execute-non-query db (format nil "INSERT INTO log VALUES (~a)" msg)))

;; defparameter-assigned concatenate build consumed by a DB call later
(defparameter *sql* (concatenate 'string "SELECT * FROM orders WHERE uid = " uid))

;; setf-assigned format build
(defvar *stmt* nil)
(setf *stmt* (format nil "DELETE FROM t WHERE id = ~a" idv))
;; (concatenate 'string ...)-built command fed to uiop:run-program
(defun list-dir (dir)
  (uiop:run-program (concatenate 'string "ls -la " dir) :output t))

;; (format nil ...)-built command fed to sb-ext:run-program
(defun show-file (file)
  (sb-ext:run-program (format nil "cat ~a" file) :output t))

;; concatenate-built command fed to run-shell-command
(defun ping-host (host)
  (run-shell-command (concatenate 'string "ping -c 1 " host)))
