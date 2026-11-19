; Bad Scheme/Racket: dynamic SQL and shell commands built with
; string-append / format, fed to db / sqlite / process sinks.

; (string-append ...)-built query fed to a Racket db:query sink
(define (run-query conn id)
  (db:query conn (string-append "SELECT * FROM users WHERE id = " id)))

; (string-append ...)-built query fed to a db:exec sink
(define (update-balance conn amt)
  (db:exec conn (string-append "UPDATE accounts SET balance = " amt)))

; string-append-built query fed to Guile sqlite:exec
(define (delete-session db sid)
  (sqlite:exec db (string-append "DELETE FROM sessions WHERE sid = '" sid "'")))

; string-append-built query fed to sqlite3:exec
(define (drop-table db tbl)
  (sqlite3:exec db (string-append "DROP TABLE " tbl)))

; format-built query fed to a db:query sink
(define (insert-log conn msg)
  (db:query conn (format "INSERT INTO log VALUES (~a)" msg)))

; define-assigned string-append build consumed by a DB call later
(define *sql* (string-append "SELECT * FROM orders WHERE uid = " uid))

; set!-assigned format build
(define *stmt* "")
(set! *stmt* (format "DELETE FROM t WHERE id = ~a" idv))

; string-append-built command fed to Racket system
(define (list-dir dir)
  (system (string-append "ls -la " dir)))

; string-append-built command fed to open-output-pipe
(define (show-file file)
  (open-output-pipe (string-append "cat " file)))

; format-built command fed to process
(define (ping-host host)
  (process (format "ping -c 1 ~a" host)))
