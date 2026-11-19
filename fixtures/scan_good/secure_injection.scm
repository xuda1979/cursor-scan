; Good Scheme/Racket: parameterized queries and static SQL / shell commands.

; Parameterized query with a prepared statement
(define (run-query conn id)
  (db:query conn "SELECT * FROM users WHERE id = ?" (list id)))

; Guile sqlite parameterized query with named placeholder
(define (delete-session db sid)
  (sqlite:exec db "DELETE FROM sessions WHERE sid = $1" (list sid)))

; static SQL, no concatenation
(define (count-users db)
  (sqlite:exec db "SELECT count(*) FROM users"))

; non-SQL string-append stays quiet
(define (greet name)
  (string-append "hello " name))

; static shell command
(define (print-dir)
  (system "ls -la"))

; truncate usage (no user input) stays quiet
(define (truncate-log file)
  (open-output-file file))
