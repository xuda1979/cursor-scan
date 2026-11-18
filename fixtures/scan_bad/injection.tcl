# Tcl injection samples (SQLite Tcl interface + exec/open pipe).

# 1. `db eval` fed a $-interpolated SQL string.
db eval "SELECT * FROM orders WHERE uid = $uid"

# 2. [db prepare ...] with an interpolated SQL string.
set stmt [db prepare "UPDATE accounts SET balance = $amt WHERE id = $id"]

# 3. set sql = "... $x" assignment build consumed on a later line.
set sql "DELETE FROM sessions WHERE sid = $sid"

# 4. exec command list with an interpolated argument.
exec echo "hello $name"

# 5. open pipe filter with an interpolated pattern.
open "| grep $pattern /var/log/messages"
