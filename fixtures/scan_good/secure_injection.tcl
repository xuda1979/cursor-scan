# Safe Tcl: braced {} literals never substitute variables, and ? placeholders
# are bound as separate arguments, so nothing here is tainted.

set q {
    SELECT * FROM users WHERE id = $id
}
db eval $q

db eval "SELECT * FROM users"

db eval "SELECT * FROM orders WHERE uid = ?" [list $uid]
set stmt [db prepare "SELECT * FROM orders WHERE uid = ? AND status = ?"]
db eval $stmt [list $uid $status]

exec ls -l /var/log
open "| grep error /var/log/messages"
