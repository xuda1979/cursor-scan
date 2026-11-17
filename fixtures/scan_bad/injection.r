# R snippets that splice runtime values into SQL queries (DBI) or shell
# commands (system) — every line below must produce a finding.

library(DBI)

# paste0() splices the value straight into the query string.
dbGetQuery(con, paste0("SELECT * FROM users WHERE id = ", id))
dbSendQuery(con, paste("SELECT * FROM t WHERE x = ", v))
dbExecute(con, paste0("UPDATE accounts SET balance = ", amt, " WHERE id = ", uid))
dbSendStatement(con, paste("DELETE FROM sessions WHERE token =", tok))

# sprintf() printf-verb formatting bakes runtime input into the SQL literal.
dbExecute(con, sprintf("UPDATE t SET n = %s WHERE id = 1", name))
dbSendStatement(con, sprintf("DELETE FROM t WHERE id = %d", uid))
dbGetQuery(con, sprintf("SELECT * FROM orders WHERE sku = '%s'", sku))

# glue() / glue_sql() interpolate {var} spans textually at runtime.
dbGetQuery(con, glue::glue_sql("SELECT * FROM t WHERE name = {name}"))
dbSendQuery(con, glue("SELECT * FROM logs WHERE level = {level}"))

# Assignment form: the tainted query is built on this line, the driver call
# sits later (out of the line-scanner's reach).
q <- paste0("SELECT * FROM users WHERE id = ", id)
sql <- sprintf("UPDATE t SET x = %s WHERE id = 1", val)
stmt <- glue::glue_sql("INSERT INTO t VALUES ({a}, {b})")

# Shell command built by splicing values into a system() command string.
system(paste0("rm -rf /tmp/", dir))
system(paste("ls ", argv))
system(sprintf("ping -c 1 %s", host))
system(glue::glue("tar czf {f}.tgz {f}"))
