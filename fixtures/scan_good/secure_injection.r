# R snippets that must produce zero findings: parameterized queries, static
# literals, and argument-list shell calls only — nothing splices a runtime
# value into a query or command string.

library(DBI)
library(glue)

# Parameterized queries: the value is bound through params, never spliced.
dbGetQuery(con, "SELECT * FROM users WHERE id = ?", params = list(id))
dbExecute(con, "UPDATE accounts SET balance = ? WHERE id = ?",
          params = list(amt, uid))
dbSendQuery(con, "SELECT * FROM t WHERE x = ?", params = list(x))
dbGetQuery(con, "SELECT * FROM orders WHERE sku = ?", params = list(sku))

# Static SQL literals with no interpolation.
dbGetQuery(con, "SELECT COUNT(*) FROM users")
dbExecute(con, "UPDATE t SET n = 1 WHERE id = 1")
dbGetQuery(con, "SELECT * FROM t WHERE id = 5")

# glue_sql() used for structure only, values bound through .envir / ? params.
dbGetQuery(con, glue_sql("SELECT * FROM t WHERE id = ?", .con = con))

# Static system commands / argument-list system2: no interpolation.
system("ls -la /tmp")
system2("ls", "/tmp")
system2("cp", c("a.txt", "b.txt"))

# paste0/sprintf building non-SQL strings is fine.
dbGetQuery(con, paste0("tbl_", "users"), params = list())
