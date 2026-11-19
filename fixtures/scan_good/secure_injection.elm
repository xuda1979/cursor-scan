port module Safe exposing (main)

import Sql
import Pool
import Ports

-- parameterized binds, static SQL, arg-array and variable-only commands stay quiet

queryUsers conn id =
    Sql.query conn "SELECT * FROM users WHERE id = ?" [ id ]

queryAudit conn =
    Sql.query conn "SELECT count(*) FROM audit_log"

updateBalance conn diff =
    Sql.execute conn "UPDATE accounts SET balance = balance - ?" [ diff ]

findPayments conn name =
    Pool.query conn ("SELECT * FROM payments WHERE name = ?") [ name ]

runBackup =
    Ports.exec "tar -czf backup.tar.gz /data"

runList dir =
    Ports.exec "ls" [ dir ]

zipTwo a b =
    String.concat [ a, b ]

greet name =
    "hello, " ++ name
