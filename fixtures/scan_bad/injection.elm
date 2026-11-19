port module Vulnerable exposing (main)

-- 7 SQL positives

import Sql
import Pool
import Ports

queryUsers conn id =
    Sql.query conn ("SELECT * FROM users WHERE id = " ++ id)

queryByIp conn ip =
    Sql.raw conn ("SELECT * FROM users WHERE ip = " ++ ip)

updateBalance conn diff =
    Sql.execute conn ("UPDATE accounts SET balance = balance - " ++ diff)

deleteSession conn sid =
    Sql.run conn ("DELETE FROM sessions WHERE sid = " ++ sid)

findPayments conn name =
    Pool.query conn ("SELECT * FROM payments WHERE name = " ++ name)

dropTable conn tbl =
    Pool.execute conn ("DROP TABLE " ++ tbl)

countItems owner =
    let
        sql = "SELECT count(*) FROM items WHERE owner = " ++ owner
    in
    Sql.query conn sql

-- 3 shell positives

runBackup target =
    Ports.exec ("tar -czf backup.tar.gz " ++ target)

pingHost host =
    Ports.exec ("ping -c 1 " ++ host)

grepLogs path needle =
    Ports.exec ("cat " ++ path ++ " | grep " ++ needle)
