@echo off
setlocal

REM SQL client calls with %VAR% interpolation into the query text.
osql -E -S . -d shop -Q "SELECT * FROM users WHERE id = %id%"
sqlcmd -S . -d shop -Q "INSERT INTO accounts (name) VALUES ('%user%')"
mysql -h db -u app -e "UPDATE accounts SET balance = %amount%"
psql -h db -U app -c "DELETE FROM sessions WHERE sid = %sid%"
sqlite3 shop.db "ALTER TABLE users ADD COLUMN %col% text"

REM set-assignment builds that interpolate a variable into SQL text.
set q=SELECT * FROM orders WHERE uid = %uid%
set "sql=SELECT * FROM users WHERE id = %k%"

REM Command execution with %VAR% in the invoked command line.
cmd /c "del C:\temp\%file%"
%comspec% /c "net user %user% hack /add"
start "" "%scripts%\deploy.cmd"
call "C:\tools\%tool%\setup.bat"
