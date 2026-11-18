@echo off
setlocal

REM Static SQL, bound parameters and quoted variable passthrough stay quiet.
osql -E -Q "SELECT * FROM users WHERE id = 100"
sqlcmd -S . -Q "INSERT INTO accounts (name) VALUES (@name)"
mysql -u app -e "SELECT COUNT(*) FROM orders"
psql -c "SELECT * FROM public.users LIMIT 10"
sqlite3 shop.db "PRAGMA integrity_check"
set sql=SELECT * FROM users WHERE active = 1
sqlcmd -Q "%sql%"
set name=Alicia

REM Static command execution and harmless variable expansion.
cmd /c "echo backup in progress"
%comspec% /c copy C:\data\in.csv D:\backup\in.csv
start notepad.exe readme.txt
call build\clean.cmd
echo Hello %name%
set target=%backup%\daily
