#!/usr/bin/env bash
# Injection-safe shell snippets — this file must produce zero findings.
# Parameterized SQL clients, static commands, and argument-list-style exec
# only; nothing interpolates a runtime variable into a query or command.

set -euo pipefail

# Static SQL literal with no variable interpolation.
sqlite3 app.db "SELECT COUNT(*) FROM users"
mysql -u root -e "SELECT id, name FROM users WHERE role = 'admin'"
psql -d app -c "SELECT 1"
mysqlsh --sql -e "SHOW TABLES"

# Parameterized SQL: values arrive as separate arguments, never spliced.
sqlite3 app.db "SELECT * FROM users WHERE id = ?" "$uid"
mysql -u root -e "UPDATE accounts SET balance = ? WHERE id = ?" "$amt" "$uid"
psql -d app -c "SELECT * FROM sessions WHERE token = ?" "$tok"

# Static commands passed to eval / sh -c with nothing to interpolate.
eval "true"
eval 'echo hi'
sh -c "echo hello"
bash -c 'ls -la'
zsh -c "echo hi"

# Non-shell SQL via parameter list: the statement never interpolates a var.
mysql -u root -e "SELECT * FROM users WHERE id = 5" &&
    echo "queried"

# Non-tainted / positional shell vars are not splice targets.
sqlite3 app.db "SELECT * FROM users WHERE id = $1"
sh -c "echo $0 running"
eval "$#"
