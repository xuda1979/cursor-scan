#!/usr/bin/env bash
# Injection-prone shell snippets — each line below must produce exactly the
# finding named in its trailing comment.
#
# SQL injection: CLI database tools handed a double-quoted SQL literal that
# interpolates a shell variable at line-splice time.

sqlite3 app.db "SELECT * FROM users WHERE id = $id"            # sql_concat
mysql -u root -e "UPDATE accounts SET balance = $amt"          # sql_concat
psql -d app -c "DELETE FROM sessions WHERE token = '$tok'"    # sql_concat
mysqlsh --sql -e "SELECT * FROM orders WHERE region = $region" # sql_concat

# Shell command injection: eval or a shell interpreter -c with the command
# taken from a runtime variable (double-quoted or bare).

eval "$cmd"        # shell_concat
eval $USER_INPUT   # shell_concat
sh -c "$pipeline"  # shell_concat
bash -c "rm -rf $target"  # shell_concat
zsh -c "echo $msg > /tmp/out"  # shell_concat
dash -c "$script"  # shell_concat
bash -c $SCRIPT    # shell_concat
