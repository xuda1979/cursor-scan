%% Good: ? placeholders, $1 binds, parameter lists and {spawn_executable, ...}
%% leave injection scanners quiet.
-module(safe_repo).
-export([find_user/1, ping/1]).

find_user(Uid) ->
    R1 = ejabberd_sql:query(conn, "SELECT * FROM users WHERE id = ?", [Uid]),
    R2 = epgsql:equery(conn, "UPDATE t SET v = $1", [Val]),
    R3 = mysql:query(conn, "SELECT COUNT(*) FROM orders"),
    R4 = emysql:execute(conn, "SELECT * FROM books WHERE isbn = ?", [Isbn]).

ping(Host) ->
    C1 = os:cmd("printf ok"),
    C2 = open_port({spawn_executable, "/bin/ping"}, [binary]).
