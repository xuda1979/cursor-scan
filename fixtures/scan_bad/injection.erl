%% Bad: ++-concatenated / io_lib:format-~s SQL and shell commands.
-module(unsafe_repo).
-export([find_user/1, run_cmd/1]).

find_user(Uid) ->
    R1 = ejabberd_sql:query(conn, "SELECT * FROM users WHERE id = " ++ Uid),
    R2 = emysql:execute(conn, "DELETE FROM logs WHERE id = " ++ Lid),
    R3 = epgsql:equery(conn, "UPDATE t SET v = " ++ Val),
    R4 = mysql:query(conn, io_lib:format("INSERT INTO books (isbn) VALUES (~s)", [Isbn])).

run_cmd(Host) ->
    C1 = os:cmd("ping -c 1 " ++ Host),
    C2 = os:cmd(io_lib:format("ls ~s", [Dir])),
    C3 = open_port({spawn, "cat " ++ Path}, [binary]).
