<?php
// Deliberately unsafe PHP SQL string concatenation and shell execution
// (CWE-89 / CWE-78): user-controlled values are spliced into query strings
// and shell commands instead of using bind parameters / parameter lists.

function find_user($conn, $name) {
    return mysqli_query($conn, "SELECT * FROM users WHERE name = '" . $name . "'");
}

function find_account($conn, $owner) {
    return pg_query($conn, "SELECT id FROM accounts WHERE owner = '" . $owner . "'");
}

function touch_row($db, $id) {
    $db->query("UPDATE logs SET status = 'ok' WHERE id = " . $id);
}

function drop_session($pdo, $t) {
    $pdo->exec("DELETE FROM sessions WHERE token = '" . $t . "'");
}

function wipe_dir($dir) {
    system("rm -rf " . $dir);
}

function run_sh($cmd) {
    exec("sh -c " . $cmd);
}

function list_files($path) {
    shell_exec("ls " . $path);
}

function open_pipe($cmd, $pipes) {
    proc_open("echo " . $cmd, $pipes);
}
