// Injection-safe C/C++ patterns — must produce zero findings.
#include <sqlite3.h>
#include <mysql.h>
#include <cstdio>
#include <string>

static int getByID(sqlite3 *db, const char *id) {
    // Prepared statement: parameter is bound separately, no splicing.
    sqlite3_stmt *stmt = 0;
    return sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, 0);
}

static int updateByID(MYSQL *conn, const char *id) {
    // Statement handle: "SELECT" only appears in the prepare parameters.
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    return mysql_stmt_prepare(stmt, "UPDATE logs SET status = 'ok' WHERE id = ?", -1);
}

static int countAll(sqlite3 *db) {
    // Static query literal: nothing runtime to interpolate.
    return sqlite3_exec(db, "SELECT COUNT(*) FROM logs", 0, 0, 0);
}

static void backupDir(const char *dir) {
    // Static command string: no %s verb, no `+` splice.
    system("tar czf /tmp/backup.tgz /var/lib");
}
