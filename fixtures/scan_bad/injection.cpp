// Deliberately unsafe C/C++ SQL string splicing and shell execution
// (CWE-89 / CWE-78): user-controlled values are concatenated into query
// strings with the std::string `+` operator or sprintf()/snprintf() verbs
// and handed to sqlite3_exec / mysql_query / mysql_real_query receivers,
// and commands built via snprintf() or std::string `+` go to system() /
// popen(), instead of prepared statements / argument-list forms.
#include <sqlite3.h>
#include <mysql.h>
#include <cstdio>
#include <cstring>
#include <string>

// FINDING 1: std::string `+` splices user input into the SQL literal.
static int bad1(sqlite3 *db, const std::string &name) {
    char *err = 0;
    return sqlite3_exec(db, ("SELECT * FROM users WHERE name = '" + name + "'").c_str(),
                        0, 0, &err);
}

// FINDING 2: snprintf() bakes a %s verb into a SQL-keyword format literal.
static int bad2(MYSQL *conn, const char *id) {
    char query[256];
    snprintf(query, sizeof query, "DELETE FROM logs WHERE id = %s", id);
    return mysql_query(conn, query);
}

// FINDING 3: snprintf()-built command handed to system() in the same line.
static int bad3(const char *dir) {
    char cmd[256];
    snprintf(cmd, sizeof cmd, "ls -la %s", dir); system(cmd);
    return 0;
}

// FINDING 4: std::string `+` concat passed straight into system().
static void bad4(const char *path) {
    system(("rm -rf /tmp/" + std::string(path)).c_str());
}

// NOT findings: prepared statements, static literals and static commands.
static int safe1(sqlite3 *db, const char *id) {
    sqlite3_stmt *stmt = 0;
    return sqlite3_prepare_v2(db, "SELECT * FROM users WHERE id = ?", -1, &stmt, 0);
}

static int safe2(MYSQL *conn, const char *id) {
    MYSQL_STMT *stmt = mysql_stmt_init(conn);
    return mysql_stmt_prepare(stmt, "SELECT * FROM users WHERE id = ?", -1);
}

static int safe3(sqlite3 *db) {
    return sqlite3_exec(db, "SELECT COUNT(*) FROM logs", 0, 0, 0);
}

static void safe4(void) {
    snprintf((char *)0, 0, "clean %s", "noop");
    system("true");
    popen("date", "r");
}
