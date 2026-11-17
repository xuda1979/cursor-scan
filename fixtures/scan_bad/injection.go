// Deliberately unsafe Go SQL string concatenation and shell execution
// (CWE-89 / CWE-78): user-controlled values are spliced into query strings
// via `+` concatenation or fmt.Sprintf verbs, and shell commands are run
// through sh -c with a concatenated command, instead of parameterized
// placeholders (?) / argument-list forms.

package fixtures

import (
	"context"
	"database/sql"
	"fmt"
	"os/exec"
)

func findUser(db *sql.DB, name string) {
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + name + "'")
	rows.Close()
}

func findAccount(db *sql.DB, owner string) {
	row := db.QueryRow("SELECT id FROM accounts WHERE owner = '" + owner + "'")
	row.Scan()
}

func touchRow(db *sql.DB, id string) {
	db.Exec("UPDATE logs SET status = 'ok' WHERE id = " + id)
}

func queryColumns(db *sql.DB, ctx context.Context, cols string) {
	rows, _ := db.QueryContext(ctx, "SELECT "+cols+" FROM reports")
	rows.Close()
}

func queryFormatted(db *sql.DB, cols string) {
	rows, _ := db.Query(fmt.Sprintf("SELECT %s FROM users WHERE id = %d", cols, 7))
	rows.Close()
}

func wipeDir(path string) {
	exec.Command("/bin/sh", "-c", "rm -rf "+path).Run()
}

func listFiles(dir string) {
	exec.Command("bash", "-c", fmt.Sprintf("ls %s", dir)).Run()
}

// NOT findings: parameterized placeholders and argument-list / static forms.
func safeQuery(db *sql.DB, id string) {
	db.Query("SELECT * FROM users WHERE id = ?", id)
	exec.Command("ping", "-c", "1", "127.0.0.1").Run()
	exec.Command("echo", "hi").Run()
}
