// Injection-safe Go patterns — must produce zero findings.
package fixtures

import (
	"database/sql"
	"os/exec"
)

func getByID(db *sql.DB, id string) {
	// Parameterized placeholder: no string concatenation.
	rows, err := db.Query("SELECT * FROM users WHERE id = ?", id)
	if err != nil {
		return
	}
	defer rows.Close()
}

func listBackup(dir string) {
	// Argument-list form: no shell involvement.
	exec.Command("grep", "-rc", "error", dir).Run()
}

func pingHost() {
	// "-c" here is ping's count flag, not a shell invocation.
	exec.Command("ping", "-c", "1", "127.0.0.1").Run()
}
