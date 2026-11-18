open System
open System.Data.SqlClient
open System.Diagnostics

// sprintf-built query string fed to an ADO.NET SqlCommand
let runQuery (conn: SqlConnection) (id: string) =
    let cmd = new SqlCommand(sprintf "SELECT * FROM users WHERE id = %s" id, conn)
    cmd.ExecuteReader()

// +-concatenated query string fed to SqlCommand
let updateBalance (conn: SqlConnection) (amt: decimal) =
    new SqlCommand("UPDATE accounts SET balance = " + string amt, conn)

// sprintf-built query string assigned to CommandText
let deleteSession (conn: SqlConnection) (sid: string) =
    let cmd = new SqlCommand()
    cmd.CommandText <- sprintf "DELETE FROM sessions WHERE sid = %s" sid

// +-concatenated query string assigned through CommandText
let dropRow (conn: SqlConnection) (uid: string) =
    let cmd = new SqlCommand()
    cmd.CommandText <- "DELETE FROM orders WHERE uid = " + uid

// let-assigned sprintf build consumed by a DB call on a later line
let sql = sprintf "SELECT * FROM orders WHERE uid = %s" uid

// sprintf-built command string fed to Process.Start
let listDir dir =
    Process.Start("ls -la " + dir)

// +-concatenated command string fed to Process.Start
let showFile file =
    Process.Start(sprintf "cat %s" file)

// concatenated command string assigned through StartInfo.Arguments
let pingHost host =
    let psi = ProcessStartInfo()
    psi.Arguments <- "ping -c 1 " + host
    Process.Start(psi)
