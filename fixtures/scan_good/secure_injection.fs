open System
open System.Data.SqlClient
open System.Diagnostics

// Parameterized query: @id placeholder with Parameters.AddWithValue bind.
let runQuery (conn: SqlConnection) (id: string) =
    let cmd = new SqlCommand("SELECT * FROM users WHERE id = @id", conn)
    cmd.Parameters.AddWithValue("@id", id) |> ignore
    cmd.ExecuteReader()

// Parameterized query with ? placeholder.
let updateBalance (conn: SqlConnection) (amt: decimal) =
    let cmd = new SqlCommand("UPDATE accounts SET balance = ?", conn)
    cmd.ExecuteNonQuery()

// Static SQL literal, no concatenation.
let queryAll (conn: SqlConnection) =
    new SqlCommand("SELECT 1", conn)

// Static command with argument list, no string concat.
let listDir dir =
    Process.Start("ls", "-la", dir)

// Static command string, no concatenation.
let showFile file =
    Process.Start("cat", file)
