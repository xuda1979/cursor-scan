' Deliberately unsafe VB.NET SQL string concatenation and shell execution
' (CWE-89 / CWE-78): user-controlled values are spliced into ADO.NET query
' strings via the `&` concatenation operator or $"-interpolated templates,
' and processes are launched with concatenated command strings, instead of
' @parameter placeholders / static command lines.

Imports System
Imports System.Data.SqlClient
Imports System.Diagnostics

Module UnsafeQueries
    Sub FindUser(conn As SqlConnection, userId As String)
        Dim cmd As New SqlCommand("SELECT * FROM Users WHERE Id = " & userId, conn)
        cmd.ExecuteReader()
    End Sub

    Sub TouchRow(cmd As SqlCommand, val As String)
        cmd.CommandText = "UPDATE logs SET status = 'ok' WHERE id = " & val
    End Sub

    Sub QueryByTemplate(cmd As SqlCommand, owner As String)
        cmd.CommandText = $"SELECT id FROM accounts WHERE owner = '{owner}'"
    End Sub

    Sub BuildQuery(cmd As SqlCommand, name As String)
        Dim sql As String = "SELECT * FROM items WHERE name = '" & name & "'"
        cmd.CommandText = sql
    End Sub

    Sub WipeDir(path As String)
        Process.Start("cmd.exe", "/c del /q " & path)
    End Sub

    Sub RunPsExec(target As String)
        Shell("psexec \\" & target & " -d cmd.exe")
    End Sub

    Sub PingHost(host As String)
        CreateObject("WScript.Shell").Run("ping " & host)
    End Sub

    Sub CmdWithArgs(psi As ProcessStartInfo, arg As String)
        psi.Arguments = "-c " & arg
    End Sub

    ' NOT findings: @parameter placeholders, .AddWithValue binding and
    ' static command lines.
    Sub SafeQuery(conn As SqlConnection, id As Integer)
        Dim cmd As New SqlCommand("SELECT * FROM Users WHERE Id = @id", conn)
        cmd.Parameters.AddWithValue("@id", id)
        Process.Start("notepad.exe")
    End Sub
End Module
