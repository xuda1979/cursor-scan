' Deliberately unsafe VBA (Access/Excel macro) SQL concatenation and shell
' execution (CWE-89 / CWE-78): user-controlled values are spliced into
' DoCmd.RunSQL / CurrentDb.Execute query strings with the `&` operator, and
' commands are launched through Shell / WScript.Shell with concatenated
' arguments, instead of parameter queries / static command lines.

Option Explicit

Sub BadQueries()
    Dim userId As String
    userId = "admin' OR '1'='1"

    ' String concatenation into SQL, executed via the DoCmd sink.
    Dim strSQL As String
    strSQL = "SELECT * FROM Users WHERE Id = " & userId

    ' DoCmd.RunSQL (Access) with a concatenated SELECT.
    DoCmd.RunSQL "SELECT * FROM Users WHERE Id = " & userId

    ' CurrentDb.Execute (Access DAO) with concatenated UPDATE.
    CurrentDb.Execute "UPDATE logs SET status = '" & status & "' WHERE id = " & Id

    ' Database object Execute with concatenated SELECT.
    db.Execute "SELECT id FROM accounts WHERE owner = '" & owner & "'"

    ' Recordset CommandText assignment with concatenated DELETE.
    cmd.CommandText = "DELETE FROM orders WHERE id > " & minId

    ' Connection Execute with concatenated DROP.
    conn.Execute "DROP TABLE IF EXISTS audit_" & suffix

    ' One-line Dim/assignment form splicing user input into SQL.
    Dim strSQL2 As String: strSQL2 = "SELECT * FROM t WHERE id = " & uid
End Sub

Sub BadShell()
    Dim path As String
    path = "C:\temp\payload"

    ' Shell function: concatenated argument passed to cmd.exe.
    Shell "cmd /c del /q " & path

    ' Shell with parentheses form.
    Shell ("psexec \\" & target & " -d cmd.exe")

    ' WScript.Shell late-bound Run with concatenated command.
    CreateObject("WScript.Shell").Run "ping " & host

    ' Pre-created WshShell object Run with concatenated command.
    WshShell.Run "wmic process " & cmd
End Sub
