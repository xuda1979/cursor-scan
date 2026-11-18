Option Explicit

' Secure VBScript / classic ASP samples: parameterized queries and static
' commands only -- must yield zero findings.

' Parameterized query: ? placeholder with ADODB parameters array.
Sub RunQuery(conn, id)
    Dim rs, cmd
    Set cmd = CreateObject("ADODB.Command")
    cmd.CommandText = "SELECT * FROM users WHERE id = ?"
    Set cmd.ActiveConnection = conn
    cmd.Parameters.Append cmd.CreateParameter("id", 200, 1, 16, id)
    Set rs = cmd.Execute
    ' ...
End Sub

' Parameterized update: ? placeholder, no concatenation.
Sub UpdateBalance(conn, amt)
    Dim cmd
    Set cmd = CreateObject("ADODB.Command")
    cmd.CommandText = "UPDATE accounts SET balance = ? WHERE id = ?"
    Set cmd.ActiveConnection = conn
    cmd.Parameters.Append cmd.CreateParameter("amt", 200, 1, 16, amt)
    cmd.Parameters.Append cmd.CreateParameter("id", 200, 1, 16, 1)
    cmd.Execute
End Sub

' Static SQL literal (no concatenation) and static command line (no splice).
Sub DeleteSession(conn, sid)
    Dim cmd
    Set cmd = CreateObject("ADODB.Command")
    cmd.CommandText = "DELETE FROM sessions WHERE sid = ?"
    Set cmd.ActiveConnection = conn
    cmd.Parameters.Append cmd.CreateParameter("sid", 200, 1, 16, sid)
    cmd.Execute
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.Run "cmd.exe /c cls", 0, True
End Sub

' Static command string fed to WScript.Shell Exec, no input splice.
Sub ListDir(dir)
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.Exec "cmd.exe /c dir C:\"
End Sub
