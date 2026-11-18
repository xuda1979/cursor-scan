Option Explicit

' Classic ASP / VBScript injection samples.
'
' 1. &-concatenated query string fed to an ADODB connection Execute.
Sub RunQuery(conn, id)
    Dim rs
    Set rs = conn.Execute("SELECT * FROM users WHERE id = " & id)
    ' ...
End Sub

' 2. Concatenated UPDATE built inline and fed to conn.Execute.
Sub UpdateBalance(conn, amt)
    conn.Execute "UPDATE accounts SET balance = " & amt
End Sub

' 3. .CommandText assignment in a concat build (ADO).
Sub DropRow(conn, uid)
    Dim cmd
    Set cmd = CreateObject("ADODB.Command")
    cmd.CommandText = "DELETE FROM orders WHERE uid = " & uid
    Set cmd.ActiveConnection = conn
    cmd.Execute
End Sub

' 4. Assignment build: query assembled into a variable first, used later.
Sub DeleteSession(conn, sid)
    Dim sql
    sql = "DELETE FROM sessions WHERE sid = " & sid
    conn.Execute sql
End Sub

' 5. concat command string fed to WScript.Shell Run (hidden shell launch).
Sub ListDir(dir)
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.Run "cmd.exe /c dir " & dir, 0, False
End Sub

' 6. &-interpolated command fed to WScript.Shell Exec.
Sub ExecHost(host)
    Dim sh
    Set sh = CreateObject("WScript.Shell")
    sh.Exec "ping -n 1 " & host
End Sub

' 7. Classic-ASP Shell() helper with a concatenated command line.
Sub NetSession(sid)
    Shell "net session " & sid
End Sub
