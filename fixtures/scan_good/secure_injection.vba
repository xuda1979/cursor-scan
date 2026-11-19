' Injection-safe VBA patterns — must produce zero findings.
Option Explicit

Sub SafeQueries()
    Dim qdf As DAO.QueryDef

    ' Parameterized query: placeholder '?' plus bound parameter.
    Set qdf = db.CreateQueryDef("qryById", "SELECT * FROM Users WHERE Id = ?")
    qdf.Parameters(0).Value = id
    qdf.Execute

    ' Named @parameter through a QueryDef.
    Set qdf = db.CreateQueryDef("qryByName", "SELECT * FROM Users WHERE Name = @name")
    qdf.Parameters("@name").Value = name

    ' Static command text: no concatenation, no user input.
    DoCmd.RunSQL "SELECT COUNT(*) FROM t"
    db.Execute "UPDATE t SET x=1"
    cmd.CommandText = "SELECT * FROM Users WHERE Id = ?"
End Sub

Sub SafeShell()
    ' Static command line: fixed argument list, no concatenation.
    Shell "ping -n 1 127.0.0.1", vbHide

    ' Static command through WshShell: fixed text, no dynamic splicing.
    WshShell.Run "date"

    ' Variable-only command (no string literal fragment): not a concat finding.
    Shell cmd

    ' Non-shell string concatenation stays quiet.
    MsgBox "Hello " & name
End Sub

Sub SetupShell()
    Set WshShell = CreateObject("WScript.Shell")
End Sub
