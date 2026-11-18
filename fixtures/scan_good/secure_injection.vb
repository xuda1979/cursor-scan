' Injection-safe VB.NET patterns — must produce zero findings.
Imports System.Data.SqlClient
Imports System.Diagnostics

Module SafeQueries
    Sub GetById(conn As SqlConnection, id As Integer)
        ' @parameter placeholder: no string concatenation.
        Dim cmd As New SqlCommand("SELECT * FROM Users WHERE Id = @id", conn)
        cmd.Parameters.AddWithValue("@id", id)
    End Sub

    Sub GetByName(conn As SqlConnection, name As String)
        ' Bind-parameter query: no `&` splicing into SQL.
        Dim q As String = "SELECT * FROM Users WHERE Name = @name"
        Dim cmd As New SqlCommand(q, conn)
        cmd.Parameters.Add("@name", SqlDbType.NVarChar, 64).Value = name
    End Sub

    Sub OpenEditor()
        ' Static command line: no dynamic arguments.
        Process.Start("notepad.exe")
    End Sub

    Sub CopyFile(src As String, dst As String)
        ' Static command line, no concatenation into the shell.
        Dim psi As New ProcessStartInfo("cp")
        psi.ArgumentList.Add(src)
        psi.ArgumentList.Add(dst)
        Process.Start(psi)
    End Sub

    Sub CheckPath()
        ' Static two-argument command line stays quiet (no concatenation).
        Process.Start("cmd.exe", "/c type nul")
    End Sub
End Module
