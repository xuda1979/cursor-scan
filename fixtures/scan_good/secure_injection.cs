// Injection-safe C# patterns — must produce zero findings.
using System.Data.SqlClient;
using System.Diagnostics;

class SafeQueries
{
    public void GetById(SqlConnection conn, int id)
    {
        // @parameter placeholder: no string concatenation.
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
    }

    public void OpenEditor()
    {
        // Static command line: no dynamic arguments.
        Process.Start("notepad.exe");
    }

    public void CopyFile(string src, string dst)
    {
        // Static command line, no concatenation into the shell.
        var psi = new ProcessStartInfo("cp", "a.txt", "b.txt");
        Process.Start(psi);
    }
}
