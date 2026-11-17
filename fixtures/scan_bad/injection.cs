// Deliberately unsafe C# SQL string concatenation and shell execution
// (CWE-89 / CWE-78): user-controlled values are spliced into query strings
// via `+` concatenation or $"-interpolated templates, and processes are
// launched with concatenated / interpolated arguments, instead of @parameter
// placeholders / static command lines.

using System;
using System.Data.SqlClient;
using System.Diagnostics;

class UnsafeQueries
{
    public void FindUser(SqlConnection conn, string userId)
    {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = " + userId, conn);
        cmd.ExecuteReader();
    }

    public void TouchRow(SqlCommand cmd, string val)
    {
        cmd.CommandText = "UPDATE logs SET status = 'ok' WHERE id = " + val;
    }

    public void QueryByTemplate(SqlCommand cmd, string owner)
    {
        cmd.CommandText = $"SELECT id FROM accounts WHERE owner = '{owner}'";
    }

    public void WipeDir(string path)
    {
        Process.Start("rm", "-rf " + path);
    }

    public void RunSh(string command)
    {
        var psi = new ProcessStartInfo("sh", "-c " + command);
        Process.Start(psi);
    }

    public void CurlUrl(string url)
    {
        var p = new Process { StartInfo = new ProcessStartInfo("curl", url + " -L") };
        p.Start();
    }

    // NOT findings: @parameter placeholders and static command lines.
    public void SafeQuery(SqlConnection conn, int id)
    {
        var cmd = new SqlCommand("SELECT * FROM Users WHERE Id = @id", conn);
        cmd.Parameters.AddWithValue("@id", id);
        Process.Start("notepad.exe");
    }
}
