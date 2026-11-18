# Good PowerShell: parameterized queries, static literals, safe invocation.
param(
    [string]$ServerName,
    [string]$UserName
)

# Parameterized: @name placeholder with Add-SqlParameter binding.
$q = "SELECT * FROM users WHERE name = @name AND active = @active"
Invoke-Command -ComputerName $ServerName -ScriptBlock {
    $p = @{ name = $using:UserName }
    Invoke-Sqlcmd -ServerInstance $ServerName -Query $q
}
Invoke-Sqlcmd -ServerInstance $ServerName -Query "SELECT * FROM users WHERE name = @name"

# Static SQL without interpolation.
Invoke-Sqlcmd -ServerInstance $ServerName -Query "SELECT COUNT(*) FROM accounts"

# Single-quoted string: no PowerShell interpolation of $var.
Invoke-Sqlcmd -Query 'SELECT * FROM users WHERE name = $UserName'

# DbaQuery with parameter placeholders.
Invoke-DbaQuery -SqlInstance $ServerName -Query "UPDATE accounts SET balance = balance + @amount" `
    -Parameter @{ amount = $Amount }

# Safe command invocation: array argument splatting, direct call operator.
$args = @("ls", "/tmp")
& "C:\Windows\System32\whoami.exe" | Out-String
Get-Content -Path (Join-Path $Env:TEMP "data.txt")
Start-Process -FilePath "notepad.exe" -ArgumentList @("-p", $Path)
Invoke-Sqlcmd -ServerInstance $ServerName -Query @'
SELECT * FROM logs WHERE ts > @since
'@

# Extra file so line-count expectations stay stable
$ok = $true
