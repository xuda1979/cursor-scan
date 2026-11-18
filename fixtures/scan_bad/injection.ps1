# Bad PowerShell: runtime input interpolated/concatenated into SQL or commands.
param(
    [string]$ServerName,
    [string]$UserName,
    [string]$Token
)

# --- SQL injection: Invoke-Sqlcmd with $var interpolation ---
$name = $UserName
Invoke-Sqlcmd -ServerInstance $ServerName -Database "app" -Query "SELECT * FROM users WHERE name = $name"

$id = Get-Random
Invoke-Sqlcmd -Query "SELECT * FROM accounts WHERE id = $id" -ServerInstance $ServerName

Invoke-Sqlcmd -Query "SELECT * FROM orders WHERE uid = $(Get-UserParam)" -ServerInstance $ServerName

# --- SQL injection: Invoke-Sqlcmd with + concatenation ---
$cols = "app_id"
Invoke-Sqlcmd -Query "SELECT " + $cols + " FROM t" -ServerInstance $ServerName

Invoke-Sqlcmd -Query "DELETE FROM sessions WHERE token = " + $Token -ServerInstance $ServerName

# --- SQL injection: Invoke-DbaQuery ---
Import-Module dbatools
Invoke-DbaQuery -SqlInstance $ServerName -Query "UPDATE accounts SET balance = balance + $amount"

Invoke-DbaQuery -SqlInstance $ServerName -Query "DROP TABLE " + $tableName

# --- SQL injection: Invoke-DbaCmd with interpolated command ---
Invoke-DbaCmd -SqlInstance $ServerName -Command "SELECT * FROM logs WHERE level = $level"

# --- Shell injection: Invoke-Expression with interpolated command ---
$target = $args[0]
Invoke-Expression "Remove-Item $target -Recurse -Force"

$file = $env:USERPROFILE
iex "Get-Content $file | Out-String"

$proc = $ProcessName
Invoke-Expression "Get-Process $($proc) | Stop-Process -Force"

iex "Copy-Item " + $src + " " + $dst

# --- Assignment-detection form: query built earlier then executed later ---
$query = "SELECT * FROM users WHERE email = " + $Email
Invoke-Sqlcmd -Query $query -ServerInstance $ServerName

# Extra file so line-count expectations stay stable
$extra = 1
