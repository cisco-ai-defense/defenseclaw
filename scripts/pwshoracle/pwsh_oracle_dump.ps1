param(
  [Parameter(Mandatory=$true)][string]$InFile,
  [Parameter(Mandatory=$true)][string]$OutFile
)
# Batch driver for the PwshOracle dumper. InFile: one base64 (UTF-8) script per line.
# OutFile: one JSON object per line (see PwshOracle.cs). Works in pwsh 7 and
# Windows PowerShell 5.1.
$ErrorActionPreference = 'Stop'
$src = Join-Path $PSScriptRoot 'PwshOracle.cs'
$refs = @([System.Management.Automation.PSObject].Assembly.Location)
if ($PSVersionTable.PSEdition -eq 'Core') { $refs += 'System.Collections'; $refs += 'System.Runtime' }
Add-Type -TypeDefinition ([System.IO.File]::ReadAllText($src)) -ReferencedAssemblies $refs
$enc = New-Object System.Text.UTF8Encoding($false)
$w = New-Object System.IO.StreamWriter($OutFile, $false, $enc)
$i = 0
foreach ($line in [System.IO.File]::ReadLines($InFile)) {
  if ($line.Length -eq 0) { $w.Write('{"i":' + $i + ',"ast":[],"tok":[],"err":[],"empty":true}' + "`n"); $i++; continue }
  $text = $enc.GetString([System.Convert]::FromBase64String($line))
  try { $w.Write([PwshOracle]::Dump($i, $text) + "`n") }
  catch { $w.Write('{"i":' + $i + ',"crash":' + (ConvertTo-Json -InputObject $_.Exception.ToString().Substring(0, [Math]::Min(400, $_.Exception.ToString().Length)) -Compress) + '}' + "`n") }
  $i++
}
$w.Close()
$ver = $PSVersionTable.PSVersion.ToString()
[System.IO.File]::WriteAllText($OutFile + '.version', $ver)
