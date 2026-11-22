package psparse

func init() {
	revExtraLines = append(revExtraLines,
		`$h = @{ a = Remove-Item C:\x }`, `$h = @{ a = Get-Item x | Remove-Item }`,
		`$r = (Remove-Item C:\x -f)`, `$r = (Get-ChildItem C:\x -in y)`, `$r = (Copy-Item a b * c)`, `$r = $(Copy-Item a -join b)`,
		`function f { param($a = (Remove-Item C:\x)) }`, `Microsoft.PowerShell.Utility\Invoke-Expression 'Remove-Item C:\x'`,
		`-Value $env:CONTENT`, "$x = 1\nRemove-Item C:\\x",
	)
}
