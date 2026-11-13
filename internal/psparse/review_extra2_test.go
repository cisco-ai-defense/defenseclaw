package psparse

func init() {
	revExtraLines = append(revExtraLines,
		`Write-Output %#; Remove-Item C:\x`, `Write-Output *#; Remove-Item C:\x`, `Write-Output 'a'#; Remove-Item C:\x`,
		`Write-Output $x#; Remove-Item C:\x`, `Write-Output (1)#; Remove-Item C:\x`, `Write-Output =#; Remove-Item C:\x`,
		`Write-Output !#; Remove-Item C:\x`, `Write-Output -#; Remove-Item C:\x`,
		`Remove-Item <#c#> C:\Windows -Recurse`, `Remove-Item . -Recurse -Force`, `Remove-Item :x -Force`,
		`Write-Output a<#c#> Remove-Item C:\x`, `Remove-Item C:\x -Recurse:$true`, `Remove-Item -Recurse: $false C:\x`,
		`Write-Output a|Remove-Item C:\x`, `Remove-Item C:\x;Remove-Item C:\y`, `Remove-Item C:\x&&Remove-Item C:\y`,
		`Remove-Item C:\x &`, `cmd /c "a" & Remove-Item C:\y`, `Remove-Item C:\x§
-Recurse`, `Remove-Item C:\x § 
-Recurse`, `Remove-Item -Path ([IO.Path]::Combine('C:\', 'x'))`,
		`Remove-Item @('C:\x')`, `Remove-Item $('C:\x')`, `Remove-Item ('C:\x')`, `Remove-Item "C:\x"`, `Remove-Item C:\x\`,
		`Remove-Item C:\x\'`, `Remove-Item 'C:\x'\y`, `Remove-Item "C:\x"\y`, `Remove-Item -Path 'C:\a' -Path 'C:\b'`,
	)
}
