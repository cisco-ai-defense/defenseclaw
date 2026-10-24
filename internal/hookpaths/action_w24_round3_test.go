// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// W24 loop round 3 (balanced defaults): a foreach collection in
// parentheses, $( ), @( ) or with a property after it is judged like the
// bare collection, and so is the scriptblock of a ForEach-Object or
// Where-Object stage. A listing command lists; a copy source is not a
// destination. Any other collection keeps the strict spelling.
func TestW24ParenthesizedForeachCollectionsAreJudged(t *testing.T) {
	w24WindowsRows(t, []w24Row{
		{`foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f out }`, false},
		{`foreach ($f in $(Get-ChildItem *.txt)) { Copy-Item $f out }`, false},
		{`foreach ($f in @(Get-ChildItem -Filter *.txt)) { Copy-Item $f out }`, false},
		{`foreach ($f in ((gci *.txt))) { Copy-Item $f out }`, false},
		{`foreach ($f in (Get-ChildItem *.txt).FullName) { Copy-Item -Path $f -Destination out\ }`, false},
		{`foreach ($f in ( Get-ChildItem -Recurse src )) { Move-Item $f archive\ }`, false},
		{`foreach ($f in ('regular.txt', 'report.txt')) { Copy-Item $f copy }`, false},
		{`foreach ($f in @('a.txt','b.txt')) { Copy-Item $f copy }`, false},
		{`foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f out }; Write-Output done`, false},
		{`foreach ($f in (Get-ChildItem 'a (1).txt')) { Copy-Item $f out }`, false},
		{`if ($true) { foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f out } }`, false},
		{`foreach ($f in(Get-ChildItem *.txt)) { Copy-Item $f out }`, false},
		{`Get-ChildItem *.txt | ForEach-Object { Copy-Item $_ out }`, false},
		{`gci *.txt | foreach { Copy-Item $_.FullName out\ }`, false},
		{`Get-ChildItem *.txt | ForEach-Object -Process { Copy-Item -Path $_ -Destination out }`, false},
		{`Get-ChildItem *.txt | Where-Object { $_.Length -gt 0 } | ForEach-Object { Copy-Item $_ out }`, false},
		{`Get-ChildItem *.txt | ForEach-Object { Set-Content $_ x }`, true},
		{`Get-ChildItem *.txt | ForEach-Object { Copy-Item $_ C:\Users\alice\.ssh\authorized_keys }`, true},
		{`gci *.txt | % { Add-Content -Path $env:USERPROFILE\.ssh\authorized_keys -Value $_ }`, true},
		{`Get-ChildItem *.txt | ForEach-Object -Begin { $n = 0 } -Process { Copy-Item $_ $d }`, true},
		{`foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f $dest }`, true},
		{`foreach ($f in (Get-ChildItem *.txt)) { Copy-Item $f C:\Users\alice\.ssh\authorized_keys }`, true},
		{`foreach ($f in (Get-ChildItem *.txt)) { Set-Content $f x }`, true},
		{`foreach ($f in (Get-ChildItem C:\Users\alice\.ssh)) { Copy-Item $f out }`, true},
		{`foreach ($f in @('C:\Users\alice\.ssh\authorized_keys')) { Add-Content $f key }`, true},
		{`foreach ($f in (Invoke-Expression $c)) { Copy-Item $f out }`, true},
		{`foreach ($f in (Get-ChildItem *.txt | ForEach-Object { $_ })) { Copy-Item $f out }`, true},
		{`foreach ($f in (Get-ChildItem $d)) { Copy-Item $f out }`, true},
		{`foreach ($f in (Get-ChildItem *.txt).CopyTo($d)) { Write-Output $f }`, true},
	})
}

// W24 loop round 3 (balanced defaults): an unread script or launcher counts
// as SSH persistence only with a path that names the .ssh directory, its 8.3
// alias or a key file in a directory. A key or .ssh name inside a longer
// word (-Case id_rsa-smoke) is data.
func TestW24ArgumentTextIsNotProtectedEvidence(t *testing.T) {
	w24POSIXRows(t, []w24Row{
		{`bash run.sh --case id_rsa-smoke`, false},
		{`./run.sh authorized_keys-report`, false},
		{`python3 scripts/gen.py --name id_ed25519_test`, false},
		{`bash run.sh --label notes.ssh-config`, false},
		{`bash run.sh --suite=ssh~notes`, false},
		{`bash run.sh id_rsa`, false},
		{`bash run.sh "$KEYDIR/id_rsa"`, true},
		{`bash run.sh --out=$HOME/.ssh/config`, true},
		{`bash run.sh ~/.ssh`, true},
		{`bash run.sh "$D/.SSH/x"`, true},
	})
	w24WindowsRows(t, []w24Row{
		{`pwsh -File .\build.ps1 -Case id_rsa-smoke`, false},
		{`.\check.ps1 -Case authorized_keys-missing -Source native`, false},
		{`& .\build.ps1 -Label my.sshconfig`, false},
		{`cmd /c build.bat id_ed25519_rotation`, false},
		{`pwsh -File .\build.ps1 -Case .ssh-check`, false},
		{`.\x.ps1 -Name id_rsa`, false},
		{`pwsh -EncodedCommand ` + w24EncodedPowerShell(`.\build.ps1 -Case id_rsa-smoke`), false},
		{`pwsh -File .\x.ps1 -Key "$keys\id_rsa"`, true},
		{`pwsh -File .\x.ps1 -Out C:\Users\alice\SSH~1\authorized_keys`, true},
		{`pwsh -File .\x.ps1 -Target:$env:USERPROFILE\.ssh`, true},
		{`.\x.ps1 -Path "$env:USERPROFILE/.SSH/id_ed25519"`, true},
		{`pwsh -EncodedCommand ` + w24EncodedPowerShell(`.\x.ps1 -Key "$keys\authorized_keys"`), true},
	})
}
