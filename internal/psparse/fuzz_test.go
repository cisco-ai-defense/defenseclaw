// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"testing"
)

// seed inputs exercising every grammar feature the parser claims to cover.
var fuzzSeeds = []string{
	`Get-Content -Path 'C:\a.txt' -Raw`,
	`gc a.txt | % { iex $_ }`,
	`& "C:\Program Files\app.exe" --flag arg`,
	`. .\script.ps1 -Verbose`,
	`powershell -EncodedCommand ZQBjAGgAbwAgAGgAaQA=`,
	`pwsh -Command "Get-Date; Write-Host done"`,
	"$x = @{ Path = 'a'; Force = $true }; New-Item @x",
	"@'" + "\nliteral $notvar\n" + "'@",
	"@\"" + "\nexpand $var and $(Get-Date)\n" + "\"@",
	`Invoke-Expression ([scriptblock]::Create('whoami'))`,
	`Start-Process powershell -ArgumentList '-NoProfile','-Command','ls'`,
	`cmd /c "dir & echo hi"`,
	"if ($true) { Remove-Item x } elseif ($false) { } else { Get-Item y }",
	"foreach ($f in Get-ChildItem) { $f.Name }",
	"try { risky } catch [IOException] { log } finally { cleanup }",
	`$a -eq $b -and ($c -lt 5)`,
	"Get-Thing -Name:Value -Switch",
	"echo a,b,c",
	`$env:PATH; ${global:x}; $using:y`,
	"1kb + 0x1F * 2",
	"ls `\n  -Recurse",
	"# comment\n<# block #> Get-Date",
	`findstr /c:"x" file.txt 2>&1 > out.txt`,
	`netsh advfirewall --% set allprofiles state off`,
	"function Foo($a) { return $a + 1 }",
	`[System.IO.File]::ReadAllText("x")`,
	"switch ($v) { 'a' { 1 } default { 2 } }",
}

// TestParseNoPanic parses the seeds and asserts the parser and projector never
// panic and always return a usable Script.
func TestParseNoPanic(t *testing.T) {
	for _, s := range fuzzSeeds {
		sc, err := Parse(s, Options{})
		if err != nil {
			t.Fatalf("unexpected err: %v (input %q)", err, s)
		}
		if sc == nil {
			t.Fatalf("nil script for %q", s)
		}
		_ = Project(sc)
	}
}

// TestParseStability checks that re-lexing the raw source of a parse is stable:
// parsing twice yields the same projection length (a cheap determinism check).
func TestParseStability(t *testing.T) {
	for _, s := range fuzzSeeds {
		a := Project(mustParse(s, DialectPwsh7))
		b := Project(mustParse(s, DialectPwsh7))
		if len(a) != len(b) {
			t.Fatalf("non-deterministic projection for %q: %d vs %d", s, len(a), len(b))
		}
	}
}

// FuzzParse ensures arbitrary input never panics and that recursion/size
// guards keep work bounded. When PSPARSE_ORACLE is set the differential test
// provides the semantic comparison; here we only assert robustness.
func FuzzParse(f *testing.F) {
	for _, s := range fuzzSeeds {
		f.Add(s)
	}
	f.Add(strings.Repeat("$(", 5000))
	f.Add(strings.Repeat("@{", 5000))
	f.Add(strings.Repeat("& ", 5000) + "x")
	f.Add(strings.Repeat("'a", 5000))
	f.Fuzz(func(t *testing.T, s string) {
		sc, err := Parse(s, Options{})
		if err != nil {
			t.Fatalf("Parse returned err (should never): %v", err)
		}
		if sc == nil {
			t.Fatal("nil script")
		}
		_ = Project(sc)
	})
}
