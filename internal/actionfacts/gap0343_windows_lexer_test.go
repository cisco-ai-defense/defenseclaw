// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// A balanced PowerShell value is opaque, but it cannot hide the next
// statement from the Windows reading (rel-1-0-6:GAP-0343).
func TestGAP0343PowerShellBalancedValuesLeaveFollowingStatementsVisible(t *testing.T) {
	const tail = `Remove-Item -Recurse -Force C:\`
	for _, tc := range []struct {
		name, prefix string
	}{
		{"subexpression", `$x = $(Get-Date); `},
		{"nested subexpression", `$x = $(Write-Output "a ) ; Remove-Item C:\decoy"; @(1, 2)); `},
		{"stop-parsing lookalike in subexpression", `$x = $(Write-Output --%abc); `},
		{"interpolated nested subexpression", `$x = $(Write-Output "$(Write-Output 'inner )')"); `},
		{"array", `$a = @(1, @(2, 3)); `},
		{"array with block comment", `$a = @(<# ) ; Remove-Item C:\decoy #> 1); `},
		{"array with line comment after comma", "$a = @(1,# ) ; Remove-Item C:\\decoy\n 2); "},
		{"hashtable", `$h = @{ a = "Remove-Item C:\decoy; }"; b = @(1, 2) }; `},
		{"hashtable with line comment", "$h = @{ a = 1 # } ; Remove-Item C:\\decoy\n b = 2 }; "},
		{"braced variable", `${x} = 1; `},
		{"single here-string", "$t = @'\nRemove-Item C:\\decoy\n'@\n"},
		{"double here-string", "$t = @\"\nRemove-Item C:\\decoy\n\"@\n"},
		{"stop parsing next line", "curl.exe --% ; Remove-Item C:\\decoy\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := parsePowerShell(tc.prefix+tail, 1, 0)
			if !hasExecutable(out.commands, "remove-item") {
				t.Fatalf("following command missing: %#v", out.commands)
			}
			if out.status == StatusComplete {
				t.Fatalf("opaque value became authoritative: %#v", out)
			}
			withoutTail := parsePowerShell(tc.prefix+"Write-Output done", 1, 0)
			if hasExecutable(withoutTail.commands, "remove-item") {
				t.Fatalf("inert content became a command: %#v", withoutTail.commands)
			}
		})
	}
}

func TestGAP0343UnbalancedValueDoesNotMintCommands(t *testing.T) {
	for _, source := range []string{
		`$x = $(Write-Output "unfinished; Remove-Item -Recurse -Force C:\`,
		`$a = @(1, 2; Remove-Item -Recurse -Force C:\`,
		"$t = @'\nRemove-Item -Recurse -Force C:\\\n",
	} {
		out := parsePowerShell(source, 1, 0)
		if hasExecutable(out.commands, "remove-item") {
			t.Errorf("unbalanced value minted a command: %q: %#v", source, out.commands)
		}
	}
}

func TestGAP0343SimpleCommandFastPathKeepsBudgetAndSideEffects(t *testing.T) {
	for _, tc := range []struct {
		command        string
		assign, output bool
	}{
		{`$h = @{ a = 1; b = 'x;y' }; Write-Output ok`, true, true},
		{`$x = $(Get-Date); Write-Output 1`, true, true},
		{`$h = @{ a = 1 } > C:\notes.txt; Write-Output ok`, false, true},
		{`$x = @(1); Write-Output $(Get-Date)`, true, false},
	} {
		input := Input{Tool: "PowerShell", Command: tc.command, DialectHint: DialectPowerShell}
		got := SimpleCommands(input, Analyze(input))
		if len(got) != 2 || got[0].OpaqueValueAssignment != tc.assign || got[1].LiteralOutputOnly != tc.output {
			t.Errorf("%q: %#v", tc.command, got)
		}
	}
	long := strings.TrimSuffix(strings.Repeat(`$h = @{ a = 1 }; `, 129), "; ")
	if !PowerShellStatementsOverBudget(long) {
		t.Fatal("opaque assignments escaped statement budget")
	}
}

func TestGAP0343PowerShellCommentAndStopParsingTokenBoundaries(t *testing.T) {
	const tail = `Remove-Item -Recurse -Force C:\`
	for _, row := range []struct{ name, prefix string }{
		{"mixed double quote", `Write-Output a"b"#; `},
		{"mixed single quote", `Write-Output a'b'#; `},
		{"right bracket", `Write-Output a]#; `},
		{"left bracket", `Write-Output a[#; `},
		{"type name", `Write-Output [int]#; `},
		{"format", `git log -1 --format="%h"#; `},
		{"path", `Get-ChildItem .\a[1]#; `},
		{"call target", `& $x=#; `},
		{"glued call target", `&$x=#; `},
		{"variable argument", `Write-Output $x=#; `},
		{"glued block opener", `Write-Output a"b"<#x#>; `},
		{"bracket block opener", `Write-Output a]<#x#>; `},
		{"quoted only block comment", `Write-Output "a"<#x#>; `},
		{"equals stop parsing lookalike", `cmd /c echo a=--% ; `},
		{"comma stop parsing lookalike", `cmd /c echo a,--% ; `},
		{"stop parsing chain", `cmd.exe /c echo --% a && `},
		{"stop parsing or chain", `cmd.exe /c echo --% a || `},
		{"stop parsing pipe", `cmd.exe /c echo --% a | `},
		{"stop parsing glued pipe", `cmd.exe /c echo --% a|`},
		{"quoted pipe in stop parsing argument", `cmd.exe /c echo --% "a | b" | `},
		{"quoted chain in stop parsing argument", `cmd.exe /c echo --% "a && b" && `},
		{"mixed quote inside array command", `$x = @(Write-Output a"b"#; Write-Output ok); `},
		{"bracket inside array command", `$x = @(Write-Output a]#; Write-Output ok); `},
		{"block marker inside array command", `$x = @(Write-Output a"b"<#x#>; Write-Output ok); `},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := row.prefix + tail
			out := parsePowerShell(command, 1, 0)
			if !hasExecutable(out.commands, "remove-item") {
				t.Fatalf("destructive command hidden: status=%s commands=%#v", out.status, out.commands)
			}
			if count, _ := powerShellStatements(command, 128); count < 2 {
				t.Fatalf("budget scanner counted %d statements, want at least 2", count)
			}
			input := Input{Tool: "PowerShell", Command: command, DialectHint: DialectPowerShell}
			var splitTail bool
			for _, simple := range SimpleCommands(input, Analyze(input)) {
				if strings.Contains(simple.Text, "Remove-Item") {
					splitTail = true
				}
			}
			if !splitTail {
				t.Fatal("simple-command splitter hid the destructive tail")
			}
		})
	}
	for _, row := range []struct {
		name, source string
		index        int
		expression   bool
		want         bool
	}{
		{"quoted only", `'a'#`, 3, false, true},
		{"quoted segment", `a'b'#`, 4, false, false},
		{"bracket argument", `a]#`, 2, false, false},
		{"bracket expression", `a]#`, 2, true, true},
		{"assignment target", `$x=#`, 3, false, true},
		{"call target", `& $x=#`, 5, false, false},
		{"argument target", `Write-Output $x=#`, 16, false, false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := windowsPowerShellCommentStarts([]rune(row.source), row.index, row.expression); got != row.want {
				t.Fatalf("comment start=%t, want %t", got, row.want)
			}
		})
	}
	for _, row := range []struct{ name, prefix string }{
		{"semicolon stays in stop parsing span", `cmd.exe /c echo --% a ; `},
		{"single ampersand stays in stop parsing span", `cmd.exe /c echo --% a & `},
		{"quoted ampersands stay in stop parsing span", `cmd.exe /c echo --% "a && b" ; `},
		{"dynamic call keeps single ampersand in stop parsing span", `& cmd.exe --% a & `},
		{"quoted-only block comment keeps its text inert", `Write-Output "a"<#; Remove-Item -Recurse -Force C:\ #> # `},
	} {
		t.Run(row.name, func(t *testing.T) {
			command := row.prefix + tail
			out := parsePowerShell(command, 1, 0)
			if hasExecutable(out.commands, "remove-item") {
				t.Fatalf("stop parsing span ended early: %#v", out.commands)
			}
			if count, _ := powerShellStatements(command, 128); count != 1 {
				t.Fatalf("budget scanner counted %d statements, want 1", count)
			}
		})
	}
}
