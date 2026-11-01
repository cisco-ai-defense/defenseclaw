// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

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
