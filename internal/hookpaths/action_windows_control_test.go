// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "testing"

// A PowerShell control body is judged statement by statement. A literal
// header and the braces run nothing; a write in a body, or a header that can
// run a command, keeps its decision.
func TestActionWindowsControlBodies(t *testing.T) {
	const cwd, home = `C:\Users\alice\project`, `C:\Users\alice`
	for _, tc := range []struct {
		name, command string
		refused       bool
	}{
		{"if block", `if ($true) { Write-Output a }`, false},
		{"if else", `if ($true) { Write-Output a } else { Write-Output b }`, false},
		{"elseif without spaces", `if($false){Write-Output a}elseif($true){Get-ChildItem}`, false},
		{"foreach literal list", `foreach ($x in 'a','b') { Write-Output $x }`, false},
		{"while block", `while ($false) { Get-ChildItem }`, false},
		{"do while", `do { Write-Output a } while ($false)`, false},
		{"try catch finally", `try { Write-Output a } catch { Write-Output b } finally { Write-Output c }`, false},
		{"multiline if", "if ($true)\n{\n  Write-Output a\n}\nWrite-Output b", false},
		{"if then statement", `if ($true) { Write-Output a }; Get-ChildItem`, false},
		{"protected write in body", `if ($true) { Set-Content C:\Users\alice\.ssh\authorized_keys k }`, true},
		{"dynamic write target in body", `if ($true) { Set-Content $p k }`, true},
		{"protected write after quoted brace", `if ($true) { Write-Output '}'; Set-Content C:\Users\alice\.ssh\authorized_keys k }`, true},
		{"protected write through braced variable", `if ($true) { Set-Content ${env:USERPROFILE}\.ssh\authorized_keys k }`, true},
		{"protected write in do body", `do { Set-Content C:\Users\alice\.ssh\authorized_keys k } while ($false)`, true},
		{"protected write in else body", `if ($false) { Write-Output a } else { Set-Content C:\Users\alice\.ssh\authorized_keys k }`, true},
		{"command in header", `if (Set-Content C:\Users\alice\.ssh\authorized_keys k) { Write-Output a }`, true},
		{"assignment in header", `if ($p = Set-Content C:\Users\alice\.ssh\authorized_keys k) { Write-Output a }`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := ActionCommandDecision(tc.command, cwd, home)
			if (got != "") != tc.refused {
				t.Fatalf("ActionCommandDecision(%q) = %q, want refused=%v", tc.command, got, tc.refused)
			}
		})
	}
}
