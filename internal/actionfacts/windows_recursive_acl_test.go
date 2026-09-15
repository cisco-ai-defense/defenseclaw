// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestExactWindowsRecursiveEveryoneFullControl(t *testing.T) {
	tests := []struct {
		name    string
		command string
		dialect Dialect
		want    bool
	}{
		{"PowerShell quoted target", `icacls 'C:\inetpub\wwwroot\intranet' /grant 'Everyone:(OI)(CI)F' /T`, DialectPowerShell, true},
		{"CMD option order", `icacls.exe C:\inetpub\wwwroot /T /Q /grant:r "Everyone:(CI)(OI)F"`, DialectCMD, true},
		{"nonrecursive", `icacls C:\inetpub\wwwroot /grant "Everyone:(OI)(CI)F"`, DialectCMD, false},
		{"read only", `icacls C:\inetpub\wwwroot /grant "Everyone:(OI)(CI)R" /T`, DialectCMD, false},
		{"inheritance only", `icacls C:\inetpub\wwwroot /grant "Everyone:(OI)(CI)(IO)F" /T`, DialectCMD, false},
		{"no inheritable ACE", `icacls C:\inetpub\wwwroot /grant Everyone:F /T`, DialectCMD, false},
		{"specific principal", `icacls C:\inetpub\wwwroot /grant "Administrators:(OI)(CI)F" /T`, DialectCMD, false},
		{"documentation text", `echo icacls C:\inetpub\wwwroot /grant "Everyone:(OI)(CI)F" /T`, DialectCMD, false},
		{"conditional", `if exist C:\inetpub icacls C:\inetpub /grant "Everyone:(OI)(CI)F" /T`, DialectCMD, false},
		{"unknown option", `icacls C:\inetpub /grant "Everyone:(OI)(CI)F" /T /save acl.txt`, DialectCMD, false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "shell", Command: test.command, DialectHint: test.dialect})
			if got := ExactWindowsRecursiveEveryoneFullControl(facts); got != test.want {
				t.Fatalf("proof=%t want=%t facts=%+v", got, test.want, facts)
			}
		})
	}
}

func TestExactWindowsRecursiveEveryoneFullControlStructuredArgv(t *testing.T) {
	facts := Analyze(Input{
		Tool:        "exec",
		Argv:        []string{"icacls.exe", `C:\inetpub\wwwroot\intranet`, "/grant", "Everyone:(OI)(CI)F", "/T"},
		DialectHint: DialectCMD,
	})
	if !ExactWindowsRecursiveEveryoneFullControl(facts) {
		t.Fatalf("structured argv proof missing: %+v", facts)
	}
}
