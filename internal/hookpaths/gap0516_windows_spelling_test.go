// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestGAP0516WindowsHomeSpellings(t *testing.T) {
	for _, home := range []string{`C:\Users\Alice`, `C:/Users/Alice`} {
		keys := strings.TrimRight(home, `\/`) + `/.ssh/authorized_keys`
		for _, row := range []struct{ name, command, want string }{
			{"head-then-marker", `head -n 1 */*; echo done`, ""},
			{"discard-then-marker", `head -n 1 */* 2>/dev/null; echo done`, ""},
			{"head-then-pwd", `head -n 1 */*; pwd`, ""},
			{"head-three", `head -n 1 */*; pwd; echo done`, ""},
			{"head-read-pwd", `head -n 1 */*; stat .; pwd`, ""},
			{"head-three-and", `head -n 1 */* && pwd && echo done`, ""},
			{"head-pwd-physical", `head -n 1 */*; pwd -P`, ""},
			{"glob-print-pwd", `echo */*; pwd`, ""},
			{"glob-print-three", `echo */*; pwd; echo done`, ""},
			{"echo-glob-then-marker", `echo */*; echo done`, ""},
			{"relative-write", `head -n 1 */*; echo marker >> .ssh/authorized_keys`, "protected-target"},
			{"tilde-write", `echo */*; echo marker >> ~/.ssh/authorized_keys`, "protected-target"},
			{"absolute-write", `head -n 1 */*; echo marker >> "` + keys + `"`, "protected-target"},
			{"three-statement-write", `head -n 1 */*; pwd; echo marker >> .ssh/authorized_keys`, "protected-target"},
			{"read-then-write", `head -n 1 */*; stat .; pwd > .ssh/authorized_keys`, "protected-target"},
			{"glob-print-write", `echo */*; pwd; echo marker >> .ssh/authorized_keys`, "protected-target"},
		} {
			t.Run(home+"/"+row.name, func(t *testing.T) {
				if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, actionfacts.DialectPOSIX, nil); got != row.want {
					t.Errorf("%q: got %q, want %q", row.command, got, row.want)
				}
			})
		}
	}
}

// PowerShell passes a native head wildcard to its executable. The MSYS
// runtime skips leading dot names, while PowerShell cmdlet path binding can
// select them. An explicit key path still reaches the private-key rule.
func TestGAP0516PowerShellNativeHeadPrivateKeyRead(t *testing.T) {
	for _, home := range []string{`C:\Users\Alice`, `C:/Users/Alice`} {
		for _, row := range []struct {
			name, command string
			want          bool
		}{
			{"direct native glob", `head -n 1 */*`, false},
			{"native glob then marker", `head -n 1 */*; echo done`, false},
			{"native exe glob", `head.exe -n 1 */*`, false},
			{"explicit key", `head -n 1 .ssh/id_ed25519`, true},
			{"explicit key glob", `head -n 1 .ssh/id_*`, true},
			{"explicit key after glob", `head -n 1 */*; head .ssh/id_ed25519`, true},
			{"PowerShell cmdlet glob", `Get-Content */*`, true},
			{"PowerShell alias glob", `cat */*`, true},
		} {
			t.Run(home+"/"+row.name, func(t *testing.T) {
				if got := ActionPrivateKeyReadWithDialect(row.command, home, home, actionfacts.DialectPowerShell); got != row.want {
					t.Errorf("%q: private-key read = %t, want %t", row.command, got, row.want)
				}
			})
		}
	}
}
