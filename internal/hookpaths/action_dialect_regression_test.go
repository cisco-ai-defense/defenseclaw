// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestR104WindowsActionExplicitDialect(t *testing.T) {
	const home = `C:\Users\alice`
	const cwd = `C:\Users\alice\project`
	for _, tc := range []struct {
		name, command string
		dialect       actionfacts.Dialect
		want          string
	}{
		{"POSIX escaped dollar", `echo \$HOME/.ssh/authorized_keys`, actionfacts.DialectPOSIX, ""},
		{"POSIX single quoted dollar", `echo '$HOME/.ssh/authorized_keys'`, actionfacts.DialectPOSIX, ""},
		{"POSIX lowercase literal dollar", `echo '$home/.ssh/authorized_keys'`, actionfacts.DialectPOSIX, ""},
		{"POSIX percent literal", `echo '%USERPROFILE%/.ssh/authorized_keys'`, actionfacts.DialectPOSIX, ""},
		{"POSIX quoted tilde", `echo '~/.ssh/authorized_keys'`, actionfacts.DialectPOSIX, ""},
		{"POSIX expanded dollar", `echo $HOME/.ssh/authorized_keys`, actionfacts.DialectPOSIX, "protected-target"},
		{"POSIX protected redirect", `echo marker > ~/.ssh/authorized_keys`, actionfacts.DialectPOSIX, "protected-target"},
		{"PowerShell escaped dollar", "Write-Output \"`$HOME/.ssh/authorized_keys\"", actionfacts.DialectPowerShell, ""},
		{"nested PowerShell escaped dollar", "pwsh -Command 'Write-Output \"`$HOME/.ssh/authorized_keys\"'", actionfacts.DialectPowerShell, ""},
		{"outer escape reaches nested PowerShell", "pwsh -Command \"Write-Output `$HOME/.ssh/authorized_keys\"", actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell expanded dollar", `Write-Output "$HOME/.ssh/authorized_keys"`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell line comment", `Write-Output ok # $HOME/.ssh/authorized_keys`, actionfacts.DialectPowerShell, ""},
		{"PowerShell block comment", `Write-Output ok <# $HOME/.ssh/authorized_keys #>`, actionfacts.DialectPowerShell, ""},
		{"PowerShell nested block comment", `Write-Output ok <# outer <# $HOME/.ssh/authorized_keys #> outer #>`, actionfacts.DialectPowerShell, ""},
		{"PowerShell block comments do not nest", `Write-Output ok <# outer <# harmless #> Write-Output $HOME/.ssh/authorized_keys #>`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell block marker in token", `Write-Output literal<# $HOME/.ssh/authorized_keys #>`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell multiline comment", "Write-Output ok # $HOME/.ssh/authorized_keys\nWrite-Output done", actionfacts.DialectPowerShell, ""},
		{"PowerShell code after block comment", `Write-Output ok <# $HOME/.ssh/authorized_keys #>; Write-Output $HOME/.ssh/authorized_keys`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell quoted literal hash", `Write-Output '# $HOME/.ssh/authorized_keys'`, actionfacts.DialectPowerShell, ""},
		{"PowerShell quoted hash", `Write-Output "#"; Write-Output $HOME/.ssh/authorized_keys`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell escaped hash", "Write-Output `#; Write-Output $HOME/.ssh/authorized_keys", actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell nested body", `pwsh -Command 'Write-Output $HOME/.ssh/authorized_keys'`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell nested body before comment", `pwsh -Command 'Write-Output $HOME/.ssh/authorized_keys # trailing'`, actionfacts.DialectPowerShell, "protected-target"},
		{"PowerShell nested body after comment", `pwsh -Command 'Write-Output ok # $HOME/.ssh/authorized_keys; Write-Output $HOME/.ssh/authorized_keys'`, actionfacts.DialectPowerShell, ""},
		{"CMD hash is data", `echo ok # %USERPROFILE%\.ssh\authorized_keys`, actionfacts.DialectCMD, "protected-target"},
		{"unknown hash is data", `echo ok # $HOME/.ssh/authorized_keys`, "", "protected-target"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(tc.command, cwd, home, tc.dialect, nil); got != tc.want {
				t.Fatalf("decision = %q, want %q", got, tc.want)
			}
		})
	}
}
