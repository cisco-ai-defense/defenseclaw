// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestWindowsHereStringThatIsOnlyPrintedOrAssignedIsText is rel-1-0-6
// GAP-0236 (filed by the GAP-0234 fix): a PowerShell here-string whose
// body names a keys-file pattern blocked a benign print or assignment. A
// here-string that is only printed, or only assigned to a variable the
// command never uses, is text; a writer that uses it still blocks.
func TestWindowsHereStringThatIsOnlyPrintedOrAssignedIsText(t *testing.T) {
	const home = `C:\Users\b00`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPowerShell}
	for _, command := range []string{
		"Write-Output @'\n.ssh/authorized_keys\n'@",
		"Write-Output @'\n.ssh/authorized_k*\n'@",
		"$t = @'\nfoo ~/.ssh/authorized_k*\n'@",
		"$t = @\"\nsee .ssh/authorized_keys\n\"@",
		"Write-Host @\"\nnotes about ~/.ssh/authorized_keys\n\"@\r\ngit status",
		"$note = @'\n.ssh/authorized_keys\n'@; Write-Output done",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "" {
				t.Errorf("dialect %q %q = %q, want allow", dialect, command, got)
			}
		}
	}
	for _, command := range []string{
		"@'\nssh-ed25519 AAAA\n'@ | Add-Content -Path '.ssh/authorized_k*'",
		"Set-Content -Path '.ssh/authorized_keys' -Value @'\nssh-ed25519 AAAA\n'@",
		"$t = @'\nk\n'@; Add-Content -Path .ssh/authorized_keys -Value $t",
		"$t = @'\n.ssh/authorized_keys\n'@; Add-Content -Path $t -Value k",
		"Write-Output @'\n.ssh/authorized_k*\n'@ | ForEach-Object { Add-Content -Path $_ -Value k }",
		"Write-Output @\"\n$(Add-Content -Path .ssh/authorized_keys -Value k)\n\"@",
		"Write-Output @'\nx\n'@; Add-Content -Path .ssh/authorized_keys -Value k",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, home, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q %q = %q, want protected-target", dialect, command, got)
			}
		}
	}
}
