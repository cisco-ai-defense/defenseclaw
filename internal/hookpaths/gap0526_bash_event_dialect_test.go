// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestGAP0526BashEventReadsByDialect pins rel-1-0-6:GAP-0526 (managed
// Windows corpus row B-Y03). The row is a Bash tool event, which Claude Code
// runs in Git Bash, but its second line is the PowerShell cmdlet
// Get-Content. A Bash call with PowerShell spelling keeps every reading
// (actionGitBashPowerShellSyntax, lead decision on GAP-1504), and in the
// POSIX reading Get-Content is no reader: the keys path it names is a
// protected-target mention. The reader the row's expected text describes
// (cat) and the cmdlet in a PowerShell event are reads and allow; every
// writer twin stays protected.
func TestGAP0526BashEventReadsByDialect(t *testing.T) {
	const home = `C:\Users\tester`
	rows := []struct {
		name, command string
		dialect       actionfacts.Dialect
		want          string
		posixHost     bool // read on a POSIX host; native Windows reads it with Git Bash alone
	}{
		{"B-Y03 bash event with a PowerShell cmdlet", "echo hi\nGet-Content .ssh/authorized_keys", actionfacts.DialectPOSIX, ProtectedTargetDecision, false},
		{"bash event with the cat reader", "echo hi\ncat .ssh/authorized_keys", actionfacts.DialectPOSIX, "", true},
		{"powershell event with the cmdlet reader", "echo hi\nGet-Content .ssh/authorized_keys", actionfacts.DialectPowerShell, "", true},
		{"bash event writer", "echo hi\ncp a.txt .ssh/authorized_keys", actionfacts.DialectPOSIX, ProtectedTargetDecision, false},
		{"bash event append writer", "echo hi\necho k >> .ssh/authorized_keys", actionfacts.DialectPOSIX, ProtectedTargetDecision, false},
		{"powershell event writer", "echo hi\nAdd-Content .ssh/authorized_keys k", actionfacts.DialectPowerShell, ProtectedTargetDecision, false},
	}
	for _, row := range rows {
		if row.posixHost && runtime.GOOS == "windows" {
			continue
		}
		if got := ActionCommandDecisionWithDialectAndGlobFacts(row.command, home, home, row.dialect, nil); got != row.want {
			t.Errorf("%s: decision %q, want %q", row.name, got, row.want)
		}
	}
}
