// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-2168 Windows leg: on a Windows home the read-only list of the Windows
// reading lacked the Git Bash search and count programs, so Claude Code's
// Bash tool `grep marker ~/.ssh/authorized_keys` (and wc -l, ssh-keygen -l)
// stayed protected-target on native Windows while the POSIX home allowed it.
// Every dialect hint gives the same answer; the write twins still block.
func TestActionWindowsHomePlainReadOfAuthorizedKeysIsNotAWrite(t *testing.T) {
	const home, cwd = `C:\Users\u`, `C:\Users\u\proj`
	dialects := []actionfacts.Dialect{"", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell}
	for _, command := range []string{
		"grep marker ~/.ssh/authorized_keys", "grep -c ssh ~/.ssh/authorized_keys",
		"egrep -n marker /c/Users/u/.ssh/authorized_keys", "fgrep marker ~/.ssh/authorized_keys",
		"wc -l ~/.ssh/authorized_keys", "ssh-keygen -l -f ~/.ssh/authorized_keys",
		"ssh-keygen -lf ~/.ssh/authorized_keys", "ssh-keygen -l -E md5 -f ~/.ssh/authorized_keys",
		`grep marker ~/.ssh/authorized_keys; status=$?; printf '\n[exit status] %s\n' "$status"; exit "$status"`,
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil); got != "" {
				t.Errorf("dialect %q: ActionCommandDecision(%q) = %q, want a plain read", dialect, command, got)
			}
		}
	}
	for _, command := range []string{
		"grep marker a.txt >> ~/.ssh/authorized_keys", "wc -l a.txt > ~/.ssh/authorized_keys",
		"ssh-keygen -R host -f ~/.ssh/authorized_keys", "ssh-keygen -l -f ~/.ssh/authorized_keys > ~/.ssh/authorized_keys2",
		"cat a.txt | tee -a ~/.ssh/authorized_keys", "grep marker ~/.ssh/authorized_keys | sh",
	} {
		for _, dialect := range dialects {
			if got := ActionCommandDecisionWithDialectAndGlobFacts(command, cwd, home, dialect, nil); got != "protected-target" {
				t.Errorf("dialect %q: ActionCommandDecision(%q) = %q, want protected-target", dialect, command, got)
			}
		}
	}
}
