// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import "testing"

// The Codex shell tool can print a patch envelope while its cwd is the
// account home. Quoted asterisks in the printed text are not path operands.
func TestCertfixGAP0489WindowsCodexPrintfFromHome(t *testing.T) {
	const home = `C:\Users\tester`
	for _, command := range []string{
		`printf "*** Begin Patch\n*** End Patch\n"`,
		`printf "*** x\n"`,
		`printf "%s\n" "***"`,
		`printf "*** Begin Patch\n*** Add File: notes.txt\n+text\n*** End Patch\n"`,
	} {
		if got := ActionCommandDecision(command, home, home); got != "" {
			t.Errorf("%q from home = %q, want allow", command, got)
		}
	}
	for _, command := range []string{
		`printf x > .ssh/authorized_keys`,
		`printf "***" > .ssh/authorized_keys`,
	} {
		if got := ActionCommandDecision(command, home, home); got != "protected-target" {
			t.Errorf("%q from home = %q, want protected-target", command, got)
		}
	}
}
