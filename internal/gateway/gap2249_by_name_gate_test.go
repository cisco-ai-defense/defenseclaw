// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/fixturefs"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// TestGAP2249HereStringShellGate: a shell fed only a one-word here-string
// (bash <<< true) no longer holds the by-name gate by itself
// (copyModeLiteralHereString, rel-1-0-10:GAP-2249), and the gate still
// never skips a call the by-name reading decides: every pinned gate call
// (fx0999GateCommands) with such a statement before or after it, and the
// rows where the shell reads more than the word.
func TestGAP2249HereStringShellGate(t *testing.T) {
	home := sandboxauth.SandboxHome
	if copyModeCallMayNameSSHFolder("cd .cache\nbash <<< 'true'\ntouch f0\ntouch f1\nls", home, home) {
		t.Error("bash <<< 'true' with plain statements holds the gate")
	}
	for _, command := range []string{"bash <<< true x.sh", "bash <<< true < x.sh", "bash <<< true 0<x.sh", "bash -s <<< true",
		"bash <<< 'true x.sh'", "echo hss. | rev | bash", "bash x.sh <<< true", "bash <<< bash", "sh <<<", "bash <<< true | sh"} {
		if !copyModeCallMayNameSSHFolder(command, home, home) {
			t.Errorf("%q: the gate skips a shell that reads more than one here-string word", command)
		}
	}
	commands := fx0999GateCommands(t, home)
	rows, decided := 0, 0
	for _, cwd := range []string{home, home + "/src"} {
		for _, base := range commands {
			for _, command := range []string{"bash <<< 'true'\n" + base, base + "\nbash <<< 'true'", "sh <<< x; " + base} {
				rows++
				var decision string
				fixturefs.Unread(func() {
					decision = hookpaths.NewTargetMemo().ActionCommandDecisionInShell(command, cwd, home, nil, true)
				})
				if decision == "" {
					continue
				}
				decided++
				if !copyModeCallMayNameSSHFolder(command, cwd, home) {
					t.Errorf("cwd %s: %q: the reading decides %q, the gate skips it", cwd, command, decision)
				}
			}
		}
	}
	if decided == 0 {
		t.Fatalf("no row of %d decided: the check proves nothing", rows)
	}
	t.Logf("GAP2249GATE rows=%d decided=%d", rows, decided)
}
