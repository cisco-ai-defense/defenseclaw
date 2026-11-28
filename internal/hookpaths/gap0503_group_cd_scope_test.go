// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestActionDecisionCdInsideAGroupEndsAtItsClose: the action decision reads
// the words after a ( ... ) group or a substitution in the folder the shell
// is in after it, the start folder, not the folder a cd inside the group led
// to (substrate-1:GAP-0503). The twin with the group line replaced by ls is
// the oracle; a move inside the group, in a { ...; } block and in a plain cd
// after the group still holds.
func TestActionDecisionCdInsideAGroupEndsAtItsClose(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text read under a POSIX home")
	}
	home := filepath.Join(t.TempDir(), "home")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	decide := func(command string) string { return ActionCommandDecision(command, home, home) }
	for _, group := range []string{"(cd .ssh && ls)", "(cd .ssh; ls)", "( (cd .ssh) && ls )", "(pushd .ssh && ls)", `echo "$(cd .ssh && ls)"`, "cat <(cd .ssh && ls)"} {
		for _, opaque := range []string{"$CMD", "bash <<< 'true'"} {
			command := group + "\n" + opaque
			if got, want := decide(command), decide("ls\n"+opaque); got != want {
				t.Errorf("%q decides %q, its twin without the group %q", command, got, want)
			}
		}
	}
	for _, command := range []string{"(cd .ssh && $CMD)", "{ cd .ssh; }\n$CMD", "(cd .ssh && ls)\ncd .ssh\n$CMD", "(cd /tmp)\ncd .ssh\n$CMD"} {
		if got := decide(command); got != "protected-target" {
			t.Errorf("%q decides %q, want protected-target (the move holds)", command, got)
		}
	}
}
