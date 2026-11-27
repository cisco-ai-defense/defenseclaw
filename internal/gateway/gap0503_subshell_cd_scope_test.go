// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gap0503Group is a line that changes the folder only inside a ( ... )
// group or a substitution, and gap0503Opaque the lines after it that the
// hook reads by their folder (an unknown program word, a shell fed a
// here-string).
var (
	gap0503Groups = []string{
		"(cd .ssh && ls)", "(cd .ssh; ls)", "( (cd .ssh) && ls )", "(pushd .ssh && ls)",
		`echo "$(cd .ssh && ls)"`, "cat <(cd .ssh && ls)",
	}
	gap0503Opaque = []string{"$CMD", "bash <<< 'true'", "$CMD | bash <<< true"}
)

// TestSubshellCdEndsAtTheGroupCloseOnTheHookRoute: a cd inside a ( ... )
// group or a command or process substitution moves only that copy of the
// shell, so what follows the group runs in the start folder. The Claude Code
// hook carried the move past the group and judged an unknown word after it
// (an unknown program, a shell fed a here-string) as if it ran in ~/.ssh: a
// block as an authorized-keys write in every pack, where the same lines
// without the group are allowed (substrate-1:GAP-0503). The oracle of each
// row is its twin with the group line replaced by ls. The move still holds
// inside the group, after a { ...; } block and after a later plain cd.
func TestSubshellCdEndsAtTheGroupCloseOnTheHookRoute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text read under a POSIX home")
	}
	h := newGAP0048Home(t)
	for name, body := range map[string]string{
		filepath.Join(h.home, ".ssh", "config"): "Host x\n", filepath.Join(h.home, "config.yaml"): "a: 1\n",
	} {
		if err := os.MkdirAll(filepath.Dir(name), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, profile := range []string{"default", "permissive", "strict"} {
		judge := newHookConfigJudge(t, "claudecode", profile)
		verdict := func(command string) (string, string) {
			got := judge(h.home, false, "Bash", map[string]any{"command": command})
			return hookConfigAction(got), got
		}
		for _, group := range gap0503Groups {
			for _, opaque := range gap0503Opaque {
				for _, tail := range []string{"", "\ncat config.yaml"} {
					command := group + "\n" + opaque + tail
					oracle, _ := verdict("ls\n" + opaque + tail)
					if got, out := verdict(command); got != oracle {
						t.Errorf("%s: %q is %s, its twin without the group is %s: %.600s", profile, command, got, oracle, out)
					}
				}
			}
		}
		// A read inside a read-only group is judged as the same read
		// outside it.
		for _, row := range []struct{ command, twin string }{
			{"(cat ~/.ssh/config)\n$CMD", "cat ~/.ssh/config\n$CMD"},
			{"(ls ~/.ssh && cat ~/.ssh/id_ed25519)\n$CMD", "ls ~/.ssh && cat ~/.ssh/id_ed25519\n$CMD"},
		} {
			oracle, _ := verdict(row.twin)
			if got, out := verdict(row.command); got != oracle {
				t.Errorf("%s: %q is %s, its twin without the group %q is %s: %.600s", profile, row.command, got, row.twin, oracle, out)
			}
		}
		for _, row := range []struct{ command, twin string }{
			{"(cd .ssh && $CMD)", "cd .ssh && $CMD"},
			{"{ cd .ssh; }\n$CMD", "cd .ssh\n$CMD"},
			{"(cd .ssh && ls)\ncd .ssh\n$CMD", "cd .ssh\n$CMD"},
			{"(cd /tmp)\ncd .ssh\n$CMD", "cd .ssh\n$CMD"},
		} {
			oracle, _ := verdict(row.twin)
			if oracle != "block" {
				t.Fatalf("%s: control twin %q is %s, the control needs a block", profile, row.twin, oracle)
			}
			if got, out := verdict(row.command); got != oracle || !strings.Contains(out, "persistence.ssh_authorized_keys_command") {
				t.Errorf("%s: %q is %s, want %s as %q: %.600s", profile, row.command, got, oracle, row.twin, out)
			}
		}
	}
}
