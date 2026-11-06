// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A copy with a runtime-expanded word ($(true)) may copy links anywhere, so
// the link walk reads every later write as unknown; a plain project copy
// that an earlier statement of the same list finished first was read the
// same way, so cp a.txt c.txt; cp c.txt d.txt $(true) blocked as an SSH
// authorized_keys command (GAP-2585, cell L-mac-J3-011). The earlier copy
// is judged as written; a write after the runtime-word copy, a copy into
// the keys file or state, and a link the command makes still block.
func TestR106CopyBeforeARuntimeWordCopyStaysAllowed(t *testing.T) {
	prepare := func(t *testing.T, f b36ManagedHookFixture) {
		for _, dir := range []string{filepath.Join(f.project, "ordinary"), filepath.Join(f.home, ".defenseclaw")} {
			if err := os.MkdirAll(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{filepath.Join(f.project, "a.txt"), filepath.Join(f.project, "b.txt"),
			filepath.Join(f.home, ".defenseclaw", "config.yaml")} {
			if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	judgeR106HookRows(t, []r106HookRow{
		{command: `cp a.txt c.txt; cp c.txt d.txt $(true)`},
		{command: `cp a.txt c.txt && cp c.txt d.txt $(true)`},
		{command: `cp a.txt ordinary/ && cp b.txt ordinary/ $(true) && git status`},
		{command: "cp a.txt c.txt; cp c.txt d.txt `true`"},
		{command: `cp a.txt c.txt; cp c.txt d.txt $(date +%s)`},
		{command: `cp b.txt e.txt $(true)`},
		{command: `cp a.txt c.txt; cp c.txt d.txt`},
		{command: `cp a.txt c.txt; cp c.txt HOMEDIR/.defenseclaw/config.yaml $(true)`, block: true},
	}, prepare)
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	for _, mode := range []struct {
		managed, header bool
	}{{true, true}, {false, true}, {false, false}} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, command := range []string{
				`cp a.txt c.txt; cp c.txt ~/.ssh/authorized_keys $(true)`,
				`ln -s ../.ssh/authorized_keys c.txt; cp a.txt c.txt $(true)`,
				`ln -s ../.ssh c; cp a.txt c/authorized_keys $(true)`,
				`cp -P keylink c.txt; cp a.txt c.txt $(true)`,
				`cp a.txt c.txt; cp c.txt d.txt $(true); echo x >> keylink`,
				`cp c.txt d.txt $(true); cp a.txt d.txt`,
			} {
				f := newB36ManagedHookFixture(t)
				prepare(t, f)
				payload := f.payload(t, command)
				header := ""
				if mode.header {
					header = f.clientHeader(t, payload)
				}
				if got := r106AlertVerdict(r106HookVerdict(t, f, mode.managed, connector, payload, header)); got != "alert" {
					t.Errorf("managed=%v header=%v %s %q: %s, want alert", mode.managed, mode.header, connector, command, got)
				}
				_ = os.Chmod(f.homes, 0o700)
			}
		}
	}
}
