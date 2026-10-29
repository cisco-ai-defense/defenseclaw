// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A benign project link next to an unrelated static rename is allowed on a
// managed gateway behind ProtectHome as on a per-user one: the user-side
// hook read the links away from state (LinksStableKey), which the gateway
// cannot repeat in the hidden home (GAP-2564, the managed leg of
// GAP-2532). Links that reach SSH or DefenseClaw state keep blocking.
func TestR105ManagedLinkThenRenameReadsTheUserView(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	if os.Geteuid() == 0 {
		t.Skip("a hidden home is readable by root")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"ln -s README.md docs.md; mv a.txt e.txt", false},
		{"ln -s README.md docs.md && mv a.txt e.txt", false},
		{"mv a.txt e.txt; ln -s README.md docs.md", false},
		{"ln -s build/out bin; mv a.txt e.txt", false},
		{"ln -s README.md docs.md; mv a.txt e.txt; ls", false},
		{"ln -s ~/.ssh ks; mv a.txt e.txt; cp b.txt ks/authorized_keys", true},
		{"ln -s ~/.defenseclaw dc; mv a.txt e.txt; cp b.txt dc/config.yaml", true},
		{"ln -s ~/.ssh/authorized_keys k; mv k k2; echo x >> k2", true},
		{"ln -s ~/.ssh ks; mv ks ks2; cp b.txt ks2/authorized_keys", true},
		{"ln -s README.md docs.md; mv a.txt ~/.ssh/authorized_keys", true},
	}
	for _, managed := range []bool{false, true} {
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				cwd := filepath.Join(home, "proj")
				for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"),
					filepath.Join(cwd, "src"), filepath.Join(cwd, "build")} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{filepath.Join(cwd, "README.md"), filepath.Join(cwd, "a.txt"),
					filepath.Join(cwd, "b.txt"), filepath.Join(home, ".ssh", "authorized_keys"),
					filepath.Join(home, ".defenseclaw", "config.yaml")} {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]string{"command": row.command}})
				targets, ok := hookpaths.Decode(hookpaths.ResolveConnector(connector, "", "", payload))
				if !ok {
					t.Fatalf("%q: client map does not decode", row.command)
				}
				if managed {
					if err := os.Chmod(filepath.Dir(home), 0); err != nil {
						t.Fatal(err)
					}
				}
				input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
					DialectHint: actionfacts.DialectPOSIX}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector,
					EnforcementCapable: true, ProtectedHomeHook: managed, ResolvedWriteTargets: targets})
				if managed {
					if err := os.Chmod(filepath.Dir(home), 0o700); err != nil {
						t.Fatal(err)
					}
				}
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					t.Errorf("managed=%v %s %q: block=%v, want %v (%s)", managed, connector, row.command, blocked, row.block,
						strings.Join(FindingStrings(findings), ","))
				}
			}
		}
	}
}
