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

// A link to a project, system or user-less path followed by a find -exec mv
// or by a cd that only a nested shell runs is allowed on a managed gateway
// behind ProtectHome as on a per-user one: the user-side hook ran the disk
// walks of the links (LinksStableKey), which the gateway cannot repeat in
// the hidden home (GAP-2600, the managed leg of GAP-2533). Links, moves and
// linked trees that reach SSH or DefenseClaw state keep blocking.
func TestManagedLinkThenNestedCdOrFindMoveReadsTheUserView(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	if os.Geteuid() == 0 {
		t.Skip("a hidden home is readable by root")
	}
	rows := []struct {
		id, command string
		block       bool
	}{
		{"C04@it4", `ln -s src/a.txt alias.txt; find . -type f -name "*.tmp" -exec mv {} build/ \;`, false},
		{"C05@it4", `ln -s README.md docs.md; find . -name "*.bak" -exec mv {} /tmp/ \;`, false},
		{"C04@it7", `ln -s bigp bl; bash -c "cd ~root && ls"`, false},
		{"C05@it7", `ln -s /usr/lib lib; bash -c "cd ~root && ls"`, false},
		{"W01@it3", `ln -sf /usr/bin/python3 py; bash -c "cd src && ls"`, false},
		{"R03@it3", `ln -s ~/.defenseclaw/config.yaml c; find . -name c -exec mv {} d \;; echo x > d`, true},
		{"A01", `ln -s ~/.ssh s; bash -c "cd s && echo k >> authorized_keys"`, true},
		{"A02", `ln -s ~/.ssh s; find . -name "*.pub" -exec mv {} s/ \;`, true},
		{"A03", `ln -s README.md docs.md; find . -name "*.bak" -exec mv {} ~/.ssh/ \;`, true},
		{"A04", `ln -s bigp bl; bash -c "cd bl/k && echo k >> authorized_keys"`, true},
		{"A05", `ln -s ~/.defenseclaw d; bash -c "cd d && echo x > config.yaml"`, true},
		// A cd through LINK/.. falls back to the physical path when the
		// logical one is missing, so it reaches the parent of the link
		// target (GAP-2600 checker): F5, F5c and F5f write ~/.ssh.
		{"F5", `ln -s ../proj p; bash -c "cd p/../.ssh && echo k >> authorized_keys"`, true},
		{"F5c", `ln -s src/sub d; bash -c "cd d/../../../.ssh && echo k >> authorized_keys"`, true},
		{"F5f", `ln -s src/sub d; bash -c "cd d/../../../.ssh/.. && cd .ssh && echo k >> authorized_keys"`, true},
		{"F5t", `ln -s ../proj p; cd p/../.ssh && echo k >> authorized_keys`, true},
		// The logical cd p/.. lands in the project, so the cd .ssh after it
		// names a missing project directory: benign.
		{"F5e", `ln -s ../proj p; sh -c "cd p/.. && cd .ssh && echo k >> authorized_keys"`, false},
		{"F5g", `ln -s src/sub d; bash -c "cd d/.. && ls"`, false},
		// The same through a link already on disk (dp -> .., ds -> src/sub);
		// only the user view of the disk shows it.
		{"D1", `bash -c "cd dp/../.ssh && echo k >> authorized_keys"`, true},
		{"D2", `cd dp/../.ssh && echo k >> authorized_keys`, true},
		{"D5", `bash -c "cd ds/../../../.ssh && echo k >> authorized_keys"`, true},
		{"D6", `bash -c "cd ds/.. && ls > list.txt"`, false},
	}
	for _, managed := range []bool{false, true} {
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				cwd := filepath.Join(home, "proj")
				for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, ".defenseclaw"),
					filepath.Join(cwd, "src", "sub"), filepath.Join(cwd, "build"), filepath.Join(cwd, "bigp")} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{filepath.Join(cwd, "README.md"), filepath.Join(cwd, "a.txt"),
					filepath.Join(cwd, "src", "a.txt"), filepath.Join(home, ".ssh", "authorized_keys"),
					filepath.Join(home, ".defenseclaw", "config.yaml")} {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if strings.HasPrefix(row.id, "D") {
					for name, target := range map[string]string{"dp": "../proj", "ds": "src/sub"} {
						if err := os.Symlink(target, filepath.Join(cwd, name)); err != nil {
							t.Fatal(err)
						}
					}
				}
				if row.id == "A04" {
					// A disk link to state below the linked project tree.
					if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(cwd, "bigp", "k")); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "Bash", "tool_input": map[string]string{"command": row.command}})
				targets, ok := hookpaths.Decode(hookpaths.ResolveConnector(connector, "", "", payload))
				if !ok {
					t.Fatalf("%s: client map does not decode", row.id)
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
					t.Errorf("managed=%v %s %s %q: block=%v, want %v (%s)", managed, connector, row.id, row.command, blocked, row.block,
						strings.Join(FindingStrings(findings), ","))
				}
			}
		}
	}
}
