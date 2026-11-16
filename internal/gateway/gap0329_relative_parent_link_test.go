// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-0329: ln -s ../.. sub/l makes one link, sub/l. The reader also took
// it as a link at sub/.. (ln's form for a target directory), which made sub
// itself an alias of a path that climbs out of a directory that does not
// exist yet, so a write after cd into the link was unknown and blocked as
// an authorized-keys write. ln never makes an entry named . or .., so a
// relative link inside the repo is ordinary; links that reach ~/.ssh still
// block, per-user and managed, on both connectors.
func TestGAP0329RelativeParentLinkInsideTheRepo(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"mkdir -p work/nested && ln -s ../.. work/nested/parent-link && cd work/nested/parent-link && echo benign > benign-link.txt", false},
		{"mkdir -p work/nested && ln -s .. work/nested/up && echo benign > work/nested/up/note.txt", false},
		{"mkdir -p work && ln -s ./. work/self && echo benign > work/self/note.txt", false},
		{"mkdir -p work/nested && ln -s ../../../../.ssh work/nested/l && cd work/nested/l && echo x >> authorized_keys", true},
		{"mkdir -p work/nested && ln -s ../../../../.ssh/authorized_keys work/nested/k && echo x >> work/nested/k", true},
		{"mkdir -p work && ln -s ~/.ssh work/s && cd work/s && echo x >> authorized_keys", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, row := range rows {
			home := t.TempDir()
			cwd := filepath.Join(home, "proj", "g329")
			for _, dir := range []string{filepath.Join(home, ".ssh"), cwd} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			t.Setenv("HOME", home)
			input := actionfacts.Input{Tool: "Bash", Command: row.command, CWD: cwd, ActiveHome: home,
				DialectHint: actionfacts.DialectPOSIX}
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
				"tool_input": map[string]string{"command": row.command}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatal("client proof did not decode")
			}
			for route, request := range map[string]trustedActionRequest{
				"per-user": {Input: input, Connector: connector, EnforcementCapable: true},
				"managed": {Input: input, Connector: connector, EnforcementCapable: true,
					ProtectedHomeHook: true, ResolvedWriteTargets: targets},
			} {
				findings := dispatchTrustedAction(t.Context(), request)
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					t.Errorf("%s %s %q: block=%v, want %v (%v)", connector, route, row.command, blocked, row.block, FindingStrings(findings))
				}
			}
		}
	}
}
