// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-2559 (managed half): a plain mv onto an existing link replaces only the
// link, whatever the spelling of the destination: cd-relative or absolute. The
// hook that runs as the user lists the link targets (the client map); the
// gateway, which cannot see the folder of the link, decides from that map. A
// write through the link keeps blocking.
func TestR106ManagedMoveOntoLinkWithCdRelativeDestinationReplacesTheLink(t *testing.T) {
	rows := []struct {
		command string
		block   bool
	}{
		{"cd {E} && mv ~/w/p/a.txt c", false},
		{"cd {E} && mv -f ~/w/p/a.txt c", false},
		{"cd {E} && mv ~/w/p/a.txt ./c", false},
		{"cd {E} && mv ~/w/p/a.txt {E}/c", false},
		{"mv ~/w/p/a.txt {E}/c", false},
		{"cd {E} && cp ~/w/p/a.txt c", true},
		{"cd {E} && echo x > c", true},
		{"cd ~/.defenseclaw && mv ~/w/p/a.txt config.yaml", true},
		{"mv ~/w/p/a.txt ~/.defenseclaw/config.yaml", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, hidden := range []bool{false, true} {
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				ext := filepath.Join(t.TempDir(), "ext")
				cwd := filepath.Join(home, "w", "p")
				state := filepath.Join(home, ".defenseclaw")
				for _, dir := range []string{cwd, state, ext} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{filepath.Join(cwd, "a.txt"), filepath.Join(state, "config.yaml")} {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				if err := os.Symlink(filepath.Join(state, "config.yaml"), filepath.Join(ext, "c")); err != nil {
					t.Fatal(err)
				}
				t.Setenv("HOME", home)
				command := strings.NewReplacer("{E}", ext).Replace(row.command)
				payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": cwd,
					"tool_input": map[string]string{"command": command}})
				if err != nil {
					t.Fatal(err)
				}
				targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
				if !ok {
					t.Fatalf("%q: no client map", command)
				}
				if hidden {
					// The gateway runs as another account and cannot see the folder.
					if err := os.Chmod(ext, 0); err != nil {
						t.Fatal(err)
					}
					t.Cleanup(func() { _ = os.Chmod(ext, 0o700) })
				}
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: actionfacts.DialectPOSIX}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector,
					EnforcementCapable: true, ProtectedHomeHook: true, ResolvedWriteTargets: targets})
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					t.Errorf("%s hidden=%v %q: block=%v, want %v (%s)", connector, hidden, row.command, blocked, row.block, strings.Join(FindingStrings(findings), ","))
				}
				_ = os.Chmod(ext, 0o700)
			}
		}
	}
}
