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

// mv onto an existing symlink to a file replaces the link; the file it
// names is untouched. A managed gateway (ProtectHome, PrivateTmp,
// PrivateDevices) judges such a move from the hook client map, so the map
// names the replaced entry, not the file behind the link, and the move is
// allowed as on OSS (GAP-2558). Writing through the same link (cp, a
// redirect), moving onto the state file through a linked directory and
// moving into a link to the state directory keep blocking.
func TestR105ManagedMoveOntoLinkToStateReplacesTheLink(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("unprivileged POSIX gateway walk")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"mv a.txt {E}/y/config.yaml", true},
		{"mv -f a.txt {E}/y/config.yaml", true},
		{"mv a.txt ~/.defenseclaw/config.yaml", true},
		{"cp a.txt {E}/c", true},
		{"echo z > {E}/c", true},
		{"mv a.txt {E}/c; cp b.txt {E}/c", true},
		{"mv a.txt {E}/c", false},
		{"mv -f a.txt {E}/c", false},
		{"mv -- a.txt {E}/c", false},
		{"mv a.txt lc", false},
		{"mv -f a.txt lc", false},
		{"mv a.txt {E}/notes2.txt", false},
		{"mv a.txt b.txt", false},
		{"ls -la", false},
		{"git status", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, row := range rows {
			home := filepath.Join(t.TempDir(), "home")
			ext := filepath.Join(t.TempDir(), "ext")
			cwd := filepath.Join(home, "w", "p")
			state := filepath.Join(home, ".defenseclaw")
			for _, dir := range []string{state, ext, cwd} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{filepath.Join(state, "config.yaml"),
				filepath.Join(ext, "notes.txt"), filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "b.txt")} {
				if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			for link, target := range map[string]string{
				filepath.Join(ext, "y"):  state,
				filepath.Join(ext, "c"):  filepath.Join(state, "config.yaml"),
				filepath.Join(cwd, "lc"): filepath.Join(state, "config.yaml"),
			} {
				if err := os.Symlink(target, link); err != nil {
					t.Fatal(err)
				}
			}
			t.Setenv("HOME", home)
			command := strings.NewReplacer("{E}", ext).Replace(row.command)
			payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
				"tool_name": "Bash", "tool_input": map[string]string{"command": command}})
			if err != nil {
				t.Fatal(err)
			}
			// The hook runs as the user and sees the outside directory.
			targets, ok := hookpaths.Decode(hookpaths.Resolve(payload))
			if !ok {
				t.Fatalf("%q: no client target map", command)
			}
			// The managed gateway cannot open the home (ProtectHome); a
			// private /tmp or /dev may also hide the outside directory, or
			// the gateway may see it (a host /dev/shm).
			for _, hidden := range [][]string{{filepath.Dir(ext), filepath.Dir(home)}, {filepath.Dir(home)}} {
				for _, dir := range hidden {
					if err := os.Chmod(dir, 0); err != nil {
						t.Fatal(err)
					}
				}
				for _, gatewayCWD := range []string{cwd, ""} {
					input := actionfacts.Input{Tool: "Bash", Command: command, CWD: gatewayCWD, ActiveHome: home,
						DialectHint: actionfacts.DialectPOSIX}
					request := trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true,
						ProtectedHomeHook: true, ResolvedWriteTargets: targets}
					findings := dispatchTrustedAction(t.Context(), request)
					if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
						ids := ""
						for _, finding := range findings {
							ids += finding.RuleID + " "
						}
						t.Errorf("%s hidden=%d cwd=%q %q: block=%v, want %v (%s)", connector, len(hidden), gatewayCWD, row.command, blocked, row.block, ids)
					}
				}
				for _, dir := range hidden {
					if err := os.Chmod(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
			}
		}
	}
}
