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

// A managed gateway (ProtectHome, PrivateTmp, PrivateDevices) cannot read a
// directory the user can make, so a move that replaces a DefenseClaw state
// file through a link (an existing disk link outside the home, a link the
// command makes, or both) is judged from the state entry the hook client
// lists, as the delete is (GAP-2554, GAP-2549). A move that replaces a link
// to state replaces the link only and stays allowed, as on OSS, and so do
// moves of ordinary files beside the links.
func TestR105ManagedMoveOntoStateThroughLinkBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"mv a.txt {E}/y/config.yaml", true},
		{"mv -f a.txt {E}/y/config.yaml", true},
		{"mv -- a.txt {E}/y/config.yaml", true},
		{"ln -s {E} e; mv a.txt e/y/config.yaml", true},
		{"ln -s {E}/y e2; mv -f a.txt e2/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; mv a.txt hc/config.yaml", true},
		{"mv a.txt ~/.defenseclaw/config.yaml", true},
		{"mv a.txt {E}/c", false},
		{"mv a.txt {E}/config.yaml", false},
		{"mv a.txt {E}/notes2.txt", false},
		{"mv {E}/notes.txt b.txt", false},
		{"mv a.txt b.txt", false},
		{"ls -la", false},
		{"git status", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, row := range rows {
			home := t.TempDir()
			ext := filepath.Join(t.TempDir(), "ext")
			cwd := filepath.Join(home, "w", "p")
			for _, dir := range []string{filepath.Join(home, ".defenseclaw"), ext, cwd} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			for _, name := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"),
				filepath.Join(ext, "notes.txt"), filepath.Join(cwd, "a.txt")} {
				if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(filepath.Join(home, ".defenseclaw"), filepath.Join(ext, "y")); err != nil {
				t.Fatal(err)
			}
			// Links that name a state file: a move onto one replaces the link.
			for _, name := range []string{"c", "config.yaml"} {
				if err := os.Symlink(filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(ext, name)); err != nil {
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
			// An OSS gateway sees the directory and reads the move the same way.
			oss := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home}
			if blocked := buildVerdict(dispatchTrustedAction(t.Context(), trustedActionRequest{Input: oss,
				Connector: connector, EnforcementCapable: true}), "tool_call").Action == "block"; blocked != row.block {
				t.Errorf("%s OSS %q: block=%v, want %v", connector, row.command, blocked, row.block)
			}
			// The managed gateway does not: its private /tmp and /dev hide
			// the directory the user made.
			if err := os.Rename(ext, ext+".hidden"); err != nil {
				t.Fatal(err)
			}
			// The gateway may also be unable to place the cwd (ProtectHome):
			// it then reads the client directory (managedClientCWD).
			for _, gatewayCWD := range []string{cwd, ""} {
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: gatewayCWD, ActiveHome: home}
				request := trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true,
					ProtectedHomeHook: true, ResolvedWriteTargets: targets}
				findings := dispatchTrustedAction(t.Context(), request)
				if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
					ids := ""
					for _, finding := range findings {
						ids += finding.RuleID + " "
					}
					t.Errorf("%s cwd=%q %q: block=%v, want %v (%s)", connector, gatewayCWD, row.command, blocked, row.block, ids)
				}
			}
		}
	}
}
