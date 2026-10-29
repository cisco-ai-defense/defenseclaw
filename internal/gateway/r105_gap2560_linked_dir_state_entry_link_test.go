// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// A move onto a DefenseClaw state entry replaces that entry, so it is the
// state write whether the entry is a file or a link the user made to a file
// elsewhere, and whatever directory spelling reaches it: mv a.txt
// /ext/y/config.yaml with y -> ~/.defenseclaw and config.yaml ->
// ~/dot/dc.yaml was ALLOW on OSS (GAP-2560). Reads of the entry and moves
// onto ordinary names beside it stay allowed.
func TestR105LinkedDirMoveOntoStateEntryLinkBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	home := filepath.Join(t.TempDir(), "home")
	ext := filepath.Join(t.TempDir(), "ext")
	cwd := filepath.Join(home, "w", "p")
	state := filepath.Join(home, ".defenseclaw")
	dot := filepath.Join(home, "dot")
	for _, dir := range []string{state, dot, filepath.Join(home, "src"), cwd, ext} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{filepath.Join(dot, "dc.yaml"), filepath.Join(state, "other.yaml"),
		filepath.Join(cwd, "a.txt")} {
		if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for link, target := range map[string]string{
		filepath.Join(state, "config.yaml"):       filepath.Join(dot, "dc.yaml"),
		filepath.Join(ext, "y"):                   state,
		filepath.Join(ext, "s"):                   filepath.Join(home, "src"),
		filepath.Join(home, "src", "config.yaml"): filepath.Join(dot, "dc.yaml"),
	} {
		if err := os.Symlink(target, link); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct {
		command string
		block   bool
	}{
		{"mv a.txt {E}/y/config.yaml", true},
		{"mv -f a.txt {E}/y/config.yaml", true},
		{"mv -- a.txt {E}/y/config.yaml", true},
		{"cd {E}/y && mv ~/w/p/a.txt config.yaml", true},
		{"mv a.txt ~/.defenseclaw/config.yaml", true},
		{"cat {E}/y/config.yaml", false},
		{"ls -l {E}/y/config.yaml", false},
		{"mv a.txt {E}/s/config.yaml", false},
		{"mv a.txt {E}/y/notes.txt", false},
		{"mv a.txt ~/dot/new.yaml", false},
	}
	replacer := strings.NewReplacer("{E}", ext)
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
			for _, row := range rows {
				command := replacer.Replace(row.command)
				input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
				findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
				got := strings.Join(FindingStrings(findings), ",")
				blocked := buildVerdict(findings, "tool_call").Action == "block"
				if blocked != row.block {
					t.Errorf("%s hint=%q %q: block=%v, want %v (%s)", connector, hint, row.command, blocked, row.block, got)
				}
				if row.block && !strings.Contains(got, "tamper.detector_state_write") {
					t.Errorf("%s hint=%q %q: want tamper.detector_state_write, got %s", connector, hint, row.command, got)
				}
			}
		}
	}
}
