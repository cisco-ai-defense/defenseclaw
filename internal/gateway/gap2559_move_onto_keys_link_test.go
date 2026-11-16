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

// A plain mv onto a user link to authorized_keys (or to the file
// authorized_keys itself links to) replaces the link and writes neither
// file, so it is allowed on a per-user gateway; it blocked as a key write
// (GAP-2559). A move onto the keys name itself, through any directory
// link, and every writer through the link keep blocking.
func TestR105MoveOntoLinkToAuthorizedKeysReplacesTheLink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX link forms")
	}
	rows := []struct {
		command string
		block   bool
	}{
		{"mv a.txt {E}/k", false},
		{"mv -f a.txt {E}/k", false},
		{"mv -- a.txt {E}/k", false},
		{"mv -fv a.txt {E}/k", false},
		{"mv a.txt {E}/k2", false},
		{"mv a.txt {E}/n", false},
		{"mv a.txt ~/.ssh/authorized_keys", true},
		{"mv -f a.txt \"$HOME/.ssh/authorized_keys\"", true},
		{"mv a.txt {E}/s/authorized_keys", true},
		{"cd ~/.ssh && mv ~/w/p/a.txt authorized_keys", true},
		{"cp a.txt {E}/k", true},
		{"cp a.txt {E}/k2", true},
		{"echo x > {E}/k", true},
		{"cat a.txt >> {E}/k", true},
		{"tee {E}/k < a.txt", true},
		{"mv a.txt {E}/k; echo x >> {E}/k", true},
		{"mv a.txt {E}/k && cp b.txt {E}/k", true},
		{"bash -c \"cp a.txt {E}/k\"", true},
	}
	for _, keysLink := range []bool{false, true} {
		for _, connector := range []string{"claudecode", "codex"} {
			installDefaultProfileConnector(t, connector)
			for _, row := range rows {
				home := filepath.Join(t.TempDir(), "home")
				ext := filepath.Join(t.TempDir(), "ext")
				cwd := filepath.Join(home, "w", "p")
				ssh := filepath.Join(home, ".ssh")
				keys := filepath.Join(home, "keys")
				for _, dir := range []string{ssh, keys, filepath.Join(home, ".defenseclaw"), cwd, ext} {
					if err := os.MkdirAll(dir, 0o700); err != nil {
						t.Fatal(err)
					}
				}
				for _, name := range []string{filepath.Join(keys, "ak"), filepath.Join(keys, "n"),
					filepath.Join(cwd, "a.txt"), filepath.Join(cwd, "b.txt")} {
					if err := os.WriteFile(name, []byte("x\n"), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				authorized := filepath.Join(ssh, "authorized_keys")
				if keysLink {
					if err := os.Symlink(filepath.Join(keys, "ak"), authorized); err != nil {
						t.Fatal(err)
					}
				} else if err := os.WriteFile(authorized, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				k2 := authorized
				if keysLink {
					k2 = filepath.Join(keys, "ak")
				}
				for link, target := range map[string]string{
					filepath.Join(ext, "k"):  authorized,
					filepath.Join(ext, "k2"): k2,
					filepath.Join(ext, "n"):  filepath.Join(keys, "n"),
					filepath.Join(ext, "s"):  ssh,
				} {
					if err := os.Symlink(target, link); err != nil {
						t.Fatal(err)
					}
				}
				t.Setenv("HOME", home)
				command := strings.NewReplacer("{E}", ext).Replace(row.command)
				for _, hint := range []actionfacts.Dialect{"", actionfacts.DialectPOSIX} {
					input := actionfacts.Input{Tool: "Bash", Command: command, CWD: cwd, ActiveHome: home, DialectHint: hint}
					findings := dispatchTrustedAction(t.Context(), trustedActionRequest{Input: input, Connector: connector, EnforcementCapable: true})
					got := strings.Join(FindingStrings(findings), ",")
					if blocked := buildVerdict(findings, "tool_call").Action == "block"; blocked != row.block {
						t.Errorf("keysLink=%v %s hint=%q %q: block=%v, want %v (%s)", keysLink, connector, hint, row.command, blocked, row.block, got)
					}
				}
			}
		}
	}
}
