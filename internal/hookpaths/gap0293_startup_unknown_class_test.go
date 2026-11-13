// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0293: an unknown shell startup (BASH_ENV, ENV, an exported bash
// function) may only take away a proof that a call is safe, never a reading
// that it reaches a protected file. Every site that reads the startup is
// checked over the GAP-0431 client proof rows, without any startup and with
// each kind: an allow proof must not appear, a block reading must not go.
func TestGAP0293StartupUnknownOnlyRemovesAllowProofs(t *testing.T) {
	root := t.TempDir()
	cwd, home := filepath.Join(root, "project"), filepath.Join(root, "home")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(cwd, "keylink")); err != nil {
		t.Fatal(err)
	}
	startup := filepath.Join(root, "startup.sh")
	if err := os.WriteFile(startup, []byte(":\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	type site struct {
		name  string
		allow bool // true: the site proves a call safe; false: it reads a block
		read  func(command string) bool
	}
	sites := []site{
		{"safe-variable-targets", true, func(c string) bool { return actionClientProvedSafeVariableTargetsForHook(c, cwd, home) }},
		{"overwritten-redirect", true, func(c string) bool { return actionClientProvedOverwrittenRedirect(c, cwd, home) }},
		{"no-dereference-touch-safe", true, func(c string) bool { safe, _ := noDereferenceTouchStatus(c, cwd, home); return safe }},
		{"no-dereference-touch-protected", false, func(c string) bool { _, protected := noDereferenceTouchStatus(c, cwd, home); return protected }},
		{"startup-conditional-alias", false, actionStartupConditionalAliasRedirect},
		{"loop-copy-destination", false, func(c string) bool { return actionClientLoopCopyDestinationProtected(c, cwd, home) }},
		{"command-decision", false, func(c string) bool { return ActionCommandDecision(c, cwd, home) != "" }},
	}
	rows := gap0431ClientProofGuardRows()
	// The same rows as touch calls: the write is the touch of the row's
	// target instead of the append (transformed, no new command text).
	for _, row := range gap0431ClientProofGuardRows() {
		if strings.Contains(row.command, `echo m >> "$f"`) {
			row.name += "/touch"
			row.command = strings.Replace(row.command, `echo m >> "$f"`, `touch -h "$f"`, 1)
			rows = append(rows, row)
		}
	}
	clearShellStartupEnv(t)
	base := map[string]bool{}
	for _, s := range sites {
		for _, row := range rows {
			base[s.name+"|"+row.name] = s.read(row.command)
		}
	}
	for _, startupKind := range []struct{ name, variable, value string }{
		{"unrelated-exported-function", "BASH_FUNC_s7probe%%", "() {  :\n}"},
		{"unrelated-patched-export", "BASH_FUNC_s7probe()", "() {  :\n}"},
		{"exported-touch-function", "BASH_FUNC_touch%%", "() {  :\n}"},
		{"startup-file", "BASH_ENV", startup},
	} {
		t.Run(startupKind.name, func(t *testing.T) {
			clearShellStartupEnv(t)
			t.Setenv(startupKind.variable, startupKind.value)
			for _, s := range sites {
				for _, row := range rows {
					was, got := base[s.name+"|"+row.name], s.read(row.command)
					if s.allow && got && !was {
						t.Errorf("%s %s: the startup added a safe proof", s.name, row.name)
					}
					if !s.allow && was && !got {
						t.Errorf("%s %s: the startup removed a protected reading", s.name, row.name)
					}
				}
			}
		})
	}
}
