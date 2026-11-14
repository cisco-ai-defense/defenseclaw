// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// gap0398AliasRows are the GAP-1445 rows that name the keydir alias by a
// pattern (review rows A0-A6 and the other keyd rows), from
// globAliasProtectedCommands of base.
func gap0398AliasRows(t *testing.T, base string) []string {
	t.Helper()
	var rows []string
	for _, command := range globAliasProtectedCommands(base) {
		if strings.Contains(command, "keyd") && !strings.HasPrefix(command, "cd ") {
			rows = append(rows, command)
		}
	}
	if len(rows) < 8 {
		t.Fatalf("only %d GAP-1445 rows name the alias", len(rows))
	}
	return rows
}

func gap0398POSIX(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("POSIX links and patterns")
	}
}

// rel-1-0-10:GAP-0398 (review P1-1, probes R4 and G3): a link to ~/.ssh in a
// folder away from the home is selected by a pattern whose later
// components select the link. The walk follows a link of any name, so
// every alias row is a protected target in a small and in a busy folder,
// without the shell word resolver.
func TestGAP0398NameGateKeepsOutsideAliasRows(t *testing.T) {
	gap0398POSIX(t)
	home, _ := globAliasFixture(t)
	outside := t.TempDir()
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(outside, "keydir")); err != nil {
		t.Fatal(err)
	}
	rows := gap0398AliasRows(t, outside)
	check := func(label string, busy bool) {
		for _, command := range rows {
			if busy && globHeldDecision(command, outside, home, nil) == globHeld {
				continue // the walk passed its bound: an unknown target (GAP-0401 moves it to the shared bound)
			}
			if got := posixShellDecision(command, outside, home); got != "protected-target" {
				t.Errorf("%s: row %d: decision = %q, want protected-target", label, gap0398Index(rows, command), got)
			}
		}
	}
	check("small folder", false)
	fillDir(t, outside, actionGlobMaxNames+1)
	check("busy folder", true)
	// The literal spellings through the link stay protected targets.
	literal := strings.NewReplacer("keyd*", "keydir", "keyd?r", "keydir")
	for i, command := range rows {
		if got := posixShellDecision(literal.Replace(command), outside, home); got != "protected-target" {
			t.Errorf("literal row %d: decision = %q, want protected-target", i, got)
		}
	}
	// The GAP-0270 read shapes in the same folder select no link: no
	// verdict.
	for i, command := range gap0270ReadShapes(outside) {
		if got := gap0270Read(command, outside, home); got.decision != "" || got.unproven != "" || got.truncated || got.keyRead {
			t.Errorf("read shape S%d beside the link: verdict %+v, want none", i, got)
		}
	}
}

func gap0398Index(rows []string, command string) int {
	for i, row := range rows {
		if row == command {
			return i
		}
	}
	return -1
}

// rel-1-0-10:GAP-0399 (review P2-1, probe K1): a key read through a link to
// the key file in a folder away from the home, named by a pattern, resolves
// every match, as the GAP-1780 alias rows do inside the home.
func TestGAP0399KeyGlobThroughOutsideLink(t *testing.T) {
	gap0398POSIX(t)
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "id_ed25519"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(root, "away")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	// The GAP-1780 aliases: dirlink (K0) to the .ssh folder, keyl (K1) to
	// the key file.
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(outside, "dirlink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(outside, "keyl")); err != nil {
		t.Fatal(err)
	}
	check := func(label string) {
		for i, command := range gap1780AliasRows {
			if !posixShellPrivateKeyRead(command, outside, home) {
				t.Errorf("%s: K%d: not a key read through the outside alias", label, i)
			}
		}
	}
	check("small folder")
	fillDir(t, outside, 64)
	check("folder with more names")
}

// rel-1-0-10:GAP-0400 (review P2-2, probes R1-R3): ".." after a link is
// resolved after the link, as the kernel does, not removed by name. plink,
// in a folder away from the home, leads to project/sub; plink/.. is the
// project, where keydir leads to ~/.ssh. The append-redirect row (A3) is a
// protected target again, and no row is a plain allow.
func TestGAP0400DotDotAfterLink(t *testing.T) {
	gap0398POSIX(t)
	home, cwd := globAliasFixture(t)
	outside := t.TempDir()
	plink := filepath.Join(outside, "plink")
	if err := os.Symlink(filepath.Join(cwd, "sub"), plink); err != nil {
		t.Fatal(err)
	}
	type spelling struct {
		name, cwd string
		rewrite   func(string) string
	}
	for _, s := range []spelling{
		{"R1 relative", outside, func(c string) string { return strings.Replace(c, "keyd", "plink/../keyd", 1) }},
		{"R2 absolute", outside, func(c string) string { return strings.Replace(c, "keyd", plink+"/../keyd", 1) }},
		{"R3 logical cwd", plink, func(c string) string { return strings.Replace(c, "keyd", "../keyd", 1) }},
	} {
		appendRow := false
		for i, command := range gap0398AliasRows(t, s.cwd) {
			if strings.Contains(command, s.cwd+"/keyd") {
				continue // the row that names the cwd itself
			}
			command = s.rewrite(command)
			decision := posixShellDecision(command, s.cwd, home)
			if strings.Contains(command, ">>") {
				appendRow = true
				if decision != "protected-target" {
					t.Errorf("%s: A3: decision = %q, want protected-target", s.name, decision)
				}
			}
			if decision == "" && UnprovenProtectedWrite(command, s.cwd, home) == "" {
				t.Errorf("%s: row %d: a plain allow", s.name, i)
			}
		}
		if !appendRow {
			t.Fatalf("%s: no append-redirect row", s.name)
		}
	}
}
