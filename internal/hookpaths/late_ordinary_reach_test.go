// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

func lateWrite(t *testing.T, path, text string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func lateSymlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
}

func lateAssertOrdinary(t *testing.T, project string, rows []struct {
	name, command string
	want          bool
}) {
	t.Helper()
	for _, tc := range rows {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct{ connector, tool string }{{"claudecode", "Bash"}, {"codex", "exec_command"}} {
				if got := LateOrdinaryCall(c.connector, lateBash(t, c.tool, project, tc.command)); got != tc.want {
					t.Errorf("%s: ordinary=%v, want %v, command=%q", c.connector, got, tc.want, tc.command)
				}
			}
		})
	}
}

// TestLateOrdinaryCallLinkHops: a link is as ordinary as every place it
// passes through and the identity it ends at. A link to a protected link, to
// the place a protected file was moved to, or into a protected folder that
// was moved, is not ordinary whatever the last name looks like; a link to an
// ordinary file or folder is.
func TestLateOrdinaryCallLinkHops(t *testing.T) {
	f := newLateFixture(t)
	keys := filepath.Join(f.home, ".ssh", "authorized_keys")
	moved := filepath.Join(f.project, "moved")
	lateWrite(t, moved, "# decoy\n")
	if err := os.Remove(keys); err != nil {
		t.Fatal(err)
	}
	lateSymlink(t, moved, keys)
	// keylink (made by the fixture) leads to the keys path, which leads to moved.
	lateSymlink(t, moved, filepath.Join(f.project, "movedlink"))
	lateSymlink(t, filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "plainlink"))
	lateSymlink(t, filepath.Join(f.project, "plainlink"), filepath.Join(f.project, "plainhop"))
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"hop through a protected link", "cat keylink", false},
		{"write through a protected link", "echo x > keylink", false},
		{"direct protected path", "cat ../.ssh/authorized_keys", false},
		{"link to the place the keys were moved to", "cat movedlink", false},
		{"write to the place the keys were moved to", "echo x > movedlink", false},
		{"link to an ordinary link", "cat plainhop", true},
		{"ordinary link", "cat l", true},
		{"ordinary file", "cat plain.txt", true},
	})

	// The whole protected folder was moved to a place with an ordinary name.
	g := newLateFixture(t)
	store := filepath.Join(filepath.Dir(g.home), "store")
	if err := os.Rename(filepath.Join(g.home, ".ssh"), store); err != nil {
		t.Fatal(err)
	}
	lateSymlink(t, store, filepath.Join(g.home, ".ssh"))
	lateWrite(t, filepath.Join(store, "id_alt"), "# decoy\n")
	lateSymlink(t, store, filepath.Join(g.project, "storelink"))
	lateSymlink(t, filepath.Join(store, "id_alt"), filepath.Join(g.project, "altlink"))
	lateWrite(t, filepath.Join(g.project, "other", "note.txt"), "x\n")
	lateSymlink(t, filepath.Join(g.project, "other"), filepath.Join(g.project, "otherlink"))
	lateAssertOrdinary(t, g.project, []struct {
		name, command string
		want          bool
	}{
		{"link to the moved folder", "ls storelink", false},
		{"entry below the moved folder", "cat storelink/id_alt", false},
		{"link to an entry of the moved folder", "cat altlink", false},
		{"link to an ordinary folder", "ls otherlink", true},
		{"entry below an ordinary linked folder", "cat otherlink/note.txt", true},
	})
}

// TestLateOrdinaryCallHardLinks: a hard link is protected only when it is the
// same file as a protected one. An ordinary file with a second name is
// ordinary; a second name of a keys file, of a file in a DefenseClaw or
// OpenClaw folder, and any hard link when the protected folders are too big
// to index, are not.
func TestLateOrdinaryCallHardLinks(t *testing.T) {
	f := newLateFixture(t)
	lateWrite(t, filepath.Join(f.project, "src", "other.txt"), "x\n")
	for link, source := range map[string]string{
		"hardplain": filepath.Join(f.project, "plain.txt"),
		"hardsrc":   filepath.Join(f.project, "src", "other.txt"),
	} {
		if err := os.Link(source, filepath.Join(f.project, link)); err != nil {
			t.Fatal(err)
		}
	}
	state := filepath.Join(f.home, ".defenseclaw", "config.yaml")
	lateWrite(t, state, "a: 1\n")
	nested := filepath.Join(f.home, ".openclaw", "work", "deep", "settings.json")
	lateWrite(t, nested, "{}\n")
	for link, source := range map[string]string{"statecopy": state, "nestedcopy": nested} {
		if err := os.Link(source, filepath.Join(f.project, link)); err != nil {
			t.Fatal(err)
		}
	}
	lateSymlink(t, filepath.Join(f.project, "hardplain"), filepath.Join(f.project, "linktohard"))
	rows := []struct {
		name, command string
		want          bool
	}{
		{"hard link of an ordinary file", "cat hardplain", true},
		{"both names of an ordinary file", "cat plain.txt hardplain", true},
		{"hard link of a file in a folder", "cat hardsrc", true},
		{"link to a hard link of an ordinary file", "cat linktohard", true},
		{"write to a hard link of an ordinary file", "echo x > hardplain", true},
		{"hard link of the keys", "cat hardlink", false},
		{"hard link of a state file", "cat statecopy", false},
		{"hard link of a deep file of another state folder", "cat nestedcopy", false},
	}
	lateAssertOrdinary(t, f.project, rows)

	// Over the bound the identity of the protected folders is not known: every
	// hard link is then not ordinary, a plain file still is.
	lateSymlink(t, filepath.Join(f.project, "src", "main.go"), filepath.Join(f.project, "srclinkfile"))
	old := lateReachEntries
	lateReachEntries = 2
	t.Cleanup(func() { lateReachEntries = old })
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"hard link of an ordinary file over the bound", "cat hardplain", false},
		{"file with one name over the bound", "cat src/main.go", true},
		{"ordinary link to it over the bound", "cat srclinkfile", true},
	})
}

// TestLateOrdinaryCallGrepFileOptionValue: the word after -f or --file is a
// file whatever it looks like, so a link named like an option is read as a
// path; the same option next to a plain file or no such file stays ordinary.
func TestLateOrdinaryCallGrepFileOptionValue(t *testing.T) {
	f := newLateFixture(t)
	keys := filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, name := range []string{"-e", "--regexp"} {
		lateSymlink(t, keys, filepath.Join(f.project, name))
	}
	lateWrite(t, filepath.Join(f.project, "patterns.txt"), "x\n")
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"short file option, next word an option-shaped link", "grep -f -e x plain.txt", false},
		{"long file option, next word an option-shaped link", "grep --file --regexp x plain.txt", false},
		{"clustered short file option", "grep -if -e x plain.txt", false},
		{"file option with the link attached", "grep -f-e x plain.txt", false},
		{"long file option with the link attached", "grep --file=--regexp x plain.txt", false},
		{"file option and a direct link", "grep -f keylink plain.txt", false},
		{"file option and a plain patterns file", "grep -f patterns.txt plain.txt", true},
		{"long file option and a plain patterns file", "grep --file patterns.txt plain.txt", true},
		{"pattern option next to a plain file", "grep -e x plain.txt", true},
		{"pattern option whose value reads like a file option", "grep -e -f plain.txt", true},
		{"file option, next word an option name with no such file", "grep -f -x x plain.txt", true},
		{"pattern as the first operand", "grep -n pattern plain.txt", true},
	})
}
