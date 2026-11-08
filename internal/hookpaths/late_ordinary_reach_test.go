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
// ordinary, also when the protected folders are too big to index; a second
// name of a keys file and of a file in a DefenseClaw or OpenClaw folder are
// not.
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

	// An ordinary alias is never denied for a budget the scan ran out of: over
	// the bound the protected folders are not fully indexed, so a file is not
	// proven protected and stays ordinary (the open tier, with the late-gateway
	// warning; the strict tier never reaches the scan).
	lateSymlink(t, filepath.Join(f.project, "src", "main.go"), filepath.Join(f.project, "srclinkfile"))
	old := lateReachEntries
	lateReachEntries = 2
	t.Cleanup(func() { lateReachEntries = old })
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"hard link of an ordinary file over the bound", "cat hardplain", true},
		{"write to a hard link of an ordinary file over the bound", "echo x > hardplain", true},
		{"file with one name over the bound", "cat src/main.go", true},
		{"ordinary link to it over the bound", "cat srclinkfile", true},
		{"directly named state path over the bound", "cat ../.defenseclaw/config.yaml", false},
		{"hard link of the keys over the bound", "cat hardlink", false},
	})
}

// TestLateOrdinaryCallHomeAndSubtreeBudget: a home with more entries than the
// scan lists, and a protected folder it cannot read, leave an ordinary link
// and an ordinary hard link ordinary; a link to a protected file by name or
// by identity of the listed part still is not.
func TestLateOrdinaryCallHomeAndSubtreeBudget(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Link(filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "hardplain")); err != nil {
		t.Fatal(err)
	}
	lateSymlink(t, filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "plainlink"))
	locked := filepath.Join(f.home, ".openclaw", "locked")
	lateWrite(t, filepath.Join(locked, "settings.json"), "{}\n")
	if os.Geteuid() != 0 {
		if err := os.Chmod(locked, 0); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = os.Chmod(locked, 0o700) })
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"hard link of an ordinary file beside an unreadable state folder", "cat hardplain", true},
		{"ordinary link beside an unreadable state folder", "cat plainlink", true},
		{"link to the keys beside an unreadable state folder", "cat keylink", false},
		{"hard link of the keys beside an unreadable state folder", "cat hardlink", false},
	}
	lateAssertOrdinary(t, f.project, rows)

	old := lateHomeEntries
	lateHomeEntries = 0
	t.Cleanup(func() { lateHomeEntries = old })
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"hard link of an ordinary file in a home over the bound", "cat hardplain", true},
		{"ordinary link in a home over the bound", "cat plainlink", true},
		{"link to the keys in a home over the bound", "cat keylink", false},
	})
}

// TestLateOrdinaryCallUnreadableKeysFolder: a keys folder the scan cannot read
// does not make every link or hard link non-ordinary. An ordinary alias stays
// ordinary (it is not found among the protected files); the keys path named
// directly, and a link to it, still are not.
func TestLateOrdinaryCallUnreadableKeysFolder(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Link(filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "hardplain")); err != nil {
		t.Fatal(err)
	}
	lateSymlink(t, filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "plainlink"))
	if os.Geteuid() == 0 {
		t.Skip("root reads a folder with mode 0")
	}
	ssh := filepath.Join(f.home, ".ssh")
	if err := os.Chmod(ssh, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(ssh, 0o700) })
	lateAssertOrdinary(t, f.project, []struct {
		name, command string
		want          bool
	}{
		{"ordinary link beside an unreadable keys folder", "cat plainlink", true},
		{"hard link of an ordinary file beside an unreadable keys folder", "cat hardplain", true},
		{"file with one name beside an unreadable keys folder", "cat plain.txt", true},
		{"direct keys path beside an unreadable keys folder", "cat ../.ssh/authorized_keys", false},
		{"link to the keys beside an unreadable keys folder", "cat keylink", false},
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
