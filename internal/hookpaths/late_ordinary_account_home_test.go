// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A shell hook replaces HOME with a scratch folder before it runs the helper,
// so the helper tells the protected files against the account home it is
// given, not against HOME. Hard links, whose identity is found only in the
// home's protected folders, were the one spelling that went missing.
func TestLateOrdinaryCallAtTellsProtectedFilesAgainstTheAccountHome(t *testing.T) {
	f := newLateFixture(t)
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", scratch)
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"hard link to the keys", "cat hardlink", false},
		{"hard link first of a long list", lateOperands(5000, "hardlink", "first"), false},
		{"hard link last of a long list", lateOperands(5000, "hardlink", "last"), false},
		{"hard link by absolute path", "cat " + filepath.Join(f.project, "hardlink"), false},
		{"link to the keys", "cat keylink", false},
		{"keys path", "cat ../.ssh/authorized_keys", false},
		{"home itself", "ls " + f.home, false},
		// Benign twins stay ordinary.
		{"plain file", "cat plain.txt", true},
		{"long list of plain names", lateOperands(5000, "", ""), true},
		{"ordinary link", "cat l", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct{ connector, tool string }{{"claudecode", "Bash"}, {"codex", "Bash"}} {
				payload := lateBash(t, c.tool, f.project, tc.command)
				if got := LateOrdinaryCallAt(f.home, c.connector, payload); got != tc.want {
					t.Errorf("%s: ordinary=%v, want %v, command=%.80q", c.connector, got, tc.want, tc.command)
				}
			}
		})
	}
}

// A given home that is no folder (missing, relative, a regular file) holds no
// protected file of its own. The scan indexes the homes the call can mean (the
// account database home, the home of the process, a relative home read against
// the folder of the call), so a protected hard link stays closed and a hard
// link to an ordinary file stays ordinary, as with a usable home.
func TestLateOrdinaryCallAtWithAHomeThatIsNoFolder(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Link(filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "hl-plain")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(f.project, "hardlink"), filepath.Join(f.project, "l-hard")); err != nil {
		t.Fatal(err)
	}
	for _, home := range []string{"relative/home", filepath.Join(f.home, "missing"), filepath.Join(f.project, "plain.txt")} {
		for _, tc := range []struct {
			name, command string
			want          bool
		}{
			{"hard link to the keys", "cat hardlink", false},
			{"hard link first of a long list", lateOperands(5000, "hardlink", "first"), false},
			{"hard link last of a long list", lateOperands(5000, "hardlink", "last"), false},
			{"hard link by absolute path", "cat " + filepath.Join(f.project, "hardlink"), false},
			{"link to a hard link of the keys", "cat l-hard", false},
			{"hard link of an ordinary file", "cat hl-plain", true},
			{"hard link of an ordinary file in a long list", lateOperands(5000, "hl-plain", "last"), true},
			{"long list of plain names", lateOperands(5000, "", ""), true},
			{"plain file", "cat plain.txt", true},
		} {
			t.Run(tc.name+" "+filepath.Base(home), func(t *testing.T) {
				for _, connector := range []string{"claudecode", "codex"} {
					payload := lateBash(t, "Bash", f.project, tc.command)
					if got := LateOrdinaryCallAt(home, connector, payload); got != tc.want {
						t.Errorf("%s home %q: ordinary=%v, want %v", connector, home, got, tc.want)
					}
				}
			})
		}
	}
}

// A relative home is read against the folder of the call, so the protected
// files of the folder it names are indexed even when the home of the process
// is another folder.
func TestLateOrdinaryCallAtReadsARelativeHomeAgainstTheCallFolder(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Link(filepath.Join(f.project, "plain.txt"), filepath.Join(f.project, "hl-plain")); err != nil {
		t.Fatal(err)
	}
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", scratch)
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"cat hardlink", false},
		{lateOperands(5000, "hardlink", "last"), false},
		{"cat hl-plain", true},
		{lateOperands(5000, "hl-plain", "first"), true},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			payload := lateBash(t, "Bash", f.project, tc.command)
			if got := LateOrdinaryCallAt("..", connector, payload); got != tc.want {
				t.Errorf("%s: ordinary=%v, want %v, command=%.60q", connector, got, tc.want, tc.command)
			}
		}
	}
}

// A relative home whose parent step comes after a link names the folder the
// file system reaches, not the one a text clean-up of the path gives: the
// protected files of that folder are indexed, so a protected hard link stays
// closed and a hard link to an ordinary file stays ordinary.
func TestLateOrdinaryCallAtReadsARelativeHomeWithALinkBeforeAParentStep(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Symlink(f.project, filepath.Join(f.project, "fold")); err != nil {
		t.Fatal(err)
	}
	for _, link := range [][2]string{{"plain.txt", "hl-plain"}, {"hardlink", "hl-keys-2"}} {
		if err := os.Link(filepath.Join(f.project, link[0]), filepath.Join(f.project, link[1])); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range [][2]string{{"hl-plain", "l-plain"}, {"hl-keys-2", "l-keys"}} {
		if err := os.Symlink(filepath.Join(f.project, link[0]), filepath.Join(f.project, link[1])); err != nil {
			t.Fatal(err)
		}
	}
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", scratch)
	saved := "fold" + string(filepath.Separator) + ".."
	if real, err := filepath.EvalSymlinks(f.project + string(filepath.Separator) + saved); err != nil || real != f.home {
		t.Fatalf("saved home should reach %q, got %q: %v", f.home, real, err)
	}
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"hard link to the keys", "cat hardlink", false},
		{"hard link first of a long list", lateOperands(5000, "hardlink", "first"), false},
		{"hard link last of a long list", lateOperands(5000, "hardlink", "last"), false},
		{"hard link by absolute path", "cat " + filepath.Join(f.project, "hardlink"), false},
		{"second hard link to the keys", "cat hl-keys-2", false},
		{"link to the second hard link", "cat l-keys", false},
		{"hard link of an ordinary file", "cat hl-plain", true},
		{"link to a hard link of an ordinary file", "cat l-plain", true},
		{"hard link of an ordinary file in a long list", lateOperands(5000, "hl-plain", "last"), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				payload := lateBash(t, "Bash", f.project, tc.command)
				if got := LateOrdinaryCallAt(saved, connector, payload); got != tc.want {
					t.Errorf("%s: ordinary=%v, want %v", connector, got, tc.want)
				}
			}
		})
	}
}

// A relative workdir is read by file system rules: a link before a parent
// step leads somewhere else than a text clean-up of the path does. The
// protected hard link in the folder the file system reaches stays closed, an
// ordinary file there stays ordinary, and the same file name in the folder a
// clean-up would name decides nothing. Both connectors, an absolute and a
// relative saved home.
func TestLateOrdinaryCallAtReadsARelativeWorkdirWithALinkBeforeAParentStep(t *testing.T) {
	f := newLateFixture(t)
	if err := os.Symlink(f.project, filepath.Join(f.project, "fold")); err != nil {
		t.Fatal(err)
	}
	// "alias" is a hard link to the keys in the folder the workdir reaches
	// and an ordinary file in the project a text clean-up would name.
	if err := os.Link(filepath.Join(f.home, ".ssh", "authorized_keys"), filepath.Join(f.home, "alias")); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{filepath.Join(f.project, "alias"), filepath.Join(f.home, "note.txt")} {
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(filepath.Join(f.home, "note.txt"), filepath.Join(f.home, "note-hl")); err != nil {
		t.Fatal(err)
	}
	scratch, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", scratch)
	workdir := "fold" + string(filepath.Separator) + ".."
	if real, err := filepath.EvalSymlinks(f.project + string(filepath.Separator) + workdir); err != nil || real != f.home {
		t.Fatalf("workdir should reach %q, got %q: %v", f.home, real, err)
	}
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"hard link to the keys", "touch alias", false},
		{"hard link first of a long list", lateOperands(5000, "alias", "first"), false},
		{"hard link last of a long list", lateOperands(5000, "alias", "last"), false},
		{"hard link by absolute path", "touch " + filepath.Join(f.home, "alias"), false},
		{"ordinary file", "cat note.txt", true},
		{"hard link of an ordinary file", "cat note-hl", true},
		{"hard link of an ordinary file in a long list", lateOperands(5000, "note-hl", "last"), true},
		{"long list of plain names", lateOperands(5000, "", ""), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, c := range []struct{ connector, tool, field string }{
				{"claudecode", "Bash", "command"}, {"codex", "exec_command", "cmd"}, {"codex", "shell", "command"},
			} {
				payload, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": f.project,
					"tool_name": c.tool, "tool_input": map[string]any{c.field: tc.command, "workdir": workdir}})
				if err != nil {
					t.Fatal(err)
				}
				for _, saved := range []string{f.home, "."} {
					if got := LateOrdinaryCallAt(saved, c.connector, payload); got != tc.want {
						t.Errorf("%s %s saved home %q: ordinary=%v, want %v", c.connector, c.tool, saved, got, tc.want)
					}
				}
			}
		})
	}
}
