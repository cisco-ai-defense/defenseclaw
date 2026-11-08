// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
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
