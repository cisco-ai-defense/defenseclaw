// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
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

// A given home that is no folder (missing, relative, a regular file) cannot
// index the protected files. The scan tells the account database home
// instead and treats any hard-linked regular file as not ordinary, so a
// protected hard link stays closed and an ordinary call stays ordinary.
func TestLateOrdinaryCallAtWithAHomeThatIsNoFolder(t *testing.T) {
	f := newLateFixture(t)
	for _, home := range []string{"relative/home", filepath.Join(f.home, "missing"), filepath.Join(f.project, "plain.txt")} {
		for _, tc := range []struct {
			name, command string
			want          bool
		}{
			{"hard link to the keys", "cat hardlink", false},
			{"hard link first of a long list", lateOperands(5000, "hardlink", "first"), false},
			{"hard link last of a long list", lateOperands(5000, "hardlink", "last"), false},
			{"hard link by absolute path", "cat " + filepath.Join(f.project, "hardlink"), false},
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
