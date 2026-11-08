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
