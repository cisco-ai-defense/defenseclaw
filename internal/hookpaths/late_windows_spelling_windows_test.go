// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The late reader reads the Windows spellings of a Git Bash call as the host
// does: a protected file named with backslashes or through a drive mount is
// named; a file it does not protect is ordinary; a process alias is unproved.
func TestLateCallGradeReadsTheWindowsSpellingsOfAGitBashCall(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{cwd, ssh} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(ssh, "authorized_keys")
	notes := filepath.Join(cwd, "notes")
	for _, file := range []string{key, notes} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mount := func(path string) string {
		volume := filepath.VolumeName(path)
		return "/" + strings.ToLower(volume[:1]) + filepath.ToSlash(path[len(volume):])
	}
	for _, row := range []struct {
		name, command string
		want          Grade
	}{
		{"backslash protected", "cat " + key, GradeNamed},
		{"backslash protected wrapper", "exec -a " + key + " bash -c " + "\"cat notes\"", GradeNamed},
		{"drive mount protected", "cat " + mount(key), GradeNamed},
		{"cygdrive mount protected", "cat /cygdrive" + mount(key), GradeNamed},
		{"backslash ordinary", "cat " + notes, GradeNone},
		{"drive mount ordinary", "cat " + mount(notes), GradeNone},
		{"relative ordinary", "cat notes", GradeNone},
		{"process alias", "cat /proc/self/cwd/notes", GradePossible},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := LateCallGrade(row.command, cwd, home); got != row.want {
				t.Errorf("LateCallGrade(%q)=%v, want %v", row.command, got, row.want)
			}
		})
	}
}
