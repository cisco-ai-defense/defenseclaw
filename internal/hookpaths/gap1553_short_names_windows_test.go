// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// gap1553Name is the spelling Windows gives path through conv (its 8.3
// short name, or the long form of a short path).
func gap1553Name(t *testing.T, path string, conv func(*uint16, *uint16, uint32) (uint32, error)) string {
	t.Helper()
	p, err := windows.UTF16PtrFromString(path)
	if err != nil {
		t.Fatal(err)
	}
	buf := make([]uint16, windows.MAX_LONG_PATH)
	n, err := conv(p, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 || n >= uint32(len(buf)) {
		t.Fatalf("convert %s: %v", path, err)
	}
	return windows.UTF16ToString(buf[:n])
}

// gap1553Tree is a home with .ssh\authorized_keys and project\notes.txt,
// spelled long, and the 8.3 short names of .ssh, authorized_keys and
// project. A volume without 8.3 names cannot show the gap: it fails.
func gap1553Tree(t *testing.T) (home, ssh, keyShort, sshShort, projShort string) {
	t.Helper()
	home = gap1553Name(t, t.TempDir(), windows.GetLongPathName)
	ssh = filepath.Join(home, ".ssh")
	project := filepath.Join(home, "project")
	for _, dir := range []string{ssh, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(ssh, "authorized_keys"), filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	sshShort = filepath.Base(gap1553Name(t, ssh, windows.GetShortPathName))
	keyShort = filepath.Base(gap1553Name(t, filepath.Join(ssh, "authorized_keys"), windows.GetShortPathName))
	projShort = filepath.Base(gap1553Name(t, project, windows.GetShortPathName))
	if sshShort == ".ssh" || keyShort == "authorized_keys" {
		t.Fatalf("the volume of %s has no 8.3 names (%s, %s): run on a volume that makes them", home, sshShort, keyShort)
	}
	return home, ssh, keyShort, sshShort, projShort
}

// rel-1-0-10:GAP-1553: the late reader reads the path Windows opens, so an
// 8.3 short name or a trailing dot of .ssh or authorized_keys names the
// home's keys file as its long spelling does; an ordinary folder's short
// name stays ordinary.
func TestGAP1553LateCallGradeReadsShortAndTrimmedSpellings(t *testing.T) {
	home, ssh, keyShort, sshShort, projShort := gap1553Tree(t)
	for _, row := range []struct {
		name, command, cwd string
		want               Grade
	}{
		{"short .ssh, append", "echo k >> " + sshShort + "/authorized_keys", home, GradeNamed},
		{"short .ssh, read", "cat " + sshShort + "/authorized_keys", home, GradeNamed},
		{"short authorized_keys from .ssh", "cat " + keyShort, ssh, GradeNamed},
		{"trailing dot .ssh.", "cat .ssh./authorized_keys", home, GradeNamed},
		{"long spelling", "cat .ssh/authorized_keys", home, GradeNamed},
		{"short project folder, ordinary", "cat " + projShort + "/notes.txt", home, GradeNone},
		{"trailing dot project folder, ordinary", "cat project./notes.txt", home, GradeNone},
	} {
		t.Run(row.name, func(t *testing.T) {
			if got := LateCallGrade(row.command, row.cwd, home); got != row.want {
				t.Errorf("LateCallGrade(%q) in %s = %v, want %v", row.command, row.cwd, got, row.want)
			}
		})
	}
}
