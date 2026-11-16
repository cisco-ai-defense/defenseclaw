// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRegistrationWriteReachRenameOntoARegisteredFile pins that a rename or
// rsync whose destination is a registered file (named, or a folder that
// receives a source of the same name) reaches it, from a straight-line call,
// a runner, a loop and a find child; and that the same calls placing another
// name, or naming the folder only as the -t destination, do not.
func TestRegistrationWriteReachRenameOntoARegisteredFile(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	project := filepath.Join(home, "proj")
	folder := filepath.Join(home, ".claude")
	settings := filepath.Join(folder, "settings.json")
	for _, path := range []string{settings, filepath.Join(project, "notes.txt"), filepath.Join(project, "settings.json")} {
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{settings, folder}
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"mv notes.txt " + settings, true},
		{"mv -f notes.txt ~/.claude/settings.json", true},
		{"mv -t " + folder + " settings.json", true},
		{"mv settings.json " + folder, true},
		{"env mv notes.txt " + settings, true},
		{"mv -ft /tmp " + settings, true},
		{"for f in settings.json; do mv \"$f\" " + folder + "; done", true},
		{"find . -name notes.txt -exec mv {} " + settings + " +", true},
		{"rsync notes.txt " + settings, true},
		{"rsync -a settings.json " + folder, true},
		{"rsync --remove-source-files " + settings + " /tmp/aside", true},
		{"mv notes.txt " + filepath.Join(folder, "notes.txt"), false},
		{"mv notes.txt " + folder, false},
		{"mv -t " + folder + " notes.txt", false},
		{"for f in notes.txt; do mv \"$f\" " + folder + "; done", false},
		{"find . -name notes.txt -exec mv {} " + folder + " +", false},
		{"rsync -a notes.txt " + folder, false},
		{"rsync notes.txt host:.claude/settings.json", false},
		{"rsync -a " + settings + " /tmp/backup.json", false},
	} {
		if got := len(RegistrationWriteReached(tc.command, project, home, names)) > 0; got != tc.want {
			t.Errorf("%q: reached %v, want %v", tc.command, got, tc.want)
		}
	}
}
