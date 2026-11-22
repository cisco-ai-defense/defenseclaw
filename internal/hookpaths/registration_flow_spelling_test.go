// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-0154: on a Windows home the registered hook configs are
// backslash paths (C:\Users\x\.codex\config.toml) while a Git Bash call spells
// the home ~/ and the rest with slashes. The flow net compared them as
// written, so eval "cp x ~/.codex/config.toml" > f and tar -xf x.tar -C
// ~/.codex config.toml reached no hook config. The rows are the same on every
// OS: they only failed where the home has backslashes.
func TestGAP0154FlowNetReadsGitBashSpellingOfAHookConfig(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "proj")
	var names []string
	for _, rel := range []string{".claude/settings.json", ".codex/config.toml"} {
		path := filepath.Join(home, rel)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		names = append(names, path)
	}
	rows := []struct {
		command string
		reach   bool
	}{
		{`eval "cp /tmp/gap0154-x ~/.codex/config.toml" > /tmp/gap0154-f`, true},
		{`eval "echo '{}' > $HOME/.claude/settings.json" > /tmp/gap0154-f`, true},
		// A call that names no hook config.
		{`eval "echo hi" > /tmp/gap0154-f`, false},
	}
	for _, row := range rows {
		if got := len(RegistrationWriteReached(row.command, cwd, home, names)) > 0; got != row.reach {
			t.Errorf("%q: reaches %v, want %v", row.command, got, row.reach)
		}
	}
}

// rel-1-0-10:GAP-0154: an extraction that names a hook config as its member
// (tar -C ~/.codex config.toml, unzip x.zip config.toml -d ~/.codex) is a
// possible write of it however the home is spelled; one that names another
// member is none.
func TestGAP0154ArchiveMemberOfAHookConfigIsReached(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	cwd := filepath.Join(home, "proj")
	path := filepath.Join(home, ".codex", "config.toml")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		command string
		reach   bool
	}{
		{`tar -xf /tmp/gap0154.tar -C ~/.codex config.toml`, true},
		{`tar -xf /tmp/gap0154.tar -C $HOME/.codex config.toml`, true},
		{`unzip /tmp/gap0154.zip config.toml -d ~/.codex`, true},
		{`tar -xf /tmp/gap0154.tar -C ~/.codex notes.txt`, false},
		{`unzip /tmp/gap0154.zip notes.txt -d ~/.codex`, false},
	}
	for _, row := range rows {
		got := RegistrationArchivePossibleReach(row.command, cwd, home, []string{path}) != ""
		if got != row.reach {
			t.Errorf("%q: reaches %v, want %v", row.command, got, row.reach)
		}
	}
}
