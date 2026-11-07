// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestBoundedTextOrdinary pins the hook reading of a command whose parse
// exceeded the proof bound (rel-1-0-6:GAP-0675): ordinary project files and
// dotfiles read ordinary, and every word that is, or sits below, a protected
// file, a link on disk, an agent folder, a dot-entry of the home or a name a
// shell may assemble keeps the call unproven.
func TestBoundedTextOrdinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX links and homes")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{".ssh", ".claude", ".defenseclaw", "project/ordinary/.cache", "project/.claude", "project/.git/hooks"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{".ssh/config", ".ssh/authorized_keys", ".claude/settings.json", ".defenseclaw/config.yaml",
		"project/settings.json", "project/.editorconfig", "project/.gitignore", "project/ordinary/.cache/config.json",
		"project/.claude/settings.json", "project/a.txt"} {
		if err := os.WriteFile(filepath.Join(home, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"alias": "../.ssh", "file_alias": "../.ssh/config", "state_alias": "../.defenseclaw", "plain_alias": "a.txt"} {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	prefix := "Write-Output $(.\\a[1]<#x#>); "
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"ordinary settings", prefix + "Remove-Item -Recurse -Force ~/project/settings.json", true},
		{"ordinary dotfile", prefix + "Remove-Item -Force ~/project/.editorconfig", true},
		{"ordinary gitignore", prefix + "Remove-Item -Force " + project + "/.gitignore", true},
		{"ordinary nested dot folder", prefix + "rm ~/project/ordinary/.cache/config.json", true},
		{"ordinary pattern", prefix + "rm *.json", true},
		{"ordinary relative word", prefix + "rm a.txt", true},
		{"ssh control file", prefix + "Remove-Item ~/.ssh/config", false},
		{"authorized keys by name", prefix + "rm authorized_keys.new", false},
		{"folder link to the ssh folder", prefix + "Remove-Item ~/project/alias/config", false},
		{"file link to the ssh folder", prefix + "Remove-Item ~/project/file_alias", false},
		{"folder link to the state", prefix + "Remove-Item ~/project/state_alias/config.yaml", false},
		{"any link on disk", prefix + "Remove-Item ~/project/plain_alias", false},
		{"link of a pattern match", prefix + "rm *_alias", false},
		{"agent folder of the home", prefix + "rm ~/.claude/settings.json", false},
		{"agent folder of the project", prefix + "rm ~/project/.claude/settings.json", false},
		{"git folder of the project", prefix + "rm ~/project/.git/hooks/pre-commit", false},
		{"startup profile", prefix + "rm ~/.bashrc", false},
		{"dot name that does not exist", prefix + "rm ~/project/.sh", false},
		{"home itself", prefix + "rm -r ~/", false},
		{"parent folder", prefix + "rm ../", false},
		{"home variable", prefix + "rm $HOME/x", false},
		{"directory change", prefix + "cd ~/project; rm a.txt", false},
		{"computed home", prefix + "rm $(getent passwd me)/x", false},
		{"pattern in the home", prefix + "rm ~/*", false},
	} {
		if got := BoundedTextOrdinary(row.command, project, home); got != row.want {
			t.Errorf("%s: %q = %t, want %t", row.name, row.command, got, row.want)
		}
	}
	if BoundedTextOrdinary(prefix+"rm a.txt", home, home) {
		t.Error("a call run in the home itself is not ordinary")
	}
	if BoundedTextOrdinary(prefix+"rm a.txt", filepath.Dir(home), home) {
		t.Error("a call run above the home is not ordinary")
	}
	if BoundedTextOrdinary(prefix+strings.Repeat("rm a.txt; ", 400), project, home) {
		t.Error("more words than the bound are unproven")
	}
	if _, ok := Decode(encodeEvidence(t, map[string]string{ParseBoundOrdinaryKey: "1"})); ok {
		t.Error("the fact without the shell-parse-bound reason must be refused")
	}
	if _, ok := Decode(encodeEvidence(t, map[string]string{ParseBoundOrdinaryKey: "1", UnprovenReasonKey: "shell-parse-bound"})); !ok {
		t.Error("the fact with the shell-parse-bound reason must decode")
	}
	if _, ok := Decode(encodeEvidence(t, map[string]string{ParseBoundOrdinaryKey: "yes", UnprovenReasonKey: "shell-parse-bound"})); ok {
		t.Error("only the value 1 must decode")
	}
}

func encodeEvidence(t *testing.T, targets map[string]string) string {
	t.Helper()
	data, err := json.Marshal(targets)
	if err != nil {
		t.Fatal(err)
	}
	return base64.RawURLEncoding.EncodeToString(data)
}
