// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// gap0545Home is a home with the actor's synthetic key, its authorized keys,
// DefenseClaw state and a project app with links into them (the J19 layout).
func gap0545Home(t *testing.T) (home, app string) {
	t.Helper()
	home = filepath.Join(t.TempDir(), "home", "alice")
	app = filepath.Join(home, "app")
	for _, dir := range []string{".ssh", ".claude", ".defenseclaw", "bak", "app/a/b"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		".ssh/id_ed25519":      "-----BEGIN OPENSSH PRIVATE KEY-----\ngap0545\n-----END OPENSSH PRIVATE KEY-----\n",
		".ssh/authorized_keys": "", ".claude/settings.json": "{}\n", ".defenseclaw/config.yaml": "a: 1\n",
		"app/README.md": "readme\n",
	} {
		if err := os.WriteFile(filepath.Join(home, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{
		"key-link": filepath.Join(home, ".ssh", "id_ed25519"), "a/b/ssh": "../../../.ssh",
		"dc-link": "../.defenseclaw/config.yaml", "claude-dir": "../.claude", "readme-link": "README.md",
	} {
		if err := os.Symlink(target, filepath.Join(app, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	return home, app
}

func gap0545HasWord(f *Facts, word, followed string) bool {
	return f != nil && slices.ContainsFunc(f.Paths, func(p PathFact) bool {
		return p.Field == CommandWordField && p.Path == word && p.Resolved == followed
	})
}

// TestGAP0546KitReadsLinksAsTheKernelWalksThem: a `..` after a symlinked
// folder ascends from the link's target, so Read a/b/ssh/../.ssh/id_ed25519
// is the actor's key (it was cleaned to the missing a/b/.ssh/id_ed25519
// first); the words of cd -P, eval and its quoted body, and a redirect get
// their places; a word that follows no link gets its entry; a link that moves
// nothing gets no fact (substrate-1 GAP-0546, GAP-0547).
func TestGAP0546KitReadsLinksAsTheKernelWalksThem(t *testing.T) {
	home, app := gap0545Home(t)
	key := filepath.Join(home, ".ssh", "id_ed25519")
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": app, "tool_name": "Read",
		"tool_input": map[string]any{"file_path": "a/b/ssh/../.ssh/id_ed25519"}})
	f := CollectFacts("claudecode", "PreToolUse", payload, 1<<20)
	if f == nil || len(f.Paths) != 1 || f.Paths[0].Resolved != key || f.Paths[0].Type != "file" ||
		f.Paths[0].Abs != filepath.Join(app, "a", "b", ".ssh", "id_ed25519") {
		t.Fatalf("Read a/b/ssh/../.ssh/id_ed25519: facts %+v, want resolved %s", f, key)
	}
	for _, row := range []struct {
		command, word, followed string
	}{
		{"cd -P a/b/ssh && cat id_ed25519", "a/b/ssh", filepath.Join(home, ".ssh")},
		{"eval cat a/b/ssh/id_ed25519", "a/b/ssh/id_ed25519", key},
		{`eval "cat key-link"`, "key-link", key},
		{`sh -c 'cat key-link'`, "key-link", key},
		{"echo x >> dc-link", "dc-link", filepath.Join(home, ".defenseclaw", "config.yaml")},
		{"echo x > claude-dir/settings.json", "claude-dir/settings.json", filepath.Join(home, ".claude", "settings.json")},
		{"cp /tmp/x claude-dir/settings.local.json", "claude-dir/settings.local.json", filepath.Join(home, ".claude", "settings.local.json")},
		{"cat --file=key-link", "key-link", key},
	} {
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": app, "tool_name": "Bash",
			"tool_input": map[string]any{"command": row.command}})
		if f := CollectFacts("claudecode", "PreToolUse", payload, 1<<20); !gap0545HasWord(f, row.word, row.followed) {
			t.Errorf("%q: facts %+v, want %s -> %s", row.command, f, row.word, row.followed)
		}
	}
	payload, _ = json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": app, "tool_name": "Bash",
		"tool_input": map[string]any{"command": "rm key-link && cat README.md"}})
	f = CollectFacts("claudecode", "PreToolUse", payload, 1<<20)
	if f == nil || !slices.ContainsFunc(f.Paths, func(p PathFact) bool {
		return p.Path == "key-link" && p.Resolved == key && p.Abs == filepath.Join(app, "key-link")
	}) || slices.ContainsFunc(f.Paths, func(p PathFact) bool { return p.Path == "README.md" }) {
		t.Errorf("rm key-link: facts %+v, want key-link with its target and no fact for README.md", f)
	}
}

// TestGAP0545KitResolvesEveryReviewedFilePathKey: every key a reviewed file
// tool names its file with is one the kit resolves, so a file tool's link
// claim is made whatever key the connector's tool uses (substrate-1
// GAP-0545); and a Cursor beforeReadFile, which has no tool_input, gets the
// facts of the file it names.
func TestGAP0545KitResolvesEveryReviewedFilePathKey(t *testing.T) {
	for _, key := range actionfacts.FileToolPathKeys() {
		if !pathKeys[key] {
			t.Errorf("file-tool path key %q is not resolved by the kit", key)
		}
	}
	home, app := gap0545Home(t)
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": "c", "cwd": app,
		"file_path": "key-link", "content": ""})
	f := CollectFacts("cursor", "beforeReadFile", payload, 1<<20)
	if f == nil || len(f.Paths) != 1 || f.Paths[0].Field != "tool_input.file_path" || f.Paths[0].Resolved != filepath.Join(home, ".ssh", "id_ed25519") {
		t.Fatalf("Cursor beforeReadFile key-link: facts %+v", f)
	}
}
