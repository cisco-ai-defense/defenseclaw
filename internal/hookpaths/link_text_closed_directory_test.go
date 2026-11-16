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

// TestResolveListsTheLinkTextOfALinkIntoAClosedDirectory: a link into a
// directory the user cannot open has no physical answer, so the client lists
// the file the link text leads to; a link the user can resolve keeps its
// physical answer and lists no link text.
func TestResolveListsTheLinkTextOfALinkIntoAClosedDirectory(t *testing.T) {
	root := t.TempDir()
	if resolved, err := filepath.EvalSymlinks(root); err == nil {
		root = resolved
	}
	closed := filepath.Join(root, "closed")
	project := filepath.Join(root, "proj")
	for _, dir := range []string{filepath.Join(closed, "sudoers.d"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	readable := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(readable, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := map[string]string{
		"closed-link":   filepath.Join(closed, "sudoers.d", "ops"),
		"readable-link": readable,
		"chain-link":    filepath.Join(project, "closed-link"),
	}
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(closed, 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	if _, err := os.Lstat(links["closed-link"]); err == nil {
		t.Skip("the directory is open to this user (root)")
	}
	for name, want := range map[string]string{
		"closed-link":   links["closed-link"],
		"chain-link":    links["closed-link"],
		"readable-link": "",
	} {
		link := filepath.Join(project, name)
		payload, err := json.Marshal(map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": project,
			"tool_name": "Write", "tool_input": map[string]any{"file_path": link, "content": "x\n"}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatalf("%s: evidence is not readable", name)
		}
		if got := targets[LinkTextFactPrefix+link]; got != want {
			t.Errorf("%s: link text = %q, want %q", name, got, want)
		}
		if name != "readable-link" && targets[link] != "" {
			t.Errorf("%s: physical answer = %q, want none", name, targets[link])
		}
		if name == "readable-link" && targets[link] != readable {
			t.Errorf("%s: physical answer = %q, want %q", name, targets[link], readable)
		}
	}
}
