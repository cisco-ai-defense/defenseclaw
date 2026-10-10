// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A hard link is compared by file identity (inode, or volume serial and file
// index on Windows), not by its own pathname.
func TestResolveHardLinkToAuthorizedKeys(t *testing.T) {
	// macOS keeps the temp dir under the /var -> /private/var link.
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link, other := filepath.Join(home, "hard.cfg"), filepath.Join(home, "notes.txt")
	if err := os.Link(keys, link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(other, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(home)
	for path, want := range map[string]string{link: keys, other: other} {
		payload, err := json.Marshal(map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": path, "content": "marker"}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok || targets[path] != want {
			t.Fatalf("target of %s = %q, want %q; all=%v", path, targets[path], want, targets)
		}
	}
}
