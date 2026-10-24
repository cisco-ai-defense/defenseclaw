// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestR103B07RelativeLinkThroughLinkedDirectory(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("POSIX link traversal")
	}
	home := t.TempDir()
	c := filepath.Join(home, "c")
	if err := os.MkdirAll(filepath.Join(c, "real"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".ssh", "d"), 0700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("marker\n"), 0600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ id, folder, want string }{
		{"ISSUE-1173", filepath.Join(c, "real"), filepath.Join(c, "ok.txt")},
		{"GAP-1556", filepath.Join(home, ".ssh", "d"), keys},
	} {
		t.Run(tc.id, func(t *testing.T) {
			folder := filepath.Join(c, "b2")
			link := filepath.Join(c, "l2")
			_ = os.Remove(folder)
			_ = os.Remove(link)
			if err := os.Symlink(tc.folder, folder); err != nil {
				t.Fatal(err)
			}
			leaf := "ok.txt"
			if tc.id == "GAP-1556" {
				leaf = "authorized_keys"
			}
			if err := os.Symlink("b2/../"+leaf, link); err != nil {
				t.Fatal(err)
			}
			got, ok := ResolveWriteTarget(link)
			if !ok || got != tc.want {
				t.Fatalf("target=%q ok=%v, want %q", got, ok, tc.want)
			}
			t.Setenv("HOME", home)
			payload, err := json.Marshal(map[string]any{"tool_name": "Bash", "cwd": c,
				"tool_input": map[string]string{"command": "echo hi >> l2"}})
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(Resolve(payload))
			if !ok || targets[link] != tc.want {
				t.Fatalf("resolved target=%q, want %q", targets[link], tc.want)
			}
		})
	}
}
