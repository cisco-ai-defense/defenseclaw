// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// POSIX symlinks and homes; the link walk itself is pinned on every OS by
// the hookpaths tests.

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0684: a Hermes native write (V4A patch, replace, write_file) of a
// project link that leads into ~/.defenseclaw writes the state file the
// link names, so it is blocked like the same write of the state path. Links
// to ordinary files, in the project or the home, stay allowed.
func TestHermesWritesThroughALinkToDefenseClawStateAreBlocked(t *testing.T) {
	const rule = "tamper.detector_state_write"
	home, project := hermesPatchHome(t)
	policies := filepath.Join(home, ".defenseclaw", "policies")
	if err := os.MkdirAll(policies, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(policies, "custom.yaml"), []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, "todo.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	links := []struct {
		name, target string
		block        bool
	}{
		{"state-abs", filepath.Join(policies, "custom.yaml"), true},
		{"state-abs-new", filepath.Join(policies, "new.yaml"), true},
		{"state-rel-new", "../.defenseclaw/policies/new.yaml", true},
		{"project-file", "notes.txt", false},
		{"project-new", "draft.txt", false},
		{"home-file", filepath.Join(home, "todo.txt"), false},
	}
	for _, link := range links {
		if err := os.Symlink(link.target, filepath.Join(project, link.name)); err != nil {
			t.Fatal(err)
		}
	}
	for _, call := range hermesPatchCalls() {
		for _, link := range links {
			t.Run(call.name+"/"+link.name, func(t *testing.T) {
				got := hermesPatchHostHook(t, home, project, hermesPatchBody(t, project, call.tool, call.args(link.name)))
				var resp map[string]any
				if err := json.Unmarshal([]byte(got), &resp); err != nil {
					t.Fatalf("verdict %q: %v", got, err)
				}
				blocked := resp["action"] == "block" && strings.Contains(got, rule)
				if blocked != link.block || !link.block && resp["action"] != "allow" {
					t.Fatalf("action %v, want block by %s = %t: %.800s", resp["action"], rule, link.block, got)
				}
			})
		}
	}
}
