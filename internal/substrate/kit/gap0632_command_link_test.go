// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0632: a bare server command the actor's PATH finds through a link
// is reported with the PATH entry itself too, so the gateway sees a link
// of the folder as the folder's; one found with no link has no such fact.
func TestGAP0632KitReportsThePathEntryOfALink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("CLAUDE_CONFIG_DIR", "")
	repo := filepath.Join(home, "work", "repo")
	bin := filepath.Join(repo, "bin")
	outside := filepath.Join(t.TempDir(), "installed")
	for _, d := range []string{bin, outside} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	target := filepath.Join(outside, "interp")
	if err := os.WriteFile(target, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(bin, "gap0632-linked")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bin, "gap0632-plain"), []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, ".mcp.json"), []byte(`{"mcpServers":{"l":{"command":"gap0632-linked","args":["tools/x.py"]},"p":{"command":"gap0632-plain"}}}`), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": repo, "tool_name": "mcp__l__read", "tool_input": map[string]any{}})
	f := CollectFacts("claudecode", "PreToolUse", payload, MaxAttachBytes)
	if f == nil {
		t.Fatal("no facts")
	}
	got := map[string]string{}
	for _, a := range f.Files {
		got[a.Role+" "+a.Path] = string(a.Content)
	}
	resolvedTarget, _ := filepath.EvalSymlinks(target)
	if c := got["mcp_command_path gap0632-linked"]; c != resolvedTarget {
		t.Errorf("resolved command path = %q, want %q", c, resolvedTarget)
	}
	if c := got["mcp_command_path_hit gap0632-linked"]; c != filepath.Join(bin, "gap0632-linked") {
		t.Errorf("PATH entry of the link = %q, want %q", c, filepath.Join(bin, "gap0632-linked"))
	}
	if _, ok := got["mcp_command_path_hit gap0632-plain"]; ok {
		t.Error("a PATH entry reported for a command found with no link")
	}
}
