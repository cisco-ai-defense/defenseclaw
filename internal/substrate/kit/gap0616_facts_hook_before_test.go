// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package kit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestFactsAgentHookBeforeEveryConnectorAndLink (substrate-1 GAP-0616,
// GAP-0618): Claude's settings snapshot is attached for every connector's
// file tool call, and for a path that reaches the settings through a link,
// keyed by the name the call used; a link to a missing settings file is an
// exact empty before-state.
func TestFactsAgentHookBeforeEveryConnectorAndLink(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	settings := filepath.Join(home, ".claude", "settings.json")
	before := []byte(`{"model":"m","hooks":{}}`)
	if err := os.WriteFile(settings, before, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(project, "review-settings.json")
	if err := os.Symlink(settings, link); err != nil {
		t.Fatal(err)
	}
	snapshot := func(connector, tool, file string) []AttachedFile {
		payload, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": project, "tool_name": tool,
			"tool_input": map[string]any{"file_path": file, "old_string": "m", "new_string": "n", "content": "{}"}})
		facts := CollectFacts(connector, "", payload, 1<<20)
		var out []AttachedFile
		if facts != nil {
			for _, f := range facts.Files {
				if f.Role == "agent_hook_config_before" {
					out = append(out, f)
				}
			}
		}
		return out
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tool := range []string{"Write", "Edit", "MultiEdit"} {
			for _, file := range []string{settings, link} {
				files := snapshot(connector, tool, file)
				if len(files) != 1 || files[0].Path != file || files[0].Truncated || string(files[0].Content) != string(before) {
					t.Fatalf("%s %s %s: %+v", connector, tool, file, files)
				}
			}
		}
	}
	if files := snapshot("codex", "Write", filepath.Join(project, "notes.json")); len(files) != 0 {
		t.Fatalf("unrelated file attached: %+v", files)
	}
	if err := os.Remove(settings); err != nil {
		t.Fatal(err)
	}
	files := snapshot("claudecode", "Write", link)
	if len(files) != 1 || files[0].Truncated || files[0].Size != 0 || len(files[0].Content) != 0 || files[0].SHA256 == "" {
		t.Fatalf("link to a missing settings file: %+v", files)
	}
}
