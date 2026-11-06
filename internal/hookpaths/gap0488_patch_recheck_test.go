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

// GAP-0488, GAP-0073: PatchEvidenceChanged is true only for a patch the hook
// attested complete whose targets read differently a second time.
func TestGAP0488PatchEvidenceChangedFollowsTheTargets(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	target := filepath.Join(project, "swap.txt")
	for path, content := range map[string]string{keys: "k\n", target: "x\n"} {
		if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	patch := "*** Begin Patch\n*** Update File: swap.txt\n@@\n x\n+y\n*** End Patch\n"
	hermes, _ := json.Marshal(map[string]any{"hook_event_name": "pre_tool_call", "tool_name": "patch",
		"tool_input": map[string]any{"mode": "patch", "patch": patch}, "cwd": project})
	opencode, _ := json.Marshal(map[string]any{"hook_event_name": "tool.execute.before", "tool_name": "patch",
		"tool_input": map[string]any{"patchText": patch}, "cwd": project})
	write, _ := json.Marshal(map[string]any{"hook_event_name": "tool.execute.before", "tool_name": "write",
		"tool_input": map[string]any{"filePath": target, "content": "y"}, "cwd": project})
	type call struct {
		connector, event string
		body             []byte
		patch            bool
	}
	calls := map[string]call{
		"hermes v4a":     {"hermes", "pre_tool_call", hermes, true},
		"opencode patch": {"opencode", "tool.execute.before", opencode, true},
		"opencode write": {"opencode", "tool.execute.before", write, false},
	}
	evidence := map[string]string{}
	for name, c := range calls {
		evidence[name] = ResolveConnector(c.connector, "", c.event, c.body)
		if PatchEvidenceChanged(c.connector, "", c.event, c.body, evidence[name]) {
			t.Errorf("%s: unchanged target read as changed", name)
		}
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, target); err != nil {
		t.Fatal(err)
	}
	for name, c := range calls {
		if got := PatchEvidenceChanged(c.connector, "", c.event, c.body, evidence[name]); got != c.patch {
			t.Errorf("%s: changed = %v after the target became a link to the keys file, want %v", name, got, c.patch)
		}
	}
	if PatchEvidenceChanged("hermes", "", "pre_tool_call", hermes, "") {
		t.Error("no evidence read as changed")
	}
}
