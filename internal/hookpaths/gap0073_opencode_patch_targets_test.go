// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// GAP-0073: the hook client describes OpenCode V2 native patch tool
// ("patch", patchText) under the apply_patch name the gateway judges it as
// (ConnectorActionTool): it lists and resolves every patch target and
// attests the complete patch, exactly as for the apply_patch spelling.
func TestGAP0073OpenCodePatchClientListsTargets(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	resolve := func(tool, patch string) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool,
			"tool_input": map[string]any{"patchText": patch}, "cwd": project})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("opencode", "", "tool.execute.before", body))
		if !ok {
			t.Fatal("client evidence did not decode")
		}
		return targets
	}
	patch := "*** Begin Patch\n*** Add File: hello.txt\n+hello\n*** Update File: notes.txt\n*** Move to: moved.txt\n" +
		"@@\n x\n+y\n*** Update File: keylink\n@@\n x\n+y\n*** End Patch"
	got := resolve("patch", patch)
	if got[PatchCompleteKey] != "1" || got[TruncatedKey] != "" {
		t.Fatalf("patch map = %v, want a complete patch", got)
	}
	for _, name := range []string{"hello.txt", "notes.txt", "moved.txt"} {
		if path := filepath.Join(project, name); got[path] != path {
			t.Errorf("target %s = %q, want itself", path, got[path])
		}
	}
	if link := filepath.Join(project, "keylink"); got[link] != keys {
		t.Errorf("linked target = %q, want %s", got[link], keys)
	}
	if want := resolve("apply_patch", patch); !reflect.DeepEqual(got, want) {
		t.Errorf("patch map = %v, apply_patch map = %v, want the same evidence", got, want)
	}
	for connector, tool := range map[string]string{"opencode": "edit", "hermes": "patch", "codex": "patch"} {
		if mapped := ConnectorActionTool(connector, tool); mapped != tool {
			t.Errorf("ConnectorActionTool(%s, %s) = %s, want unchanged", connector, tool, mapped)
		}
	}
}
