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

// GAP-0488, GAP-0073: whatever shape of call carries a patch, evidence that
// attests the patch complete comes with the watch of every target it lists,
// so the managed hook reads each of them again after the gateway answered. A
// parallel Copilot envelope is one shape of it; a target of any call that is
// retargeted to the keys file afterwards is reported changed.
func TestCompletePatchEvidenceIsAlwaysWatched(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	project := filepath.Join(home, "proj")
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, dir := range []string{project, filepath.Dir(keys)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	names := []string{"a.txt", "b.txt", "c.txt"}
	for _, path := range append([]string{keys}, names...) {
		if !filepath.IsAbs(path) {
			path = filepath.Join(project, path)
		}
		if err := os.WriteFile(path, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	patch := func(name string) string {
		return "*** Begin Patch\n*** Update File: " + name + "\n@@\n x\n+y\n*** End Patch\n"
	}
	copilot := func(patched ...string) []byte {
		calls := []any{}
		for _, name := range patched {
			calls = append(calls, map[string]any{"id": "call_" + name, "name": "apply_patch", "args": patch(name)})
		}
		body, err := json.Marshal(map[string]any{"cwd": project, "toolCalls": calls})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	native := func(event string, input map[string]any) []byte {
		body, err := json.Marshal(map[string]any{"hook_event_name": event, "tool_name": "patch", "tool_input": input, "cwd": project})
		if err != nil {
			t.Fatal(err)
		}
		return body
	}
	for _, tc := range []struct {
		name, connector, event string
		payload                []byte
		targets                []string
	}{
		{"copilot one call", "copilot", "preToolUse", copilot("a.txt"), []string{"a.txt"}},
		{"copilot two parallel calls", "copilot", "preToolUse", copilot("a.txt", "b.txt"), []string{"a.txt", "b.txt"}},
		{"copilot three parallel calls", "copilot", "preToolUse", copilot("a.txt", "b.txt", "c.txt"), []string{"a.txt", "b.txt", "c.txt"}},
		{"hermes v4a", "hermes", "pre_tool_call", native("pre_tool_call", map[string]any{"mode": "patch", "patch": patch("a.txt")}), []string{"a.txt"}},
		{"opencode patch", "opencode", "tool.execute.before", native("tool.execute.before", map[string]any{"patchText": patch("a.txt")}), []string{"a.txt"}},
	} {
		for _, name := range tc.targets {
			t.Run(tc.name+" retargets "+name, func(t *testing.T) {
				target := filepath.Join(project, name)
				evidence, watch := ResolveConnectorWatch(tc.connector, "", tc.event, tc.payload)
				facts, ok := Decode(evidence)
				if !ok || facts[PatchCompleteKey] != "1" {
					t.Fatalf("evidence is not an attested complete patch: %v", facts)
				}
				for _, listed := range tc.targets {
					if facts[filepath.Join(project, listed)] == "" {
						t.Fatalf("target %s is not listed: %v", listed, facts)
					}
				}
				if watch == nil {
					t.Fatal("complete patch evidence came without its watch")
				}
				if watch.Changed() {
					t.Fatal("untouched targets read as changed")
				}
				saved := target + ".saved"
				if err := os.WriteFile(saved, []byte("x\n"), 0o600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(saved, target); err != nil {
					t.Fatal(err)
				}
				if watch.Changed() {
					t.Fatal("an ordinary save of the same path read as changed")
				}
				if err := os.Remove(target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(keys, target); err != nil {
					t.Fatal(err)
				}
				defer func() {
					_ = os.Remove(target)
					_ = os.WriteFile(target, []byte("x\n"), 0o600)
				}()
				if !watch.Changed() {
					t.Fatal("a target retargeted to the keys file read as unchanged")
				}
			})
		}
	}
}
