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

// GAP-0488: the Hermes hook client lists and resolves every file a V4A
// patch's headers name, as the gateway judges them, and attests the
// complete patch; a body Hermes would refuse leaves the map incomplete.
func TestGAP0488HermesV4AClientListsHeaderTargets(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keys-link")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	resolve := func(args map[string]any) map[string]string {
		t.Helper()
		body, err := json.Marshal(map[string]any{"hook_event_name": "pre_tool_call", "tool_name": "patch",
			"tool_input": args, "cwd": project})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("hermes", "", "pre_tool_call", body))
		if !ok {
			t.Fatal("client evidence did not decode")
		}
		return targets
	}
	patch := func(body string) map[string]any { return map[string]any{"mode": "patch", "patch": body} }
	got := resolve(patch("*** Begin Patch\n*** Update File: notes.txt\n@@\n x\n+y\n*** Add File: sub/new.txt\n+z\n" +
		"*** Move File: a.txt -> b.txt\n*** Delete File: c.txt\n*** End Patch\n"))
	if got[PatchCompleteKey] != "1" || got[TruncatedKey] != "" {
		t.Fatalf("ordinary V4A map = %v, want a complete patch", got)
	}
	for _, name := range []string{"notes.txt", "sub/new.txt", "a.txt", "b.txt", "c.txt"} {
		if path := filepath.Join(project, name); got[path] != path {
			t.Errorf("target %s = %q, want itself", path, got[path])
		}
	}
	linked := resolve(patch("*** Begin Patch\n*** Update File: keys-link\n@@\n x\n+y\n*** End Patch\n"))
	if linked[filepath.Join(project, "keys-link")] != keys {
		t.Errorf("linked V4A target = %v, want it resolved to %s", linked, keys)
	}
	for name, args := range map[string]map[string]any{
		"no operations": patch("*** Begin Patch\n*** End Patch\n"),
		"prose":         patch("please update notes.txt"),
		"empty":         patch(""),
		"traversal":     patch("*** Delete File: x/../../.ssh/authorized_keys\n"),
	} {
		if got := resolve(args); got[TruncatedKey] != "1" || got[PatchCompleteKey] != "" {
			t.Errorf("%s: map = %v, want incomplete", name, got)
		}
	}
	replace := resolve(map[string]any{"mode": "replace", "path": "notes.txt", "old_string": "x", "new_string": "y"})
	if replace[PatchCompleteKey] != "" {
		t.Errorf("replace map = %v, want no patch attestation", replace)
	}
}
