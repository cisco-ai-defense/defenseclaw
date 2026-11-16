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

// GAP-1501 (requested by instr-protect): from a linked working directory the
// kernel resolves "../x" against the physical directory. The hook evidence
// named only the lexical parent, so a managed gateway behind ProtectHome had
// no target or identity for ~/real-project/AGENTS.md when the agent ran
// `printf x >> ../AGENTS.md` in ~/linked-inner. The physical target is now
// listed with its instruction identity.
func TestResolveListsThePhysicalParentOfALinkedCWD(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	inner := filepath.Join(home, "real-project", "inner")
	if err := os.MkdirAll(inner, 0o700); err != nil {
		t.Fatal(err)
	}
	agents := filepath.Join(home, "real-project", "AGENTS.md")
	if err := os.WriteFile(agents, []byte("# rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(home, "linked-inner")
	if err := os.Symlink(inner, linked); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	payload, err := json.Marshal(map[string]any{"tool_name": "exec_command", "cwd": linked,
		"tool_input": map[string]any{"cmd": "printf x >> ../AGENTS.md"}})
	if err != nil {
		t.Fatal(err)
	}
	targets, ok := Decode(Resolve(payload))
	if !ok {
		t.Fatal("no decodable evidence")
	}
	if _, listed := targets[agents]; !listed {
		t.Fatalf("physical parent target %s not listed: %v", agents, targets)
	}
	if _, listed := targets[filepath.Join(home, "AGENTS.md")]; !listed {
		t.Fatalf("lexical parent target no longer listed: %v", targets)
	}
}
