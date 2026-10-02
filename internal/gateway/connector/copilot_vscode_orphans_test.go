// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// BENIGN-MAC-02: an enterprise uninstall from before MAC-U2-06 left the VS
// Code Local hook file and the Copilot plugin, which run the removed
// administrator hook binary, and the Copilot CLI denied every tool call.
// A per-user Copilot setup removes exactly those leftovers; a live
// enterprise render and the user's own hooks stay.
func TestRemoveOrphanedCopilotVSCodeLocalRenders(t *testing.T) {
	render := func(binary string) []byte {
		hooks := map[string]any{}
		for _, event := range CopilotVSCodeLocalHookEvents {
			hooks[event] = []any{map[string]any{"type": "command", "command": CopilotVSCodeLocalManagedHookCommand(runtime.GOOS, binary, event), "timeout": 30}}
		}
		data, _ := json.Marshal(map[string]any{"hooks": hooks})
		return data
	}
	seed := func(t *testing.T, hookDoc []byte) string {
		t.Helper()
		home := t.TempDir()
		files := map[string][]byte{
			".copilot/hooks/" + orphanCopilotVSCodeHookFile:                       hookDoc,
			".copilot/installed-plugins/defenseclaw/defenseclaw/hooks/hooks.json": hookDoc,
			".copilot/installed-plugins/defenseclaw/defenseclaw/plugin.json":      []byte(`{"name":"defenseclaw"}`),
		}
		for name, body := range files {
			path := filepath.Join(home, filepath.FromSlash(name))
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, body, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return home
	}
	exists := func(path string) bool { _, err := os.Lstat(path); return err == nil }

	gone := filepath.Join(t.TempDir(), "opt", "cisco", "defenseclaw", "bin", "defenseclaw-hook")
	home := seed(t, render(gone))
	removed, err := RemoveOrphanedCopilotVSCodeLocalRenders(home)
	if err != nil || len(removed) != 2 {
		t.Fatalf("removed %v, %v; want the hook file and the plugin", removed, err)
	}
	if exists(filepath.Join(home, ".copilot", "hooks", orphanCopilotVSCodeHookFile)) || exists(filepath.Join(home, ".copilot", "installed-plugins", "defenseclaw")) {
		t.Fatal("the orphaned enterprise renders stayed")
	}
	if !exists(filepath.Join(home, ".copilot", "hooks")) {
		t.Fatal("the user's Copilot hooks folder was removed")
	}

	// A live enterprise install's render (its binary exists) stays.
	live := filepath.Join(t.TempDir(), "defenseclaw-hook")
	if err := os.WriteFile(live, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	home = seed(t, render(live))
	if removed, _ := RemoveOrphanedCopilotVSCodeLocalRenders(home); len(removed) != 0 {
		t.Fatalf("removed a live enterprise render: %v", removed)
	}

	// A file with the user's own handler stays.
	var doc map[string]map[string][]any
	_ = json.Unmarshal(render(gone), &doc)
	doc["hooks"]["PreToolUse"] = append(doc["hooks"]["PreToolUse"], map[string]any{"type": "command", "command": "my-own-hook"})
	mixed, _ := json.Marshal(doc)
	home = seed(t, mixed)
	if removed, _ := RemoveOrphanedCopilotVSCodeLocalRenders(home); len(removed) != 0 {
		t.Fatalf("removed a file holding the user's own hook: %v", removed)
	}
}
