// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

var windsurfHookEventsForTest = []string{
	"pre_read_code",
	"post_read_code",
	"pre_write_code",
	"post_write_code",
	"pre_run_command",
	"post_run_command",
	"pre_mcp_tool_use",
	"post_mcp_tool_use",
	"pre_user_prompt",
	"post_cascade_response",
	"post_cascade_response_with_transcript",
	"post_setup_worktree",
}

func TestPatchWindsurfWindowsHooksUsesPowerShellOnlyAndPreservesForeignEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	foreign := map[string]interface{}{
		"command":     `C:\Vendor Tools\audit.exe --event pre_read_code`,
		"show_output": false,
		"vendor":      map[string]interface{}{"keep": "exactly"},
	}
	legacy := map[string]interface{}{
		"command": legacyWindsurfWindowsHookCommand(),
	}
	document := map[string]interface{}{
		"unrelated": map[string]interface{}{"preserve": []interface{}{1.0, "two", true}},
		"hooks": map[string]interface{}{
			"pre_read_code": []interface{}{foreign, legacy},
			"vendor_event":  []interface{}{map[string]interface{}{"command": "vendor-hook"}},
		},
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}

	const adapter = `& 'C:\DefenseClaw Data\hooks\windsurf-hook.ps1'`
	const legacyShell = `C:\DefenseClaw Data\hooks\windsurf-hook.sh`
	if err := patchWindsurfHooksForOS(path, adapter, legacyShell, "windows"); err != nil {
		t.Fatalf("patch Windsurf hooks: %v", err)
	}

	var got map[string]interface{}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(updated, &got); err != nil {
		t.Fatalf("parse updated config: %v", err)
	}
	if !reflect.DeepEqual(got["unrelated"], document["unrelated"]) {
		t.Fatalf("unrelated top-level config changed: got=%#v want=%#v", got["unrelated"], document["unrelated"])
	}
	hooks, ok := got["hooks"].(map[string]interface{})
	if !ok {
		t.Fatalf("hooks = %#v, want object", got["hooks"])
	}
	vendorEvent := hooks["vendor_event"]
	if !reflect.DeepEqual(vendorEvent, document["hooks"].(map[string]interface{})["vendor_event"]) {
		t.Fatalf("foreign event changed: got=%#v want=%#v", vendorEvent, document["hooks"].(map[string]interface{})["vendor_event"])
	}
	for _, event := range windsurfHookEventsForTest {
		handlers, ok := hooks[event].([]interface{})
		if !ok {
			t.Fatalf("%s handlers = %#v, want array", event, hooks[event])
		}
		wantCount := 1
		if event == "pre_read_code" {
			wantCount = 2
			if !reflect.DeepEqual(handlers[0], foreign) {
				t.Fatalf("foreign pre_read_code handler changed: got=%#v want=%#v", handlers[0], foreign)
			}
		}
		if len(handlers) != wantCount {
			t.Fatalf("%s handler count = %d, want %d: %#v", event, len(handlers), wantCount, handlers)
		}
		managed, ok := handlers[len(handlers)-1].(map[string]interface{})
		if !ok {
			t.Fatalf("%s managed handler = %#v, want object", event, handlers[len(handlers)-1])
		}
		if managed["powershell"] != adapter || managed["show_output"] != true {
			t.Fatalf("%s managed handler = %#v", event, managed)
		}
		if _, exists := managed["command"]; exists {
			t.Fatalf("%s managed handler has forbidden command fallback: %#v", event, managed)
		}
	}
}

func TestPatchWindsurfWindowsHooksReconcilesExactManagedEntryWithoutClaimingForeignAdapter(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hooks.json")
	const oldAdapter = `& 'C:\Old Root\windsurf-hook.ps1'`
	const currentAdapter = `& 'C:\New Root\windsurf-hook.ps1'`
	document := map[string]interface{}{
		"hooks": map[string]interface{}{
			"pre_user_prompt": []interface{}{
				map[string]interface{}{"powershell": oldAdapter, "show_output": true},
				map[string]interface{}{"command": `C:\Foreign\keep.exe`, "show_output": true},
				map[string]interface{}{"powershell": currentAdapter, "show_output": true},
			},
		},
	}
	body, err := json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := patchWindsurfHooksForOS(path, currentAdapter, `C:\New Root\windsurf-hook.sh`, "windows"); err != nil {
		t.Fatalf("first reconcile: %v", err)
	}
	if err := patchWindsurfHooksForOS(path, currentAdapter, `C:\New Root\windsurf-hook.sh`, "windows"); err != nil {
		t.Fatalf("second reconcile: %v", err)
	}

	var got map[string]interface{}
	updated, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(updated, &got); err != nil {
		t.Fatal(err)
	}
	hooks := got["hooks"].(map[string]interface{})
	handlers := hooks["pre_user_prompt"].([]interface{})
	if len(handlers) != 3 {
		t.Fatalf("pre_user_prompt handlers = %#v, want two foreign plus one current", handlers)
	}
	if handlers[0].(map[string]interface{})["powershell"] != oldAdapter ||
		handlers[1].(map[string]interface{})["command"] != `C:\Foreign\keep.exe` {
		t.Fatalf("foreign handlers were not preserved exactly and in order: %#v", handlers)
	}
	if handlers[2].(map[string]interface{})["powershell"] != currentAdapter {
		t.Fatalf("current handler missing: %#v", handlers)
	}
}

func TestWindsurfSetupTeardownRestoresExactBytesAndForeignHooks(t *testing.T) {
	root := t.TempDir()
	configPath := filepath.Join(root, "profile", ".codeium", "windsurf", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(configPath), 0o700); err != nil {
		t.Fatal(err)
	}
	pristine := []byte("{\r\n  \"vendor\": {\"preserve\": true},\r\n  \"hooks\": {\r\n    \"pre_read_code\": [{\"command\":\"C:\\\\Vendor\\\\audit.exe\",\"show_output\":false,\"owner\":\"vendor\"}],\r\n    \"vendor_event\": [{\"command\":\"C:\\\\Vendor\\\\other.exe\"}]\r\n  }\r\n}\r\n")
	if err := os.WriteFile(configPath, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	previous := WindsurfHooksPathOverride
	WindsurfHooksPathOverride = configPath
	t.Cleanup(func() { WindsurfHooksPathOverride = previous })

	conn := NewWindsurfConnector()
	opts := SetupOpts{
		DataDir:      filepath.Join(root, "data"),
		APIAddr:      "127.0.0.1:18970",
		APIToken:     "test-token",
		WorkspaceDir: filepath.Join(root, "workspace"),
	}
	if err := conn.Setup(context.Background(), opts); err != nil {
		t.Fatalf("setup: %v", err)
	}
	if err := conn.Teardown(context.Background(), opts); err != nil {
		t.Fatalf("teardown: %v", err)
	}
	restored, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(restored, pristine) {
		t.Fatalf("Windsurf config was not restored byte-for-byte:\ngot  %q\nwant %q", restored, pristine)
	}
	if err := conn.VerifyClean(opts); err != nil {
		t.Fatalf("verify clean: %v", err)
	}
}
