// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The managed native hook resolves a call's write targets as its connector's
// gateway profile reads the call: for a Copilot CLI hook command the
// camelCase toolName and toolArgs, not a decoy tool_name beside them; for a
// command of the vscode-local surface the Local tool_name and tool_input,
// not a decoy toolName and toolArgs beside them.
func TestManagedHookWriteEvidenceReadsTheConnectorsCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	cwd, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(cwd, "notes.txt")
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch\n"
	payload, err := json.Marshal(map[string]any{"cwd": cwd, "toolName": "apply_patch", "tool_name": "read_file", "toolArgs": patch})
	if err != nil {
		t.Fatal(err)
	}
	local, err := json.Marshal(map[string]any{"cwd": cwd, "hook_event_name": "PreToolUse", "tool_name": "create_file",
		"tool_input": map[string]any{"filePath": target, "content": "b"}, "toolName": "view", "toolArgs": `{"path":"x"}`})
	if err != nil {
		t.Fatal(err)
	}
	permission, err := json.Marshal(map[string]any{"cwd": cwd, "hookName": "permissionRequest", "toolName": "edit",
		"toolInput": map[string]any{"file_path": target, "diff": "\ndiff --git a" + target + " b" + target +
			"\nindex 1234567..abcdef0 100644\n--- a" + target + "\n+++ b" + target + "\n@@ -1 +1 @@\n-a\n+b\n"}})
	if err != nil {
		t.Fatal(err)
	}
	for name, call := range map[string]struct {
		opts    Options
		payload []byte
	}{
		"cli":          {Options{Connector: "copilot", Event: "preToolUse", ManagedEnterprise: true}, payload},
		"permission":   {Options{Connector: "copilot", Event: "permissionRequest", ManagedEnterprise: true}, permission},
		"vscode-local": {Options{Connector: "copilot", Event: "PreToolUse", HookSurface: copilotVSCodeLocalSurface, ManagedEnterprise: true}, local},
	} {
		t.Run(name, func(t *testing.T) {
			header := http.Header{}
			setHookRequestFacts(header, call.opts, call.payload)
			targets, ok := hookpaths.Decode(header.Get(hookpaths.Header))
			if !ok {
				t.Fatal("no decodable write evidence")
			}
			if _, listed := targets[target]; !listed {
				t.Fatalf("write target missing from the evidence: %v", targets)
			}
		})
	}
}
