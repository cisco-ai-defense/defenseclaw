// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
)

// A Copilot body is resolved as the gateway's Copilot profiles read it
// (copilotargs): in the dialect the hook command's surface and bound event
// select (the CLI's toolName and toolArgs, or the VS Code Local harness's
// tool_name and tool_input), a freeform apply_patch, a toolArgs JSON string
// and a VS Code Local tool. A body that spells the tool name or the
// arguments twice with different values gets the map of the spelling the
// gateway reads, marked incomplete, for every connector. A write over the
// analysis limits lists the targets of its reduced call, which the gateway
// judges, and the limit alone leaves the map complete.
func TestResolveConnectorReadsTheGatewayProjection(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the managed hook sends write evidence on Linux and macOS only")
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(project, "notes.txt")
	if err := os.WriteFile(target, []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n-a\n+b\n*** End Patch\n"
	nativeDiff := "\ndiff --git a" + target + " b" + target + "\nindex 1234567..abcdef0 100644\n--- a" + target + "\n+++ b" + target + "\n@@ -1 +1 @@\n-a\n+b\n"
	jsonText := func(v any) string {
		encoded, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return string(encoded)
	}
	shell := map[string]any{"command": "echo b >> notes.txt"}
	big := strings.Repeat("# k\n", 17000)
	const local = copilotargs.SurfaceVSCodeLocal
	localBody := func(content string, extra map[string]any) map[string]any {
		body := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
			"tool_input": map[string]any{"filePath": target, "content": content}}
		for key, value := range extra {
			body[key] = value
		}
		return body
	}
	cliDecoys := map[string]any{"toolName": "view", "toolArgs": jsonText(map[string]any{"path": project})}
	for _, row := range []struct {
		name, connector   string
		surface, event    string
		body              map[string]any
		listed, truncated bool
	}{
		{"cli apply_patch text", "copilot", "", "preToolUse", map[string]any{"toolName": "apply_patch", "toolArgs": patch}, true, false},
		{"cli apply_patch JSON string", "copilot", "", "preToolUse", map[string]any{"toolName": "apply_patch", "toolArgs": jsonText(patch)}, true, false},
		{"native permissionRequest edit", "copilot", "", "permissionRequest", map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{"file_path": target, "diff": nativeDiff}}, true, false},
		{"native permissionRequest mismatched diff", "copilot", "", "permissionRequest", map[string]any{"hookName": "permissionRequest", "toolName": "edit", "toolInput": map[string]any{"file_path": target, "diff": strings.Replace(nativeDiff, "+++ b"+target, "+++ b"+filepath.Join(project, "other.txt"), 1)}}, false, true},
		{"native permissionRequest shell", "copilot", "", "permissionRequest", map[string]any{"hookName": "permissionRequest", "permissionSuggestions": []any{}, "toolName": "bash", "toolInput": shell}, true, false},
		{"cli shell toolArgs JSON string", "copilot", "", "preToolUse", map[string]any{"toolName": "bash", "toolArgs": jsonText(shell)}, true, false},
		{"cli shell toolArgs object", "copilot", "", "preToolUse", map[string]any{"toolName": "bash", "toolArgs": shell}, true, false},
		{"local create_file", "copilot", local, "PreToolUse", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
			"tool_input": map[string]any{"filePath": target, "content": "b"}}, true, false},
		{"local tool in a CLI body", "copilot", "", "preToolUse", map[string]any{"toolName": "replace_string_in_file",
			"toolArgs": jsonText(map[string]any{"filePath": target, "oldString": "a", "newString": "b"})}, true, false},
		{"local run_in_terminal", "copilot", local, "PreToolUse", map[string]any{"tool_name": "run_in_terminal",
			"tool_input": map[string]any{"command": "echo b >> notes.txt", "explanation": "x", "isBackground": false}}, true, false},
		// The finding: the gateway judges toolName, a decoy tool_name hid
		// the patch from the resolver.
		{"decoy snake tool name", "copilot", "", "preToolUse", map[string]any{"toolName": "apply_patch", "tool_name": "read_file", "toolArgs": patch}, true, true},
		{"decoy camel tool name", "copilot", "", "preToolUse", map[string]any{"toolName": "read_file", "tool_name": "apply_patch", "toolArgs": patch}, false, true},
		{"decoy snake arguments", "copilot", "", "preToolUse", map[string]any{"toolName": "bash", "toolArgs": shell,
			"tool_input": map[string]any{"command": "true"}}, true, true},
		{"decoy args alias", "copilot", "", "preToolUse", map[string]any{"toolName": "bash", "toolArgs": shell, "args": map[string]any{"command": "true"}}, true, true},
		{"same tool name twice", "copilot", "", "preToolUse", map[string]any{"toolName": "apply_patch", "tool_name": " apply_patch", "toolArgs": patch}, true, true},
		{"null alias is absent", "copilot", "", "preToolUse", map[string]any{"toolName": "apply_patch", "tool_name": nil, "toolArgs": patch, "tool_input": nil}, true, false},
		// No projection the gateway reads: nothing to describe, but the
		// disagreement still leaves it incomplete.
		{"unreadable toolArgs with a decoy", "copilot", "", "preToolUse", map[string]any{"toolName": "bash", "toolArgs": "not json",
			"tool_input": map[string]any{"command": "true"}}, false, true},
		// Every connector: two spellings that disagree are incomplete.
		{"claude decoy camel arguments", "", "", "", map[string]any{"tool_name": "Bash", "tool_input": map[string]any{"command": "true"},
			"toolArgs": shell}, false, true},
		{"claude decoy camel tool name", "claudecode", "", "", map[string]any{"tool_name": "Bash", "toolName": "Write",
			"tool_input": shell}, true, true},
		{"claude one spelling", "claudecode", "", "", map[string]any{"tool_name": "Bash", "tool_input": shell}, true, false},
		// A CLI-registered hook cannot be switched to Local by body fields.
		// The mismatched schema is incomplete and its target is not trusted.
		{"local body from the CLI hook file", "copilot", "", "preToolUse", localBody("b", nil), false, true},
		{"local body from the CLI hook file with a CLI field", "copilot", "", "preToolUse",
			localBody("b", map[string]any{"toolName": "view"}), false, true},
		// The vscode-local surface reads tool_name and tool_input: CLI-shaped
		// decoys beside them neither hide the target nor become the call.
		{"local surface with CLI decoys", "copilot", local, "PreToolUse", localBody("b", cliDecoys), true, true},
		{"local surface with a decoy toolInput", "copilot", local, "PreToolUse",
			localBody("b", map[string]any{"toolInput": map[string]any{"filePath": project}}), true, true},
		// Over the analysis limits: the reduced call's target is listed; the
		// limit alone keeps the map complete, a decoy does not.
		{"local surface over-limit create_file", "copilot", local, "PreToolUse", localBody(big, nil), true, false},
		{"local surface over-limit create_file with CLI decoys", "copilot", local, "PreToolUse",
			localBody(big, cliDecoys), true, true},
		{"CLI hook file over-limit local body", "copilot", "", "preToolUse", localBody(big, nil), false, true},
		{"cli over-limit create", "copilot", "", "preToolUse", map[string]any{"toolName": "create",
			"toolArgs": jsonText(map[string]any{"path": target, "file_text": big})}, true, false},
		{"cli over-limit create with a decoy tool_name", "copilot", "", "preToolUse", map[string]any{"toolName": "create",
			"tool_name": "view", "toolArgs": jsonText(map[string]any{"path": target, "file_text": big})}, true, true},
		{"claude over-limit Write", "claudecode", "", "", map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": target, "content": big}}, true, false},
		{"claude over-limit Edit", "", "", "", map[string]any{"tool_name": "Edit",
			"tool_input": map[string]any{"file_path": target, "old_string": "a", "new_string": big}}, true, false},
		// A call the reduction cannot read stays incomplete.
		{"claude over-limit Write with an unknown key", "claudecode", "", "", map[string]any{"tool_name": "Write",
			"tool_input": map[string]any{"file_path": target, "content": big, "mode": "x"}}, false, true},
	} {
		t.Run(row.name, func(t *testing.T) {
			row.body["cwd"] = project
			payload, err := json.Marshal(row.body)
			if err != nil {
				t.Fatal(err)
			}
			targets, ok := Decode(ResolveConnector(row.connector, row.surface, row.event, payload))
			if !ok {
				t.Fatal("no decodable write evidence")
			}
			if resolved, listed := targets[target]; listed != row.listed || listed && resolved != target {
				t.Fatalf("listed=%t (%q), want %t: %v", listed, resolved, row.listed, targets)
			}
			if got := targets[TruncatedKey] == "1"; got != row.truncated {
				t.Fatalf("incomplete=%t, want %t: %v", got, row.truncated, targets)
			}
		})
	}
}
