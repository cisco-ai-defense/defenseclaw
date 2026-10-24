// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A managed gateway cannot look into the user's home (ProtectHome; the
// mode-zero parent stands in for it), so a symlink there to authorized_keys
// is known only from the write evidence of the hook running as the user.
// That evidence must describe the Copilot call the gateway judges: a decoy
// tool_name or tool_input beside the camelCase toolName and toolArgs, a
// toolArgs JSON string, or a VS Code Local tool name. Each write to the link
// blocks; an ordinary file the evidence lists stays allowed. A write over the
// 64 KiB string limit is judged on its reduced call
// (actionfacts.OverLimitWriteTargetReduction), and the evidence must describe
// that call in the dialect the gateway reads: a VS Code Local body (the
// vscode-local hook surface, or a CLI hook file the Local harness runs) with
// CLI-shaped decoys beside it hid the target from the resolver, and the
// reduction then dropped the marker that said so. A Copilot CLI edit or
// create carries a display-only description or file mode: the gateway
// judged the call as partial, with no target, and the evidence listed none,
// so a write through the link (or a hard link) to authorized_keys was
// allowed. Both now read the call without its metadata, at any size. A
// relative target had no resolved path on a gateway that cannot validate
// the event cwd, so the link was never judged; it is placed in the hook's
// cwd, as the evidence keys it.
func TestManagedCopilotWriteThroughHomeSymlinkUsesTheJudgedCall(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "alice")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	notes := filepath.Join(project, "notes.txt")
	for _, file := range []string{keys, notes} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	link := filepath.Join(project, "deploy.cfg")
	if err := os.Symlink(keys, link); err != nil {
		t.Fatal(err)
	}
	hard := filepath.Join(project, "hard.cfg")
	if err := os.Link(keys, hard); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n # base\n+ssh-ed25519 AAAA marker\n*** End Patch\n"
	}
	nativePermissionEdit := func(path string) map[string]any {
		diff := "\ndiff --git a" + path + " b" + path + "\nindex 1234567..abcdef0 100644\n" +
			"--- a" + path + "\n+++ b" + path + "\n@@ -1 +1 @@\n-# base\n+ssh-ed25519 AAAA marker\n"
		return map[string]any{"hookName": "permissionRequest", "toolName": "edit",
			"toolInput": map[string]any{"file_path": path, "diff": diff}}
	}
	invalidNativePermissionEdit := nativePermissionEdit(notes)
	invalidInput := invalidNativePermissionEdit["toolInput"].(map[string]any)
	invalidInput["diff"] = strings.Replace(invalidInput["diff"].(string), "+++ b"+notes, "+++ b"+keys, 1)
	ambiguousNativePermissionEdit := nativePermissionEdit(notes)
	ambiguousNativePermissionEdit["toolArgs"] = map[string]any{"path": notes, "old_str": "# base", "new_str": "another change"}
	jsonText := func(v any) string { return string(mustJSON(t, v)) }
	big := strings.Repeat("# k\n", 17000)
	local := func(path string, extra map[string]any) map[string]any {
		body := map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
			"tool_input": map[string]any{"filePath": path, "content": big}}
		for key, value := range extra {
			body[key] = value
		}
		return body
	}
	cliDecoys := map[string]any{"toolName": "view", "toolArgs": jsonText(map[string]any{"path": notes})}
	// edit and create in the Copilot CLI's own shape, with their metadata.
	edit := func(path, text string, args func(map[string]any) any) map[string]any {
		call := map[string]any{"path": path, "old_str": "# base", "new_str": text, "description": "add a key"}
		return map[string]any{"toolName": "edit", "toolArgs": args(call)}
	}
	create := func(path, text string, args func(map[string]any) any) map[string]any {
		call := map[string]any{"path": path, "file_text": text, "mode": "0600"}
		return map[string]any{"toolName": "create", "toolArgs": args(call)}
	}
	asString := func(call map[string]any) any { return jsonText(call) }
	asObject := func(call map[string]any) any { return call }
	key := "ssh-ed25519 AAAA marker\n"
	for _, row := range []struct {
		name           string
		surface, event string
		body           map[string]any
		block          bool
	}{
		{"apply_patch with a decoy tool_name", "", "preToolUse", map[string]any{"toolName": "apply_patch", "tool_name": "read_file",
			"toolArgs": patch(link)}, true},
		{"apply_patch JSON string with a decoy tool_name", "", "preToolUse", map[string]any{"toolName": "apply_patch", "tool_name": "view",
			"toolArgs": jsonText(patch(link))}, true},
		{"shell toolArgs JSON string", "", "preToolUse", map[string]any{"toolName": "bash",
			"toolArgs": jsonText(map[string]any{"command": "echo marker >> deploy.cfg", "description": "x"})}, true},
		{"shell toolArgs with a decoy tool_input", "", "preToolUse", map[string]any{"toolName": "bash",
			"toolArgs":   map[string]any{"command": "echo marker >> deploy.cfg"},
			"tool_input": map[string]any{"command": "true"}}, true},
		{"VS Code Local tool in a CLI body", "", "preToolUse", map[string]any{"toolName": "create_file",
			"toolArgs": jsonText(map[string]any{"filePath": link, "content": "ssh-ed25519 AAAA marker\n"})}, true},
		{"apply_patch of an ordinary file with a decoy tool_name", "", "preToolUse", map[string]any{"toolName": "apply_patch",
			"tool_name": "read_file", "toolArgs": patch(notes)}, true},
		{"native permission edit of ordinary file", "", "permissionRequest", nativePermissionEdit(notes), false},
		{"native permission edit through home symlink", "", "permissionRequest", nativePermissionEdit(link), true},
		{"native permission edit with mismatched diff target", "", "permissionRequest", invalidNativePermissionEdit, true},
		{"native permission edit with two argument shapes", "", "permissionRequest", ambiguousNativePermissionEdit, true},
		{"VS Code Local over-limit create_file with CLI decoys", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse",
			local(link, cliDecoys), true},
		{"VS Code Local over-limit create_file", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse", local(link, nil), true},
		{"VS Code Local over-limit create_file with a decoy toolInput", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse",
			local(link, map[string]any{"toolInput": map[string]any{"filePath": notes, "content": "x"}}), true},
		{"VS Code Local over-limit create_file of an ordinary file", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse",
			local(notes, nil), false},
		{"CLI hook file run by the Local harness, over-limit, decoy args", "", "preToolUse",
			local(link, map[string]any{"args": map[string]any{"filePath": notes}}), true},
		{"CLI hook file Local create_file with CLI decoy", "", "preToolUse",
			map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
				"tool_input": map[string]any{"filePath": link, "content": key},
				"toolName":   "view", "toolArgs": map[string]any{"path": notes}}, true},
		{"CLI over-limit create with decoy snake fields", "", "preToolUse", map[string]any{"toolName": "create",
			"toolArgs":  jsonText(map[string]any{"path": link, "file_text": big}),
			"tool_name": "view", "tool_input": map[string]any{"path": notes}}, true},
		{"CLI edit with a description", "", "preToolUse", edit(link, key, asString), true},
		{"CLI edit object with a description, relative path", "", "preToolUse", edit("deploy.cfg", key, asObject), true},
		{"CLI edit with a description through a hard link", "", "preToolUse", edit(hard, key, asString), true},
		{"CLI over-limit edit with a description", "", "preToolUse", edit(link, big, asString), true},
		{"CLI edit, relative path", "", "preToolUse", map[string]any{"toolName": "edit",
			"toolArgs": jsonText(map[string]any{"path": "deploy.cfg", "old_str": "# base", "new_str": key})}, true},
		{"VS Code Local create_file, relative path", connector.CopilotHookSurfaceVSCodeLocal, "PreToolUse",
			map[string]any{"hook_event_name": "PreToolUse", "tool_name": "create_file",
				"tool_input": map[string]any{"filePath": "deploy.cfg", "content": key}}, true},
		{"CLI edit with a description of an ordinary file, relative path", "", "preToolUse", edit("notes.txt", key, asString), false},
		{"CLI edit with a description of an ordinary file", "", "preToolUse", edit(notes, key, asString), false},
		{"CLI over-limit edit with a description of an ordinary file", "", "preToolUse", edit(notes, big, asString), false},
		{"CLI create with a mode", "", "preToolUse", create(link, key, asString), true},
		{"CLI create object with a mode, relative path", "", "preToolUse", create("deploy.cfg", key, asObject), true},
		{"CLI create with a mode through a hard link", "", "preToolUse", create(hard, key, asString), true},
		{"CLI over-limit create with a mode", "", "preToolUse", create(link, big, asString), true},
		{"CLI create with a mode of a new file", "", "preToolUse", create(filepath.Join(project, "new.txt"), key, asString), false},
	} {
		t.Run(row.name, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			row.body["sessionId"] = "s-" + strings.ReplaceAll(row.name, " ", "-")
			row.body["timestamp"] = 1790483549431
			row.body["cwd"] = project
			body := mustJSON(t, row.body)
			header := resolveCopilotTestEvidence(row.surface, row.event, body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", row.event)
			if row.surface != "" {
				req.Header.Set(connector.HookDialectHeader, row.surface)
			}
			req.Header.Set(hookpaths.Header, header)
			req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
			recorder := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(recorder, req)
			var verdict map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("verdict %q: %v", recorder.Body.String(), err)
			}
			want := "allow"
			if row.block {
				want = "block"
			}
			if verdict["action"] != want {
				t.Fatalf("action = %v, want %s: %.800s", verdict["action"], want, recorder.Body.String())
			}
		})
	}
}

// resolveCopilotTestEvidence is the managed native hook's write evidence for
// a Copilot body sent by a hook command of surface bound to event.
func resolveCopilotTestEvidence(surface, event string, body []byte) string {
	return hookpaths.ResolveConnector("copilot", surface, event, body)
}
