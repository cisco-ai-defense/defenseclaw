// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0850: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 0c21f0e73b lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestWindowsHostAntigravityCredentialOperandPastTheArgvBound: the
// acp_parity Bash case gap/rel-1-0-6_GAP-1069/128 (a credential-file operand
// past the argv bound) sent as agy run_command on a Windows host answers at
// least what Claude Code Bash answers, in every tier: the POSIX reading
// proves the credential operand that the PowerShell reading left at the
// unknown tier (rel-1-0-10:GAP-0850, native dc-win2 in review s7-tfprev2).
func TestCCP2G0850_WindowsHostAntigravityCredentialOperandPastTheArgvBound(t *testing.T) {
	prev := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prev })
	var args map[string]any
	for _, c := range shapeParityCases(t) {
		if c.id == "gap/rel-1-0-6_GAP-1069/128" && c.tool == "Bash" {
			args = c.args
		}
	}
	if args == nil {
		t.Fatal("fixture case gap/rel-1-0-6_GAP-1069/128 not found")
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		agy := gap0437Server(t, p, "antigravity", "action")
		installToolCallCorpusProfileConnector(t, "antigravity", p.pack)
		base := ccp2g0850_shapeParityHook(t, claude.handleAgentHook("claudecode"), ccp2g0850_shapeParityCall{name: "claudecode/Bash",
			conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "Bash", args)}, p.managed)
		seen := 0
		for _, call := range ccp2g0850_shapeParityNative("Bash", args, cwd) {
			if call.conn != "antigravity" {
				continue
			}
			seen++
			if got := ccp2g0850_shapeParityHook(t, agy.handleAgentHook("antigravity"), call, p.managed); shapeParityRank[got] < shapeParityRank[base] {
				t.Errorf("%s: %s answered %s, Claude Code Bash %s", p.name, call.name, got, base)
			}
		}
		if seen == 0 {
			t.Fatal("no antigravity rendering of the Bash case")
		}
	})
}

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector's hook.
type ccp2g0850_shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// shapeParityHook answers one hook call through the connector's handler.
func ccp2g0850_shapeParityHook(t *testing.T, h http.HandlerFunc, call ccp2g0850_shapeParityCall, managedTier bool) string {
	t.Helper()
	raw, _ := json.Marshal(call.body)
	route := call.route
	if route == "" {
		route = "/api/v1/" + call.conn + "/hook"
	}
	req := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range call.headers {
		req.Header.Set(key, value)
	}
	// The inspect route's caller (OpenClaw's plugin) sends no hook
	// evidence header.
	if managedTier && call.route == "" {
		if ev := hookpaths.ResolveConnector(call.conn, "", call.event, raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: http %d", call.name, w.Code)
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: answer is not JSON", call.name)
	}
	return resp.Action
}

// shapeParityNative renders a Claude Code call (tool Bash, Write, Edit or
// Read) as the native shapes the train maps.
func ccp2g0850_shapeParityNative(tool string, args map[string]any, cwd string) []ccp2g0850_shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	agy := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	var out []ccp2g0850_shapeParityCall
	switch tool {
	case "Bash":
		out = append(out, ccp2g0850_shapeParityCall{name: "antigravity/run_command", conn: "antigravity", event: "PreToolUse", headers: agy,
			body: func() map[string]any {
				m := shapeParityAntigravity("run_command", map[string]any{"Cwd": cwd, "CommandLine": str("command"), "WaitMsBeforeAsync": 5000})
				m["workspacePaths"] = []string{cwd}
				return m
			}()})
	case "Write":
		out = append(out,
			ccp2g0850_shapeParityCall{name: "antigravity/write_to_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("write_to_file", map[string]any{"TargetFile": str("file_path"), "CodeContent": str("content")})},
			ccp2g0850_shapeParityCall{name: "codex/apply_patch-add", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " +
					str("file_path") + "\n+" + strings.ReplaceAll(str("content"), "\n", "\n+") + "\n*** End Patch"})},
		)
	case "Edit":
		out = append(out,
			ccp2g0850_shapeParityCall{name: "antigravity/replace_file_content", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("replace_file_content", map[string]any{"TargetFile": str("file_path"),
					"TargetContent": str("old_string"), "ReplacementContent": str("new_string")})},
			ccp2g0850_shapeParityCall{name: "amp/edit_file", conn: "amp", event: "tool.call",
				body: shapeParityEnvelope("tool.call", cwd, "edit_file", map[string]any{"path": str("file_path"),
					"old_str": str("old_string"), "new_str": str("new_string")})},
			// The Update File of the same edit (rel-1-0-10:GAP-0947).
			ccp2g0850_shapeParityCall{name: "codex/apply_patch-update", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": ccp2g0850_shapeParityUpdatePatch(
					str("file_path"), str("old_string"), str("new_string"))})},
		)
	case "Read":
		copilotArgs, _ := json.Marshal(map[string]any{"path": str("file_path")})
		sid := fmt.Sprintf("sp-%d", shapeParitySeq.Add(1))
		out = append(out,
			ccp2g0850_shapeParityCall{name: "antigravity/view_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("view_file", map[string]any{"AbsolutePath": str("file_path")})},
			ccp2g0850_shapeParityCall{name: "copilot/view", conn: "copilot", event: "preToolUse",
				headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				body:    map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(copilotArgs)}},
			ccp2g0850_shapeParityCall{name: "cursor/beforeReadFile", conn: "cursor", event: "beforeReadFile",
				body: map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
					"session_id": sid, "cwd": cwd, "file_path": str("file_path"), "content": ""}},
		)
	}
	return out
}

func ccp2g0850_shapeParityUpdatePatch(path, oldText, newText string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-" + strings.ReplaceAll(oldText, "\n", "\n-") +
		"\n+" + strings.ReplaceAll(newText, "\n", "\n+") + "\n*** End Patch"
}
