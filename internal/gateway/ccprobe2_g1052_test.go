// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-1052: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha be09cdf80c lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// TestProxyToolCallsNeverWeakerThanClaudeCode: the LLM proxy's tool-call
// route judges a model reply's Bash, Write, Edit and Read calls at least as
// the Claude Code hook does (GAP-0782), in the default, permissive and strict
// packs (the proxy has no managed tier).
func TestCCP2G1052_ProxyToolCallsNeverWeakerThanClaudeCode(t *testing.T) {
	cases := shapeParityCases(t)
	if testing.Short() {
		cases = cases[:len(cases)/4]
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		if p.managed {
			t.Skip("the proxy route has no managed tier")
		}
		srv := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		hook := srv.handleAgentHook("claudecode")
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.cfg.RulePack = p.pack
		installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
		// A model reply names no session directory, so the proxy judges a
		// call in an empty directory of its own (proxyNeutralCWD); Claude
		// Code is asked in an empty directory too, so a relative operand
		// names no real file on either side.
		cwd := t.TempDir()
		for _, c := range cases {
			base := ccp2g1052_shapeParityHook(t, hook, ccp2g1052_shapeParityCall{name: "claudecode", conn: "claudecode",
				event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, c.tool, c.args)}, false)
			args, _ := json.Marshal(c.args)
			calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": c.tool, "arguments": string(args)}}})
			got := "allow"
			if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
				got = v.Action
			}
			if shapeParityRank[got] < shapeParityRank[base] {
				t.Errorf("%s %s: proxy %s, Claude Code %s %s", p.name, c.id, got, c.tool, base)
			}
		}
	})
}

// TestWindowsHostShellDialectEveryRoute: on a Windows host the fixture's
// PowerShell commands are read as PowerShell through antigravity run_command
// ({"CommandLine": ...}), /inspect/tool exec and the proxy tool-call route,
// at least as strongly as through the Claude Code PowerShell tool (GAP-0784).
func TestCCP2G1052_WindowsHostShellDialectEveryRoute(t *testing.T) {
	prev := windowsHookHost
	windowsHookHost = func() bool { return true }
	t.Cleanup(func() { windowsHookHost = prev })
	var commands []struct{ id, command string }
	for _, c := range loadACPParityCases(t) {
		if !strings.EqualFold(c.Tool, "powershell") {
			continue
		}
		var args struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(c.Args, &args) == nil && strings.TrimSpace(args.Command) != "" {
			commands = append(commands, struct{ id, command string }{c.ID, args.Command})
		}
	}
	if len(commands) == 0 {
		t.Fatal("no PowerShell fixture case")
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		cwd := t.TempDir()
		claude := gap0437Server(t, p, "claudecode", "action")
		installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
		agy := gap0437Server(t, p, "antigravity", "action")
		installToolCallCorpusProfileConnector(t, "antigravity", p.pack)
		inspect := gap0437Server(t, p, "openclaw", "action")
		// The generic route caps its scan at 200 ms; a loaded native box
		// answers past it, which is not the reading under test.
		inspect.inspectToolScanTimeout = time.Minute
		installToolCallCorpusProfileConnector(t, "openclaw", p.pack)
		var proxy *GuardrailProxy
		if !p.managed {
			proxy = newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.RulePack = p.pack
			installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
		}
		for _, c := range commands {
			base := ccp2g1052_shapeParityHook(t, claude.handleAgentHook("claudecode"), ccp2g1052_shapeParityCall{name: "claudecode/PowerShell",
				conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell",
					map[string]any{"command": c.command})}, p.managed)
			for _, call := range ccp2g1052_shapeParityNative("Bash", map[string]any{"command": c.command}, cwd) {
				if got := ccp2g1052_shapeParityHook(t, agy.handleAgentHook("antigravity"), call, p.managed); shapeParityRank[got] < shapeParityRank[base] {
					t.Errorf("%s %s: %s answered %s, Claude Code PowerShell %s", p.name, c.id, call.name, got, base)
				}
			}
			body, _ := json.Marshal(map[string]any{"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": c.command, "workdir": cwd}})
			req := httptest.NewRequest(http.MethodPost, "/api/v1/inspect/tool", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			inspect.handleInspectTool(w, req)
			var resp struct {
				Action string `json:"action"`
			}
			_ = json.Unmarshal(w.Body.Bytes(), &resp)
			if shapeParityRank[resp.Action] < shapeParityRank[base] {
				t.Errorf("%s %s: inspect-tool exec answered %s, Claude Code PowerShell %s", p.name, c.id, resp.Action, base)
			}
			if proxy != nil {
				args, _ := json.Marshal(map[string]any{"command": c.command})
				calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "shell", "arguments": string(args)}}})
				got := "allow"
				if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
					got = v.Action
				}
				if shapeParityRank[got] < shapeParityRank[base] {
					t.Errorf("%s %s: proxy shell answered %s, Claude Code PowerShell %s", p.name, c.id, got, base)
				}
			}
		}
	})
}

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector's hook.
type ccp2g1052_shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// shapeParityHook answers one hook call through the connector's handler.
func ccp2g1052_shapeParityHook(t *testing.T, h http.HandlerFunc, call ccp2g1052_shapeParityCall, managedTier bool) string {
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
func ccp2g1052_shapeParityNative(tool string, args map[string]any, cwd string) []ccp2g1052_shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	agy := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	var out []ccp2g1052_shapeParityCall
	switch tool {
	case "Bash":
		out = append(out, ccp2g1052_shapeParityCall{name: "antigravity/run_command", conn: "antigravity", event: "PreToolUse", headers: agy,
			body: func() map[string]any {
				m := shapeParityAntigravity("run_command", map[string]any{"Cwd": cwd, "CommandLine": str("command"), "WaitMsBeforeAsync": 5000})
				m["workspacePaths"] = []string{cwd}
				return m
			}()})
	case "Write":
		out = append(out,
			ccp2g1052_shapeParityCall{name: "antigravity/write_to_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("write_to_file", map[string]any{"TargetFile": str("file_path"), "CodeContent": str("content")})},
			ccp2g1052_shapeParityCall{name: "codex/apply_patch-add", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " +
					str("file_path") + "\n+" + strings.ReplaceAll(str("content"), "\n", "\n+") + "\n*** End Patch"})},
		)
	case "Edit":
		out = append(out,
			ccp2g1052_shapeParityCall{name: "antigravity/replace_file_content", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("replace_file_content", map[string]any{"TargetFile": str("file_path"),
					"TargetContent": str("old_string"), "ReplacementContent": str("new_string")})},
			ccp2g1052_shapeParityCall{name: "amp/edit_file", conn: "amp", event: "tool.call",
				body: shapeParityEnvelope("tool.call", cwd, "edit_file", map[string]any{"path": str("file_path"),
					"old_str": str("old_string"), "new_str": str("new_string")})},
			// The Update File of the same edit (rel-1-0-10:GAP-0947).
			ccp2g1052_shapeParityCall{name: "codex/apply_patch-update", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": ccp2g1052_shapeParityUpdatePatch(
					str("file_path"), str("old_string"), str("new_string"))})},
		)
	case "Read":
		copilotArgs, _ := json.Marshal(map[string]any{"path": str("file_path")})
		sid := fmt.Sprintf("sp-%d", shapeParitySeq.Add(1))
		out = append(out,
			ccp2g1052_shapeParityCall{name: "antigravity/view_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("view_file", map[string]any{"AbsolutePath": str("file_path")})},
			ccp2g1052_shapeParityCall{name: "copilot/view", conn: "copilot", event: "preToolUse",
				headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				body:    map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(copilotArgs)}},
			ccp2g1052_shapeParityCall{name: "cursor/beforeReadFile", conn: "cursor", event: "beforeReadFile",
				body: map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
					"session_id": sid, "cwd": cwd, "file_path": str("file_path"), "content": ""}},
		)
	}
	return out
}

func ccp2g1052_shapeParityUpdatePatch(path, oldText, newText string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-" + strings.ReplaceAll(oldText, "\n", "\n-") +
		"\n+" + strings.ReplaceAll(newText, "\n", "\n+") + "\n*** End Patch"
}
