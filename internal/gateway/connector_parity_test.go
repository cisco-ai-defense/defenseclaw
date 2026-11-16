// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// T-PARITY fix train (rel-1-0-10:GAP-0776 to GAP-0784): the same action gets
// a verdict at least as strong as Claude Code's whatever connector, native
// tool shape or route carries it, in every tier. The cases are not written
// here: each is a Claude Code tool call of testdata/acp_parity_cases.jsonl
// (gap-regression and win-credential-paths, by case id) rendered as each
// connector's own tool shape.
//
// Native shapes with no vendor fixture in the repo (from the vendor schemas,
// to confirm on a live agent): antigravity write_to_file, replace_file_content,
// view_file; Amp edit_file; Copilot view; Cursor beforeReadFile; OpenCode V2
// read; OpenClaw write, edit and read.

var shapeParityRank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

// shapeParityConnectors are the connectors shapeParityNative renders calls
// for, and claudecode, the baseline. Every shipped connector with a hook or
// inspect route is here: OpenCode (tool.execute.before), Devin (PreToolUse),
// Hermes (pre_tool_call), Kiro (preToolUse, and PreToolUse for --v3) and
// OpenClaw (its plugin's /api/v1/inspect/tool call; OpenClaw has no command
// hook).
var shapeParityConnectors = []string{"claudecode", "antigravity", "codex", "amp", "copilot", "cursor",
	"opencode", "devin", "hermes", "kiro", "openclaw"}

// shapeParityInspectRoute is the route OpenClaw's plugin asks before a tool
// runs (extensions/defenseclaw before_tool_call).
const shapeParityInspectRoute = "/api/v1/inspect/tool"

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector's hook.
type shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// shapeParityHandlers answers each of shapeParityConnectors in tier p: its
// hook, or for OpenClaw the inspect route.
func shapeParityHandlers(t *testing.T, p gap0437Pack) map[string]http.HandlerFunc {
	t.Helper()
	handlers := map[string]http.HandlerFunc{}
	for _, conn := range shapeParityConnectors {
		srv := gap0437Server(t, p, conn, "action")
		installToolCallCorpusProfileConnector(t, conn, p.pack)
		if conn == "openclaw" {
			// The route caps its scan at 200 ms; a loaded box answers
			// past it, which is not the reading under test (as in
			// TestWindowsHostShellDialectEveryRoute).
			srv.inspectToolScanTimeout = time.Minute
			handlers[conn] = srv.handleInspectTool
			continue
		}
		handlers[conn] = srv.handleAgentHook(conn)
	}
	return handlers
}

// shapeParityCheckedEveryConnector fails a tier in which a connector of
// shapeParityConnectors other than the baseline had no call checked.
func shapeParityCheckedEveryConnector(t *testing.T, checked map[string]int) {
	t.Helper()
	for _, conn := range shapeParityConnectors[1:] {
		if checked[conn] == 0 {
			t.Errorf("no %s native shape was checked", conn)
		}
	}
}

// shapeParityOpenCode is an OpenCode V2 tool.execute.before body as its
// plugin posts it (internal/gateway/connector/hooks/opencode-plugin.js),
// after the plugin's config hook proved the plugin order.
func shapeParityOpenCode(cwd, tool string, input map[string]any) map[string]any {
	n := shapeParitySeq.Add(1)
	return map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": input,
		"session_id": fmt.Sprintf("sp-%d", n), "turn_id": fmt.Sprintf("m-sp-%d", n), "tool_call_id": fmt.Sprintf("tu-sp-%d", n),
		"agent_name": "build", "cwd": cwd, "load_heartbeat": true, "arguments_authoritative": true, "mcp_identity_status": "not_mcp"}
}

// shapeParityHermes is a Hermes pre_tool_call body.
func shapeParityHermes(cwd, tool string, input map[string]any) map[string]any {
	return map[string]any{"hook_event_name": "pre_tool_call", "tool_name": tool, "tool_input": input,
		"session_id": fmt.Sprintf("sp-%d", shapeParitySeq.Add(1)), "cwd": cwd}
}

// shapeParityOpenClaw is the inspect body OpenClaw's plugin posts before a
// tool runs: the tool, its params, the session, and no working directory.
func shapeParityOpenClaw(tool string, args map[string]any) map[string]any {
	n := shapeParitySeq.Add(1)
	return map[string]any{"tool": tool, "args": args, "tool_call_id": fmt.Sprintf("tu-sp-%d", n),
		"session_id": fmt.Sprintf("sp-%d", n), "approval_surface": "native"}
}

// shapeParityPatch is an apply_patch envelope: one Add File of content, or
// an Update File replacing oldText by newText.
func shapeParityPatch(path, content string) string {
	return "*** Begin Patch\n*** Add File: " + path + "\n+" + strings.ReplaceAll(content, "\n", "\n+") + "\n*** End Patch"
}

func shapeParityUpdatePatch(path, oldText, newText string) string {
	return "*** Begin Patch\n*** Update File: " + path + "\n@@\n-" + strings.ReplaceAll(oldText, "\n", "\n-") +
		"\n+" + strings.ReplaceAll(newText, "\n", "\n+") + "\n*** End Patch"
}

// shapeParitySeq numbers the calls: every call is its own session and
// invocation, so no call joins another's correlation state.
var shapeParitySeq atomic.Int64

func shapeParityEnvelope(event, cwd, tool string, input map[string]any) map[string]any {
	n := shapeParitySeq.Add(1)
	return map[string]any{"hook_event_name": event, "session_id": fmt.Sprintf("sp-%d", n), "cwd": cwd, "tool_name": tool,
		"tool_use_id": fmt.Sprintf("tu-sp-%d", n), "tool_input": input}
}

func shapeParityAntigravity(tool string, args map[string]any) map[string]any {
	return map[string]any{"conversationId": fmt.Sprintf("sp-%d", shapeParitySeq.Add(1)), "stepIdx": 1, "toolCall": map[string]any{"name": tool, "args": args}}
}

// shapeParityNative renders a Claude Code call (tool Bash, Write, Edit or
// Read) as the native shapes the train maps.
func shapeParityNative(tool string, args map[string]any, cwd string) []shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	agy := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	var out []shapeParityCall
	switch tool {
	case "Bash":
		out = append(out, shapeParityCall{name: "antigravity/run_command", conn: "antigravity", event: "PreToolUse", headers: agy,
			body: func() map[string]any {
				m := shapeParityAntigravity("run_command", map[string]any{"Cwd": cwd, "CommandLine": str("command"), "WaitMsBeforeAsync": 5000})
				m["workspacePaths"] = []string{cwd}
				return m
			}()})
	case "Write":
		out = append(out,
			shapeParityCall{name: "antigravity/write_to_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("write_to_file", map[string]any{"TargetFile": str("file_path"), "CodeContent": str("content")})},
			shapeParityCall{name: "codex/apply_patch-add", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": "*** Begin Patch\n*** Add File: " +
					str("file_path") + "\n+" + strings.ReplaceAll(str("content"), "\n", "\n+") + "\n*** End Patch"})},
		)
	case "Edit":
		out = append(out,
			shapeParityCall{name: "antigravity/replace_file_content", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("replace_file_content", map[string]any{"TargetFile": str("file_path"),
					"TargetContent": str("old_string"), "ReplacementContent": str("new_string")})},
			shapeParityCall{name: "amp/edit_file", conn: "amp", event: "tool.call",
				body: shapeParityEnvelope("tool.call", cwd, "edit_file", map[string]any{"path": str("file_path"),
					"old_str": str("old_string"), "new_str": str("new_string")})},
			// The Update File of the same edit (rel-1-0-10:GAP-0947).
			shapeParityCall{name: "codex/apply_patch-update", conn: "codex", event: "PreToolUse",
				headers: map[string]string{"X-DefenseClaw-Hook-Event": "PreToolUse", "X-DefenseClaw-Hook-Contract": defaultTestCodexHookContract},
				body: shapeParityEnvelope("PreToolUse", cwd, "apply_patch", map[string]any{"command": shapeParityUpdatePatch(
					str("file_path"), str("old_string"), str("new_string"))})},
		)
	case "Read":
		copilotArgs, _ := json.Marshal(map[string]any{"path": str("file_path")})
		sid := fmt.Sprintf("sp-%d", shapeParitySeq.Add(1))
		out = append(out,
			shapeParityCall{name: "antigravity/view_file", conn: "antigravity", event: "PreToolUse", headers: agy,
				body: shapeParityAntigravity("view_file", map[string]any{"AbsolutePath": str("file_path")})},
			shapeParityCall{name: "copilot/view", conn: "copilot", event: "preToolUse",
				headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				body:    map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(copilotArgs)}},
			shapeParityCall{name: "cursor/beforeReadFile", conn: "cursor", event: "beforeReadFile",
				body: map[string]any{"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
					"session_id": sid, "cwd": cwd, "file_path": str("file_path"), "content": ""}},
		)
	}
	return out
}

// shapeParityNativeMore renders a Claude Code call (tool Bash, Write, Edit or
// Read) as the shell and file tools of OpenCode, Devin, Hermes, Kiro and
// OpenClaw (shapeParityNative keeps the train's shapes, which other tests
// read alone). A connector with no native
// tool for an action has no call for it: Devin's file tools (only exec is
// confirmed, by its audit rows and trusted shell schema) and OpenCode V2's
// edit (its patch tool, captured on a managed host, carries the edit).
func shapeParityNativeMore(tool string, args map[string]any, cwd string) []shapeParityCall {
	str := func(key string) string { value, _ := args[key].(string); return value }
	kiroV3 := map[string]string{connector.HookDialectHeader: connector.KiroHookSurfaceV3}
	var out []shapeParityCall
	switch tool {
	case "Bash":
		command := str("command")
		out = append(out,
			shapeParityCall{name: "opencode/shell", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "shell", map[string]any{"command": command})},
			shapeParityCall{name: "devin/exec", conn: "devin", event: "PreToolUse",
				body: shapeParityEnvelope("PreToolUse", cwd, "exec", map[string]any{"command": command})},
			shapeParityCall{name: "hermes/terminal", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "terminal", map[string]any{"command": command})},
			shapeParityCall{name: "openclaw/exec", conn: "openclaw", route: shapeParityInspectRoute,
				body: shapeParityOpenClaw("exec", map[string]any{"command": command, "workdir": cwd})},
		)
		if runtime.GOOS == "windows" {
			// The kiro-cli --v3 engine is the Windows one; it names its
			// shell tool execute_pwsh.
			out = append(out, shapeParityCall{name: "kiro/v3-execute_pwsh", conn: "kiro", event: "PreToolUse", headers: kiroV3,
				body: shapeParityEnvelope("PreToolUse", cwd, "execute_pwsh", map[string]any{"command": command})})
		} else {
			out = append(out,
				shapeParityCall{name: "kiro/execute_bash", conn: "kiro", event: "preToolUse",
					body: shapeParityEnvelope("preToolUse", cwd, "execute_bash", map[string]any{"command": command})},
				shapeParityCall{name: "kiro/v3-execute_bash", conn: "kiro", event: "PreToolUse", headers: kiroV3,
					body: shapeParityEnvelope("PreToolUse", cwd, "execute_bash", map[string]any{"command": command})},
			)
		}
	case "Write":
		path, content := str("file_path"), str("content")
		out = append(out,
			shapeParityCall{name: "opencode/write", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "write", map[string]any{"path": path, "content": content})},
			shapeParityCall{name: "opencode/patch-add", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "patch", map[string]any{"patchText": shapeParityPatch(path, content)})},
			shapeParityCall{name: "hermes/write_file", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "write_file", map[string]any{"path": path, "content": content})},
			shapeParityCall{name: "hermes/patch-v4a-add", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "patch", map[string]any{"mode": "patch", "patch": shapeParityPatch(path, content)})},
			shapeParityCall{name: "kiro/fs_write", conn: "kiro", event: "preToolUse",
				body: shapeParityEnvelope("preToolUse", cwd, "fs_write", map[string]any{"path": path, "content": content})},
			shapeParityCall{name: "kiro/fs_write-create", conn: "kiro", event: "preToolUse",
				body: shapeParityEnvelope("preToolUse", cwd, "fs_write", map[string]any{"command": "create", "path": path, "file_text": content})},
			shapeParityCall{name: "openclaw/write", conn: "openclaw", route: shapeParityInspectRoute,
				body: shapeParityOpenClaw("write", map[string]any{"path": path, "content": content})},
		)
	case "Edit":
		path, oldText, newText := str("file_path"), str("old_string"), str("new_string")
		out = append(out,
			shapeParityCall{name: "opencode/patch-update", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "patch", map[string]any{"patchText": shapeParityUpdatePatch(path, oldText, newText)})},
			shapeParityCall{name: "hermes/patch-replace", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "patch", map[string]any{"mode": "replace", "path": path, "old_string": oldText, "new_string": newText})},
			shapeParityCall{name: "kiro/str_replace", conn: "kiro", event: "preToolUse",
				body: shapeParityEnvelope("preToolUse", cwd, "str_replace", map[string]any{"path": path, "oldStr": oldText, "newStr": newText})},
			shapeParityCall{name: "kiro/fs_write-str_replace", conn: "kiro", event: "preToolUse",
				body: shapeParityEnvelope("preToolUse", cwd, "fs_write", map[string]any{"command": "str_replace", "path": path,
					"old_str": oldText, "new_str": newText})},
			shapeParityCall{name: "openclaw/edit", conn: "openclaw", route: shapeParityInspectRoute,
				body: shapeParityOpenClaw("edit", map[string]any{"path": path, "oldText": oldText, "newText": newText})},
		)
	case "Read":
		path := str("file_path")
		out = append(out,
			shapeParityCall{name: "opencode/read", conn: "opencode", event: "tool.execute.before",
				body: shapeParityOpenCode(cwd, "read", map[string]any{"path": path})},
			shapeParityCall{name: "hermes/read_file", conn: "hermes", event: "pre_tool_call",
				body: shapeParityHermes(cwd, "read_file", map[string]any{"path": path})},
			shapeParityCall{name: "kiro/fs_read", conn: "kiro", event: "preToolUse",
				body: shapeParityEnvelope("preToolUse", cwd, "fs_read", map[string]any{"path": path})},
			shapeParityCall{name: "openclaw/read", conn: "openclaw", route: shapeParityInspectRoute,
				body: shapeParityOpenClaw("read", map[string]any{"path": path})},
		)
	}
	return out
}

// shapeParityHook answers one hook call through the connector's handler.
func shapeParityHook(t *testing.T, h http.HandlerFunc, call shapeParityCall, managedTier bool) string {
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

// shapeParityCases is the fixture calls as Claude Code tool calls, plus a
// Read of each written path.
func shapeParityCases(t *testing.T) []struct {
	id   string
	tool string
	args map[string]any
} {
	t.Helper()
	var out []struct {
		id   string
		tool string
		args map[string]any
	}
	seen := map[string]bool{}
	for _, c := range loadACPParityCases(t) {
		var args map[string]any
		if json.Unmarshal(c.Args, &args) != nil {
			continue
		}
		tool := c.Tool
		switch strings.ToLower(tool) {
		case "bash", "terminal", "shell":
			tool = "Bash"
		case "write", "edit":
		default:
			continue
		}
		out = append(out, struct {
			id   string
			tool string
			args map[string]any
		}{c.ID, tool, args})
		if path, ok := args["file_path"].(string); ok && path != "" && !seen[path] {
			seen[path] = true
			out = append(out, struct {
				id   string
				tool string
				args map[string]any
			}{c.ID + "/read", "Read", map[string]any{"file_path": path}})
		}
	}
	return out
}

func shapeParityTiers(t *testing.T, fn func(t *testing.T, p gap0437Pack)) {
	for _, p := range gap0437Packs {
		p := p
		t.Run(p.name, func(t *testing.T) { fn(t, p) })
	}
}

// TestProxyToolCallsNeverWeakerThanClaudeCode: the LLM proxy's tool-call
// route judges a model reply's Bash, Write, Edit and Read calls at least as
// the Claude Code hook does (GAP-0782), in the default, permissive and strict
// packs (the proxy has no managed tier).
func TestProxyToolCallsNeverWeakerThanClaudeCode(t *testing.T) {
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
			base := shapeParityHook(t, hook, shapeParityCall{name: "claudecode", conn: "claudecode",
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
func TestWindowsHostShellDialectEveryRoute(t *testing.T) {
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
			base := shapeParityHook(t, claude.handleAgentHook("claudecode"), shapeParityCall{name: "claudecode/PowerShell",
				conn: "claudecode", event: "PreToolUse", body: shapeParityEnvelope("PreToolUse", cwd, "PowerShell",
					map[string]any{"command": c.command})}, p.managed)
			for _, call := range shapeParityNative("Bash", map[string]any{"command": c.command}, cwd) {
				if got := shapeParityHook(t, agy.handleAgentHook("antigravity"), call, p.managed); shapeParityRank[got] < shapeParityRank[base] {
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

func TestTrustedShellCommandArgumentReadsEveryCommandKey(t *testing.T) {
	for _, tc := range []struct {
		raw  string
		want string
		ok   bool
	}{
		{`{"command":"Get-ChildItem"}`, "Get-ChildItem", true},
		{`{"CommandLine":"Get-ChildItem"}`, "Get-ChildItem", true},
		{`{"cmd":"ls"}`, "ls", true},
		{`{"command":"ls","CommandLine":"ls"}`, "ls", true},
		{`{"command":"ls","CommandLine":"pwd"}`, "", false},
		{`{"path":"/tmp/x"}`, "", false},
		{`{"command":7}`, "", false},
	} {
		got, ok := trustedShellCommandArgument(json.RawMessage(tc.raw))
		if got != tc.want || ok != tc.ok {
			t.Errorf("%s: got %q %v, want %q %v", tc.raw, got, ok, tc.want, tc.ok)
		}
	}
}
