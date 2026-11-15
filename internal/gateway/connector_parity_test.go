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
	"strings"
	"sync/atomic"
	"testing"
	"time"

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
// view_file; Amp edit_file; Copilot view; Cursor beforeReadFile.

var shapeParityRank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

// shapeParityCall is one tool call of a connector: its hook event, body and
// headers.
type shapeParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
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

// shapeParityHook answers one hook call through the connector's handler.
func shapeParityHook(t *testing.T, h http.HandlerFunc, call shapeParityCall, managedTier bool) string {
	t.Helper()
	raw, _ := json.Marshal(call.body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+call.conn+"/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for key, value := range call.headers {
		req.Header.Set(key, value)
	}
	if managedTier {
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
