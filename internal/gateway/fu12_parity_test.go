// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// FU12 test train (TT1b): code-close tests for the T-PARITY gaps GAP-0776,
// GAP-0780 and GAP-0793. Each renders one Claude Code tool call as the native
// shape of every other connector that carries it and requires a verdict at
// least as strong as Claude Code's, in the five tiers. The file builds only on
// the helpers that exist at the fix parents (shapeParityNative, ...Envelope,
// ...Hook, ...Tiers, gap0437Server), so it runs red at each parent.


var fu12ParityRank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

// fu12ParityCall is one tool call of a connector: its hook event, body and
// headers, and the route when it is not the connector hook.
type fu12ParityCall struct {
	name    string
	conn    string
	event   string
	body    map[string]any
	headers map[string]string
	route   string
}

// fu12ParityFrom lifts the calls of shapeParityNative, which exists at every
// fix parent, into fu12ParityCall.
func fu12ParityFrom(calls []shapeParityCall) []fu12ParityCall {
	out := make([]fu12ParityCall, 0, len(calls))
	for _, c := range calls {
		out = append(out, fu12ParityCall{name: c.name, conn: c.conn, event: c.event, body: c.body, headers: c.headers})
	}
	return out
}

// fu12ParityHook answers one call through the connector handler h.
func fu12ParityHook(t *testing.T, h http.HandlerFunc, call fu12ParityCall, managedTier bool) string {
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

const fu12ParityInspectRoute = "/api/v1/inspect/tool"

// fu12ParityHandlers answers the connectors the tests render, in tier p.
func fu12ParityHandlers(t *testing.T, p gap0437Pack) map[string]http.HandlerFunc {
	t.Helper()
	handlers := map[string]http.HandlerFunc{}
	for _, conn := range []string{"claudecode", "antigravity", "codex", "amp", "copilot", "kiro", "opencode", "openclaw"} {
		srv := gap0437Server(t, p, conn, "action")
		installToolCallCorpusProfileConnector(t, conn, p.pack)
		if conn == "openclaw" {
			srv.inspectToolScanTimeout = time.Minute
			handlers[conn] = srv.handleInspectTool
			continue
		}
		handlers[conn] = srv.handleAgentHook(conn)
	}
	return handlers
}

func fu12ParityCopilot(cwd, tool string, args map[string]any) fu12ParityCall {
	raw, _ := json.Marshal(args)
	return fu12ParityCall{name: "copilot/" + tool, conn: "copilot", event: "preToolUse",
		headers: map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
		body: map[string]any{"sessionId": fmt.Sprintf("fu12-%d", shapeParitySeq.Add(1)), "timestamp": float64(1),
			"cwd": cwd, "toolName": tool, "toolArgs": string(raw)}}
}

func fu12ParityOpenCode(cwd, tool string, input map[string]any) fu12ParityCall {
	n := shapeParitySeq.Add(1)
	return fu12ParityCall{name: "opencode/" + tool, conn: "opencode", event: "tool.execute.before",
		body: map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": input,
			"session_id": fmt.Sprintf("fu12-%d", n), "turn_id": fmt.Sprintf("m-fu12-%d", n), "tool_call_id": fmt.Sprintf("tu-fu12-%d", n),
			"agent_name": "build", "cwd": cwd, "load_heartbeat": true, "arguments_authoritative": true, "mcp_identity_status": "not_mcp"}}
}

func fu12ParityOpenClaw(tool string, args map[string]any) fu12ParityCall {
	n := shapeParitySeq.Add(1)
	return fu12ParityCall{name: "openclaw/" + tool, conn: "openclaw", route: fu12ParityInspectRoute,
		body: map[string]any{"tool": tool, "args": args, "tool_call_id": fmt.Sprintf("tu-fu12-%d", n),
			"session_id": fmt.Sprintf("fu12-%d", n), "approval_surface": "native"}}
}

// fu12ParityWriteShapes is a file write of content to path as the native tool
// of each connector (the shapes of the GAP-0776 report).
func fu12ParityWriteShapes(cwd, path, content string) []fu12ParityCall {
	out := fu12ParityFrom(shapeParityNative("Write", map[string]any{"file_path": path, "content": content}, cwd))
	out = append(out,
		fu12ParityCopilot(cwd, "create", map[string]any{"path": path, "file_text": content}),
		fu12ParityCall{name: "kiro/fs_write-create", conn: "kiro", event: "preToolUse",
			body: shapeParityEnvelope("preToolUse", cwd, "fs_write", map[string]any{"command": "create", "path": path, "file_text": content})},
		fu12ParityCall{name: "amp/create_file", conn: "amp", event: "tool.call",
			body: shapeParityEnvelope("tool.call", cwd, "create_file", map[string]any{"path": path, "content": content})},
		fu12ParityOpenCode(cwd, "write", map[string]any{"filePath": path, "content": content}),
		fu12ParityOpenClaw("write", map[string]any{"path": path, "content": content}),
	)
	return out
}

// fu12ParityEditShapes is the same content arriving as the new text of an edit.
func fu12ParityEditShapes(cwd, path, oldText, newText string) []fu12ParityCall {
	out := fu12ParityFrom(shapeParityNative("Edit", map[string]any{"file_path": path, "old_string": oldText, "new_string": newText}, cwd))
	out = append(out,
		fu12ParityCopilot(cwd, "edit", map[string]any{"path": path, "old_str": oldText, "new_str": newText}),
		fu12ParityCall{name: "kiro/fs_write-str_replace", conn: "kiro", event: "preToolUse",
			body: shapeParityEnvelope("preToolUse", cwd, "fs_write", map[string]any{"command": "str_replace", "path": path,
				"old_str": oldText, "new_str": newText})},
		fu12ParityOpenCode(cwd, "edit", map[string]any{"filePath": path, "oldString": oldText, "newString": newText}),
		fu12ParityOpenClaw("edit", map[string]any{"path": path, "oldText": oldText, "newText": newText}),
	)
	return out
}

// fu12ParityCheck answers the baseline Claude Code call of tool/args and every
// native call in tier p, and returns the baseline verdict with the native calls
// weaker than it.
func fu12ParityCheck(t *testing.T, p gap0437Pack, h map[string]http.HandlerFunc, cwd, tool string, args map[string]any,
	calls []fu12ParityCall) (string, []string, int) {
	t.Helper()
	base := fu12ParityHook(t, h["claudecode"], fu12ParityCall{name: "claudecode", conn: "claudecode", event: "PreToolUse",
		body: shapeParityEnvelope("PreToolUse", cwd, tool, args)}, p.managed)
	var weaker []string
	for _, call := range calls {
		got := fu12ParityHook(t, h[call.conn], call, p.managed)
		if fu12ParityRank[got] < fu12ParityRank[base] {
			weaker = append(weaker, fmt.Sprintf("%s %s (Claude Code %s)", call.name, got, base))
		}
	}
	return base, weaker, len(calls)
}

// requireStrongTier fails a default or strict tier in which the baseline did
// not judge the call: a test whose baseline allows proves nothing there.
func fu12ParityBaselineJudged(t *testing.T, p gap0437Pack, what, base string) {
	t.Helper()
	if (p.pack == "default" || p.pack == "strict") && fu12ParityRank[base] < fu12ParityRank["alert"] {
		t.Errorf("%s %s: the Claude Code baseline is %q, the fixture proves nothing", p.name, what, base)
	}
}

// GAP-0776: the same file content gets the same CG-* verdict whatever the
// write tool is called.
func TestFU12GAP0776CodeGuardReadsEveryNativeWriteTool(t *testing.T) {
	rows := []struct{ id, file, content string }{
		{"CG-EXEC-001", "run.py", "import os\ndef go(cmd):\n    os.system(cmd)\n"},
		{"CG-DESER-001", "load.py", "import pickle\ndef load(data):\n    return pickle.loads(data)\n"},
		{"CG-NET-001", "fetch.py", "import requests\ndef fetch(url):\n    return requests.get(url)\n"},
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		h := fu12ParityHandlers(t, p)
		cwd := t.TempDir()
		for _, r := range rows {
			path := filepath.Join(cwd, r.file)
			write := map[string]any{"file_path": path, "content": r.content}
			base, weaker, n := fu12ParityCheck(t, p, h, cwd, "Write", write, fu12ParityWriteShapes(cwd, path, r.content))
			if n == 0 {
				t.Fatalf("%s %s: no native write call was rendered", p.name, r.id)
			}
			fu12ParityBaselineJudged(t, p, r.id+" write", base)
			if len(weaker) > 0 {
				t.Errorf("%s %s write: weaker than Claude Code: %s", p.name, r.id, strings.Join(weaker, "; "))
			}
			edit := map[string]any{"file_path": path, "old_string": "pass\n", "new_string": r.content}
			base, weaker, _ = fu12ParityCheck(t, p, h, cwd, "Edit", edit, fu12ParityEditShapes(cwd, path, "pass\n", r.content))
			fu12ParityBaselineJudged(t, p, r.id+" edit", base)
			if len(weaker) > 0 {
				t.Errorf("%s %s edit: weaker than Claude Code: %s", p.name, r.id, strings.Join(weaker, "; "))
			}
		}
		// Benign twin: clean code through every native tool stays allowed.
		clean := "def add(a, b):\n    return a + b\n"
		path := filepath.Join(cwd, "ok.py")
		for _, call := range fu12ParityWriteShapes(cwd, path, clean) {
			if got := fu12ParityHook(t, h[call.conn], call, p.managed); got != "allow" {
				t.Errorf("%s benign %s: %s, want allow", p.name, call.name, got)
			}
		}
	})
}

// GAP-0780: a system schedule written through a native write tool is read by
// the path rule, whatever the tool's content key.
func TestFU12GAP0780SystemScheduleWriteIsReadThroughNativeWriteTools(t *testing.T) {
	const content = "* * * * * root /tmp/fu12-job.sh\n"
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		h := fu12ParityHandlers(t, p)
		cwd := t.TempDir()
		path := "/etc/cron.d/fu12-x"
		args := map[string]any{"file_path": path, "content": content}
		calls := fu12ParityFrom(shapeParityNative("Write", args, cwd))
		base, weaker, n := fu12ParityCheck(t, p, h, cwd, "Write", args, calls)
		if n == 0 {
			t.Fatalf("%s: no native write call was rendered", p.name)
		}
		fu12ParityBaselineJudged(t, p, "cron.d write", base)
		if len(weaker) > 0 {
			t.Errorf("%s: a /etc/cron.d write is weaker than Claude Code: %s", p.name, strings.Join(weaker, "; "))
		}
	})
}

// GAP-0793: Antigravity run_command names its command CommandLine; the
// DefenseClaw control and hook-config guards read it as they read Bash.
func TestFU12GAP0793AntigravityRunCommandReadsTheControlAndHookConfigGuards(t *testing.T) {
	commands := []string{
		"defenseclaw-gateway stop",
		"sudo systemctl stop defenseclaw-gateway",
		"rm -f ~/.claude/settings.json",
		`sed -i 's/"hooks"/"x"/' ~/.claude/settings.json`,
	}
	shapeParityTiers(t, func(t *testing.T, p gap0437Pack) {
		h := fu12ParityHandlers(t, p)
		cwd := t.TempDir()
		for _, command := range commands {
			args := map[string]any{"command": command}
			calls := fu12ParityFrom(shapeParityNative("Bash", args, cwd))
			base, weaker, n := fu12ParityCheck(t, p, h, cwd, "Bash", args, calls)
			if n == 0 {
				t.Fatalf("%s: no native shell call was rendered", p.name)
			}
			fu12ParityBaselineJudged(t, p, command, base)
			if len(weaker) > 0 {
				t.Errorf("%s %q: weaker than Claude Code: %s", p.name, command, strings.Join(weaker, "; "))
			}
		}
		// Benign twin: a read-only command is allowed through run_command.
		for _, call := range fu12ParityFrom(shapeParityNative("Bash", map[string]any{"command": "ls -la"}, cwd)) {
			if got := fu12ParityHook(t, h[call.conn], call, p.managed); got != "allow" {
				t.Errorf("%s benign %s: %s, want allow", p.name, call.name, got)
			}
		}
	})
}
