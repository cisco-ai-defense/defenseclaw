// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0784, NATIVE WINDOWS ONLY (the
// gap's evidence was a Linux simulation with windowsHookHost forced; this
// probe runs on a real Windows host, where windowsHookHost is true by itself,
// and skips elsewhere): every PowerShell case of
// testdata/acp_parity_cases.jsonl (identical at the pre-fix sha and at rel)
// sent through antigravity run_command ({"CommandLine": ...}), /inspect/tool
// exec and the proxy tool-call route gets a verdict at least as strong as
// through the Claude Code PowerShell tool, in the default, strict and
// permissive packs. Old API only: gap0437Server, handleAgentHook,
// handleInspectTool, newTestProxy, inspectToolCalls, loadACPParityCases.
// Scratch, test-only branch.

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
	"testing"
	"time"
)

var ccp2g0784Rank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

func ccp2g0784Ask(t *testing.T, h http.HandlerFunc, route string, headers map[string]string, body map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: http %d", route, w.Code)
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: answer is not JSON", route)
	}
	return resp.Action
}

func TestCCP2G0784_NativeWindowsPowerShellTextEveryRouteNeverWeakerThanClaudeCode(t *testing.T) {
	if runtime.GOOS != "windows" {
		t.Skip("native Windows probe: windowsHookHost must be true by itself")
	}
	if !windowsHookHost() {
		t.Fatal("windowsHookHost is false on a Windows host")
	}
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
	agyHeaders := map[string]string{"X-DefenseClaw-Antigravity-Event": "PreToolUse"}
	for _, p := range gap0437Packs {
		if p.managed {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) {
			cwd := t.TempDir()
			claude := gap0437Server(t, p, "claudecode", "action")
			installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
			agy := gap0437Server(t, p, "antigravity", "action")
			installToolCallCorpusProfileConnector(t, "antigravity", p.pack)
			inspect := gap0437Server(t, p, "openclaw", "action")
			inspect.inspectToolScanTimeout = time.Minute
			installToolCallCorpusProfileConnector(t, "openclaw", p.pack)
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.RulePack = p.pack
			installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
			weaker := map[string]int{}
			for i, c := range commands {
				sid := fmt.Sprintf("ccp2g0784-%s-%d", p.name, i)
				base := ccp2g0784Ask(t, claude.handleAgentHook("claudecode"), "/api/v1/claudecode/hook", nil, map[string]any{
					"hook_event_name": "PreToolUse", "session_id": sid, "cwd": cwd, "tool_name": "PowerShell",
					"tool_use_id": "tu-" + sid, "tool_input": map[string]any{"command": c.command}})
				got := ccp2g0784Ask(t, agy.handleAgentHook("antigravity"), "/api/v1/antigravity/hook", agyHeaders, map[string]any{
					"conversationId": sid, "stepIdx": 1, "workspacePaths": []string{cwd},
					"toolCall": map[string]any{"name": "run_command", "args": map[string]any{"Cwd": cwd, "CommandLine": c.command, "WaitMsBeforeAsync": 5000}}})
				if ccp2g0784Rank[got] < ccp2g0784Rank[base] {
					weaker["antigravity"]++
					t.Errorf("%s %s: antigravity run_command answered %s, Claude Code PowerShell %s", p.name, c.id, got, base)
				}
				got = ccp2g0784Ask(t, inspect.handleInspectTool, "/api/v1/inspect/tool", nil, map[string]any{
					"tool": "exec", "connector": "openclaw", "args": map[string]any{"command": c.command, "workdir": cwd}})
				if ccp2g0784Rank[got] < ccp2g0784Rank[base] {
					weaker["inspect"]++
					t.Errorf("%s %s: inspect-tool exec answered %s, Claude Code PowerShell %s", p.name, c.id, got, base)
				}
				args, _ := json.Marshal(map[string]any{"command": c.command})
				calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "shell", "arguments": string(args)}}})
				got = "allow"
				if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
					got = v.Action
				}
				if ccp2g0784Rank[got] < ccp2g0784Rank[base] {
					weaker["proxy"]++
					t.Errorf("%s %s: proxy shell answered %s, Claude Code PowerShell %s", p.name, c.id, got, base)
				}
			}
			t.Logf("%s: %d PowerShell cases, weaker %v", p.name, len(commands), weaker)
		})
	}
}
