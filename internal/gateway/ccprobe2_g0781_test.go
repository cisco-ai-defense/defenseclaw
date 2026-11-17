// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0781: a Copilot view call and a
// Cursor beforeReadFile event that read the account's SSH private key are
// judged at least as the Claude Code Read of the same file, in the default,
// strict and permissive packs (the gap names default and permissive). Hook
// route: each connector's own handleAgentHook with its native payload, the
// servers built by gap0437Server (present at the pre-fix sha). The probe has
// its own request helper, so it needs none of the parity-test helpers that
// changed after the pre-fix sha. Scratch, test-only branch.

package gateway

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

var ccp2g0781Rank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

func ccp2g0781Ask(t *testing.T, h http.HandlerFunc, conn string, headers map[string]string, body map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+conn+"/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("%s: http %d %s", conn, w.Code, w.Body.String())
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("%s: answer is not JSON: %s", conn, w.Body.String())
	}
	return resp.Action
}

func TestCCP2G0781_CopilotViewAndCursorBeforeReadFileNeverWeakerThanClaudeCodeRead(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	paths := []string{"~/.ssh/id_rsa", home + "/.ssh/id_rsa", "~/.ssh/id_ed25519"}
	n := 0
	for _, p := range gap0437Packs {
		if p.managed {
			continue
		}
		handlers := map[string]http.HandlerFunc{}
		for _, conn := range []string{"claudecode", "copilot", "cursor"} {
			srv := gap0437Server(t, p, conn, "action")
			installToolCallCorpusProfileConnector(t, conn, p.pack)
			handlers[conn] = srv.handleAgentHook(conn)
		}
		for _, path := range paths {
			n++
			sid := fmt.Sprintf("ccp2g0781-%s-%d", p.name, n)
			base := ccp2g0781Ask(t, handlers["claudecode"], "claudecode", nil, map[string]any{
				"hook_event_name": "PreToolUse", "session_id": sid, "cwd": cwd, "tool_name": "Read",
				"tool_use_id": "tu-" + sid, "tool_input": map[string]any{"file_path": path}})
			viewArgs, _ := json.Marshal(map[string]any{"path": path})
			copilot := ccp2g0781Ask(t, handlers["copilot"], "copilot", map[string]string{"X-DefenseClaw-Copilot-Event": "preToolUse"},
				map[string]any{"sessionId": sid, "timestamp": float64(1), "cwd": cwd, "toolName": "view", "toolArgs": string(viewArgs)})
			cursor := ccp2g0781Ask(t, handlers["cursor"], "cursor", nil, map[string]any{
				"hook_event_name": "beforeReadFile", "conversation_id": sid, "generation_id": "g-" + sid,
				"session_id": sid, "cwd": cwd, "file_path": path, "content": ""})
			t.Logf("%s %s: claudecode Read %s, copilot view %s, cursor beforeReadFile %s", p.name, path, base, copilot, cursor)
			if ccp2g0781Rank[base] < ccp2g0781Rank["alert"] {
				t.Fatalf("%s %s: Claude Code Read answered %s; the baseline must flag a private-key read", p.name, path, base)
			}
			if ccp2g0781Rank[copilot] < ccp2g0781Rank[base] {
				t.Errorf("%s %s: copilot view answered %s, Claude Code Read %s", p.name, path, copilot, base)
			}
			if ccp2g0781Rank[cursor] < ccp2g0781Rank[base] {
				t.Errorf("%s %s: cursor beforeReadFile answered %s, Claude Code Read %s", p.name, path, cursor, base)
			}
		}
	}
}
