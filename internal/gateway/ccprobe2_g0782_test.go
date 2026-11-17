// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0782: the LLM proxy's tool-call
// route (GuardrailProxy.inspectToolCalls) judges a model reply's Bash, Write,
// Edit and Read call at least as the Claude Code hook judges the same call,
// in the default, strict and permissive packs (the proxy has no managed
// tier). The calls are every Bash/Write/Edit case of
// testdata/acp_parity_cases.jsonl (identical at the pre-fix sha and at rel)
// plus a Read of each written path, and hand rows whose targets are
// ~-relative (the gap: the proxy built actionfacts.Input with no caller
// home, so a ~ target named no home file). Old API only: gap0437Server,
// newTestProxy, inspectToolCalls, loadACPParityCases. Scratch, test-only.

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

var ccp2g0782Rank = map[string]int{"allow": 0, "": 0, "alert": 2, "warn": 2, "confirm": 2, "ask": 2, "block": 3}

type ccp2g0782Case struct {
	id   string
	tool string
	args map[string]any
}

func ccp2g0782Cases(t *testing.T) []ccp2g0782Case {
	t.Helper()
	var out []ccp2g0782Case
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
		out = append(out, ccp2g0782Case{c.ID, tool, args})
		if path, ok := args["file_path"].(string); ok && path != "" && !seen[path] {
			seen[path] = true
			out = append(out, ccp2g0782Case{c.ID + "/read", "Read", map[string]any{"file_path": path}})
		}
	}
	// ~-relative targets of the account home.
	out = append(out,
		ccp2g0782Case{"hand/read-key", "Read", map[string]any{"file_path": "~/.ssh/id_rsa"}},
		ccp2g0782Case{"hand/bash-read-key", "Bash", map[string]any{"command": "cat ~/.ssh/id_rsa"}},
		ccp2g0782Case{"hand/bash-authkeys", "Bash", map[string]any{"command": "echo ssh-ed25519 AAAAC3Nza probe >> ~/.ssh/authorized_keys"}},
		ccp2g0782Case{"hand/write-authkeys", "Write", map[string]any{"file_path": "~/.ssh/authorized_keys", "content": "ssh-ed25519 AAAAC3Nza probe\n"}},
	)
	return out
}

func ccp2g0782Hook(t *testing.T, h http.HandlerFunc, cwd, sid, tool string, input map[string]any) string {
	t.Helper()
	raw, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": sid, "cwd": cwd,
		"tool_name": tool, "tool_use_id": "tu-" + sid, "tool_input": input})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("claudecode: http %d", w.Code)
	}
	var resp struct {
		Action string `json:"action"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("claudecode: answer is not JSON")
	}
	return resp.Action
}

func TestCCP2G0782_ProxyToolCallsNeverWeakerThanClaudeCode(t *testing.T) {
	cases := ccp2g0782Cases(t)
	if len(cases) < 100 {
		t.Fatalf("only %d cases", len(cases))
	}
	for _, p := range gap0437Packs {
		if p.managed {
			continue
		}
		p := p
		t.Run(p.name, func(t *testing.T) {
			srv := gap0437Server(t, p, "claudecode", "action")
			installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
			hook := srv.handleAgentHook("claudecode")
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.RulePack = p.pack
			installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
			cwd := t.TempDir()
			weaker := 0
			for i, c := range cases {
				base := ccp2g0782Hook(t, hook, cwd, fmt.Sprintf("ccp2g0782-%s-%d", p.name, i), c.tool, c.args)
				args, _ := json.Marshal(c.args)
				calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": c.tool, "arguments": string(args)}}})
				got := "allow"
				if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
					got = v.Action
				}
				if ccp2g0782Rank[got] < ccp2g0782Rank[base] {
					weaker++
					t.Errorf("%s %s: proxy %s, Claude Code %s %s", p.name, c.id, got, c.tool, base)
				}
			}
			t.Logf("%s: %d cases, %d weaker on the proxy", p.name, len(cases), weaker)
		})
	}
}
