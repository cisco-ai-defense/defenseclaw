// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The LLM proxy judges a model reply Read of a credential file under a
// Windows home at least as the Claude Code hook judges the same Read from a
// Windows folder, in all five tiers, the managed ones included
// (rel-1-0-10:GAP-0909): the proxy read the Windows path from its POSIX
// neutral folder only, so it alerted MEDIUM where the hook blocks. An
// ordinary project file under the same home stays allowed on both.
func TestGAP0909ProxyWindowsCredentialReadNeverWeakerThanHook(t *testing.T) {
	files := []string{".git-credentials", ".netrc", ".pgpass", ".ssh/id_rsa", ".aws/credentials", ".kube/config"}
	for _, agentHome := range []string{"/home/alice", "/root"} {
		t.Setenv("HOME", agentHome)
		for _, p := range gap0437Packs {
			srv := gap0437Server(t, p, "claudecode", "action")
			installToolCallCorpusProfileConnector(t, "claudecode", p.pack)
			hook := srv.handleAgentHook("claudecode")
			proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
			proxy.cfg.RulePack = p.pack
			installToolCallCorpusProfileConnector(t, proxy.connectorName(), p.pack)
			read := func(path string) (string, string) {
				base := gap0909Hook(t, hook, shapeParityEnvelope("PreToolUse", `C:\work`, "Read", map[string]any{"file_path": path}), p.managed)
				args, _ := json.Marshal(map[string]string{"file_path": path})
				calls, _ := json.Marshal([]map[string]any{{"type": "function", "function": map[string]string{"name": "Read", "arguments": string(args)}}})
				got := "allow"
				if v := proxy.inspectToolCalls(context.Background(), calls); v != nil {
					got = v.Action
				}
				return base, got
			}
			for _, f := range files {
				for _, path := range []string{`C:\Users\x\` + strings.ReplaceAll(f, "/", `\`), "C:/Users/x/" + f} {
					base, got := read(path)
					if shapeParityRank[got] < shapeParityRank[base] {
						t.Errorf("home %s %s Read %s: proxy %s, Claude Code hook %s", agentHome, p.name, path, got, base)
					}
				}
			}
			for _, path := range []string{`C:\Users\x\project\notes.txt`, "C:/Users/x/project/README.md"} {
				if _, got := read(path); got != "allow" {
					t.Errorf("home %s %s Read %s: proxy %s, want allow (benign twin)", agentHome, p.name, path, got)
				}
			}
		}
	}
}

// gap0909Hook is the Claude Code hook's action for a Read, as shapeParityHook
// asks it. The strict install window (HOOK-INSTALL-WINDOW-STRICT) blocks every
// call of a session the hook has not seen installed; the proxy has no such
// window, so a verdict that only the window gives is no parity target, and
// such a call is judged allow here.
func gap0909Hook(t *testing.T, h http.HandlerFunc, body map[string]any, managedTier bool) string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	if managedTier {
		if ev := hookpaths.ResolveConnector("claudecode", "", "PreToolUse", raw); ev != "" {
			req.Header.Set(hookpaths.Header, ev)
		}
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	var resp struct {
		Action  string   `json:"action"`
		RuleIDs []string `json:"rule_ids"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil || w.Code != http.StatusOK {
		t.Fatalf("hook answer %d %q is not a decision", w.Code, w.Body.String())
	}
	if slices.Equal(resp.RuleIDs, []string{"HOOK-INSTALL-WINDOW-STRICT"}) {
		return "allow"
	}
	return resp.Action
}
