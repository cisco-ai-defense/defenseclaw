// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func kiroDedupeRequest(surface, tool, command string) agentHookRequest {
	input := map[string]interface{}{"command": command}
	args, _ := json.Marshal(input)
	return agentHookRequest{HookEventName: "preToolUse", SessionID: "kiro-s1", CWD: "/project", HookSurface: surface,
		ToolName: tool, ToolArgs: args, Payload: map[string]interface{}{"tool_name": tool, "tool_input": input}}
}

// TestKiroHookDedupeAcrossSurfaces (GAP-0165): kiro-cli 3.x runs the agent
// file's hook (bare command, v2 surface) and the hooks file's hook (v3
// marker) for one tool call. The second delivery takes the first one's
// verdict; a call that only one surface delivers, a repeat on the same
// surface, other arguments and a missing session are each evaluated alone.
func TestKiroHookDedupeAcrossSurfaces(t *testing.T) {
	ctx := context.Background()
	block := agentHookResponse{Action: "block", Severity: "HIGH", EvaluationID: "k1"}

	var d copilotHookDedupe
	_, hit, first := d.begin(ctx, "kiro", kiroDedupeRequest("", "execute_bash", "ls"), "")
	if hit {
		t.Fatal("first delivery hit")
	}
	go func() {
		time.Sleep(20 * time.Millisecond)
		first.complete(block)
	}()
	got, hit, _ := d.begin(ctx, "kiro", kiroDedupeRequest(connector.KiroHookSurfaceV3, "shell", "ls"), "")
	if !hit || got.Action != "block" || got.EvaluationID != "k1" {
		t.Fatalf("hooks-file delivery did not take the agent-file verdict: hit=%v got=%+v", hit, got)
	}
	// The pair is consumed: the next identical call starts a new pair.
	_, hit, again := d.begin(ctx, "kiro", kiroDedupeRequest("", "execute_bash", "ls"), "")
	if hit {
		t.Fatal("a later identical call reused a consumed verdict")
	}
	again.complete(block)
	if _, hit, _ := d.begin(ctx, "kiro", kiroDedupeRequest("", "execute_bash", "ls"), ""); hit {
		t.Fatal("same-surface repeat reused the verdict")
	}
	if _, hit, _ := d.begin(ctx, "kiro", kiroDedupeRequest(connector.KiroHookSurfaceV3, "execute_bash", "rm -rf /"), ""); hit {
		t.Fatal("other arguments reused the verdict")
	}

	// kiro-cli --v2 delivers one surface only: nothing to match, ever.
	var single copilotHookDedupe
	for i := 0; i < 3; i++ {
		if _, hit, ticket := single.begin(ctx, "kiro", kiroDedupeRequest("", "execute_bash", "ls"), ""); hit {
			t.Fatalf("single-surface call %d answered from the cache", i)
		} else {
			ticket.complete(block)
		}
	}

	noSession := kiroDedupeRequest("", "execute_bash", "ls")
	noSession.SessionID = ""
	var bare copilotHookDedupe
	_, _, t1 := bare.begin(ctx, "kiro", noSession, "")
	t1.complete(block)
	noSession.HookSurface = connector.KiroHookSurfaceV3
	if _, hit, _ := bare.begin(ctx, "kiro", noSession, ""); hit {
		t.Fatal("a call without a session id was deduplicated")
	}

	var other copilotHookDedupe
	_, _, c1 := other.begin(ctx, "claudecode", kiroDedupeRequest("", "execute_bash", "ls"), "")
	c1.complete(block)
	if _, hit, _ := other.begin(ctx, "claudecode", kiroDedupeRequest(connector.KiroHookSurfaceV3, "execute_bash", "ls"), ""); hit {
		t.Fatal("a non-Kiro, non-Copilot connector was deduplicated")
	}
}

// TestKiroBothSurfacesAuditOnceAndBlockOnEach: through the real hook
// handler, kiro-cli 3.x (both surfaces) and kiro-cli --v2 on a 3.x install
// (the agent file's bare hook only) both block a destructive shell call in
// action mode, and the two-surface call is audited once.
func TestKiroBothSurfacesAuditOnceAndBlockOnEach(t *testing.T) {
	newAPI := func(t *testing.T) (*APIServer, func() int) {
		t.Helper()
		store, logger := testStoreAndLogger(t)
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = "kiro"
		api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
		rows := func() int {
			t.Helper()
			events, err := store.ListEvents(100)
			if err != nil {
				t.Fatal(err)
			}
			n := 0
			for _, ev := range events {
				if ev.Action == string(audit.ActionConnectorHook) {
					n++
				}
			}
			return n
		}
		return api, rows
	}
	workDir := t.TempDir()
	deliver := func(t *testing.T, api *APIServer, event, surface string) map[string]interface{} {
		t.Helper()
		// An existing directory: a missing one resolves to no working directory.
		cwd := workDir
		body, err := json.Marshal(map[string]interface{}{
			"hook_event_name": event,
			"session_id":      "kiro-session",
			"cwd":             cwd,
			"tool_name":       "execute_bash",
			"tool_input":      map[string]interface{}{"command": "rm -rf /"},
		})
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodPost, "/api/v1/kiro/hook", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		if surface != "" {
			req.Header.Set(connector.KiroSurfaceHeader, surface)
		}
		w := httptest.NewRecorder()
		http.HandlerFunc(api.handleAgentHook("kiro")).ServeHTTP(w, req)
		if w.Code != http.StatusOK {
			t.Fatalf("status=%d body=%s", w.Code, w.Body.String())
		}
		var parsed map[string]interface{}
		if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
			t.Fatalf("response not JSON: %v body=%s", err, w.Body.String())
		}
		return parsed
	}

	t.Run("v2 engine alone is protected", func(t *testing.T) {
		api, rows := newAPI(t)
		resp := deliver(t, api, "preToolUse", "")
		if resp["action"] != "block" {
			t.Fatalf("kiro-cli --v2 delivery was not blocked: %v", resp)
		}
		if n := rows(); n != 1 {
			t.Fatalf("v2 delivery rows = %d, want 1", n)
		}
	})
	t.Run("v3 engine blocks both deliveries, audits once", func(t *testing.T) {
		api, rows := newAPI(t)
		for _, surface := range []string{"", connector.KiroHookSurfaceV3} {
			if resp := deliver(t, api, "preToolUse", surface); resp["action"] != "block" {
				t.Fatalf("surface %q was not blocked: %v", surface, resp)
			}
		}
		if n := rows(); n != 1 {
			t.Fatalf("pre-tool rows for one call on two surfaces = %d, want 1", n)
		}
	})
	t.Run("concurrent deliveries, either order", func(t *testing.T) {
		for _, order := range [][2]string{{"", connector.KiroHookSurfaceV3}, {connector.KiroHookSurfaceV3, ""}} {
			api, rows := newAPI(t)
			var wg sync.WaitGroup
			actions := make([]interface{}, 2)
			for i, surface := range order {
				wg.Add(1)
				go func(i int, surface string) {
					defer wg.Done()
					actions[i] = deliver(t, api, "preToolUse", surface)["action"]
				}(i, surface)
			}
			wg.Wait()
			if actions[0] != "block" || actions[1] != "block" {
				t.Fatalf("order %q: actions = %v, want both block", order, actions)
			}
			if n := rows(); n != 1 {
				t.Fatalf("order %q: rows = %d, want 1", order, n)
			}
		}
	})
	t.Run("post tool use on both surfaces audits once", func(t *testing.T) {
		api, rows := newAPI(t)
		deliver(t, api, "postToolUse", "")
		deliver(t, api, "postToolUse", connector.KiroHookSurfaceV3)
		if n := rows(); n != 1 {
			t.Fatalf("post-tool rows for one call on two surfaces = %d, want 1", n)
		}
	})
}
