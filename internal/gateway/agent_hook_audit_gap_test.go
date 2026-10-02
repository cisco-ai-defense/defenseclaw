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
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// TestHookCorrelationSurvivesConcurrentSessionHooks pins that concurrent
// hooks of one session (SessionStart next to SubagentStart, as Claude Code
// and Codex send them) all correlate: an attempt whose cursor another hook
// moved in the meantime starts over instead of failing, which dropped the
// verdict's audit row.
func TestHookCorrelationSurvivesConcurrentSessionHooks(t *testing.T) {
	installCorrelationHMACForTest()
	server, store := newHookCorrelationServer(t, filepath.Join(t.TempDir(), "audit.db"))
	defer store.Close() //nolint:errcheck
	for _, name := range []string{"claudecode", "codex"} {
		profile := server.hookProfileForConnector(name)
		for round := 0; round < 3; round++ {
			session := fmt.Sprintf("%s-session-%d", name, round)
			var wg sync.WaitGroup
			var mu sync.Mutex
			var failures []string
			for i := 0; i < 24; i++ {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					payload := map[string]interface{}{"hook_event_name": "SessionStart", "session_id": session, "source": "startup"}
					if i%2 == 1 {
						payload = map[string]interface{}{"hook_event_name": "SubagentStart", "session_id": session,
							"agent_id": fmt.Sprintf("agent-%d", i), "agent_type": "general-purpose"}
					}
					raw, err := json.Marshal(payload)
					if err != nil {
						panic(err)
					}
					req := normalizeAgentHookRequestWithProfile(name, payload, profile)
					_, req, err = server.correlateHookOccurrence(t.Context(), profile, req, raw)
					mu.Lock()
					defer mu.Unlock()
					if err != nil || req.SuppressCorrelationEmit {
						failures = append(failures, fmt.Sprintf("%v (suppressed %t, err %v)", payload["hook_event_name"], req.SuppressCorrelationEmit, err))
					}
				}(i)
			}
			wg.Wait()
			if len(failures) > 0 {
				t.Fatalf("%s round %d: %d of 24 concurrent hooks did not correlate: %v", name, round, len(failures), failures)
			}
		}
	}
}

// TestHookVerdictKeepsItsAuditRowWhenCorrelationFails pins that a verdict
// whose correlation failed still gets its connector-hook audit row (only
// its export is withheld), while an exact replay of a delivery already
// persisted does not get a second one.
func TestHookVerdictKeepsItsAuditRowWhenCorrelationFails(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	rows := func() int {
		t.Helper()
		events, err := store.ListEvents(50)
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
	resp := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
	unavailable := agentHookRequest{ConnectorName: "codex", HookEventName: "SubagentStart", SessionID: "s-1",
		SuppressCorrelationEmit: true, CorrelationUnavailable: true}
	if !api.finalizeAgentHook(context.Background(), "codex", unavailable, resp, nil, []byte(`{}`), time.Millisecond, false, nil) {
		t.Fatal("the audit row of a verdict whose correlation failed was not persisted")
	}
	if n := rows(); n != 1 {
		t.Fatalf("connector-hook rows = %d, want 1", n)
	}
	replay := agentHookRequest{ConnectorName: "codex", HookEventName: "SubagentStart", SessionID: "s-1", SuppressCorrelationEmit: true}
	if api.finalizeAgentHook(context.Background(), "codex", replay, resp, nil, []byte(`{}`), time.Millisecond, false, nil) {
		t.Fatal("an exact replay was audited again")
	}
	if n := rows(); n != 1 {
		t.Fatalf("connector-hook rows after the replay = %d, want 1", n)
	}
}

// A hook client that gives up (its budget ran out while the gateway waited on
// the local store) has its verdict enforced all the same, so the verdict keeps
// its correlation, its hook_decision and its audit row: they used to be
// written with the request context, which the disconnect had cancelled.
func TestHookVerdictIsRecordedAfterTheClientDisconnects(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	fixture := newSidecarRuntimeFixture(t, true)
	fingerprints, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	logger := audit.NewLogger(fixture.store)
	logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: fixture.runtime, redactionEngine: fingerprints})
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	api := NewAPIServer("127.0.0.1:0", NewSidecarHealth(), nil, fixture.store, logger, cfg)
	bindHookLifecycleV8(t, api, fixture.runtime)

	body, err := json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s-disconnect", "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": "toolu-disconnect", "tool_input": map[string]any{"command": "ls"},
	})
	if err != nil {
		t.Fatal(err)
	}
	gone, hangUp := context.WithCancel(t.Context())
	hangUp()
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(gone)
	api.handleAgentHook("claudecode").ServeHTTP(httptest.NewRecorder(), request)

	decisions := 0
	for _, row := range readClaudeCodeReplayRows(t, fixture.path) {
		if row.event == "hook_decision" {
			decisions++
		}
	}
	events, err := fixture.store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	audited := 0
	for _, ev := range events {
		if ev.Action == string(audit.ActionConnectorHook) {
			audited++
		}
	}
	if decisions != 1 || audited != 1 {
		t.Fatalf("hook_decision rows = %d, connector-hook rows = %d, want 1 and 1", decisions, audited)
	}

	// Once the disconnect grace has run out the hook's remaining work is
	// cancelled, but the verdict it returns still gets its audit row.
	grace := agentHookDisconnectGrace
	agentHookDisconnectGrace = 0
	t.Cleanup(func() { agentHookDisconnectGrace = grace })
	body, err = json.Marshal(map[string]any{
		"hook_event_name": "PreToolUse", "session_id": "s-disconnect-expired", "cwd": t.TempDir(),
		"tool_name": "Bash", "tool_use_id": "toolu-disconnect-expired", "tool_input": map[string]any{"command": "ls"},
	})
	if err != nil {
		t.Fatal(err)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(gone)
	api.handleAgentHook("claudecode").ServeHTTP(httptest.NewRecorder(), request)
	if events, err = fixture.store.ListEvents(50); err != nil {
		t.Fatal(err)
	}
	audited = 0
	for _, ev := range events {
		if ev.Action == string(audit.ActionConnectorHook) {
			audited++
		}
	}
	if audited != 2 {
		t.Fatalf("connector-hook rows after the grace expired = %d, want 2", audited)
	}
}
