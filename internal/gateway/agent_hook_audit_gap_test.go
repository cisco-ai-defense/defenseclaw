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
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
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
