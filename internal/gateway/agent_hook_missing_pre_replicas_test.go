// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/historystore"
)

// substrate-1 GAP-0267: on Agent Substrate the hooks of one actor are spread
// over the gateway replicas. A PostToolUse that landed on another replica
// than its audited PreToolUse wrote a false "Tool result arrived without an
// audited PreToolUse decision" alert, because each replica kept its own
// ring. The replicas now share an actor's decisions through the leader's
// record (here one shared store, as the leader is in production).
func gap0267Replicas(t *testing.T) (a, b *APIServer, shared *historystore.Process, alerts func(*APIServer) int) {
	t.Helper()
	shared = &historystore.Process{}
	setSubstrateHistoryStore(shared)
	t.Cleanup(func() { setSubstrateHistoryStore(nil) })
	stores := map[*APIServer]*audit.Store{}
	mk := func() *APIServer {
		store, logger := testStoreAndLogger(t)
		api := &APIServer{store: store, logger: logger}
		stores[api] = store
		return api
	}
	a, b = mk(), mk()
	alerts = func(api *APIServer) int {
		events, err := stores[api].ListEvents(100)
		if err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, event := range events {
			if event.Action == string(audit.ActionAlert) && event.Actor == "hook-pre-tool-missing" {
				n++
			}
		}
		return n
	}
	return a, b, shared, alerts
}

func gap0267Finish(t *testing.T, ctx context.Context, api *APIServer, connector, event, session, tool string) {
	t.Helper()
	req := agentHookRequest{ConnectorName: connector, ConnectorInstanceID: "caller-instance",
		HookEventName: event, SessionID: session, ToolInvocationID: tool, ToolName: "Bash"}
	resp := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action"}
	if !api.finalizeAgentHook(ctx, connector, req, resp, nil, []byte(`{}`), time.Millisecond, false, nil).AuditPersisted {
		t.Fatal("hook decision audit was not persisted")
	}
}

// gap0267AwaitShared waits (up to 2 s, the time a tool takes to run at
// least) until the shared record holds something.
func gap0267AwaitShared(shared *historystore.Process) {
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if scopes, _, _ := shared.Stats("", ""); scopes > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestGAP0267PostToolUseOnAnotherReplicaFindsItsPreToolUse(t *testing.T) {
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tc := range []struct {
			name, preTool, postTool string
			pre, wantAlert          bool
		}{
			{"pre on the other replica", "tool-1", "tool-1", true, false},
			{"no pre anywhere", "", "tool-1", false, true},
			{"pre of another invocation", "tool-2", "tool-1", true, true},
		} {
			t.Run(connector+"/"+tc.name, func(t *testing.T) {
				a, b, shared, alerts := gap0267Replicas(t)
				ctx := withSubstrateActor(t.Context(), *f14Actor(t, "gap0267", "3b6c2d1e-8f4a-4b9c-a1d2-5e6f7a8b9c0d"))
				if tc.pre {
					gap0267Finish(t, ctx, a, connector, "PreToolUse", "session-1", tc.preTool)
					gap0267AwaitShared(shared)
				}
				gap0267Finish(t, ctx, b, connector, "PostToolUse", "session-1", tc.postTool)
				if got := alerts(b) == 1; got != tc.wantAlert {
					t.Fatalf("replica B alerts=%d, want alert=%v", alerts(b), tc.wantAlert)
				}
				if n := alerts(a); n != 0 {
					t.Fatalf("replica A wrote %d missing-pre alerts", n)
				}
			})
		}
	}
}

// A host call (not an actor's) keeps its process-local ring: nothing of it
// goes to the shared record.
func TestGAP0267HostCallsStayProcessLocal(t *testing.T) {
	a, b, shared, alerts := gap0267Replicas(t)
	gap0267Finish(t, t.Context(), a, "claudecode", "PreToolUse", "session-1", "tool-1")
	gap0267AwaitShared(shared)
	if scopes, _, _ := shared.Stats("", ""); scopes != 0 {
		t.Fatalf("a host call wrote %d scopes to the shared record", scopes)
	}
	gap0267Finish(t, t.Context(), b, "claudecode", "PostToolUse", "session-1", "tool-1")
	if alerts(b) != 1 {
		t.Fatalf("a host PostToolUse on another process found a PreToolUse it never saw")
	}
}
