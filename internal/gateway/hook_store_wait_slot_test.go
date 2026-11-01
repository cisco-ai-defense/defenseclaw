// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// TestHookStoreWaitsDoNotHoldTheCallerRunSlot: the run slot bounds the
// gateway CPU one caller's hooks use. A hook that waits on audit.db (the
// correlation ledger, the scan record, the delivery journal's durable
// insert) uses no CPU, so it gives the slot up for the wait and takes it back
// before it goes on. With one slot (a host of two or three processors) a
// caller's next hooks otherwise queued behind every store wait of the call
// before them, and after a cold start on a multi-GB store they passed their
// answer budget and were closed as a gateway no-answer (GAP-1790).
func TestHookStoreWaitsDoNotHoldTheCallerRunSlot(t *testing.T) {
	steps := map[string]func(*APIServer, context.Context){
		"correlation": func(a *APIServer, ctx context.Context) {
			req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
				SessionID: "store-wait-correlation", ToolName: "Bash", ToolInvocationID: "store-wait-tool", CWD: "/tmp"}
			_, _, _ = a.correlateHookOccurrence(ctx, a.hookProfileForRequest(ctx, "claudecode"), req,
				[]byte(managedHookBody("store-wait-correlation", "PreToolUse")))
		},
		"scan record": func(a *APIServer, ctx context.Context) {
			a.emitHookRuleFindings(ctx, "claudecode", "PreToolUse", &ToolInspectVerdict{Action: "allow", Severity: "NONE"},
				"tool_call", time.Millisecond)
		},
		"delivery journal": func(a *APIServer, ctx context.Context) {
			req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse",
				SessionID: "store-wait-journal", ToolName: "Bash", ToolInvocationID: "store-wait-journal-tool", CWD: "/tmp"}
			_, _ = a.journalHookDelivery(ctx, &req, agentHookResponse{Action: "allow", Severity: "NONE"},
				nil, 64, time.Millisecond, false, nil)
		},
	}
	for name, step := range steps {
		t.Run(name, func(t *testing.T) {
			// A fresh store per step: the first write that meets the held
			// lock waits out busy_timeout; later ones may fail at once.
			f := newManagedHookAuditFixture(t, nil)
			locker, err := sql.Open("sqlite", "file:"+f.path)
			if err != nil {
				t.Fatal(err)
			}
			defer locker.Close()
			conn, err := locker.Conn(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			if _, err := conn.ExecContext(context.Background(), "BEGIN IMMEDIATE"); err != nil {
				t.Fatal(err)
			}
			unlocked := false
			unlock := func() {
				if !unlocked {
					unlocked = true
					_, _ = conn.ExecContext(context.Background(), "ROLLBACK")
				}
			}
			defer unlock()

			run := make(chan struct{}, 1)
			run <- struct{}{}
			slot := &hookRunSlot{run: run, held: true}
			ctx := context.WithValue(t.Context(), hookRunSlotContextKey{}, slot)
			done := make(chan struct{})
			go func() {
				defer close(done)
				step(f.api, ctx)
			}()
			freed := false
			deadline := time.After(10 * time.Second)
		wait:
			for {
				select {
				case <-done:
					break wait
				case <-deadline:
					unlock()
					<-done
					t.Fatal("the store step did not end")
				case <-time.After(time.Millisecond):
					if len(run) == 0 {
						freed = true
						// The slot is free: release the store so the step
						// can finish and take it back.
						unlock()
					}
				}
			}
			if !freed {
				t.Fatal("the hook held its caller's run slot while it waited on the audit store")
			}
			slot.mu.Lock()
			held := slot.held
			slot.mu.Unlock()
			if !held || len(run) != 1 {
				t.Fatalf("after the store wait the hook did not take its run slot back: held=%v tokens=%d", held, len(run))
			}
		})
	}
}
