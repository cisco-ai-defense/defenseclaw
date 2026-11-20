// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0273, GAP-0274: a --task actor's relay reports how the task ended;
// the gateway audits it and marks a task_end for the controller.
func TestSubstrateRelayTaskEnd(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	body := `{"exit_code":124,"stalled":true,"duration_ms":901000,"cause":"the task made no progress for 10m0s\u0007; the cluster gateway answers"}`
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", body); rec.Code != http.StatusNoContent {
		t.Fatalf("task end: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	marks := strings.Join(f.activity, ",")
	f.mu.Unlock()
	if !strings.Contains(marks, SubstrateActivityTaskEnd+":"+subUID2) {
		t.Fatalf("activity %s: no task_end mark", marks)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	var row *audit.Event
	for i := range events {
		if strings.Contains(events[i].Details, "task_end") {
			row = &events[i]
		}
	}
	if row == nil || !strings.Contains(row.Details, `"source":"substrate"`) || row.Severity != "HIGH" ||
		!strings.Contains(row.Details, "task ended by the relay: eng-web/bob-1 exit 124 after 15m1s") ||
		!strings.Contains(row.Details, "no progress for 10m0s ; the cluster gateway answers") ||
		!strings.Contains(row.Details, `"batch_id":"b1"`) {
		t.Fatalf("audit row %+v (of %d)", row, len(events))
	}
	// An interactive actor has no task to end.
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-alice", `{"exit_code":0}`); rec.Code != http.StatusForbidden {
		t.Fatalf("interactive actor: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodGet, substrateRelayTask, "tok-bob", ""); rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET: %d", rec.Code)
	}
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "", `{"exit_code":0}`); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no actor token: %d", rec.Code)
	}
	// GAP-0291: no report is dropped; those after the first are repeats.
	for range 4 {
		f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", `{"exit_code":0}`)
	}
	events, _ = store.ListEvents(100)
	n, repeats := 0, 0
	for _, e := range events {
		if strings.Contains(e.Details, "task_end") && strings.Contains(e.Details, "eng-web/bob-1") {
			n++
			if strings.Contains(e.Details, `"repeat":true`) && strings.Contains(e.Details, "repeat ") {
				repeats++
			}
		}
	}
	if n != 5 || repeats != 4 {
		t.Fatalf("%d task-end rows (%d repeats) for 5 reports, want 5 (4 repeats)", n, repeats)
	}
}
