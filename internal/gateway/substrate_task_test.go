// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// The substrate fixture (substrate_listener_test.go) is not built on Windows.

//go:build !windows

package gateway

import (
	"context"
	"fmt"
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
	// GAP-0291: no report goes uncounted; those after the first are repeats.
	// GAP-0303: the first few of a kind are audited one by one.
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
	if n != 4 || repeats != 3 {
		t.Fatalf("%d task-end rows (%d repeats) for 5 reports, want 4 (3 repeats)", n, repeats)
	}
}

// GAP-0303 (expected item 3): repeats of one kind of end collapse after a few
// rows, the count is kept, and a different kind of end still gets its row, so
// the agent cannot mint HIGH rows at the actor rate limit.
func TestGAP0303TaskEndRepeatsCollapse(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	const flood = 100
	stalled := `{"exit_code":124,"stalled":true,"duration_ms":1000,"cause":"agent chosen"}`
	for i := range flood {
		if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", stalled); rec.Code != http.StatusNoContent {
			t.Fatalf("report %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	// The relay's own end, a different kind, after the flood.
	own := `{"exit_code":124,"stalled":true,"duration_ms":901000,"cause":"the task made no progress for 10m0s"}`
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", own); rec.Code != http.StatusNoContent {
		t.Fatalf("relay end: %d %s", rec.Code, rec.Body)
	}
	f.mu.Lock()
	marks := 0
	for _, m := range f.activity {
		if m == SubstrateActivityTaskEnd+":"+subUID2 {
			marks++
		}
	}
	f.mu.Unlock()
	if marks != flood+1 {
		t.Fatalf("%d task_end marks for %d reports: the collapse must not drop the mark", marks, flood+1)
	}
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	rows, sawOwn, sawGap := 0, false, false
	for _, e := range events {
		if !strings.Contains(e.Details, "task_end") || !strings.Contains(e.Details, "eng-web/bob-1") {
			continue
		}
		rows++
		if strings.Contains(e.Details, "no progress for 10m0s") {
			sawOwn = true
		}
		// The 8th report of the flood says how many repeats it stands for.
		if strings.Contains(e.Details, "4 earlier reports of this kind not audited") && strings.Contains(e.Details, `"kind_count":8`) {
			sawGap = true
		}
	}
	// 3 plain rows, then 8, 16, 32 and 64 of the flood, plus the relay's end.
	if want := 3 + 4 + 1; rows != want {
		t.Fatalf("%d task-end rows for %d reports, want %d", rows, flood+1, want)
	}
	if !sawOwn {
		t.Fatal("the relay's own end was not audited after the agent's flood")
	}
	if !sawGap {
		t.Fatal("the row at the 8th report does not say how many repeats were not audited")
	}
}

// GAP-0303: distinct causes cannot defeat the collapse; the kinds tracked per
// actor are bounded, the rest share one kind per severity.
func TestGAP0303TaskEndKindsAreBounded(t *testing.T) {
	f := newSubstrateFixture(t)
	store, logger := testStoreAndLogger(t)
	f.api.store, f.api.logger = store, logger
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	const reports = 200
	for i := range reports {
		body := fmt.Sprintf(`{"exit_code":124,"stalled":true,"cause":"cause %d"}`, i)
		if rec := f.do(t, f.actor, http.MethodPost, substrateRelayTask, "tok-bob", body); rec.Code != http.StatusNoContent {
			t.Fatalf("report %d: %d %s", i, rec.Code, rec.Body)
		}
	}
	events, err := store.ListEvents(500)
	if err != nil {
		t.Fatal(err)
	}
	rows, last := 0, 0
	for _, e := range events {
		if strings.Contains(e.Details, "task_end") && strings.Contains(e.Details, "eng-web/bob-1") {
			rows++
			if strings.Contains(e.Details, `"report":200,`) {
				last++
			}
		}
	}
	// 16 kinds of one report each, then the shared kind: 3 plain rows and 8, 16, 32, 64, 128.
	if rows != 16+3+5 {
		t.Fatalf("%d of %d distinct-cause reports audited, want 24", rows, reports)
	}
	if last != 0 {
		t.Fatalf("report 200 of a shared kind (count 185) was audited")
	}
}
