// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/managed/refusalpipe"
)

// GAP-1253: a stop writes the rows still queued and the counts of the windows
// still open before the refusal audit returns.
func TestUnenrolledRefusalStopWritesQueuedRowsAndOpenWindowCounts(t *testing.T) {
	sid := "S-1-5-21-1111-2222-3333-1042"
	report := refusalpipe.Report{Connector: "claudecode", Reason: refusalpipe.ReasonSIDUnregistered, Tool: "Bash"}
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	var mu sync.Mutex
	var rows []unenrolledRefusalRow
	write := func(ctx context.Context, row unenrolledRefusalRow) {
		<-release // a slow account lookup holds the writer past the stop
		if ctx.Err() != nil {
			t.Errorf("row written with a canceled context: %+v", row)
		}
		mu.Lock()
		rows = append(rows, row)
		mu.Unlock()
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUnenrolledRefusalAudit(ctx, func(ctx context.Context, auditor *unenrolledRefusalAuditor) {
			for range 50 {
				auditor.record(sid, report)
			}
			auditor.record(sid, refusalpipe.Report{Connector: "codex", Reason: refusalpipe.ReasonSIDUnregistered})
			cancel()
			<-ctx.Done()
		}, write)
	}()
	<-ctx.Done()
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refusal audit did not return after the stop")
	}
	mu.Lock()
	defer mu.Unlock()
	// A stalled writer can merge the first refusal with its open window.
	// The number of rows depends on scheduling; every connector's count must
	// still be preserved when the stop drains the queue.
	attemptsByConnector := make(map[string]int)
	for _, row := range rows {
		if row.SID != sid || row.Report.Reason != refusalpipe.ReasonSIDUnregistered || row.Attempts <= 0 {
			t.Fatalf("unexpected refusal row after the stop: %+v", row)
		}
		attemptsByConnector[row.Report.Connector] += row.Attempts
	}
	if len(attemptsByConnector) != 2 || attemptsByConnector["claudecode"] != 50 || attemptsByConnector["codex"] != 1 {
		t.Fatalf("rows after the stop = %+v (attempts by connector %+v), want claudecode=50 and codex=1", rows, attemptsByConnector)
	}
}

// GAP-1253: a writer that stalls while first refusals for every table entry
// fill the queue still gets, after the stop, the repeat counts of every open
// window: no refusal is lost, the drained counts merge into the waiting rows.
func TestUnenrolledRefusalStopKeepsEveryCountBehindAStalledWriter(t *testing.T) {
	report := refusalpipe.Report{Connector: "claudecode", Reason: refusalpipe.ReasonSIDUnregistered, Tool: "Bash"}
	ctx, cancel := context.WithCancel(context.Background())
	release := make(chan struct{})
	var mu sync.Mutex
	attempts := 0
	write := func(_ context.Context, row unenrolledRefusalRow) {
		<-release
		mu.Lock()
		attempts += row.Attempts
		mu.Unlock()
	}
	const repeats = 3
	queue := newUnenrolledRefusalQueue(unenrolledRefusalMaxEntries)
	done := make(chan struct{})
	go func() {
		defer close(done)
		runUnenrolledRefusalAuditQueue(ctx, queue, func(ctx context.Context, auditor *unenrolledRefusalAuditor) {
			for i := range unenrolledRefusalMaxEntries {
				sid := fmt.Sprintf("S-1-5-21-1111-2222-3333-%d", 2000+i)
				for range 1 + repeats {
					auditor.record(sid, report)
				}
			}
			cancel()
			<-ctx.Done()
		}, write)
	}()
	// Release the writer only once the stop has drained and closed the queue.
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(time.Millisecond) {
		queue.mu.Lock()
		closed := queue.closed
		queue.mu.Unlock()
		if closed {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the refusal audit did not drain after the stop")
		}
	}
	close(release)
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("refusal audit did not return after the stop")
	}
	mu.Lock()
	defer mu.Unlock()
	if want := unenrolledRefusalMaxEntries * (1 + repeats); attempts != want {
		t.Fatalf("refusals written after the stop = %d, want all %d", attempts, want)
	}
	if rows, lost := queue.lost(); rows != 0 || lost != 0 {
		t.Fatalf("queue dropped %d rows (%d refusals)", rows, lost)
	}
}

// A writer that falls behind costs rows past the queue bound, never silently:
// the dropped rows and refusals are counted.
func TestUnenrolledRefusalQueueCountsWhatItDrops(t *testing.T) {
	queue := newUnenrolledRefusalQueue(1)
	row := func(sid string, attempts int) unenrolledRefusalRow {
		return unenrolledRefusalRow{SID: sid, Report: refusalpipe.Report{Connector: "codex"}, Attempts: attempts}
	}
	queue.push(row("S-1-5-21-1-1-1-1001", 1), false)
	queue.push(row("S-1-5-21-1-1-1-1001", 4), false) // merged
	queue.push(row("S-1-5-21-1-1-1-1002", 2), false) // past the bound
	queue.push(row("S-1-5-21-1-1-1-1003", 3), true)  // a drain is never dropped
	if rows, attempts := queue.pending(); rows != 2 || attempts != 8 {
		t.Fatalf("pending = %d rows, %d refusals; want 2 rows, 8 refusals", rows, attempts)
	}
	if rows, attempts := queue.lost(); rows != 1 || attempts != 2 {
		t.Fatalf("lost = %d rows, %d refusals; want 1 row, 2 refusals", rows, attempts)
	}
}

// GAP-1242: a call the Windows standalone hook refuses for an excluded or
// not-yet-enrolled account is written as a block row naming the account the
// pipe client token identified, the connector, the event, the tool and the
// reason; a refusal loop is coalesced to one row a window per account and
// connector, with the count of the refusals that followed.
func TestUnenrolledRefusalWritesACoalescedBlockRowForTheAccount(t *testing.T) {
	sid := "S-1-5-21-1111-2222-3333-1042"
	report := refusalpipe.Report{
		Connector: "claudecode", Reason: refusalpipe.ReasonSIDUnregistered, Event: "PreToolUse", Tool: "Bash",
	}
	var rows []unenrolledRefusalRow
	auditor := newUnenrolledRefusalAuditor(func(row unenrolledRefusalRow) { rows = append(rows, row) })
	now := time.Unix(1_800_000_000, 0)
	auditor.now = func() time.Time { return now }
	for range 50 {
		auditor.record(sid, report)
	}
	auditor.record(sid, refusalpipe.Report{Connector: "codex", Reason: refusalpipe.ReasonSIDUnregistered})
	auditor.flush()
	if len(rows) != 2 || rows[0].Attempts != 1 || rows[0].Report != report || rows[1].Report.Connector != "codex" {
		t.Fatalf("rows in the first window = %+v, want one claudecode and one codex row", rows)
	}
	now = now.Add(unenrolledRefusalWindow)
	auditor.flush()
	if len(rows) != 3 || rows[2].Attempts != 49 || rows[2].SID != sid || len(auditor.entries) != 0 {
		t.Fatalf("rows after the window = %+v entries = %d, want the 49 coalesced refusals", rows, len(auditor.entries))
	}

	// The rows audit export reads: a hook decision and a connector-hook block
	// naming the account, with the tool and the coalesced count.
	fixture := newSidecarV8BootstrapFixture(t, 8, "")
	api := &APIServer{store: fixture.store, logger: fixture.logger}
	fixture.sidecar.setAPIServer(api)
	if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(t.Context(), fixture.configPath, fixture.raw); err != nil || !bound {
		t.Fatalf("bootstrap bound=%t error=%v", bound, err)
	}
	api.auditUnenrolledRefusal(context.Background(), rows[2])
	var decision, block *audit.Event
	for wait := time.Now().Add(5 * time.Second); (decision == nil || block == nil) && time.Now().Before(wait); time.Sleep(10 * time.Millisecond) {
		events, err := fixture.store.ListEvents(50)
		if err != nil {
			t.Fatal(err)
		}
		for i := range events {
			switch events[i].Action {
			case "hook_decision":
				decision = &events[i]
			case string(audit.ActionConnectorHook):
				block = &events[i]
			}
		}
	}
	if decision == nil || block == nil {
		t.Fatalf("hook decision row %v, connector-hook row %v", decision != nil, block != nil)
	}
	if decision.Structured["user.id"] != sid || decision.Structured["defenseclaw.guardrail.effective_action"] != "block" ||
		decision.Structured["defenseclaw.guardrail.reason"] != refusalpipe.ReasonSIDUnregistered || decision.Connector != "claudecode" {
		t.Fatalf("hook decision row connector=%q structured=%v", decision.Connector, decision.Structured)
	}
	extra, _ := block.Structured["extra"].(map[string]any)
	if block.Structured[auditUserIDKey] != sid || block.Structured["action"] != "block" ||
		block.Structured["reason"] != refusalpipe.ReasonSIDUnregistered || extra["tool"] != "Bash" || extra["attempts"] != "49" {
		t.Fatalf("connector-hook row connector=%q structured=%v", block.Connector, block.Structured)
	}
}

func TestUnenrolledRefusalAuditorFlushesEndedWindowOnShutdown(t *testing.T) {
	var rows []unenrolledRefusalRow
	auditor := newUnenrolledRefusalAuditor(func(row unenrolledRefusalRow) { rows = append(rows, row) })
	now := time.Unix(1_800_000_000, 0)
	auditor.now = func() time.Time { return now }
	report := refusalpipe.Report{Connector: "codex", Reason: refusalpipe.ReasonSIDUnregistered}
	auditor.record("account-sid", report)
	auditor.record("account-sid", report)
	now = now.Add(unenrolledRefusalWindow)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	auditor.run(ctx)
	if len(rows) != 2 || rows[1].Attempts != 1 || rows[1].SID != "account-sid" {
		t.Fatalf("shutdown rows = %+v, want the ended window's coalesced refusal", rows)
	}
}
