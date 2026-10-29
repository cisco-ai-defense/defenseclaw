// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"testing"
	"time"
)

// groupWritingBusyObserver records every busy report as a correlation
// observation in the store it observes, as the gateway's busy metric does
// (RecordGeneratedMetricBatch -> RecordObservations, the same writeGroup).
type groupWritingBusyObserver struct {
	repo *CorrelationRepository
	done chan error
}

func (observer *groupWritingBusyObserver) RecordSQLiteBusyMetric(ctx context.Context, _ string) error {
	missing, _ := NewSemanticEventID()
	err := observer.repo.RecordObservations(ctx, CorrelationObservation{
		RecordID: "busy-metric", SemanticEventID: missing, Signal: CorrelationSignalMetrics,
		Bucket: "system", EventName: "busy", ObservedAt: time.Now().UTC(),
		Status: CorrelationObservationExportEligible,
	})
	select {
	case observer.done <- err:
	default:
	}
	return err
}

// rel-1-0-5 GAP-0027: a grouped write that met SQLITE_BUSY reported the busy
// metric while its caller still led the write group; the report's own
// correlation observation joined that group and waited for its leader, so no
// audit write committed again and the managed gateway answered no hook until
// a restart.
func TestGroupedWriteBusyReportDoesNotWaitForItsOwnGroup(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "codex", ConnectorCustodyExternal)
	event, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{})
	observer := &groupWritingBusyObserver{repo: repo, done: make(chan error, 1)}
	store.BindSQLiteBusyObservabilityV8(observer)

	contender, err := sql.Open("sqlite", store.DatabasePath()+"?_pragma=busy_timeout(0)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = contender.Close() })
	conn, err := contender.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	if _, err := conn.ExecContext(t.Context(), `BEGIN IMMEDIATE`); err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		result <- repo.RecordObservations(context.Background(), CorrelationObservation{
			RecordID: "hook-record", SemanticEventID: event.SemanticEventID,
			Signal: CorrelationSignalTraces, Bucket: "agent", EventName: event.EventName,
			ObservedAt: time.Now().UTC(), TraceID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			SpanID: "bbbbbbbbbbbbbbbb", Status: CorrelationObservationExportEligible,
		})
	}()
	time.Sleep(1500 * time.Millisecond)
	if _, err := conn.ExecContext(t.Context(), `ROLLBACK`); err != nil {
		t.Fatal(err)
	}
	select {
	case <-result:
	case <-time.After(10 * time.Second):
		t.Fatal("the grouped write did not return after the write lock was released: its busy report waits for its own group")
	}
	select {
	case <-observer.done:
	case <-time.After(10 * time.Second):
		t.Fatal("the busy report did not run once the group let go")
	}
	// The store still commits: a later write of the same group returns.
	later := make(chan error, 1)
	go func() {
		later <- repo.RecordObservations(context.Background(), CorrelationObservation{
			RecordID: "later-record", SemanticEventID: event.SemanticEventID,
			Signal: CorrelationSignalTraces, Bucket: "agent", EventName: event.EventName,
			ObservedAt: time.Now().UTC(), TraceID: "cccccccccccccccccccccccccccccccc",
			SpanID: "dddddddddddddddd", Status: CorrelationObservationExportEligible,
		})
	}()
	select {
	case err := <-later:
		if err != nil {
			t.Fatalf("write after the busy report: %v", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("a later grouped write did not return")
	}
}
