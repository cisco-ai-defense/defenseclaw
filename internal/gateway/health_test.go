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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

type fakeObservabilityV8HealthSource struct {
	mu       sync.RWMutex
	snapshot observabilityruntime.DestinationHealthSnapshot
}

func (source *fakeObservabilityV8HealthSource) DestinationHealthSnapshot(
	context.Context,
) (observabilityruntime.DestinationHealthSnapshot, error) {
	source.mu.RLock()
	defer source.mu.RUnlock()
	return source.snapshot, nil
}

func (source *fakeObservabilityV8HealthSource) set(
	snapshot observabilityruntime.DestinationHealthSnapshot,
) {
	source.mu.Lock()
	source.snapshot = snapshot
	source.mu.Unlock()
}

type observabilityV8HealthSourceFunc func(
	context.Context,
) (observabilityruntime.DestinationHealthSnapshot, error)

func (source observabilityV8HealthSourceFunc) DestinationHealthSnapshot(
	ctx context.Context,
) (observabilityruntime.DestinationHealthSnapshot, error) {
	return source(ctx)
}

// connByName indexes a snapshot's per-connector roster by connector name.
func connByName(conns []ConnectorHealth) map[string]ConnectorHealth {
	out := make(map[string]ConnectorHealth, len(conns))
	for _, c := range conns {
		out[c.Name] = c
	}
	return out
}

func TestConnectorLastActivityTracksAcceptedRequests(t *testing.T) {
	h := NewSidecarHealth()
	h.SetConnector("codex", "", "")

	initial := h.Snapshot()
	if initial.Connector == nil {
		t.Fatal("expected primary connector")
	}
	if initial.Connector.LastActivityAt != nil {
		t.Fatalf("initial last activity = %v, want nil", initial.Connector.LastActivityAt)
	}
	encoded, err := json.Marshal(initial)
	if err != nil {
		t.Fatalf("marshal initial health: %v", err)
	}
	if strings.Contains(string(encoded), "last_activity_at") {
		t.Fatalf("initial health unexpectedly includes last_activity_at: %s", encoded)
	}

	before := time.Now().UTC()
	h.RecordConnectorRequestFor("codex")
	after := time.Now().UTC()

	snap := h.Snapshot()
	codex := connByName(snap.Connectors)["codex"]
	if codex.LastActivityAt == nil {
		t.Fatal("connector last activity is nil after request")
	}
	if codex.LastActivityAt.Before(before) || codex.LastActivityAt.After(after) {
		t.Fatalf("last activity %s outside request bounds [%s, %s]", codex.LastActivityAt, before, after)
	}
	if snap.Connector == nil || snap.Connector.LastActivityAt == nil {
		t.Fatal("primary connector is missing last activity after request")
	}
	if !snap.Connector.LastActivityAt.Equal(*codex.LastActivityAt) {
		t.Fatalf("primary last activity %v != roster last activity %v", snap.Connector.LastActivityAt, codex.LastActivityAt)
	}
	encoded, err = json.Marshal(snap)
	if err != nil {
		t.Fatalf("marshal active health: %v", err)
	}
	if !strings.Contains(string(encoded), `"last_activity_at":"`) {
		t.Fatalf("active health is missing last_activity_at: %s", encoded)
	}
}

func TestConnectorLastActivityNeverRegresses(t *testing.T) {
	h := NewSidecarHealth()
	stats := h.statsFor("codex")
	later := time.Now().UTC()
	stats.recordActivity(later)
	stats.recordActivity(later.Add(-time.Hour))

	got := connByName(h.Snapshot().Connectors)["codex"].LastActivityAt
	if got == nil || !got.Equal(later) {
		t.Fatalf("last activity = %v, want %s", got, later)
	}
}

// TestConnectorCountersAreIsolated verifies that each connector accumulates its
// own counters — the core multi-connector parity guarantee. A tool block on
// codex must never show up under cursor.
func TestConnectorCountersAreIsolated(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", connector.ToolInspectionMode("observe"), connector.SubprocessPolicy("monitor"))
	h.RegisterConnector("cursor", connector.ToolInspectionMode("enforce"), connector.SubprocessPolicy("block"))

	// codex: 3 requests, 1 tool block, 2 inspections.
	h.RecordConnectorRequestFor("codex")
	h.RecordConnectorRequestFor("codex")
	h.RecordConnectorRequestFor("codex")
	h.RecordToolBlockFor("codex")
	h.RecordToolInspectionFor("codex")
	h.RecordToolInspectionFor("codex")

	// cursor: 1 request, 0 tool blocks.
	h.RecordConnectorRequestFor("cursor")

	snap := h.Snapshot()
	if len(snap.Connectors) != 2 {
		t.Fatalf("expected 2 connectors in roster, got %d", len(snap.Connectors))
	}
	byName := connByName(snap.Connectors)

	codex, ok := byName["codex"]
	if !ok {
		t.Fatalf("codex missing from roster: %+v", snap.Connectors)
	}
	if codex.Requests != 3 || codex.ToolBlocks != 1 || codex.ToolInspections != 2 {
		t.Errorf("codex counters wrong: requests=%d toolBlocks=%d inspections=%d",
			codex.Requests, codex.ToolBlocks, codex.ToolInspections)
	}

	cursor, ok := byName["cursor"]
	if !ok {
		t.Fatalf("cursor missing from roster: %+v", snap.Connectors)
	}
	if cursor.Requests != 1 || cursor.ToolBlocks != 0 || cursor.ToolInspections != 0 {
		t.Errorf("cursor counters bled from codex: requests=%d toolBlocks=%d inspections=%d",
			cursor.Requests, cursor.ToolBlocks, cursor.ToolInspections)
	}

	// Static fields are per-connector too.
	if codex.ToolInspectionMode != connector.ToolInspectionMode("observe") {
		t.Errorf("codex mode = %q, want observe", codex.ToolInspectionMode)
	}
	if cursor.ToolInspectionMode != connector.ToolInspectionMode("enforce") {
		t.Errorf("cursor mode = %q, want enforce", cursor.ToolInspectionMode)
	}
}

// TestSetConnectorMarksPrimary confirms the back-compat singular Connector
// tracks whichever connector was set via SetConnector, while every registered
// connector still appears in the Connectors roster.
func TestSetConnectorMarksPrimary(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", "", "")
	h.SetConnector("cursor", "", "") // cursor is primary

	snap := h.Snapshot()
	if snap.Connector == nil {
		t.Fatal("expected singular Connector to be set")
	}
	if snap.Connector.Name != "cursor" {
		t.Errorf("primary = %q, want cursor", snap.Connector.Name)
	}
	if len(snap.Connectors) != 2 {
		t.Errorf("expected both connectors in roster, got %d", len(snap.Connectors))
	}
}

// TestRecordForUnregisteredConnectorLazyCreates ensures a hook firing for a
// connector that has not been registered yet still records its counts (counts
// must never be silently dropped).
func TestRecordForUnregisteredConnectorLazyCreates(t *testing.T) {
	h := NewSidecarHealth()
	h.RecordConnectorRequestFor("ghost")

	snap := h.Snapshot()
	byName := connByName(snap.Connectors)
	ghost, ok := byName["ghost"]
	if !ok {
		t.Fatalf("ghost connector not lazily created: %+v", snap.Connectors)
	}
	if ghost.Requests != 1 {
		t.Errorf("ghost requests = %d, want 1", ghost.Requests)
	}
}

// TestConnectorNameNormalization confirms names are matched case-insensitively
// and trimmed so "Codex", " codex " and "codex" all hit the same bucket.
func TestConnectorNameNormalization(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("Codex", "", "")
	h.RecordConnectorRequestFor(" codex ")
	h.RecordConnectorRequestFor("CODEX")

	snap := h.Snapshot()
	if len(snap.Connectors) != 1 {
		t.Fatalf("expected names to collapse to 1 bucket, got %d: %+v", len(snap.Connectors), snap.Connectors)
	}
	if snap.Connectors[0].Requests != 2 {
		t.Errorf("requests = %d, want 2", snap.Connectors[0].Requests)
	}
}

// TestConcurrentConnectorCounters drives concurrent increments across two
// connectors. Run with -race to assert the per-connector hot path is free of
// data races, and check totals to confirm no increments are lost.
func TestConcurrentConnectorCounters(t *testing.T) {
	h := NewSidecarHealth()
	h.RegisterConnector("codex", "", "")
	h.RegisterConnector("cursor", "", "")

	const perConn = 1000
	var wg sync.WaitGroup
	for _, name := range []string{"codex", "cursor"} {
		name := name
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < perConn; i++ {
				h.RecordConnectorRequestFor(name)
			}
		}()
	}
	wg.Wait()

	byName := connByName(h.Snapshot().Connectors)
	if byName["codex"].Requests != perConn {
		t.Errorf("codex requests = %d, want %d", byName["codex"].Requests, perConn)
	}
	if byName["cursor"].Requests != perConn {
		t.Errorf("cursor requests = %d, want %d", byName["cursor"].Requests, perConn)
	}
}

func TestObservabilityV8HealthRendersBoundedGenerationSnapshot(t *testing.T) {
	now := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	queue := &delivery.QueueSnapshot{
		Items: 2, Bytes: 200, InFlightItems: 1, InFlightBytes: 100,
		MaxItems: 16, MaxBytes: 4096,
	}
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{
		Generation: 4,
		Destinations: []observabilityruntime.DestinationHealth{
			{
				Name: config.ObservabilityV8LocalDestinationName,
				Kind: config.ObservabilityV8DestinationLocalSQLite, Enabled: true,
				Signals: []observability.Signal{observability.SignalLogs},
				State:   delivery.HealthHealthy, Reason: string(delivery.HealthReasonActivated),
			},
			{
				Name: "all-signals", Kind: config.ObservabilityV8DestinationOTLP, Enabled: true,
				Signals: []observability.Signal{
					observability.SignalLogs, observability.SignalTraces, observability.SignalMetrics,
				},
				State: delivery.HealthDegraded, Reason: string(delivery.HealthReasonQueueFull),
				CircuitState: delivery.CircuitOpen, ConsecutiveFailures: 4,
				CircuitOpenUntil: now.Add(24 * time.Hour),
				LastFailureClass: delivery.FailureClassAuthentication,
				Queue:            queue, Counters: delivery.Counters{Accepted: 8, Delivered: 5, Dropped: 2},
				LastSuccess: now.Add(-time.Minute), LastFailure: now,
				Sources: []delivery.HealthSnapshot{{
					Destination: "all-signals", Generation: 4, Signal: string(observability.SignalTraces),
					State: delivery.HealthDegraded, Reason: string(delivery.HealthReasonQueueFull),
					CircuitState: delivery.CircuitOpen, ConsecutiveFailures: 4,
					CircuitOpenUntil: now.Add(24 * time.Hour),
					LastFailureClass: delivery.FailureClassAuthentication,
					Queue:            queue, Counters: delivery.Counters{Accepted: 8, Delivered: 5, Dropped: 2},
					LastSuccess: now.Add(-time.Minute), LastFailure: now,
				}},
			},
			{
				Name: "disabled", Kind: config.ObservabilityV8DestinationConsole,
				Signals: []observability.Signal{observability.SignalLogs}, State: delivery.HealthDisabled,
			},
		},
	}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.setObservabilityV8Retention("healthy", 90, "")
	health.observeObservabilityV8Failure("all-signals", 3, "stale_failure", now.Add(time.Hour))

	snapshot := health.Snapshot()
	if snapshot.Telemetry.State != StateError || snapshot.Telemetry.LastError != "" {
		t.Fatalf("telemetry=%+v", snapshot.Telemetry)
	}
	details := snapshot.Telemetry.Details
	if details["generation"] != uint64(4) || details["destination_count"] != 3 ||
		details["retention_state"] != "healthy" || details["retention_days"] != int64(90) {
		t.Fatalf("details=%+v", details)
	}
	if _, ok := details["event_history_failure"]; ok {
		t.Fatalf("empty event history failure was exposed: %+v", details)
	}
	rows, ok := details["destinations"].([]map[string]interface{})
	if !ok || len(rows) != 3 {
		t.Fatalf("destinations=%T %+v", details["destinations"], details["destinations"])
	}
	row := rows[1]
	if row["name"] != "all-signals" || row["state"] != "degraded" ||
		row["reason"] != "queue_full" || row["failure"] != nil ||
		row["circuit_state"] != "open" || row["consecutive_failures"] != uint64(4) ||
		row["circuit_open_until"] != now.Add(24*time.Hour).Format(time.RFC3339Nano) ||
		row["last_failure_class"] != "authentication" {
		t.Fatalf("destination row=%+v", row)
	}
	signalRows, ok := row["signal_health"].([]map[string]interface{})
	if !ok || len(signalRows) != 1 || signalRows[0]["circuit_state"] != "open" ||
		signalRows[0]["consecutive_failures"] != uint64(4) ||
		signalRows[0]["last_failure_class"] != "authentication" {
		t.Fatalf("signal health=%T %+v", row["signal_health"], row["signal_health"])
	}
	queueMap, ok := row["queue"].(map[string]interface{})
	if !ok || queueMap["items"] != 2 || queueMap["max_items"] != 16 ||
		queueMap["dropped"] != uint64(2) {
		t.Fatalf("queue=%T %+v", row["queue"], row["queue"])
	}
	encoded, err := json.Marshal(snapshot.Telemetry)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"endpoint", "header", "payload", "raw_error", "stale_failure"} {
		if stringContains(string(encoded), forbidden) {
			t.Fatalf("health disclosed forbidden %q: %s", forbidden, encoded)
		}
	}
}

func TestObservabilityV8HealthOnlyExposesValidRetentionFailures(t *testing.T) {
	tests := []struct {
		name          string
		failure       string
		wantFailure   string
		wantPublished bool
	}{
		{
			name:          "valid",
			failure:       "scheduler_failed",
			wantFailure:   "scheduler_failed",
			wantPublished: true,
		},
		{
			name:    "invalid",
			failure: "secret_internal_failure",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := renderObservabilityV8Health(
				time.Now().UTC(),
				observabilityruntime.DestinationHealthSnapshot{},
				nil,
				"degraded",
				test.failure,
				30,
				observabilityV8EventHistorySnapshot{},
			)
			failure, published := health.Details["retention_failure"]
			if published != test.wantPublished {
				t.Fatalf(
					"retention_failure published = %t, want %t: %+v",
					published,
					test.wantPublished,
					health.Details,
				)
			}
			if published && failure != test.wantFailure {
				t.Fatalf("retention_failure = %v, want %q", failure, test.wantFailure)
			}
		})
	}
}

func TestObservabilityV8HealthHidesInvalidEventHistoryFailureButFailsClosed(t *testing.T) {
	health := renderObservabilityV8Health(
		time.Now().UTC(),
		observabilityruntime.DestinationHealthSnapshot{},
		nil,
		"healthy",
		"",
		30,
		observabilityV8EventHistorySnapshot{activeCode: "secret_internal_failure"},
	)
	if health.State != StateError {
		t.Fatalf("telemetry state = %q, want %q", health.State, StateError)
	}
	if _, published := health.Details["event_history_failure"]; published {
		t.Fatalf("invalid event_history_failure was exposed: %+v", health.Details)
	}
}

func TestObservabilityV8HealthRejectsStaleFailureAcrossReload(t *testing.T) {
	now := time.Now().UTC()
	makeSnapshot := func(generation uint64, success time.Time) observabilityruntime.DestinationHealthSnapshot {
		return observabilityruntime.DestinationHealthSnapshot{
			Generation: generation,
			Destinations: []observabilityruntime.DestinationHealth{{
				Name: "reload-safe", Kind: config.ObservabilityV8DestinationOTLP, Enabled: true,
				Signals: []observability.Signal{observability.SignalTraces},
				State:   delivery.HealthHealthy, Reason: string(delivery.HealthReasonRecovered),
				LastSuccess: success,
			}},
		}
	}
	source := &fakeObservabilityV8HealthSource{snapshot: makeSnapshot(8, now)}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.observeObservabilityV8Failure("reload-safe", 8, "projection_failed", now.Add(-time.Second))
	health.observeObservabilityV8Failure("reload-safe", 7, "old_generation", now.Add(time.Hour))

	rows := health.Snapshot().Telemetry.Details["destinations"].([]map[string]interface{})
	if rows[0]["failure"] != nil {
		t.Fatalf("recovered failure was not cleared: %+v", rows[0])
	}
	source.set(makeSnapshot(9, now.Add(time.Minute)))
	health.observeObservabilityV8Failure("reload-safe", 8, "retired_generation", now.Add(2*time.Hour))
	rows = health.Snapshot().Telemetry.Details["destinations"].([]map[string]interface{})
	if rows[0]["failure"] != nil || rows[0]["generation"] != uint64(9) {
		t.Fatalf("stale transition contaminated successor: %+v", rows[0])
	}
}

func eventHistoryTransition(
	generation, sequence uint64,
	state audit.EventHistoryHealthState,
	code audit.EventHistoryHealthCode,
	class audit.EventHistorySQLiteClass,
	primary uint8,
) audit.EventHistoryHealthTransition {
	return audit.EventHistoryHealthTransition{
		Generation: generation, Sequence: sequence, State: state, Code: code,
		OccurredAt:  time.Date(2026, 8, 12, 12, 0, int(sequence), 0, time.UTC),
		SQLiteClass: class, SQLitePrimaryCode: primary,
	}
}

func TestObservabilityV8EventHistoryFailureRecoversAndKeepsBoundedHistory(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{
		Generation: 4,
	}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.bindObservabilityV8EventHistoryGeneration(4)
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		4, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteBusyLocked, 5,
	))
	failed := health.Snapshot().Telemetry
	if failed.State != StateError || failed.Details["event_history_failure"] != "sqlite_write_failed" ||
		failed.Details["event_history_last_sqlite_class"] != "busy_locked" ||
		failed.Details["event_history_last_sqlite_primary_code"] != uint8(5) {
		t.Fatalf("failed health = %+v", failed)
	}
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		4, 2, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	recovered := health.Snapshot().Telemetry
	if recovered.State != StateRunning {
		t.Fatalf("recovered health = %+v", recovered)
	}
	if _, active := recovered.Details["event_history_failure"]; active {
		t.Fatalf("recovered health retained active failure: %+v", recovered.Details)
	}
	if recovered.Details["event_history_last_sqlite_class"] != "busy_locked" ||
		recovered.Details["event_history_last_sqlite_primary_code"] != uint8(5) {
		t.Fatalf("recovery lost bounded failure history: %+v", recovered.Details)
	}
	// A delayed older callback cannot relatch the cleared failure.
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		4, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteFull, 13,
	))
	if stale := health.Snapshot().Telemetry; stale.State != StateRunning {
		t.Fatalf("stale failure relatched health: %+v", stale)
	}
}

func TestObservabilityV8EventHistoryBlockedDeliveryRetainsFailureClassAfterRecovery(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 14}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.bindObservabilityV8EventHistoryGeneration(14)
	// These are the ordered transitions emitted after an unrelated reporter
	// callback unblocks: the bounded failure diagnostic must arrive before its
	// recovery even though Snapshot observes only the final active state.
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		14, 2, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteFull, 13,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		14, 3, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	snapshot := health.Snapshot().Telemetry
	if snapshot.State != StateRunning {
		t.Fatalf("final recovered state = %+v", snapshot)
	}
	if _, active := snapshot.Details["event_history_failure"]; active ||
		snapshot.Details["event_history_last_sqlite_class"] != "full" ||
		snapshot.Details["event_history_last_sqlite_primary_code"] != uint8(13) {
		t.Fatalf("recovered state lost queued failure diagnostic: %+v", snapshot.Details)
	}
}

func TestObservabilityV8EventHistoryNewerFailureBeatsStaleRecovery(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 5}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.bindObservabilityV8EventHistoryGeneration(5)
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		5, 3, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteIO, 10,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		5, 2, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	snapshot := health.Snapshot().Telemetry
	if snapshot.State != StateError || snapshot.Details["event_history_failure"] != "sqlite_write_failed" ||
		snapshot.Details["event_history_last_sqlite_class"] != "io" {
		t.Fatalf("stale recovery cleared newer failure: %+v", snapshot)
	}
}

func TestObservabilityV8EventHistoryRecoveryLeavesUnrelatedFailureActive(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 6}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.bindObservabilityV8EventHistoryGeneration(6)
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		6, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthProjectionRejected, "", 0,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		6, 2, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteFull, 13,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		6, 3, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	snapshot := health.Snapshot().Telemetry
	if snapshot.State != StateError || snapshot.Details["event_history_failure"] != "projection_rejected" {
		t.Fatalf("write recovery cleared unrelated failure: %+v", snapshot)
	}
}

func TestObservabilityV8EventHistoryGenerationCarriesFailureAndRejectsRetiredCallbacks(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 1}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	_ = health.Snapshot()
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 7, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteBusyLocked, 5,
	))
	source.snapshot = observabilityruntime.DestinationHealthSnapshot{Generation: 2}
	carried := health.Snapshot().Telemetry
	if carried.State != StateError || carried.Details["event_history_failure"] != "sqlite_write_failed" {
		t.Fatalf("reload cleared unproven failure: %+v", carried)
	}
	for _, retired := range []audit.EventHistoryHealthTransition{
		eventHistoryTransition(1, 8, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0),
		eventHistoryTransition(1, 9, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed, audit.EventHistorySQLiteIO, 10),
	} {
		health.observeObservabilityV8EventHistory(retired)
	}
	if stale := health.Snapshot().Telemetry; stale.Details["event_history_last_sqlite_class"] != "busy_locked" {
		t.Fatalf("retired callback contaminated generation two: %+v", stale)
	}
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		2, 1, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	if recovered := health.Snapshot().Telemetry; recovered.State != StateRunning {
		t.Fatalf("generation two proof did not recover inherited failure: %+v", recovered)
	}
}

func TestObservabilityV8EventHistoryReloadPreservesCrossCodeOrder(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 1}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	_ = health.Snapshot()
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteBusyLocked, 5,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 2, audit.EventHistoryHealthFailed, audit.EventHistoryHealthSigningFailed, "", 0,
	))
	source.snapshot = observabilityruntime.DestinationHealthSnapshot{Generation: 2}
	for index := 0; index < 20; index++ {
		snapshot := health.Snapshot().Telemetry
		if snapshot.State != StateError || snapshot.Details["event_history_failure"] != "integrity_signing_failed" {
			t.Fatalf("reload snapshot %d lost cross-code order: %+v", index, snapshot)
		}
	}
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		2, 1, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	for index := 0; index < 20; index++ {
		snapshot := health.Snapshot().Telemetry
		if snapshot.State != StateError || snapshot.Details["event_history_failure"] != "integrity_signing_failed" {
			t.Fatalf("write recovery %d cleared unrelated health: %+v", index, snapshot)
		}
	}
}

func TestObservabilityV8EventHistoryNewGenerationCallbackPreservesOtherCodesBeforeBind(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 1}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	_ = health.Snapshot()
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteBusyLocked, 5,
	))
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 2, audit.EventHistoryHealthFailed, audit.EventHistoryHealthProjectionRejected, "", 0,
	))
	// A generation-two callback may arrive after graph publication but before
	// owner.reload returns and explicitly advances the health generation floor.
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		2, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthSigningFailed, "", 0,
	))
	health.mu.RLock()
	if len(health.observabilityV8EventHistory) != 3 {
		health.mu.RUnlock()
		t.Fatalf("new generation callback erased inherited failures: %+v", health.observabilityV8EventHistory)
	}
	health.mu.RUnlock()
	health.observeObservabilityV8EventHistory(eventHistoryTransition(
		2, 2, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0,
	))
	health.bindObservabilityV8EventHistoryGeneration(2)
	source.snapshot = observabilityruntime.DestinationHealthSnapshot{Generation: 2}
	snapshot := health.Snapshot().Telemetry
	if snapshot.State != StateError || snapshot.Details["event_history_failure"] != "integrity_signing_failed" {
		t.Fatalf("write recovery erased unrelated inherited failure: %+v", snapshot)
	}
	health.mu.RLock()
	projection := health.observabilityV8EventHistory[string(audit.EventHistoryHealthProjectionRejected)]
	health.mu.RUnlock()
	if !projection.active || projection.generation != 1 {
		t.Fatalf("inherited projection failure was not preserved: %+v", projection)
	}
}

func TestObservabilityV8EventHistoryActivationRejectsDelayedRetiredCallback(t *testing.T) {
	health := NewSidecarHealth()
	health.bindObservabilityV8EventHistoryGeneration(1)
	started := make(chan struct{})
	release := make(chan struct{})
	done := make(chan struct{})
	go func() {
		close(started)
		<-release
		health.observeObservabilityV8EventHistory(eventHistoryTransition(
			1, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
			audit.EventHistorySQLiteBusyLocked, 5,
		))
		close(done)
	}()
	<-started
	// This is the local component Activate-time bind performed immediately
	// after graph publication, while retirement may still be waiting on a
	// generation-one lease and its delayed callback.
	health.bindObservabilityV8EventHistoryGeneration(2)
	close(release)
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("delayed callback did not return")
	}
	health.mu.RLock()
	defer health.mu.RUnlock()
	if len(health.observabilityV8EventHistory) != 0 ||
		health.observabilityV8EventHistoryGeneration != 2 {
		t.Fatalf("retired callback crossed activation boundary: generation=%d observations=%+v",
			health.observabilityV8EventHistoryGeneration, health.observabilityV8EventHistory)
	}
}

func TestObservabilityV8EventHistoryRejectsMismatchedSQLiteDiagnostics(t *testing.T) {
	tests := []struct {
		name    string
		class   audit.EventHistorySQLiteClass
		primary uint8
	}{
		{name: "busy with arbitrary code", class: audit.EventHistorySQLiteBusyLocked, primary: 255},
		{name: "busy with io code", class: audit.EventHistorySQLiteBusyLocked, primary: 10},
		{name: "unavailable with driver code", class: audit.EventHistorySQLiteUnavailable, primary: 28},
		{name: "full without full code", class: audit.EventHistorySQLiteFull, primary: 0},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := NewSidecarHealth()
			health.bindObservabilityV8EventHistoryGeneration(1)
			health.observeObservabilityV8EventHistory(eventHistoryTransition(
				1, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
				test.class, test.primary,
			))
			health.mu.RLock()
			defer health.mu.RUnlock()
			if len(health.observabilityV8EventHistory) != 0 {
				t.Fatalf("mismatched diagnostic was accepted: %+v", health.observabilityV8EventHistory)
			}
		})
	}
}

func TestObservabilityV8EventHistoryStateDoesNotSurviveSidecarRestart(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 1}}
	failed := NewSidecarHealth()
	failed.bindObservabilityV8HealthSource(source)
	failed.observeObservabilityV8EventHistory(eventHistoryTransition(
		1, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed,
		audit.EventHistorySQLiteOther, 0,
	))
	if failed.Snapshot().Telemetry.State != StateError {
		t.Fatal("failure fixture did not latch")
	}
	restarted := NewSidecarHealth()
	restarted.bindObservabilityV8HealthSource(source)
	if snapshot := restarted.Snapshot().Telemetry; snapshot.State != StateRunning {
		t.Fatalf("new sidecar inherited process-local latch: %+v", snapshot)
	}
}

func TestObservabilityV8HealthSnapshotFailureIsBoundedAndFailClosed(t *testing.T) {
	const secret = "https://secret.example.invalid?token=do-not-disclose"
	tests := []struct {
		name   string
		source observabilityV8HealthSource
	}{
		{
			name: "source error",
			source: observabilityV8HealthSourceFunc(func(
				context.Context,
			) (observabilityruntime.DestinationHealthSnapshot, error) {
				return observabilityruntime.DestinationHealthSnapshot{}, errors.New(secret)
			}),
		},
		{
			name: "source timeout",
			source: observabilityV8HealthSourceFunc(func(
				ctx context.Context,
			) (observabilityruntime.DestinationHealthSnapshot, error) {
				<-ctx.Done()
				return observabilityruntime.DestinationHealthSnapshot{}, errors.New(secret)
			}),
		},
		{
			name: "source panic",
			source: observabilityV8HealthSourceFunc(func(
				context.Context,
			) (observabilityruntime.DestinationHealthSnapshot, error) {
				panic(secret)
			}),
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			health := NewSidecarHealth()
			health.bindObservabilityV8HealthSource(test.source)
			health.setObservabilityV8Retention("degraded", 30, "scheduler_failed")
			health.observeObservabilityV8EventHistory(audit.EventHistoryHealthTransition{
				Generation: 1, Sequence: 1, State: audit.EventHistoryHealthFailed,
				Code: audit.EventHistoryHealthWriteFailed, OccurredAt: time.Now().UTC(),
				SQLiteClass: audit.EventHistorySQLiteOther,
			})

			snapshot := health.Snapshot()
			if snapshot.Telemetry.State != StateError {
				t.Fatalf("telemetry state = %q, want %q", snapshot.Telemetry.State, StateError)
			}
			if snapshot.Telemetry.LastError != ObservabilityV8HealthSnapshotUnavailable {
				t.Fatalf(
					"telemetry last_error = %q, want %q",
					snapshot.Telemetry.LastError,
					ObservabilityV8HealthSnapshotUnavailable,
				)
			}
			details := snapshot.Telemetry.Details
			if details["snapshot_state"] != "unavailable" ||
				details["retention_state"] != "degraded" ||
				details["retention_days"] != int64(30) ||
				details["retention_failure"] != "scheduler_failed" ||
				details["event_history_failure"] != "sqlite_write_failed" {
				t.Fatalf("telemetry details = %+v", details)
			}
			if _, ok := details["generation"]; ok {
				t.Fatalf("unavailable snapshot retained a generation: %+v", details)
			}
			if _, ok := details["destinations"]; ok {
				t.Fatalf("unavailable snapshot retained destination health: %+v", details)
			}

			encoded, err := json.Marshal(snapshot.Telemetry)
			if err != nil {
				t.Fatalf("marshal telemetry: %v", err)
			}
			if strings.Contains(string(encoded), secret) {
				t.Fatalf("telemetry disclosed source failure: %s", encoded)
			}
		})
	}
}

func stringContains(value, fragment string) bool {
	for index := 0; index+len(fragment) <= len(value); index++ {
		if value[index:index+len(fragment)] == fragment {
			return true
		}
	}
	return false
}

// TestSetEnumeratorPublishesSubsystem pins the wire contract spec 005
// Workstream D introduces: SidecarHealth.Enumerator is nil until
// SetEnumerator is called, then holds the last-published state +
// LastError + Details verbatim. Snapshot() must surface the field
// in the JSON payload so a Cisco Secure Client IPC consumer can
// render "enumerator error: <reason>" alongside the gateway +
// guardian tiles.
func TestSetEnumeratorPublishesSubsystem(t *testing.T) {
	h := NewSidecarHealth()

	// Pre-call: enumerator absent from the snapshot (nil pointer
	// omits the field in JSON via omitempty).
	before := h.Snapshot()
	if before.Enumerator != nil {
		t.Fatalf("Enumerator should be nil before SetEnumerator; got %+v", before.Enumerator)
	}

	h.SetEnumerator(StateRunning, "", map[string]interface{}{"cycle_count": int64(3)})

	after := h.Snapshot()
	if after.Enumerator == nil {
		t.Fatal("Enumerator should be non-nil after SetEnumerator")
	}
	if after.Enumerator.State != StateRunning {
		t.Fatalf("Enumerator.State = %v, want %v", after.Enumerator.State, StateRunning)
	}
	if after.Enumerator.LastError != "" {
		t.Fatalf("Enumerator.LastError = %q, want empty", after.Enumerator.LastError)
	}
	if v, ok := after.Enumerator.Details["cycle_count"].(int64); !ok || v != 3 {
		t.Fatalf("Enumerator.Details[cycle_count] = %v, want int64(3)", after.Enumerator.Details["cycle_count"])
	}

	// Second call flips the state and clears LastError back to empty.
	h.SetEnumerator(StateError, "walk profiles: registry unreadable", nil)
	after2 := h.Snapshot()
	if after2.Enumerator.State != StateError {
		t.Fatalf("after second SetEnumerator: State = %v, want %v", after2.Enumerator.State, StateError)
	}
	if after2.Enumerator.LastError != "walk profiles: registry unreadable" {
		t.Fatalf("LastError not surfaced: %q", after2.Enumerator.LastError)
	}
}

// TestSetEnumeratorNilReceiverIsSafe asserts SetEnumerator can be
// called against a nil *SidecarHealth without panicking. The
// enumerator CLI subcommand may run standalone (`--once` from an
// installer shell-out) with no sidecar wired; the CLI passes a
// nil receiver in that case and expects a no-op.
func TestSetEnumeratorNilReceiverIsSafe(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("SetEnumerator on nil receiver panicked: %v", r)
		}
	}()
	var h *SidecarHealth
	h.SetEnumerator(StateStarting, "", nil)
}

// TestSetEnumeratorNotifiesSubscribers asserts the pub/sub wake-up
// invariant SetEnumerator inherits from the pattern SetManaged /
// SetGuardrail / etc. use — a change to the enumerator's state
// wakes any registered subscriber exactly once.
func TestSetEnumeratorNotifiesSubscribers(t *testing.T) {
	h := NewSidecarHealth()
	ch, cancel := h.Subscribe()
	defer cancel()

	h.SetEnumerator(StateStarting, "", nil)

	select {
	case <-ch:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("SetEnumerator did not wake subscriber within 500ms")
	}
}

// TestSetEnumeratorJSONShape asserts the field appears in the
// wire-level JSON payload as `enumerator` (lower-case, matches the
// json tag) — a rename here would break every downstream dashboard
// or CI check keyed on the field.
func TestSetEnumeratorJSONShape(t *testing.T) {
	h := NewSidecarHealth()
	h.SetEnumerator(StateRunning, "", nil)
	raw, err := json.Marshal(h.Snapshot())
	if err != nil {
		t.Fatalf("marshal snapshot: %v", err)
	}
	if !stringContains(string(raw), `"enumerator":`) {
		t.Fatalf("snapshot JSON missing `enumerator` key:\n%s", string(raw))
	}
}

// TestSetEnumeratorDeepCopiesDetails is the regression pin CR
// spec-005:PRRT_kwDORuAK-s6atyfQ asks for: mutating the caller's
// input map after SetEnumerator MUST NOT mutate the stored
// subsystem health; mutating the Snapshot()-returned pointer's
// Details map MUST NOT mutate the stored subsystem health either.
// Without the boundary-copy discipline, a concurrent JSON marshal
// and a live setter race on the same map header.
func TestSetEnumeratorDeepCopiesDetails(t *testing.T) {
	h := NewSidecarHealth()

	// Round 1: input-map mutation.
	details := map[string]interface{}{"cycle_count": int64(1)}
	h.SetEnumerator(StateRunning, "", details)
	// Caller mutates the map they retained.
	details["cycle_count"] = int64(99)
	details["injected"] = "attacker-controlled"

	got := h.Snapshot().Enumerator
	if got == nil {
		t.Fatal("Enumerator nil after SetEnumerator")
	}
	if got.Details["cycle_count"] != int64(1) {
		t.Fatalf("input-map mutation leaked: cycle_count = %v, want int64(1)", got.Details["cycle_count"])
	}
	if _, present := got.Details["injected"]; present {
		t.Fatalf("input-map mutation leaked: injected key present in stored details: %+v", got.Details)
	}

	// Round 2: snapshot-return mutation.
	snap := h.Snapshot()
	if snap.Enumerator == nil {
		t.Fatal("second Snapshot() returned nil Enumerator")
	}
	snap.Enumerator.Details["cycle_count"] = int64(-1)
	snap.Enumerator.Details["poisoned"] = true

	// A fresh snapshot must still show the original value.
	fresh := h.Snapshot()
	if fresh.Enumerator.Details["cycle_count"] != int64(1) {
		t.Fatalf("snapshot mutation leaked: cycle_count = %v, want int64(1)", fresh.Enumerator.Details["cycle_count"])
	}
	if _, present := fresh.Enumerator.Details["poisoned"]; present {
		t.Fatalf("snapshot mutation leaked: poisoned key present: %+v", fresh.Enumerator.Details)
	}
}
