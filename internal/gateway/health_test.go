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
				"",
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
		"secret_internal_failure",
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
			health.setObservabilityV8EventHistoryFailure("sqlite_write_failed")

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
