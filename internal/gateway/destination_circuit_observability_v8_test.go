// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

func destinationHealthSnapshotFixture(
	generation uint64,
	name string,
	state delivery.CircuitState,
	consecutiveFailures uint64,
) observabilityruntime.DestinationHealthSnapshot {
	return observabilityruntime.DestinationHealthSnapshot{
		Generation: generation,
		PlanDigest: "digest-fixture",
		Destinations: []observabilityruntime.DestinationHealth{
			{
				Name: name, Kind: config.ObservabilityV8DestinationSplunkHEC, Enabled: true,
				CircuitState:        state,
				ConsecutiveFailures: consecutiveFailures,
				LastFailureClass:    delivery.FailureClassTransient,
			},
		},
	}
}

func queryDestinationCircuitLog(
	t *testing.T,
	dbPath string,
	action string,
) (mandatory int, subsystem string, healthState string, errorCode string) {
	t.Helper()
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var raw string
	row := database.QueryRow(`SELECT mandatory, projected_record_json FROM audit_events
		WHERE bucket = 'platform.health' AND action = ?`, action)
	if err := row.Scan(&mandatory, &raw); err != nil {
		t.Fatal(err)
	}
	var projected struct {
		Body map[string]any `json:"body"`
	}
	if err := json.Unmarshal([]byte(raw), &projected); err != nil {
		t.Fatal(err)
	}
	subsystem, _ = projected.Body["defenseclaw.health.subsystem"].(string)
	healthState, _ = projected.Body["defenseclaw.health.state"].(string)
	errorCode, _ = projected.Body["defenseclaw.schema.error_code"].(string)
	return mandatory, subsystem, healthState, errorCode
}

func countDestinationCircuitLogs(t *testing.T, dbPath string, action string) int {
	t.Helper()
	database, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	row := database.QueryRow(`SELECT COUNT(*) FROM audit_events
		WHERE bucket = 'platform.health' AND action = ?`, action)
	if err := row.Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

// TestDestinationCircuitTransitionV8EmitsOpenThenClosedExactlyOnce exercises
// the closed -> open -> open -> closed sequence a real cooldown/probe cycle
// produces and asserts a durable log fires only on the two genuine
// transitions, not on the repeated "still open" poll in between.
func TestDestinationCircuitTransitionV8EmitsOpenThenClosedExactlyOnce(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, _ := platformHealthCorrelatedContext(t)
	sidecar := &Sidecar{}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitClosed, 0),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 0 {
		t.Fatalf("unexpected open log after first closed observation: count=%d", got)
	}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitOpen, 3),
	)
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitOpen, 4),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("expected exactly one open transition log, got %d", got)
	}
	mandatory, subsystem, healthState, errorCode := queryDestinationCircuitLog(
		t, capture.store.DatabasePath(), "circuit_breaker_open",
	)
	if mandatory != 1 || subsystem != "soc_primary" || healthState != "degraded" ||
		errorCode != "destination_circuit_open" {
		t.Fatalf("open transition projection wrong: mandatory=%d subsystem=%s state=%s code=%s",
			mandatory, subsystem, healthState, errorCode)
	}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitHalfOpen, 4),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_closed"); got != 0 {
		t.Fatalf("half-open probe must not emit a closed log, got %d", got)
	}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitClosed, 0),
	)
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitClosed, 0),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_closed"); got != 1 {
		t.Fatalf("expected exactly one closed transition log, got %d", got)
	}
	mandatory, subsystem, healthState, _ = queryDestinationCircuitLog(
		t, capture.store.DatabasePath(), "circuit_breaker_closed",
	)
	if mandatory != 1 || subsystem != "soc_primary" || healthState != "restored" {
		t.Fatalf("closed transition projection wrong: mandatory=%d subsystem=%s state=%s",
			mandatory, subsystem, healthState)
	}
}

// TestDestinationCircuitTransitionV8FirstSeenClosedIsNotLogged guards against
// a noisy false-positive "restored" log for every destination on every
// process start: a destination observed for the first time in a generation
// that is already closed is the routine baseline, not a recovery.
func TestDestinationCircuitTransitionV8FirstSeenClosedIsNotLogged(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, _ := platformHealthCorrelatedContext(t)
	sidecar := &Sidecar{}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(7, "s3_export", delivery.CircuitClosed, 0),
	)
	openCount := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open")
	closedCount := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_closed")
	if openCount != 0 || closedCount != 0 {
		t.Fatalf("first-seen closed destination must not log a transition: open=%d closed=%d",
			openCount, closedCount)
	}
}

// TestDestinationCircuitTransitionV8FirstSeenOpenIsLogged guards the inverse:
// a config reload that resolves directly into an already-broken destination
// (for example the process restarted mid-outage) must still surface an open
// log, since silence here would hide a real ongoing outage.
func TestDestinationCircuitTransitionV8FirstSeenOpenIsLogged(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, _ := platformHealthCorrelatedContext(t)
	sidecar := &Sidecar{}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(9, "s3_export", delivery.CircuitOpen, 5),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("expected exactly one open transition log for first-seen open destination, got %d", got)
	}
}

// TestDestinationCircuitTransitionV8GenerationResetReopensBaseline confirms a
// new config generation cannot inherit a stale "open" baseline from a prior
// generation and thereby suppress a genuinely new open transition as a
// no-op duplicate.
func TestDestinationCircuitTransitionV8GenerationResetReopensBaseline(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, _ := platformHealthCorrelatedContext(t)
	sidecar := &Sidecar{}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitOpen, 3),
	)
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitClosed, 0),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("expected one open log from generation 1, got %d", got)
	}

	// New generation reopens for the same destination name.
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(2, "soc_primary", delivery.CircuitOpen, 1),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 2 {
		t.Fatalf("expected a second open log after generation reset, got %d", got)
	}

}

// TestDestinationCircuitTransitionV8HalfOpenDoesNotResetBaseline guards
// against a stale-baseline bug: a half-open cooldown probe must never
// replace the tracked "open" baseline. If it did, an open -> half-open ->
// open sequence (the probe failing and the circuit reopening) would be
// misread as a brand-new transition and logged a second time, even though
// it is the same ongoing outage.
func TestDestinationCircuitTransitionV8HalfOpenDoesNotResetBaseline(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	ctx, _ := platformHealthCorrelatedContext(t)
	sidecar := &Sidecar{}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitOpen, 3),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("expected exactly one open log before the probe, got %d", got)
	}

	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitHalfOpen, 4),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("half-open probe must not itself log or reset the baseline, got %d open logs", got)
	}
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_closed"); got != 0 {
		t.Fatalf("half-open probe must not log a closed transition, got %d", got)
	}

	// The probe fails and the circuit reopens. This must NOT be treated as
	// a new transition, since the baseline was never moved off "open".
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitOpen, 5),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_open"); got != 1 {
		t.Fatalf("expected still exactly one open log after a failed probe reopened the same outage, got %d", got)
	}

	// A genuine recovery is still correctly recognized afterward.
	sidecar.recordDestinationCircuitTransitionsV8(
		ctx, time.Now().UTC(), runtime,
		destinationHealthSnapshotFixture(1, "soc_primary", delivery.CircuitClosed, 0),
	)
	if got := countDestinationCircuitLogs(t, capture.store.DatabasePath(), "circuit_breaker_closed"); got != 1 {
		t.Fatalf("expected exactly one closed log after genuine recovery, got %d", got)
	}
}
