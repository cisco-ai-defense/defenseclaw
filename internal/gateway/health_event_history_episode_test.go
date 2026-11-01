// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// The audit store reports one failed transition per failure episode. Writes
// that failed for 20 minutes and then recovered had their last failure dated
// at the start of the episode, so status and verify dropped the audit warning
// at once, seconds after the last failed write (GAP-1752).
func TestObservabilityV8EventHistoryDatesAFailureEpisodeFromItsRecovery(t *testing.T) {
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(&fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 7}})
	health.bindObservabilityV8EventHistoryGeneration(7)
	start := time.Date(2026, 10, 26, 8, 0, 0, 0, time.UTC)
	failure := eventHistoryTransition(7, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed, audit.EventHistorySQLiteConstraintCorrupt, 19)
	failure.OccurredAt = start
	health.observeObservabilityV8EventHistory(failure)
	recovered := eventHistoryTransition(7, 2, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0)
	recovered.OccurredAt = start.Add(20 * time.Minute)
	health.observeObservabilityV8EventHistory(recovered)
	details := health.Snapshot().Telemetry.Details
	if want := recovered.OccurredAt.Format(time.RFC3339Nano); details["event_history_last_failure_at"] != want {
		t.Fatalf("event_history_last_failure_at = %v, want the recovery time %s (writes failed until then)", details["event_history_last_failure_at"], want)
	}
	// A later recovery with no failure in between does not move it.
	again := eventHistoryTransition(7, 3, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0)
	again.OccurredAt = start.Add(40 * time.Minute)
	health.observeObservabilityV8EventHistory(again)
	if want := recovered.OccurredAt.Format(time.RFC3339Nano); health.Snapshot().Telemetry.Details["event_history_last_failure_at"] != want {
		t.Fatalf("a recovery without a failure moved the last failure time to %v", health.Snapshot().Telemetry.Details["event_history_last_failure_at"])
	}
}
