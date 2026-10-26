// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// /health gives the time of the last failed audit write, kept after the
// gateway recovers, so status and verify can tell a recent failure from one
// fixed long ago (GAP-1627).
func TestObservabilityV8EventHistoryKeepsTheLastFailureTime(t *testing.T) {
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(&fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 7}})
	health.bindObservabilityV8EventHistoryGeneration(7)
	failure := eventHistoryTransition(7, 1, audit.EventHistoryHealthFailed, audit.EventHistoryHealthWriteFailed, audit.EventHistorySQLiteFull, 13)
	health.observeObservabilityV8EventHistory(failure)
	health.observeObservabilityV8EventHistory(eventHistoryTransition(7, 2, audit.EventHistoryHealthRecovered, audit.EventHistoryHealthWriteFailed, "", 0))
	details := health.Snapshot().Telemetry.Details
	want := failure.OccurredAt.UTC().Format(time.RFC3339Nano)
	if details["event_history_last_failure_at"] != want || details["event_history_last_sqlite_class"] != "full" {
		t.Fatalf("recovered details = %+v, want event_history_last_failure_at %s", details, want)
	}
}
