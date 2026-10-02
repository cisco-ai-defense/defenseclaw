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
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// GAP-1800: after the audit store recovers, telemetry reads RUNNING since the
// recovery, not since the bind time the outage started from.
func TestTelemetrySinceFollowsEventHistoryFailureAndRecovery(t *testing.T) {
	source := &fakeObservabilityV8HealthSource{snapshot: observabilityruntime.DestinationHealthSnapshot{Generation: 3}}
	health := NewSidecarHealth()
	health.bindObservabilityV8HealthSource(source)
	health.bindObservabilityV8EventHistoryGeneration(3)
	bound := health.Snapshot().Telemetry
	if bound.State != StateRunning || bound.Since.IsZero() {
		t.Fatalf("bound telemetry = %+v", bound)
	}
	if again := health.Snapshot().Telemetry; !again.Since.Equal(bound.Since) {
		t.Fatalf("unchanged state moved since: %v -> %v", bound.Since, again.Since)
	}

	failedAt := bound.Since.Add(2 * time.Minute)
	failure := eventHistoryTransition(3, 1, audit.EventHistoryHealthFailed,
		audit.EventHistoryHealthWriteFailed, audit.EventHistorySQLiteFull, 13)
	failure.OccurredAt = failedAt
	health.observeObservabilityV8EventHistory(failure)
	failed := health.Snapshot().Telemetry
	if failed.State != StateError || !failed.Since.Equal(failedAt) {
		t.Fatalf("failed telemetry = %s since %v, want ERROR since %v", failed.State, failed.Since, failedAt)
	}

	recoveredAt := failedAt.Add(6 * time.Minute)
	recovery := eventHistoryTransition(3, 2, audit.EventHistoryHealthRecovered,
		audit.EventHistoryHealthWriteFailed, "", 0)
	recovery.OccurredAt = recoveredAt
	health.observeObservabilityV8EventHistory(recovery)
	recovered := health.Snapshot().Telemetry
	if recovered.State != StateRunning || !recovered.Since.Equal(recoveredAt) {
		t.Fatalf("recovered telemetry = %s since %v, want RUNNING since %v", recovered.State, recovered.Since, recoveredAt)
	}
}
