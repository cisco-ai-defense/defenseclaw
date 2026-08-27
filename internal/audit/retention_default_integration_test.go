// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// This joins the two halves of the default-retention contract: an omitted v8
// setting must compile to seven days, and that exact value must drive the
// graph-aware SQLite reaper rather than stopping at configuration metadata.
func TestDefaultSevenDayRetentionReapsSQLiteHistoryAndCorrelationAtStrictBoundary(t *testing.T) {
	plan, err := config.CompileObservabilityV8(nil)
	if err != nil {
		t.Fatal(err)
	}
	days := plan.Snapshot().Local.RetentionDays
	if days != config.ObservabilityV8DefaultRetentionDays {
		t.Fatalf("compiled default retention = %d days, constant = %d", days, config.ObservabilityV8DefaultRetentionDays)
	}
	if days != 7 {
		t.Fatalf("compiled default retention = %d days, want 7", days)
	}

	store, judge := newRetentionStores(t)
	now := time.Date(2026, 8, 26, 18, 0, 0, 0, time.FixedZone("west", -7*60*60))
	cutoff := now.UTC().Add(-time.Duration(days) * 24 * time.Hour)
	before := cutoff.Add(-time.Nanosecond)
	after := cutoff.Add(time.Nanosecond)
	seedRetentionHistory(t, store, judge, before, cutoff, after)

	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance := mustCorrelationInstance(t, repo, "default-seven-day-boundary", ConnectorCustodyDefenseClaw)
	equalEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: cutoff})
	afterEvent, _ := seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: after})

	reaper := newRetentionReaperAt(t, store, judge, int64(days), now, RetentionOptions{}, retentionHooks{})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Cutoff.Equal(cutoff) {
		t.Fatalf("cutoff = %s, want %s", result.Cutoff, cutoff)
	}
	if result.RowsDeleted[RetentionCorrelationEvents] == 0 {
		t.Fatal("seven-day run did not reap any eligible correlation_events")
	}

	for _, table := range []string{
		"audit_events", "activity_events", "network_egress_events", "sink_health",
		"scan_findings", "findings", "scan_results", "judge_responses",
	} {
		assertRetentionSuffixes(t, store.db, table)
	}
	assertRetentionSuffixes(t, judge.db, "judge_responses")
	for _, table := range []string{
		"guardrail_chain_deny_receipts", "guardrail_chain_events", "guardrail_chain_partitions",
		"correlation_receipts", "correlation_cursors", "correlation_pending_operations",
		"correlation_relationships",
	} {
		if countRetentionRows(t, store.db, table) != 0 {
			t.Errorf("old correlation table %s was not fully reaped", table)
		}
	}
	for _, eventID := range []SemanticEventID{equalEvent.SemanticEventID, afterEvent.SemanticEventID} {
		if countCorrelationEvent(t, store, eventID) != 1 {
			t.Fatalf("in-window correlation event %s was reaped", eventID)
		}
	}
	if got := countRetentionRows(t, store.db, "correlation_events"); got != 2 {
		t.Fatalf("correlation_events after seven-day reap = %d, want only boundary and in-window rows", got)
	}
}
