// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2106: the agent ledger's prune keeps a uid's rows for the configured
// observability.local.retention_days, so the row window that bounds a
// pruned holder's sighting (GAP-2069) follows it: 3 days of retention is a
// 3-day window, not the 7-day default, and a retention of 0 (rows kept)
// bounds nothing.
func TestAgentLedgerRowWindowFollowsTheConfiguredRetention(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	for _, tc := range []struct {
		days int
		want time.Duration
	}{
		{3, 3 * day},
		{config.ObservabilityV8DefaultRetentionDays, 7 * day},
		{30, 30 * day},
		{0, 0},
		{-1, 0},
		{config.ObservabilityV8MaxRetentionDays, 0},
	} {
		if got := AgentLedgerRowWindow(tc.days, now); got != tc.want {
			t.Errorf("AgentLedgerRowWindow(%d) = %v; want %v", tc.days, got, tc.want)
		}
	}
	const uid = 1006
	pruned := map[int]int64{uid + 1: now.UnixNano()}
	if got, want := AgentLedgerSightingBound(pruned, uid, now, AgentLedgerRowWindow(3, now)), now.Add(-3*day).UnixNano(); got != want {
		t.Errorf("pruned ledger, 3-day retention: bound %d; want %d", got, want)
	}
	if got := AgentLedgerSightingBound(pruned, uid, now, AgentLedgerRowWindow(0, now)); got != 0 {
		t.Errorf("ledger that keeps every row, no row of the uid: bound %d; want 0", got)
	}
	if got, want := AgentLedgerSightingBound(map[int]int64{uid: 42}, uid, now, 3*day), int64(42); got != want {
		t.Errorf("uid's last hook: bound %d; want %d", got, want)
	}
	if got := AgentLedgerSightingBound(nil, uid, now, 3*day); got != 0 {
		t.Errorf("unreadable ledger: bound %d; want 0", got)
	}
}
