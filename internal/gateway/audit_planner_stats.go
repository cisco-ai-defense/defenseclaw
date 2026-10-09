// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"time"
)

// auditPlannerStatsInterval is how often the size of the audit history is
// checked (two MAX(rowid) lookups).
const auditPlannerStatsInterval = 30 * time.Second

// runAuditPlannerStats keeps SQLite's query-planner statistics for the audit
// database current as the history grows, so a hook's ledger lookups stay
// index seeks (see audit.Store.RefreshPlannerStatistics). The first pass runs
// at start, which covers a database that grew before this release.
func (s *Sidecar) runAuditPlannerStats(ctx context.Context) {
	if s == nil || s.store == nil || s.currentConfig().SecureClientIntegration() {
		return
	}
	ticker := time.NewTicker(auditPlannerStatsInterval)
	defer ticker.Stop()
	for {
		if _, err := s.store.RefreshPlannerStatistics(ctx); err != nil && ctx.Err() == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] audit planner statistics failed: %v\n", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}
