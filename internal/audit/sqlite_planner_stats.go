// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"strings"
)

const (
	// plannerStatsMinRows is the history below which the default query plans
	// cost nothing and ANALYZE is not worth a write.
	plannerStatsMinRows = 1000
	// plannerStatsGrowth is how many times larger than at the last ANALYZE the
	// history must be before the statistics are taken again.
	plannerStatsGrowth = 2
	// plannerStatsRowLimit bounds the rows ANALYZE reads per index, so it takes
	// milliseconds on a multi-gigabyte database.
	plannerStatsRowLimit = 1000
)

// plannerStatsTables are the tables that grow with every hook. Their highest
// rowids stand for the size of the history.
var plannerStatsTables = [...]string{"audit_events", "correlation_observations"}

// RefreshPlannerStatistics takes SQLite's planner statistics (ANALYZE) once
// the history has reached plannerStatsMinRows rows and again each time it has
// doubled, and reports whether it did.
//
// The database never had any. Without them the planner assumes every equality
// on an index prefix returns about ten rows, and for a lookup by
// semantic_event_id and connector_instance_id (loadExactToolChainSession) or
// by several identifiers of one connector (matchIdentifiers) it chose the
// connector_instance_id prefix of the unique index, which every row of the
// connector shares: each hook scanned the whole identifier ledger. Hook
// throughput fell from 30 to 16 per second over 16,000 hooks and 2 GB, and a
// retention run that deleted the rows did not bring it back, while the same
// database with statistics served 29 per second (GAP-0233). The statistics
// describe the shape of the data (one connector, one event per identifier
// value), not its size, so doubling is often enough.
func (s *Store) RefreshPlannerStatistics(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("audit: planner statistics context is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return false, err
	}
	defer release()
	var query strings.Builder
	query.WriteString("SELECT 0")
	for _, table := range plannerStatsTables {
		query.WriteString(" + (SELECT COALESCE(MAX(rowid), 0) FROM " + table + ")")
	}
	var rows int64
	if err := s.scanRow(ctx, "audit_planner_stats_size", s.db.QueryRowContext(ctx, query.String()), &rows); err != nil {
		return false, fmt.Errorf("audit: measure history for planner statistics: %w", err)
	}
	last := s.plannerStatsRows.Load()
	if rows < plannerStatsMinRows || (last > 0 && rows < plannerStatsGrowth*last) {
		return false, nil
	}
	// The limit belongs to the connection that runs ANALYZE, which the pool
	// may replace: set it on the one connection used here.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return false, fmt.Errorf("audit: open connection for planner statistics: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA analysis_limit=%d", plannerStatsRowLimit)); err != nil {
		return false, fmt.Errorf("audit: limit planner statistics: %w", err)
	}
	err = retryBusyObserved(ctx, "audit_planner_stats", s.sqliteBusyObservabilityV8(), func() error {
		_, execErr := conn.ExecContext(ctx, "ANALYZE")
		return execErr
	})
	_, _ = conn.ExecContext(ctx, "PRAGMA analysis_limit=0")
	if err != nil {
		return false, fmt.Errorf("audit: take planner statistics: %w", err)
	}
	s.plannerStatsRows.Store(rows)
	return true, nil
}
