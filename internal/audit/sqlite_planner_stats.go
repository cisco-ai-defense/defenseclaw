// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
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
	// plannerStatsRowLimit bounds the rows ANALYZE samples per index for the
	// shape of the data. SQLite still counts every entry of the index, so one
	// index costs a read of the whole index.
	plannerStatsRowLimit = 1000
)

// plannerStatsTables are the tables that grow with every hook. The spans of
// their rowids stand for the size of the history.
var plannerStatsTables = [...]string{"audit_events", "correlation_observations"}

// RefreshPlannerStatistics takes SQLite's planner statistics (ANALYZE) once
// the history has reached plannerStatsMinRows rows and again each time it has
// doubled, and reports whether it did.
//
// Databases from before 1.0.3 have none. Without them the planner assumes
// every equality on an index prefix returns about ten rows, and for a lookup
// by semantic_event_id and connector_instance_id (loadExactToolChainSession)
// or by several identifiers of one connector (matchIdentifiers) it chose the
// connector_instance_id prefix of the unique index, which every row of the
// connector shares: each hook scanned the whole identifier ledger. Hook
// throughput fell from 30 to 16 per second over 16,000 hooks and 2 GB, and a
// retention run that deleted the rows did not bring it back, while the same
// database with statistics served 29 per second (GAP-0233). The statistics
// describe the shape of the data (one connector, one event per identifier
// value), not its size, so doubling is often enough.
//
// ANALYZE counts every entry of each index it reads, on the audit store's one
// connection. On a multi-gigabyte store with a cold page cache that took the
// connection for tens of seconds right after every gateway start, and the
// hooks queued behind it were closed as "did not answer in time" (GAP-1790).
// So statistics an earlier process took count as current until the history
// has doubled from the row counts they hold, and when ANALYZE does run it
// takes one index at a time and gives the connection back between them.
func (s *Store) RefreshPlannerStatistics(ctx context.Context) (bool, error) {
	if ctx == nil {
		return false, fmt.Errorf("audit: planner statistics context is required")
	}
	// ANALYZE holds the writer connection. While the WAL is over its limit it
	// waits for the next interval, so the checkpoint copies get their gaps.
	if s.walPressure.Load() {
		return false, nil
	}
	release, err := s.acquireReady()
	if err != nil {
		return false, err
	}
	defer release()
	var rows int64
	if err := s.scanRow(ctx, "audit_planner_stats_size", s.db.QueryRowContext(ctx, plannerStatsSizeQuery()), &rows); err != nil {
		return false, fmt.Errorf("audit: measure history for planner statistics: %w", err)
	}
	last := s.plannerStatsRows.Load()
	if last == 0 {
		if last, err = s.plannerStatsAnalyzedRows(ctx); err != nil {
			return false, err
		}
		s.plannerStatsRows.Store(last)
	}
	if rows < plannerStatsMinRows || (last > 0 && rows < plannerStatsGrowth*last) {
		return false, nil
	}
	targets, err := s.plannerStatsTargets(ctx)
	if err != nil {
		return false, err
	}
	for _, target := range targets {
		if s.walPressure.Load() {
			return false, nil
		}
		if err := s.analyzeOne(ctx, target); err != nil {
			return false, err
		}
	}
	s.plannerStatsRows.Store(rows)
	return true, nil
}

// plannerStatsSizeQuery measures the history as the rowid span of each
// history table. MAX and MIN each sit in their own subquery: SQLite reads one
// end of the b-tree for a lone MIN or MAX, but an aggregate holding both
// scans the whole table.
func plannerStatsSizeQuery() string {
	var query strings.Builder
	query.WriteString("SELECT 0")
	for _, table := range plannerStatsTables {
		query.WriteString(" + COALESCE((SELECT MAX(rowid) FROM " + table + ") - (SELECT MIN(rowid) FROM " + table + ") + 1, 0)")
	}
	return query.String()
}

// plannerStatsAnalyzedRows is the history the stored statistics describe:
// the rows ANALYZE counted in each history table, summed. It is 0 when there
// are none yet or a history table with rows has none.
func (s *Store) plannerStatsAnalyzedRows(ctx context.Context) (int64, error) {
	var stored int
	if err := s.scanRow(ctx, "audit_planner_stats_stored", s.db.QueryRowContext(ctx,
		`SELECT EXISTS (SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'sqlite_stat1')`), &stored); err != nil {
		return 0, fmt.Errorf("audit: look for planner statistics: %w", err)
	}
	if stored == 0 {
		return 0, nil
	}
	var total int64
	for _, table := range plannerStatsTables {
		var counted sql.NullInt64
		row := s.db.QueryRowContext(ctx, `SELECT MAX(CAST(stat AS INTEGER)) FROM sqlite_stat1
			WHERE tbl = ? AND idx IS NOT NULL`, table)
		if err := s.scanRow(ctx, "audit_planner_stats_analyzed", row, &counted); err != nil {
			return 0, fmt.Errorf("audit: read planner statistics: %w", err)
		}
		if counted.Valid && counted.Int64 > 0 {
			total += counted.Int64
			continue
		}
		var hasRows int
		if err := s.scanRow(ctx, "audit_planner_stats_rows", s.db.QueryRowContext(ctx,
			"SELECT EXISTS (SELECT 1 FROM "+table+")"), &hasRows); err != nil {
			return 0, fmt.Errorf("audit: measure %s for planner statistics: %w", table, err)
		}
		if hasRows != 0 {
			return 0, nil
		}
	}
	return total, nil
}

// plannerStatsTargets lists what a full ANALYZE reads: every index, and each
// table that has none (its row count is its only statistic).
func (s *Store) plannerStatsTargets(ctx context.Context) ([]string, error) {
	var targets []string
	err := retryBusyObserved(ctx, "audit_planner_stats_targets", s.sqliteBusyObservabilityV8(), func() error {
		targets = targets[:0]
		list, err := s.db.QueryContext(ctx, `SELECT name FROM sqlite_schema
			WHERE type = 'index' AND tbl_name NOT LIKE 'sqlite\_%' ESCAPE '\'
			UNION ALL
			SELECT t.name FROM sqlite_schema t
			WHERE t.type = 'table' AND t.name NOT LIKE 'sqlite\_%' ESCAPE '\'
				AND NOT EXISTS (SELECT 1 FROM sqlite_schema i WHERE i.type = 'index' AND i.tbl_name = t.name)`)
		if err != nil {
			return err
		}
		defer list.Close()
		for list.Next() {
			var name string
			if err := list.Scan(&name); err != nil {
				return err
			}
			targets = append(targets, name)
		}
		return list.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("audit: list planner statistics targets: %w", err)
	}
	return targets, nil
}

// analyzeOne takes the statistics of one index or index-less table on a
// connection it gives back when done.
func (s *Store) analyzeOne(ctx context.Context, target string) error {
	// The limit belongs to the connection that runs ANALYZE, which the pool
	// may replace: set it on the one connection used here.
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return fmt.Errorf("audit: open connection for planner statistics: %w", err)
	}
	defer conn.Close()
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA analysis_limit=%d", plannerStatsRowLimit)); err != nil {
		return fmt.Errorf("audit: limit planner statistics: %w", err)
	}
	err = retryBusyObserved(ctx, "audit_planner_stats", s.sqliteBusyObservabilityV8(), func() error {
		_, execErr := conn.ExecContext(ctx, `ANALYZE "`+strings.ReplaceAll(target, `"`, `""`)+`"`)
		return execErr
	})
	_, _ = conn.ExecContext(ctx, "PRAGMA analysis_limit=0")
	if err != nil {
		return fmt.Errorf("audit: take planner statistics of %s: %w", target, err)
	}
	return nil
}
