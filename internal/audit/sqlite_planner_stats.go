// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
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
	if rows < plannerStatsMinRows {
		return false, nil
	}
	targets, err := s.plannerStatsTargets(ctx)
	if err != nil {
		return false, err
	}
	if last > 0 && rows < plannerStatsGrowth*last {
		// The stored statistics are current, but an index the migrations
		// rebuilt since they were taken has none: DROP INDEX deletes its
		// sqlite_stat1 row (migrateSparseKeyIndexes on a store from 1.0.2,
		// 1.0.3 or 1.0.4). Without one SQLite prefers it over the selective
		// analyzed index (the GAP-0233 misplan), so the first complete pass
		// of a process takes the statistics of just those targets.
		if s.plannerStatsComplete.Load() {
			return false, nil
		}
		if targets, err = s.plannerStatsMissingTargets(ctx, targets); err != nil {
			return false, err
		}
		for _, target := range targets {
			if s.walPressure.Load() {
				return false, nil
			}
			// An index without statistics misplans the hooks' lookups
			// (GAP-0233): taking them does not yield.
			if err := s.analyzeOne(ctx, target, false); err != nil {
				return false, err
			}
		}
		s.plannerStatsComplete.Store(true)
		return len(targets) > 0, nil
	}
	// Statistics that only describe a smaller history are refreshed behind
	// the hooks: each ANALYZE yields to a waiting write. A pass that yielded
	// goes on from the target it yielded at, so a busy store still gets
	// through every target. A history without statistics (last == 0, a
	// store from before 1.0.3) misplans the hooks' lookups until they are
	// taken, so that first pass does not yield.
	refresh := last > 0
	for i := int(s.plannerStatsNext.Load()); i < len(targets); i++ {
		if s.walPressure.Load() {
			s.plannerStatsNext.Store(int64(i))
			return false, nil
		}
		if err := s.analyzeOne(ctx, targets[i], refresh); err != nil {
			if errors.Is(err, errPlannerStatsYielded) {
				s.plannerStatsNext.Store(int64(i))
				return false, nil
			}
			return false, err
		}
	}
	s.plannerStatsNext.Store(0)
	s.plannerStatsRows.Store(rows)
	s.plannerStatsComplete.Store(true)
	return true, nil
}

// plannerStatsMissingTargets are the targets that have no sqlite_stat1 row
// where ANALYZE would write one: an index of a table with rows, a partial
// index (ANALYZE records an empty one too), or an index-less table with rows.
func (s *Store) plannerStatsMissingTargets(ctx context.Context, targets []string) ([]string, error) {
	var missing []string
	for _, target := range targets {
		var absent int
		row := s.db.QueryRowContext(ctx, `SELECT NOT EXISTS (SELECT 1 FROM sqlite_stat1
			WHERE idx = ?1 OR (idx IS NULL AND tbl = ?1))`, target)
		if err := s.scanRow(ctx, "audit_planner_stats_missing", row, &absent); err != nil {
			return nil, fmt.Errorf("audit: read planner statistics of %s: %w", target, err)
		}
		if absent == 0 {
			continue
		}
		var table, definition string
		row = s.db.QueryRowContext(ctx, `SELECT tbl_name, COALESCE(sql, '') FROM sqlite_schema WHERE name = ?`, target)
		if err := s.scanRow(ctx, "audit_planner_stats_target", row, &table, &definition); err != nil {
			return nil, fmt.Errorf("audit: read the schema of %s: %w", target, err)
		}
		if table != target && strings.Contains(strings.ToUpper(definition), " WHERE ") {
			missing = append(missing, target)
			continue
		}
		var hasRows int
		if err := s.scanRow(ctx, "audit_planner_stats_rows", s.db.QueryRowContext(ctx,
			`SELECT EXISTS (SELECT 1 FROM "`+strings.ReplaceAll(table, `"`, `""`)+`")`), &hasRows); err != nil {
			return nil, fmt.Errorf("audit: measure %s for planner statistics: %w", table, err)
		}
		if hasRows != 0 {
			missing = append(missing, target)
		}
	}
	return missing, nil
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
func (s *Store) analyzeOne(ctx context.Context, target string, yield bool) error {
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
	statementCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	yielded := func() bool { return false }
	if yield {
		yielded = s.yieldPlannerStatsToWriters(statementCtx, cancel)
	}
	err = retryBusyObserved(statementCtx, "audit_planner_stats", s.sqliteBusyObservabilityV8(), func() error {
		if plannerStatsAnalyzePhaseHook != nil {
			plannerStatsAnalyzePhaseHook(statementCtx)
		}
		_, execErr := conn.ExecContext(statementCtx, `ANALYZE "`+strings.ReplaceAll(target, `"`, `""`)+`"`)
		return execErr
	})
	cancel()
	_, _ = conn.ExecContext(ctx, "PRAGMA analysis_limit=0")
	if yielded() && ctx.Err() == nil {
		// SQLite rolled the statement back; the next pass takes it again,
		// with the pages this one read still cached.
		return fmt.Errorf("%w: %s", errPlannerStatsYielded, target)
	}
	if err != nil {
		return fmt.Errorf("audit: take planner statistics of %s: %w", target, err)
	}
	return nil
}

// errPlannerStatsYielded reports an ANALYZE that gave the store's connection
// back to a waiting writer before it finished (yieldPlannerStatsToWriters).
var errPlannerStatsYielded = errors.New("audit: planner statistics yielded to waiting writers")

// plannerStatsYieldWait is how long ANALYZE keeps the store's one connection
// once another statement waits for it, and plannerStatsYieldPoll how often it
// looks. Variables so tests can change them.
var (
	plannerStatsYieldWait = 100 * time.Millisecond
	plannerStatsYieldPoll = 10 * time.Millisecond
)

// plannerStatsAnalyzePhaseHook runs inside each ANALYZE attempt while it
// holds the store's connection: a test seam that holds the statement open.
var plannerStatsAnalyzePhaseHook func(context.Context)

// yieldPlannerStatsToWriters interrupts the ANALYZE on ctx (cancel) once a
// statement has waited plannerStatsYieldWait for the store's one connection,
// and returns whether it did. ANALYZE reads a whole index on that connection:
// on a multi-gigabyte store with a cold page cache one index took it for
// tens of seconds, and when the history had doubled since the last
// statistics every hook queued behind it, an account's 32 requests filled,
// and its later calls were refused and blocked as a gateway no-answer
// (GAP-1790, managed RHEL, 3.7 GB store). Hooks come first; the statistics
// are taken again at the next pass.
func (s *Store) yieldPlannerStatsToWriters(ctx context.Context, cancel context.CancelFunc) func() bool {
	var yielded bool
	done := make(chan struct{})
	base := s.db.Stats().WaitCount
	go func() {
		defer close(done)
		ticker := time.NewTicker(plannerStatsYieldPoll)
		defer ticker.Stop()
		var waitingSince time.Time
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if s.db.Stats().WaitCount == base {
					continue
				}
				if waitingSince.IsZero() {
					waitingSince = now
				}
				if now.Sub(waitingSince) >= plannerStatsYieldWait {
					yielded = true
					cancel()
					return
				}
			}
		}
	}()
	return func() bool {
		<-done
		return yielded
	}
}
