// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"strings"
)

// preparedStatementQueries are the inserts every hook call repeats: about 7
// event-history rows and 21 correlation observations per call. Executed as
// plain text, SQLite parsed and planned each one again; that parse was about
// 17% of the gateway's CPU per hook call (hook-answer round a profile), CPU
// a hook waits for under load, when the store's one connection is the queue
// every audit write of every hook call stands in (GAP-1489, GAP-1211). They
// are prepared once when the store is ready and run in each caller's
// transaction.
var preparedStatementQueries = []string{eventHistoryInsertSQL, correlationObservationInsertSQL}

// prepareStatements prepares the repeated inserts on the store's connection.
// A statement that does not prepare runs as text, as before.
func (s *Store) prepareStatements(ctx context.Context) {
	prepared := make(map[string]*sql.Stmt, len(preparedStatementQueries))
	for _, query := range preparedStatementQueries {
		stmt, err := s.db.PrepareContext(ctx, query)
		if err != nil {
			continue
		}
		prepared[query] = stmt
	}
	s.prepared.Store(&prepared)
}

// txExecPrepared runs query in tx through its prepared statement when it has
// one, and otherwise as txExecContextObserved does.
func (s *Store) txExecPrepared(ctx context.Context, tx *sql.Tx, op, query string, args ...any) (sql.Result, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	var stmt *sql.Stmt
	if s != nil {
		if prepared := s.prepared.Load(); prepared != nil {
			stmt = (*prepared)[query]
		}
	}
	if stmt == nil {
		return txExecContextObserved(ctx, tx, op, s.sqliteBusyObservabilityV8(), query, args...)
	}
	res, err := tx.StmtContext(ctx, stmt).ExecContext(ctx, args...)
	if err != nil && strings.Contains(err.Error(), "statement from different database") {
		// A transaction of another handle: run the text there.
		return txExecContextObserved(ctx, tx, op, s.sqliteBusyObservabilityV8(), query, args...)
	}
	if isSQLiteBusy(err) {
		if observer := s.sqliteBusyObservabilityV8(); observer != nil {
			reportSQLiteBusyDetached(ctx, observer, op)
		}
	}
	return res, err
}
