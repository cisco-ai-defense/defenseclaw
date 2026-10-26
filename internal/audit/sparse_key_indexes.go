// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
)

const sparseKeyIndexesMigrationDescription = "audit: index sparse correlation keys only on the rows that have them"

// sparseKeyIndex is an index whose leading key is NULL on most rows a hook
// call writes. Each hook call writes about 7 audit_events rows and 21
// correlation_observations rows in about 15 commits, and every commit
// rewrote the last page of each of these indexes for a NULL key no query
// reads: about 100 of the 382 write-ahead-log frames (1.5 MiB) of a call
// (GAP-1303, GAP-0614). The partial form leaves those rows out.
//
// Every reader filters or joins these columns with = (correlation anchors,
// the TUI run filter, the finding and quarantine joins, the enforcement
// block lookup). "column = value" implies "column IS NOT NULL", so SQLite
// still uses the partial index for each of them
// (TestSparseKeyIndexesServeTheirQueries).
type sparseKeyIndex struct {
	name, table, columns, key string
}

var sparseKeyIndexes = []sparseKeyIndex{
	{"idx_audit_run_id", "audit_events", "run_id", "run_id"},
	{"idx_audit_request_id", "audit_events", "request_id", "request_id"},
	{"idx_audit_evaluation_id", "audit_events", "evaluation_id", "evaluation_id"},
	{"idx_audit_enforcement_action_id", "audit_events", "enforcement_action_id", "enforcement_action_id"},
	{"idx_correlation_observations_turn", "correlation_observations", "turn_id, observed_time_unix_nano", "turn_id"},
	{"idx_correlation_observations_agent", "correlation_observations", "agent_id, observed_time_unix_nano", "agent_id"},
	{"idx_correlation_observations_lifecycle", "correlation_observations", "lifecycle_id, observed_time_unix_nano", "lifecycle_id"},
	{"idx_correlation_observations_execution", "correlation_observations", "execution_id, observed_time_unix_nano", "execution_id"},
	{"idx_correlation_observations_model_request", "correlation_observations", "model_request_id", "model_request_id"},
	{"idx_correlation_observations_model_response", "correlation_observations", "model_response_id", "model_response_id"},
	{"idx_correlation_observations_trace", "correlation_observations", "trace_id, span_id", "trace_id"},
}

func (index sparseKeyIndex) create(partial bool) string {
	statement := "CREATE INDEX " + index.name + " ON " + index.table + "(" + index.columns + ")"
	if partial {
		statement += " WHERE " + index.key + " IS NOT NULL"
	}
	return statement
}

// migrateSparseKeyIndexes rebuilds each sparse-key index in its partial
// form. The rebuild reads the table once per index; on a store upgraded from
// 1.0.2, 1.0.3 or 1.0.4 the launcher applies it before the gateway's
// readiness wait (PendingMigrations), and a gateway applies it at start.
// The schema version moves, so an older binary opened on the store after a
// rollback keeps the partial indexes; its queries use them the same way.
func migrateSparseKeyIndexes(ex dbExecer) error {
	return setSparseKeyIndexForm(ex, true)
}

// setSparseKeyIndexForm makes each sparse-key index partial, or full on a
// Secure Client store, whose schema stays main's. An index already in the
// wanted form is left as it is.
func setSparseKeyIndexForm(ex dbExecer, partial bool) error {
	for _, index := range sparseKeyIndexes {
		var definition sql.NullString
		err := ex.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`, index.name).Scan(&definition)
		switch {
		case errors.Is(err, sql.ErrNoRows):
			// A partial fixture schema without this table's index: nothing to
			// convert; the migration that owns the index creates it.
			continue
		case err != nil:
			return fmt.Errorf("audit: read index %s: %w", index.name, err)
		}
		if strings.Contains(strings.ToUpper(definition.String), " WHERE ") == partial {
			continue
		}
		if _, err := ex.Exec("DROP INDEX " + index.name); err != nil {
			return fmt.Errorf("audit: drop index %s: %w", index.name, err)
		}
		if _, err := ex.Exec(index.create(partial)); err != nil {
			return fmt.Errorf("audit: create index %s: %w", index.name, err)
		}
	}
	return nil
}

// keepSecureClientSparseKeyIndexes puts back the full indexes of main on a
// Secure Client store after the migrations ran.
func (s *Store) keepSecureClientSparseKeyIndexes() error {
	if !s.secureClientSchema {
		return nil
	}
	tx, err := s.db.Begin()
	if err != nil {
		return fmt.Errorf("audit: begin sparse-key index check: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	if err := setSparseKeyIndexForm(tx, false); err != nil {
		return err
	}
	return tx.Commit()
}
