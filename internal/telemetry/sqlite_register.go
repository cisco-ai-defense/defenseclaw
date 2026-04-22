// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"database/sql"
	"os"
	"sync/atomic"
	"time"
)

var registeredAuditDB atomic.Pointer[sql.DB]

// RegisterAuditDB wires the audit SQLite connection for PRAGMA-based health metrics.
// Safe to call once at store open; nil clears the registration.
func RegisterAuditDB(db *sql.DB) {
	registeredAuditDB.Store(db)
}

func collectSQLiteHealth(ctx context.Context, db *sql.DB) SQLiteHealthMetrics {
	var h SQLiteHealthMetrics
	if db == nil {
		return h
	}

	var mainPath string
	rows, err := db.QueryContext(ctx, "PRAGMA database_list")
	if err != nil {
		return h
	}
	defer rows.Close()
	for rows.Next() {
		var seq int
		var name, file string
		if scanErr := rows.Scan(&seq, &name, &file); scanErr != nil {
			continue
		}
		if name == "main" && file != "" {
			mainPath = file
			break
		}
	}
	if mainPath != "" {
		if st, err := os.Stat(mainPath); err == nil {
			h.DBSizeBytes = st.Size()
		}
		wal := mainPath + "-wal"
		if st, err := os.Stat(wal); err == nil {
			h.WALSizeBytes = st.Size()
		}
	}

	_ = db.QueryRowContext(ctx, "PRAGMA page_count").Scan(&h.PageCount)
	_ = db.QueryRowContext(ctx, "PRAGMA freelist_count").Scan(&h.FreelistCount)

	t0 := time.Now()
	_, _ = db.ExecContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)")
	h.CheckpointMs = float64(time.Since(t0).Milliseconds())

	return h
}
