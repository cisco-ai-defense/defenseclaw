// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

func BenchmarkRetentionReaperThousandRowsWithConcurrentReader(b *testing.B) {
	directory := b.TempDir()
	store, err := NewStore(filepath.Join(directory, "audit.db"))
	if err != nil {
		b.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = store.Close() })
	reader, err := openSQLite(store.dbPath)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = reader.Close() })
	if err := reader.PingContext(context.Background()); err != nil {
		b.Fatal(err)
	}
	reaper, err := NewRetentionReaper(store, nil, 90, RetentionOptions{})
	if err != nil {
		b.Fatal(err)
	}
	old := time.Now().UTC().Add(-91 * 24 * time.Hour)
	b.ReportAllocs()
	b.ResetTimer()
	for iteration := range b.N {
		b.StopTimer()
		seedBenchmarkRetentionRows(b, store, iteration, old)
		readTx, err := reader.BeginTx(context.Background(), nil)
		if err != nil {
			b.Fatal(err)
		}
		var visible int
		if err := readTx.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM activity_events`,
		).Scan(&visible); err != nil {
			_ = readTx.Rollback()
			b.Fatal(err)
		}
		if visible != RetentionBatchSize {
			_ = readTx.Rollback()
			b.Fatalf("reader snapshot rows=%d want=%d", visible, RetentionBatchSize)
		}
		b.StartTimer()
		result, err := reaper.Run(b.Context())
		b.StopTimer()
		if rollbackErr := readTx.Rollback(); rollbackErr != nil {
			b.Fatal(rollbackErr)
		}
		if err != nil {
			b.Fatal(err)
		}
		if result.RowsDeleted[RetentionActivityEvents] != RetentionBatchSize || result.BatchCount != 1 {
			b.Fatalf("reaper deleted=%d batches=%d want=%d/1",
				result.RowsDeleted[RetentionActivityEvents], result.BatchCount, RetentionBatchSize)
		}
		var remaining int
		if err := reader.QueryRowContext(context.Background(),
			`SELECT COUNT(*) FROM activity_events`,
		).Scan(&remaining); err != nil {
			b.Fatal(err)
		}
		if remaining != 0 {
			b.Fatalf("rows after reaper=%d", remaining)
		}
		b.StartTimer()
	}
	b.ReportMetric(float64(RetentionBatchSize), "rows/batch")
}

func seedBenchmarkRetentionRows(b *testing.B, store *Store, iteration int, timestamp time.Time) {
	b.Helper()
	tx, err := store.db.Begin()
	if err != nil {
		b.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	statement, err := tx.Prepare(`INSERT INTO activity_events
		(id, timestamp, retention_timestamp_unix_nano, actor, action, target_type, target_id)
		VALUES (?, ?, ?, 'operator', 'config-update', 'config', 'main')`)
	if err != nil {
		b.Fatal(err)
	}
	defer statement.Close() //nolint:errcheck
	for row := range RetentionBatchSize {
		if _, err := statement.Exec(
			fmt.Sprintf("benchmark-%d-%04d", iteration, row),
			timestamp.Format(time.RFC3339Nano), timestamp.UnixNano(),
		); err != nil {
			b.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		b.Fatal(err)
	}
}
