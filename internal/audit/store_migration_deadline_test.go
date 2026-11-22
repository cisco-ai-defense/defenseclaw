// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// A migration that stalls inside SQLite (GAP-0664: a loaded -race run sat
// 50 minutes in the scan_findings ALTER) must end Init with an error instead
// of blocking it for ever. The query below never finishes on its own; only
// the migration deadline reaching SQLite stops it.
func TestApplyMigrationStopsAStalledStatementAtTheDeadline(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	store.migrationTimeout = 200 * time.Millisecond
	stalled := migration{description: "test: a statement that never finishes", apply: func(ex dbExecer) error {
		var n int64
		return ex.QueryRow("WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x + 1 FROM c) SELECT count(*) FROM c").Scan(&n)
	}}

	done := make(chan error, 1)
	go func() { done <- store.applyMigration(1, stalled) }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a stalled migration returned no error")
		}
		if !errors.Is(err, context.DeadlineExceeded) && !isInterrupted(err) {
			t.Fatalf("stalled migration error is not the deadline: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("a stalled migration was not stopped by its deadline (GAP-0664)")
	}
}

func isInterrupted(err error) bool {
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "interrupted") || strings.Contains(text, "deadline")
}
