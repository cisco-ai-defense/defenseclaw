// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	_ "modernc.org/sqlite"
)

func TestSecureClientAuditMaintenanceLeavesPlannerStatisticsAbsent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1000; i++ {
		if err := store.LogEvent(audit.Event{Action: "hook_decision", Target: "planner-stats", Severity: "INFO", SessionID: "s"}); err != nil {
			t.Fatal(err)
		}
	}
	sidecar := &Sidecar{cfg: &config.Config{DeploymentMode: "managed_enterprise"}, store: store}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	sidecar.runAuditPlannerStats(ctx)
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='sqlite_stat1'").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("Secure Client audit database gained sqlite_stat1")
	}
}
