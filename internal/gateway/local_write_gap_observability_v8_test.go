// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"database/sql"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// GAP-1129: records lost while SQLite writes fail are kept in the loss journal
// across a crash; once writes work again one sqlite.write_failed record reports
// them, and a second restart reports nothing.
func TestLocalWriteGapSurvivesRestartAndIsReportedOnce(t *testing.T) {
	dataDir := t.TempDir()
	start := func() (sidecarV8BootstrapFixture, *sidecarOwnedObservabilityV8Runtime) {
		fixture := newSidecarV8BootstrapFixtureIn(t, 8, "", dataDir)
		if bound, err := fixture.sidecar.BootstrapObservabilityRuntime(
			t.Context(), fixture.configPath, fixture.raw,
		); err != nil || !bound {
			t.Fatalf("bootstrap bound=%t error=%v", bound, err)
		}
		owner, _ := fixture.sidecar.observabilityV8.(*sidecarOwnedObservabilityV8Runtime)
		return fixture, owner
	}
	stop := func(fixture sidecarV8BootstrapFixture) {
		// A stop after failed writes may report a degraded close.
		_ = fixture.sidecar.closeOwnedObservabilityV8Runtime()
		fixture.logger.Close()
		_ = fixture.store.Close()
	}
	storePath := filepath.Join(dataDir, config.DefaultAuditDBName)
	gapReports := func() []string {
		database, err := sql.Open("sqlite", storePath)
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		rows, err := database.Query(`SELECT COALESCE(details, '') || COALESCE(structured_json, '') FROM audit_events
			WHERE COALESCE(details, '') || COALESCE(structured_json, '') LIKE '%loss journal generation%'`)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var reports []string
		for rows.Next() {
			var report string
			if err := rows.Scan(&report); err != nil {
				t.Fatal(err)
			}
			reports = append(reports, report)
		}
		return reports
	}

	first, owner := start()
	database, err := sql.Open("sqlite", first.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.Exec(`CREATE TRIGGER local_history_full BEFORE INSERT ON audit_events
		BEGIN SELECT RAISE(ABORT, 'database or disk is full'); END`); err != nil {
		t.Fatal(err)
	}
	// Any mandatory log record does; this one fails its SQLite append.
	if _, err := emitLocalWriteGapV8(t.Context(), owner, observabilityruntime.LocalWriteLosses{Records: 1},
		time.Now().UTC()); err == nil {
		t.Fatal("the local append succeeded under a failing SQLite writer")
	}
	journalPath := filepath.Join(dataDir, observabilityruntime.LocalWriteLossJournalFile)
	crashed, crashedErr := os.ReadFile(journalPath)
	if _, err := database.Exec(`DROP TRIGGER local_history_full`); err != nil {
		t.Fatal(err)
	}
	_ = database.Close()
	stop(first)
	// Leave the journal as a crash at the failed write would have.
	if crashedErr == nil {
		if err := os.WriteFile(journalPath, crashed, 0o600); err != nil {
			t.Fatal(err)
		}
	}

	second, _ := start()
	second.sidecar.recordLocalWriteGapV8()
	reports := gapReports()
	if len(reports) != 1 || !strings.Contains(reports[0], "1 log record could not be stored") {
		t.Fatalf("gap reports after the restart = %q, want one for 1 record", reports)
	}
	stop(second)

	third, _ := start()
	third.sidecar.recordLocalWriteGapV8()
	if reports := gapReports(); len(reports) != 1 {
		t.Fatalf("gap reports after a second restart = %d, want still 1", len(reports))
	}
}
