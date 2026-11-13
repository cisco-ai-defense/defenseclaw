// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// prunedAuditStore is an initialized audit.db with auto_vacuum off and most
// of its rows deleted (issue #1440): the file keeps its size.
func prunedAuditStore(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close() //nolint:errcheck
	db.SetMaxOpenConns(1)
	for _, statement := range []string{
		`PRAGMA auto_vacuum=NONE`, `VACUUM`,
		`CREATE TABLE compact_filler (id INTEGER PRIMARY KEY, body BLOB NOT NULL)`,
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 2000)
			INSERT INTO compact_filler (body) SELECT randomblob(4000) FROM n`,
		`DELETE FROM compact_filler WHERE id % 10 != 0`,
		`PRAGMA wal_checkpoint(TRUNCATE)`,
	} {
		if _, err := db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	return path
}

// useAuditCompact points the command at db with the gateway's state given.
func useAuditCompact(t *testing.T, db string, running bool, pid int) *cobra.Command {
	t.Helper()
	previousCfg, previousRunning, previousFree := cfg, auditCompactGatewayRunning, dataDirFreeBytes
	previousDry, previousJSON, previousLive := auditCompactDryRun, auditCompactJSON, auditCompactServiceLive
	t.Cleanup(func() {
		cfg, auditCompactGatewayRunning, dataDirFreeBytes = previousCfg, previousRunning, previousFree
		auditCompactDryRun, auditCompactJSON, auditCompactServiceLive = previousDry, previousJSON, previousLive
	})
	auditCompactServiceLive = func() (bool, error) { return false, nil }
	cfg = &config.Config{AuditDB: db}
	auditCompactGatewayRunning = func() (bool, int) { return running, pid }
	dataDirFreeBytes = func(string) (uint64, error) { return 1 << 40, nil }
	auditCompactDryRun, auditCompactJSON = false, false
	cmd := &cobra.Command{}
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	return cmd
}

func auditCompactSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Size()
}

func TestAuditCompactRefusesWhileTheGatewayRunsAndNamesStopAndStart(t *testing.T) {
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, true, 4242)
	err := runAuditCompact(cmd, nil)
	if err == nil {
		t.Fatal("compact ran beside a running gateway")
	}
	for _, want := range []string{"PID 4242", "defenseclaw-gateway stop", "defenseclaw audit compact again", "defenseclaw-gateway start", "Nothing was changed"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("refusal %q does not name %q", err, want)
		}
	}
	if size := auditCompactSize(t, db); size != before {
		t.Fatalf("a refused compaction changed audit.db (%d -> %d bytes)", before, size)
	}
}

func TestAuditCompactDryRunReportsBesideARunningGatewayAndChangesNothing(t *testing.T) {
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, true, 4242)
	auditCompactDryRun = true
	if err := runAuditCompact(cmd, nil); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{"auto_vacuum none", "would rewrite it (VACUUM)", "reclaim about", "free disk space", "The gateway is running: stop it first (defenseclaw-gateway stop)", "Dry run: nothing was changed."} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output does not say %q:\n%s", want, out)
		}
	}
	if size := auditCompactSize(t, db); size != before {
		t.Fatalf("the dry run changed audit.db (%d -> %d bytes)", before, size)
	}
}

func TestAuditCompactShrinksTheStoreAndPrintsTheReclaimedSpace(t *testing.T) {
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, false, 0)
	if err := runAuditCompact(cmd, nil); err != nil {
		t.Fatalf("compact: %v", err)
	}
	out := cmd.OutOrStdout().(*bytes.Buffer).String()
	for _, want := range []string{"Rewrote it (VACUUM); auto_vacuum is now incremental.", "Reclaimed: ", "Start the gateway again with: defenseclaw-gateway start"} {
		if !strings.Contains(out, want) {
			t.Errorf("output does not say %q:\n%s", want, out)
		}
	}
	if size := auditCompactSize(t, db); size >= before/2 {
		t.Fatalf("audit.db %d -> %d bytes", before, size)
	}

	// Again, as JSON: nothing left to reclaim.
	cmd = useAuditCompact(t, db, false, 0)
	auditCompactJSON = true
	if err := runAuditCompact(cmd, nil); err != nil {
		t.Fatalf("second compact: %v", err)
	}
	var result map[string]any
	if err := json.Unmarshal(cmd.OutOrStdout().(*bytes.Buffer).Bytes(), &result); err != nil {
		t.Fatalf("JSON: %v", err)
	}
	if result["method"] != "none" || result["auto_vacuum_before"] != "incremental" || result["reclaimed_bytes"] != float64(0) || result["dry_run"] != false {
		t.Fatalf("second run JSON = %v", result)
	}
}

func TestAuditCompactRefusesAShortDiskWithTheNumbers(t *testing.T) {
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, false, 0)
	dataDirFreeBytes = func(string) (uint64, error) { return 1 << 20, nil }
	err := runAuditCompact(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "not enough free disk space") || !strings.Contains(err.Error(), "1 MiB are free") ||
		!strings.Contains(err.Error(), "Nothing was changed") {
		t.Fatalf("compact on a short disk = %v", err)
	}
	if size := auditCompactSize(t, db); size != before {
		t.Fatalf("a refused compaction changed audit.db (%d -> %d bytes)", before, size)
	}
}

func TestAuditCompactManagedRefusalNamesTheServiceCommands(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, managed.DeploymentModeManagedEnterprise)
	stop, start := auditCompactStopStart()
	err := auditCompactInUse("/var/lib/defenseclaw/audit.db", 0)
	if !strings.Contains(err.Error(), stop) || !strings.Contains(err.Error(), start) || strings.Contains(stop, "defenseclaw-gateway stop") {
		t.Fatalf("managed refusal %q, stop %q, start %q", err, stop, start)
	}
}

func TestAuditCompactRefusesWhileTheManagedGatewayServiceRuns(t *testing.T) {
	db := prunedAuditStore(t)
	before := auditCompactSize(t, db)
	cmd := useAuditCompact(t, db, false, 0)
	auditCompactServiceLive = func() (bool, error) { return true, nil }
	err := runAuditCompact(cmd, nil)
	if err == nil || !strings.Contains(err.Error(), "compact needs it alone") {
		t.Fatalf("compact beside a running gateway service = %v", err)
	}
	if size := auditCompactSize(t, db); size != before {
		t.Fatalf("a refused compaction changed audit.db (%d -> %d bytes)", before, size)
	}
}

func TestAuditCompactRefusesADiskWithZeroFreeBytes(t *testing.T) {
	db := prunedAuditStore(t)
	cmd := useAuditCompact(t, db, false, 0)
	dataDirFreeBytes = func(string) (uint64, error) { return 0, nil }
	if err := runAuditCompact(cmd, nil); err == nil || !strings.Contains(err.Error(), "0 MiB are free") {
		t.Fatalf("compact on a full disk = %v", err)
	}
}
