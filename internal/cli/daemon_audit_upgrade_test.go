// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/daemon"
)

// GAP-1909: start applies a pending audit upgrade before it launches the
// gateway, so the readiness wait no longer covers a long one-time migration.
// GAP-0363: the terminal gets one line; each migration applied is written to
// gateway.log, stamped, not printed among the installer's lines.
func TestUpgradeAuditStoreBeforeStartAppliesPendingMigrations(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{AuditDB: filepath.Join(dir, "audit.db")}
	d := daemon.New(dir)

	var out, warn bytes.Buffer
	upgradeAuditStoreBeforeStart(cfg, &out, &warn, d)
	if out.Len() != 0 {
		t.Fatalf("missing store printed %q", out.String())
	}
	if _, err := os.Stat(cfg.AuditDB); !os.IsNotExist(err) {
		t.Fatalf("a missing store was created: %v", err)
	}

	if err := os.WriteFile(cfg.AuditDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	upgradeAuditStoreBeforeStart(cfg, &out, &warn, d)
	if !strings.Contains(out.String(), "Upgrading the audit database") || !strings.Contains(out.String(), "OK") {
		t.Fatalf("output = %q, warnings = %q", out.String(), warn.String())
	}
	if strings.Contains(out.String()+warn.String(), "applying migration") {
		t.Fatalf("the migrations were printed: output = %q, warnings = %q", out.String(), warn.String())
	}
	if n, err := audit.PendingMigrations(cfg.AuditDB); err != nil || n != 0 {
		t.Fatalf("pending after upgrade: %d, %v", n, err)
	}
	logged, err := os.ReadFile(d.LogFile())
	if err != nil {
		t.Fatal(err)
	}
	first, _, _ := strings.Cut(string(logged), "\n")
	if os.Getenv(daemon.EnvLogTimestamps) != "0" && !strings.Contains(first, "Z [audit] applying migration 1: ") {
		t.Fatalf("gateway.log starts %q, want the first migration, stamped", first)
	}

	out.Reset()
	upgradeAuditStoreBeforeStart(cfg, &out, &warn, d)
	if out.Len() != 0 {
		t.Fatalf("a current store printed %q", out.String())
	}
}
