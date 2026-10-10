// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1909: start applies a pending audit upgrade before it launches the
// gateway, so the readiness wait no longer covers a long one-time migration.
func TestUpgradeAuditStoreBeforeStartAppliesPendingMigrations(t *testing.T) {
	dir := t.TempDir()
	cfg := &config.Config{AuditDB: filepath.Join(dir, "audit.db")}

	var out, warn bytes.Buffer
	upgradeAuditStoreBeforeStart(cfg, &out, &warn)
	if out.Len() != 0 {
		t.Fatalf("missing store printed %q", out.String())
	}
	if _, err := os.Stat(cfg.AuditDB); !os.IsNotExist(err) {
		t.Fatalf("a missing store was created: %v", err)
	}

	if err := os.WriteFile(cfg.AuditDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	// GAP-0153: the per-migration notes are not part of the launcher's output.
	stderr := captureStderr(t, func() { upgradeAuditStoreBeforeStart(cfg, &out, &warn) })
	if !strings.Contains(out.String(), "Upgrading the audit database") || !strings.Contains(out.String(), "OK") {
		t.Fatalf("output = %q, warnings = %q", out.String(), warn.String())
	}
	if stderr != "" {
		t.Fatalf("the upgrade wrote %q to stderr", stderr)
	}
	if n, err := audit.PendingMigrations(cfg.AuditDB); err != nil || n != 0 {
		t.Fatalf("pending after upgrade: %d, %v", n, err)
	}

	out.Reset()
	upgradeAuditStoreBeforeStart(cfg, &out, &warn)
	if out.Len() != 0 {
		t.Fatalf("a current store printed %q", out.String())
	}
}

// A Secure Client host keeps the per-migration notes of main on stderr, in
// the start upgrade and in one-shot commands (issue #1092).
func TestSecureClientKeepsTheMigrationNotesOfMain(t *testing.T) {
	secureClient := &config.Config{DeploymentMode: "managed_enterprise", AuditDB: filepath.Join(t.TempDir(), "audit.db")}
	if err := os.WriteFile(secureClient.AuditDB, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	var out, warn bytes.Buffer
	if stderr := captureStderr(t, func() { upgradeAuditStoreBeforeStart(secureClient, &out, &warn) }); !strings.Contains(stderr, "[audit] applying migration 1: ") {
		t.Fatalf("Secure Client start upgrade wrote %q to stderr (output %q, warnings %q)", stderr, out.String(), warn.String())
	}
	previous := cfg
	cfg = &config.Config{DeploymentMode: "managed_enterprise"}
	t.Cleanup(func() { cfg = previous })
	stderr := captureStderr(t, func() {
		store, err := openCommandAuditStore(filepath.Join(t.TempDir(), "audit.db"))
		if err != nil {
			t.Error(err)
			return
		}
		_ = store.Close()
	})
	if !strings.Contains(stderr, "[audit] applying migration 1: ") {
		t.Fatalf("Secure Client command wrote %q to stderr", stderr)
	}
}

func captureStderr(t *testing.T, run func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stderr
	os.Stderr = w
	defer func() { os.Stderr = saved }()
	run()
	_ = w.Close()
	captured, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return string(captured)
}
