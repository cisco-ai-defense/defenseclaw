// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package enterpriseunix

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A managed computer refuses defenseclaw status, doctor and the TUI, which
// show the audit store retention and size cap per user, and the gateway
// status printed only the retention: an applied max_store_mb showed nowhere.
// Linux and macOS status now report the store (GAP-0141).
func TestStatusReportsTheAuditStoreSizeCap(t *testing.T) {
	dataDir := t.TempDir()
	source := []byte("config_version: 8\nobservability:\n  local:\n    retention_days: 7\n    max_store_mb: 64\n")
	_, local, err := config.SummarizeObservabilityV8("config.yaml", source, dataDir)
	if err != nil {
		t.Fatal(err)
	}
	store := describeAuditStore(local)
	if store.RetentionDays != 7 || store.MaxStoreMB != 64 || store.SizeBytes != nil {
		t.Fatalf("store = %+v, want 7 days, cap 64 MiB and no size before audit.db exists", store)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "audit.db"), make([]byte, 3<<20), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, "audit.db-wal"), make([]byte, 1<<19), 0o600); err != nil {
		t.Fatal(err)
	}
	store = describeAuditStore(local)
	if store.SizeBytes == nil || *store.SizeBytes != 3<<20+1<<19 {
		t.Fatalf("store = %+v, want the size of audit.db and its WAL", store)
	}
	var out bytes.Buffer
	enterprisestatus.WriteAuditStore(&out, store)
	if got, want := out.String(), "  audit store retention: 7 days, size cap 64 MiB (3.5 MiB on disk)\n"; got != want {
		t.Fatalf("status line = %q, want %q", got, want)
	}
}
