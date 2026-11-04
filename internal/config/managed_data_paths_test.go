// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"testing"
)

func TestManagedDataPathsDefaults(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "data")
	paths := (&Config{DataDir: dir}).ManagedDataPaths()
	if paths.DataDir != dir ||
		paths.AuditDBPath != filepath.Join(dir, DefaultAuditDBName) ||
		paths.JudgeBodyDBPath != filepath.Join(dir, DefaultJudgeBodiesDBName) ||
		paths.RedactionKeyPath != filepath.Join(dir, "redaction-correlation.key") {
		t.Fatalf("paths = %+v", paths)
	}
	custom := filepath.Join(t.TempDir(), "audit", "a.db")
	if got := (&Config{DataDir: dir, AuditDB: custom}).ManagedDataPaths().AuditDBPath; got != custom {
		t.Fatalf("audit path = %s, want %s", got, custom)
	}
	if got := (*Config)(nil).ManagedDataPaths(); got.DataDir != "" {
		t.Fatalf("nil config paths = %+v", got)
	}
}
