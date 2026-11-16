// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestConfigManagerReconcilesLegacyUpdateSettingsReadOnly(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	raw := []byte("config_version: 8\ndata_dir: " + filepath.ToSlash(dir) + "\nupdate_check: false\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	initial, err := loadRuntimeConfigCandidate(path, raw)
	if err != nil {
		t.Fatal(err)
	}
	mgr := newConfigManagerWithSnapshot(path, initial, nil, nil, "", nil)
	next, source, err := mgr.loadStableCandidate(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if next.Update.Check == nil || *next.Update.Check || source.compiledV8 == nil || !bytes.Equal(source.raw, raw) {
		t.Fatalf("legacy update setting or original source lost: update=%+v", next.Update)
	}
	saved, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(saved, raw) {
		t.Fatalf("read-only reconcile changed config.yaml: %v", err)
	}
}
