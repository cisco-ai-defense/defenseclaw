// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// TestWriteManagedFileBackup_DirIs0o700 (M-5) verifies the per-connector
// backup dir under ${data_dir}/connector_backups/<connector>/ is owner-
// only. Listing the connector_backups tree leaks which connectors are
// installed; the payload itself already has 0o600 from atomicWriteFile,
// but a 0o755 parent dir was the historical default (MkdirAll's
// argument, not a security choice).
func TestWriteManagedFileBackup_DirIs0o700(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	target := filepath.Join(tmp, "agent.json")
	if err := os.WriteFile(target, []byte(`{"hello":"world"}`), 0o600); err != nil {
		t.Fatalf("seed target: %v", err)
	}

	if err := captureManagedFileBackup(tmp, "claudecode", "config", target); err != nil {
		t.Fatalf("captureManagedFileBackup: %v", err)
	}

	dir := filepath.Join(tmp, "connector_backups", "claudecode")
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatalf("stat backup dir: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("backup dir mode = %v, want 0o700 (operator state must not be world-listable)", mode)
	}
}

func TestEnsureManagedBackupDirRestricted_TightensExistingDir(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	if err := os.MkdirAll(tmp, 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.Chmod(tmp, 0o755); err != nil {
		t.Fatalf("chmod 0o755: %v", err)
	}
	if err := ensureManagedBackupDirRestricted(tmp); err != nil {
		t.Fatalf("ensureManagedBackupDirRestricted: %v", err)
	}
	info, err := os.Stat(tmp)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if mode := info.Mode().Perm(); mode != 0o700 {
		t.Fatalf("dir mode = %v, want 0o700 (must tighten existing 0o755 dir)", mode)
	}
}
