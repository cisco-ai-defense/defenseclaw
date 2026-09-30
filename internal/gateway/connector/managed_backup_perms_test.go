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

	"github.com/defenseclaw/defenseclaw/internal/testenv"
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
	testenv.AssertPrivateDirectory(t, dir)
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
	testenv.AssertPrivateDirectory(t, tmp)
}

// The rollback of a failed first Windows install puts back every agent file
// setup recorded: the captured bytes, or no file when setup created it. A
// file changed since DefenseClaw wrote it, or outside the account's home,
// stays.
func TestRestoreManagedFileBackupsPutsBackWhatSetupFound(t *testing.T) {
	t.Parallel()
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	patched := filepath.Join(home, ".gemini", "hooks.json")
	created := filepath.Join(home, "plugins", "defenseclaw.ts")
	edited := filepath.Join(home, "hermes", "config.yaml")
	outside := filepath.Join(t.TempDir(), "config.json")
	write := func(path, body string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	read := func(path string) string {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return string(data)
	}
	write(patched, "{}\n")
	write(edited, "a: 1\n")
	write(outside, "{}\n")
	if err := os.MkdirAll(filepath.Dir(created), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ connector, logical, path, body string }{
		{"antigravity", "hooks.json", patched, `{"defenseclaw-antigravity-stop":{}}`},
		{"amp", "config", created, "// defenseclaw-managed-plugin v1\n"},
		{"hermes", "config.yaml", edited, "a: 1\nhooks: {}\n"},
		{"devin", "config", outside, `{"hooks":{}}`},
	} {
		if err := captureManagedFileBackup(dataDir, item.connector, item.logical, item.path); err != nil {
			t.Fatal(err)
		}
		write(item.path, item.body)
		if err := updateManagedFileBackupPostHash(dataDir, item.connector, item.logical, item.path); err != nil {
			t.Fatal(err)
		}
	}
	write(edited, "a: 2\n")

	restored, kept, err := RestoreManagedFileBackups(dataDir, home)
	if err != nil {
		t.Fatalf("RestoreManagedFileBackups: %v", err)
	}
	if len(restored) != 2 || len(kept) != 2 {
		t.Fatalf("restored=%v kept=%v, want the patched and created files restored", restored, kept)
	}
	if got := read(patched); got != "{}\n" {
		t.Fatalf("patched file = %q, want its captured bytes", got)
	}
	if _, err := os.Lstat(created); !os.IsNotExist(err) {
		t.Fatalf("a file setup created must be removed: %v", err)
	}
	if got := read(edited); got != "a: 2\n" {
		t.Fatalf("a file changed after setup must stay: %q", got)
	}
	if got := read(outside); got != `{"hooks":{}}` {
		t.Fatalf("a file outside home must stay: %q", got)
	}
	if _, err := os.Lstat(managedFileBackupPath(dataDir, "antigravity", "hooks.json")); !os.IsNotExist(err) {
		t.Fatalf("a restored backup record must be consumed: %v", err)
	}
}
