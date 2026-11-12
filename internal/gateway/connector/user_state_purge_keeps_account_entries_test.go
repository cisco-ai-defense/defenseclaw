// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// GAP-0669: a managed account can have its own files next to, or below,
// DefenseClaw's state. Purge removes the files it knows it wrote and keeps
// other entries, including those of an account with no per-user install.
func TestGAP0669PurgeKeepsUnownedEntries(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	files := map[string]string{
		"session-facts.json":      "{}",
		"gateway-api.json":        "{}",
		"hooks/codex-hook.sh":     "managed",
		"hooks/.gateway-helper":   "managed helper",
		"hooks/.config-record":    "managed config",
		"hooks/.otlp-codex.token": "managed token",
		"hooks/personal.txt":      "keep hook note",
		"logs/personal.txt":       "keep log note",
		"personal.txt":            "keep account note",
	}
	for name, body := range files {
		path := filepath.Join(dataDir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"session-facts.json", "gateway-api.json", "hooks/codex-hook.sh", "hooks/.gateway-helper", "hooks/.config-record", "hooks/.otlp-codex.token"} {
		if _, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Errorf("managed entry %s stayed: %v", name, err)
		}
	}
	for _, name := range []string{"personal.txt", "hooks/personal.txt", "logs/personal.txt"} {
		if got, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(name))); err != nil || string(got) != files[name] {
			t.Errorf("account entry %s changed: %q, %v", name, got, err)
		}
	}
}

func TestGAP0669PurgeKeepsAccountOnlyFolder(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "personal.txt")
	if err := os.WriteFile(path, []byte("account note"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := PurgeUserStateWithResult(dataDir)
	if err != nil || result.Removed || len(result.Kept) != 1 || result.Kept[0] != "personal.txt" {
		t.Fatalf("purge result = %+v, %v", result, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "account note" {
		t.Fatalf("account file changed: %q, %v", got, err)
	}
}

func TestGAP0669PurgeClearsEmptyManagedBackupDirAndKeepsAccountFile(t *testing.T) {
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	backupDir := filepath.Join(dataDir, "connector_backups", "opencode")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	accountFile := filepath.Join(dataDir, "personal.txt")
	if err := os.WriteFile(accountFile, []byte("account note"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(backupDir); !os.IsNotExist(err) {
		t.Fatalf("empty managed backup folder stayed: %v", err)
	}
	if got, err := os.ReadFile(accountFile); err != nil || string(got) != "account note" {
		t.Fatalf("account file changed: %q, %v", got, err)
	}
}

func TestGAP0669PurgeReportsAccountNamesAsPrintableText(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not accept control characters in filenames")
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dataDir, "note\nname")
	if err := os.WriteFile(path, []byte("account note"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := PurgeUserStateWithResult(dataDir)
	if err != nil || len(result.Kept) != 1 || result.Kept[0] != `note\u000aname` {
		t.Fatalf("purge result = %+v, %v", result, err)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != "account note" {
		t.Fatalf("account file changed: %q, %v", got, err)
	}
}
