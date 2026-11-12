// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
)

// Purge removes managed files while retaining user data and saved originals
// that have not been restored.
func TestPurgeUserStateRemovesManagedFilesAndKeepsOtherEntries(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the purge runs for the Linux and macOS standalone profile")
	}
	dataDir := filepath.Join(t.TempDir(), ".defenseclaw")
	files := map[string]string{
		"hooks/devin-hook.sh":                             "#!/bin/bash\n" + hookMarker + "5\ncurl gateway\n",
		"hooks/.hook-devin.token":                         "secret",
		"hooks/.hookcfg.devin":                            "cfg",
		"hook_contract_lock.json":                         "{}",
		"connector_backups/devin/config.json":             "{}",
		"logs/hooks.log":                                  "log",
		"foreign-hooks-backup/cursor/20260929/hooks.json": "{\"own\":true}",
		".venv/bin/defenseclaw":                           "#!/bin/sh\n",
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
	result, err := PurgeUserStateWithResult(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Removed || !slices.Contains(result.Kept, ".venv/bin/defenseclaw") ||
		!slices.Contains(result.Kept, "foreign-hooks-backup/cursor/20260929/hooks.json") ||
		!slices.Contains(result.Kept, "connector_backups/devin/config.json") {
		t.Fatalf("purge result = %+v", result)
	}
	for _, name := range []string{"hooks/devin-hook.sh", "hooks/.hook-devin.token", "hooks/.hookcfg.devin", "hook_contract_lock.json", "logs/hooks.log"} {
		if _, err := os.Lstat(filepath.Join(dataDir, filepath.FromSlash(name))); !os.IsNotExist(err) {
			t.Errorf("managed entry %s stayed: %v", name, err)
		}
	}
	for _, name := range []string{".venv/bin/defenseclaw", "foreign-hooks-backup/cursor/20260929/hooks.json", "connector_backups/devin/config.json"} {
		if got, err := os.ReadFile(filepath.Join(dataDir, filepath.FromSlash(name))); err != nil || string(got) != files[name] {
			t.Errorf("account entry %s changed: %q, %v", name, got, err)
		}
	}
	// A rerun keeps the same account entries.
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatalf("rerun: %v", err)
	}
}

// The purge deleted ~/.defenseclaw, and with it the list of the agent
// folders DefenseClaw had created, so those folders stayed in the purged
// home, empty. They go first; a listed folder with content stays.
func TestPurgeUserStateRemovesTheEmptyFoldersDefenseClawCreated(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the purge runs for the Linux and macOS standalone profile")
	}
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	created := []string{
		filepath.Join(home, ".copilot"), filepath.Join(home, ".copilot", "hooks"),
		filepath.Join(home, ".claude", "commands"), filepath.Join(home, ".config", "opencode", "plugins"),
	}
	for _, dir := range append(created, dataDir) {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	userFile := filepath.Join(home, ".claude", "commands", "mine.md")
	if err := os.WriteFile(userFile, []byte("mine"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RecordWatcherCreatedDirs(dataDir, created); err != nil {
		t.Fatal(err)
	}
	if err := WithUserHomeDir(home, func() error { return PurgeUserState(dataDir) }); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{dataDir, filepath.Join(home, ".copilot"), filepath.Join(home, ".config", "opencode", "plugins")} {
		if _, err := os.Lstat(dir); !os.IsNotExist(err) {
			t.Fatalf("%s stayed after the purge: %v", dir, err)
		}
	}
	if _, err := os.Stat(userFile); err != nil {
		t.Fatalf("a listed folder with the user's file in it must stay: %v", err)
	}
	if _, err := os.Stat(filepath.Join(home, ".config", "opencode")); err != nil {
		t.Fatalf("an unlisted parent must stay: %v", err)
	}
}
