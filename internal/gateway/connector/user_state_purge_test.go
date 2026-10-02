// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// uninstall --purge left every enrolled account's ~/.defenseclaw, then kept
// its hook scripts as stubs and its foreign-hooks-backup. The purge removes
// all of it: nothing of ~/.defenseclaw stays.
func TestPurgeUserStateRemovesEverything(t *testing.T) {
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
	if err := PurgeUserState(dataDir); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(dataDir); !os.IsNotExist(err) {
		var left []string
		_ = filepath.Walk(dataDir, func(path string, info os.FileInfo, err error) error {
			if err == nil && !info.IsDir() {
				rel, _ := filepath.Rel(dataDir, path)
				left = append(left, filepath.ToSlash(rel))
			}
			return nil
		})
		t.Fatalf("the purge left %s: %v (%s)", dataDir, err, strings.Join(left, ","))
	}
	// A rerun on the removed folder is a no-op.
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
