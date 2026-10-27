// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// writeUnusedSharedHookRuntime lays out the shared hook runtime of an account
// whose last connector was removed: a lock naming no connector and the
// shared scripts, with no connector's runtime record.
func writeUnusedSharedHookRuntime(t *testing.T) (dataDir string, scripts []string) {
	t.Helper()
	dataDir = t.TempDir()
	hookDir := filepath.Join(dataDir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dataDir, hookContractLockFile), []byte(`{"version":1,"connectors":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, name := range append(append([]string{}, genericHookScripts...), hookHelperScripts...) {
		path := filepath.Join(hookDir, name)
		if err := os.WriteFile(path, []byte("#!/bin/sh\n"), 0o700); err != nil {
			t.Fatal(err)
		}
		scripts = append(scripts, path)
	}
	return dataDir, scripts
}

func TestRemoveUnusedSharedHookRuntimeRemovesAnUnusedRuntime(t *testing.T) {
	dataDir, scripts := writeUnusedSharedHookRuntime(t)
	hookDir := filepath.Join(dataDir, "hooks")
	record := filepath.Join(hookDir, ".gateway-helper")
	markers := filepath.Join(hookDir, ".outage-warnings")
	if err := os.WriteFile(record, []byte("helper\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(markers, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(markers, "old-session"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUnusedSharedHookRuntime(dataDir); err != nil {
		t.Fatalf("RemoveUnusedSharedHookRuntime: %v", err)
	}
	for _, path := range append(scripts, record, markers, filepath.Join(dataDir, hookContractLockFile)) {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("%s survived an unused runtime's removal: %v", path, err)
		}
	}
}

// A hooks/.hookcfg that cannot be read is not an unused one: the removal
// fails and keeps the shared scripts and the lock (W16 review). It went on
// and deleted them.
func TestRemoveUnusedSharedHookRuntimeKeepsTheRuntimeWhenTheSidecarIsUnreadable(t *testing.T) {
	dataDir, scripts := writeUnusedSharedHookRuntime(t)
	// A directory at the sidecar path fails every read, also as root.
	if err := os.Mkdir(filepath.Join(dataDir, "hooks", hookConfigSidecarName), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := RemoveUnusedSharedHookRuntime(dataDir); err == nil {
		t.Fatal("RemoveUnusedSharedHookRuntime succeeded over an unreadable hook config sidecar")
	}
	for _, path := range append(scripts, filepath.Join(dataDir, hookContractLockFile)) {
		if _, err := os.Stat(path); err != nil {
			t.Fatalf("%s was removed over an unreadable hook config sidecar: %v", path, err)
		}
	}
}
