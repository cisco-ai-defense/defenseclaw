// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"testing"
)

// A read-only hook script or credential stayed after a Windows purge. Both
// go now, with the rest of the folder.
func TestPurgeUserStateInRootHandlesReadOnlyFiles(t *testing.T) {
	dataDir := t.TempDir()
	hooks := filepath.Join(dataDir, "hooks")
	if err := os.Mkdir(hooks, 0o700); err != nil {
		t.Fatal(err)
	}
	script, token := filepath.Join(hooks, "devin-hook.ps1"), filepath.Join(hooks, ".hook-devin.token")
	for path, body := range map[string]string{script: hookMarker + "5\r\n", token: "secret"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o400); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := PurgeUserStateInRoot(root, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(token); !os.IsNotExist(err) {
		t.Fatalf("read-only credential stayed: %v", err)
	}
	if _, err := os.Lstat(script); !os.IsNotExist(err) {
		t.Fatalf("read-only hook script stayed: %v", err)
	}
	if _, err := os.Lstat(hooks); !os.IsNotExist(err) {
		t.Fatalf("the hooks folder stayed: %v", err)
	}
}

func TestGAP0669WindowsPurgeKeepsDirectoryAtManagedFileName(t *testing.T) {
	dataDir := t.TempDir()
	keptDir := filepath.Join(dataDir, "hooks", "codex-hook.ps1")
	if err := os.MkdirAll(keptDir, 0o700); err != nil {
		t.Fatal(err)
	}
	accountFile := filepath.Join(keptDir, "personal.txt")
	if err := os.WriteFile(accountFile, []byte("account note"), 0o600); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dataDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := PurgeUserStateInRoot(root, nil); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(accountFile); err != nil || string(got) != "account note" {
		t.Fatalf("account file changed: %q, %v", got, err)
	}
}

// GAP-0669 review M1: the ACP-only purge opens the acp folder as root. It
// removes the managed copies there and keeps account files, including one
// named like a managed file at the data directory's top.
func TestGAP0669WindowsACPRootPurgeUsesThePathFromTheDataDir(t *testing.T) {
	acpDir := filepath.Join(t.TempDir(), ".defenseclaw", "acp")
	if err := os.MkdirAll(acpDir, 0o700); err != nil {
		t.Fatal(err)
	}
	foreign := filepath.Join(acpDir, "inventory.db")
	token := filepath.Join(acpDir, "zed-kiro.token")
	for path, body := range map[string]string{foreign: "account data", token: "managed token"} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(acpDir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	if err := PurgeUserStateInRootAt(root, "acp", nil); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(foreign); err != nil || string(got) != "account data" {
		t.Errorf("account file changed: %q, %v", got, err)
	}
	if _, err := os.Lstat(token); !os.IsNotExist(err) {
		t.Errorf("managed token stayed: %v", err)
	}
	if err := PurgeUserStateInRootAt(root, "hooks", nil); err == nil {
		t.Error("a folder that is not a managed folder was accepted")
	}
}
