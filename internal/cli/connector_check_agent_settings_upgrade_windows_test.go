// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

// Administrator-created files may inherit the Administrators group as owner.
// The predecessor fixture represents the current user's settings file.
func ownUpgradeFixtureForTest(t *testing.T, path string) {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("inspect predecessor settings owner: %v", err)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		t.Fatalf("read predecessor settings owner: %v", err)
	}
	if owner != nil && owner.Equals(user.User.Sid) {
		return
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, user.User.Sid, nil, nil, nil); err != nil {
		t.Fatalf("own predecessor settings fixture: %v", err)
	}
}

// A native Windows Codex Setup requires a fresh trusted executable receipt.
// The predecessor's version-1 backup record supplies the earlier root for
// this precheck, without running a new Setup before the migration check.
func registerPriorCodexRootForTest(t *testing.T, dataDir, oldRoot string) {
	t.Helper()
	backupDir := filepath.Join(dataDir, "connector_backups", "codex")
	if err := os.MkdirAll(backupDir, 0o700); err != nil {
		t.Fatal(err)
	}
	backup, err := json.Marshal(map[string]any{
		"version":         1,
		"connector":       "codex",
		"logical_name":    "config.toml",
		"path":            filepath.Join(oldRoot, "config.toml"),
		"existed":         false,
		"pristine_sha256": "missing",
		"captured_at":     "2026-10-23T00:00:00Z",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(backupDir, "config.toml.json"), backup, 0o600); err != nil {
		t.Fatal(err)
	}
}
