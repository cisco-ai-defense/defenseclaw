// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestStaleAmpNPMLauncherDoesNotCountAsAgentBinary(t *testing.T) {
	appData := t.TempDir()
	npmDir := filepath.Join(appData, "npm")
	if err := os.Mkdir(npmDir, 0o700); err != nil {
		t.Fatal(err)
	}
	launcher := filepath.Join(npmDir, "amp.cmd")
	if err := os.WriteFile(launcher, []byte("@echo off\r\n%~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe %*\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !staleAmpNPMLauncherAt(launcher, appData) {
		t.Fatal("launcher for removed package was counted as an installed agent")
	}
	packageDir := filepath.Join(npmDir, "node_modules", "@ampcode", "cli")
	if err := os.MkdirAll(packageDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if staleAmpNPMLauncherAt(launcher, appData) {
		t.Fatal("launcher with an installed package was classified as stale")
	}
	if err := os.Remove(packageDir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(launcher, []byte("@echo off\r\necho another installer\r\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if staleAmpNPMLauncherAt(launcher, appData) {
		t.Fatal("unrecognized launcher was classified as stale")
	}
}
