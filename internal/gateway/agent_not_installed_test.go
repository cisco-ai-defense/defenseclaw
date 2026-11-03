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

func TestStaleAmpNPMLauncherRequiresInvokedMissingPackage(t *testing.T) {
	appData := t.TempDir()
	npmDir := filepath.Join(appData, "npm")
	alternate := filepath.Join(t.TempDir(), "Amp")
	if err := os.Mkdir(npmDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(alternate, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(alternate, "amp.exe"), []byte("alternate image"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AMP_HOME", alternate)
	launcher := filepath.Join(npmDir, "amp.cmd")
	for _, tc := range []struct {
		name, body string
		stale      bool
	}{
		{"removed package target", "@echo off\r\n%~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe %*\r\n", true},
		{"npm shim removed package target", "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\n\"%dp0%\\node_modules\\@ampcode\\cli\\bin\\amp.exe\"  %*\r\n", true},
		{"npm interpreter shim removed package target", "@ECHO off\r\nGOTO start\r\n:find_dp0\r\nSET dp0=%~dp0\r\nEXIT /b\r\n:start\r\nSETLOCAL\r\nCALL :find_dp0\r\nIF EXIST \"%dp0%\\node.exe\" (\r\n  SET \"_prog=%dp0%\\node.exe\"\r\n) ELSE (\r\n  SET \"_prog=node\"\r\n  SET PATHEXT=%PATHEXT:;.JS;=;%\r\n)\r\nendLocal & goto #_undefined_# 2>NUL || title %COMSPEC% & \"%_prog%\" \"%dp0%\\node_modules\\@ampcode\\cli\\bin\\amp.js\" %*\r\n", true},
		{"old path in comment with alternate target", "@echo off\r\nREM old target: %~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe\r\n\"%AMP_HOME%\\amp.exe\" %*\r\n", false},
		{"comment with command separator", "@echo off\r\nREM note & \"%AMP_HOME%\\amp.exe\" %*\r\n%~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe %*\r\n", false},
		{"old path in output with alternate target", "@echo off\r\necho %~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe\r\n\"%AMP_HOME%\\amp.exe\" %*\r\n", false},
		{"multiple active targets", "@echo off\r\n\"%AMP_HOME%\\amp.exe\" %*\r\n%~dp0\\node_modules\\@ampcode\\cli\\bin\\amp.exe %*\r\n", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.WriteFile(launcher, []byte(tc.body), 0o600); err != nil {
				t.Fatal(err)
			}
			if got := staleAmpNPMLauncherAt(launcher, appData); got != tc.stale {
				t.Fatalf("stale=%t, want %t", got, tc.stale)
			}
		})
	}
}
