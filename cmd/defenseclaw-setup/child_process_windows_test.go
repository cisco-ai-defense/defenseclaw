// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"
)

func TestCapturedSetupCommandDoesNotCreateAConsoleWindow(t *testing.T) {
	cmd := newCapturedSetupCommand(context.Background(), "cmd.exe", "/c", "exit", "0")
	if cmd.SysProcAttr == nil {
		t.Fatal("captured setup command has no Windows process attributes")
	}
	if !cmd.SysProcAttr.HideWindow {
		t.Fatal("captured setup command does not hide its child window")
	}
	if cmd.SysProcAttr.CreationFlags&windows.CREATE_NO_WINDOW == 0 {
		t.Fatalf("captured setup command creation flags = %#x, missing CREATE_NO_WINDOW", cmd.SysProcAttr.CreationFlags)
	}
}

func TestDirectoryCleanupCommandDeletesLiteralTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw Installer's Cache")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "marker.txt"), []byte("owned"), 0o600); err != nil {
		t.Fatal(err)
	}
	powerShell, err := systemPowerShellPath()
	if err != nil {
		t.Fatal(err)
	}
	// A non-existent PID makes Wait-Process return immediately. The literal
	// apostrophe and spaces in root ensure no command-string quoting is relied on.
	cmd := directoryCleanupCommand(powerShell, root, 2147483647)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cleanup helper failed: %v: %s", err, output)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("cleanup target still exists (stat error %v)", err)
	}
}
