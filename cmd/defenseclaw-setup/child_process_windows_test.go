// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

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
	journalPath := filepath.Join(t.TempDir(), "setup-transaction.json")
	transactionID := "0123456789abcdef0123456789abcdef"
	writeDeferredCleanupJournal(t, journalPath, root, transactionID)
	powerShell, err := systemPowerShellPath()
	if err != nil {
		t.Fatal(err)
	}
	// A non-existent PID makes Wait-Process return immediately. The literal
	// apostrophe and spaces in root ensure no command-string quoting is relied on.
	cmd := directoryCleanupCommand(
		powerShell,
		root,
		journalPath,
		2147483647,
		transactionID,
		5*time.Second,
	)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cleanup helper failed: %v: %s", err, output)
	}
	if _, err := os.Stat(root); !os.IsNotExist(err) {
		t.Fatalf("cleanup target still exists (stat error %v)", err)
	}
}

func TestDirectoryCleanupCommandPreservesRecreatedTransactionTarget(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw Installer Cache")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "new-install.txt"), []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "setup-transaction.json")
	oldID := "0123456789abcdef0123456789abcdef"
	newID := "fedcba9876543210fedcba9876543210"
	writeDeferredCleanupJournal(t, journalPath, root, oldID)
	powerShell, err := systemPowerShellPath()
	if err != nil {
		t.Fatal(err)
	}
	parent := newCapturedSetupCommand(
		context.Background(),
		powerShell,
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"Start-Sleep -Milliseconds 500",
	)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	parentWaited := false
	t.Cleanup(func() {
		if !parentWaited && parent.Process != nil {
			_ = parent.Process.Kill()
			_ = parent.Wait()
		}
	})
	cleanup := directoryCleanupCommand(
		powerShell,
		root,
		journalPath,
		parent.Process.Pid,
		oldID,
		5*time.Second,
	)
	if err := cleanup.Start(); err != nil {
		t.Fatal(err)
	}
	writeDeferredCleanupJournal(t, journalPath, root, newID)
	if err := parent.Wait(); err != nil {
		t.Fatalf("wait for short-lived parent: %v", err)
	}
	parentWaited = true
	if err := cleanup.Wait(); err != nil {
		t.Fatalf("stale cleanup helper failed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "new-install.txt")); err != nil {
		t.Fatalf("stale cleanup removed recreated install target: %v", err)
	}
}

func TestDirectoryCleanupCommandSkipsDeleteWhenParentWaitTimesOut(t *testing.T) {
	root := filepath.Join(t.TempDir(), "DefenseClaw Installer Cache")
	if err := os.MkdirAll(root, 0o755); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(t.TempDir(), "setup-transaction.json")
	transactionID := "0123456789abcdef0123456789abcdef"
	writeDeferredCleanupJournal(t, journalPath, root, transactionID)
	powerShell, err := systemPowerShellPath()
	if err != nil {
		t.Fatal(err)
	}
	parent := newCapturedSetupCommand(
		context.Background(),
		powerShell,
		"-NoProfile",
		"-NonInteractive",
		"-Command",
		"Start-Sleep -Seconds 5",
	)
	if err := parent.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if parent.Process != nil {
			_ = parent.Process.Kill()
			_ = parent.Wait()
		}
	})
	cleanup := directoryCleanupCommand(
		powerShell,
		root,
		journalPath,
		parent.Process.Pid,
		transactionID,
		100*time.Millisecond,
	)
	started := time.Now()
	if output, err := cleanup.CombinedOutput(); err != nil {
		t.Fatalf("bounded cleanup helper failed: %v: %s", err, output)
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("cleanup helper exceeded bounded parent wait: %s", elapsed)
	}
	if _, err := os.Stat(root); err != nil {
		t.Fatalf("cleanup helper deleted target while parent was still running: %v", err)
	}
}

func writeDeferredCleanupJournal(t *testing.T, journalPath, maintenanceRoot, transactionID string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(journalPath), 0o700); err != nil {
		t.Fatal(err)
	}
	journal := setupJournal{
		SchemaVersion: setupJournalSchemaVersion,
		Phase:         setupPhaseConverged,
		Transaction: setupTransaction{
			SchemaVersion:   setupTransactionSchemaVersion,
			ID:              transactionID,
			Action:          "uninstall",
			MaintenancePath: filepath.Join(maintenanceRoot, setupArtifactName),
		},
	}
	if err := writeJSON(journalPath, journal); err != nil {
		t.Fatalf("write deferred cleanup journal: %v", err)
	}
}
