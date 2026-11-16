// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func writeManagedTargetFixture(t *testing.T) (dataDir, target string) {
	t.Helper()
	root := t.TempDir()
	target = filepath.Join(root, "agent", "config.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("{\"operator\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return filepath.Join(root, "data"), target
}

func holdExclusivelyFor(t *testing.T, target string, d time.Duration) {
	t.Helper()
	release := holdConnectorStateFile(t, target, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	timer := time.AfterFunc(d, release)
	t.Cleanup(func() { timer.Stop() })
}

// A holder that denies sharing on a managed target for a moment delays the
// read of it; it does not fail the Setup or Teardown that inspects the file.
func TestReadManagedTargetWaitsForTransientExclusiveHolder(t *testing.T) {
	_, target := writeManagedTargetFixture(t)
	holdExclusivelyFor(t, target, 300*time.Millisecond)

	data, info, err := readManagedTarget(target)
	if err != nil || info == nil || string(data) != "{\"operator\":true}\n" {
		t.Fatalf("readManagedTarget() = %q, %v, %v; want the file bytes", data, info, err)
	}
}

// A publisher that still holds its renamed handle (write and delete access,
// read sharing only) does not make the read fail either.
func TestReadManagedTargetSharesWithPublisherHandle(t *testing.T) {
	_, target := writeManagedTargetFixture(t)
	holdConnectorStateFile(t, target,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.DELETE, windows.FILE_SHARE_READ)

	if data, info, err := readManagedTarget(target); err != nil || info == nil || len(data) == 0 {
		t.Fatalf("readManagedTarget() = %q, %v, %v; want the file bytes", data, info, err)
	}
}

// A holder that outlasts the retry window is reported, never read as absent.
func TestReadManagedTargetReportsPersistentLock(t *testing.T) {
	_, target := writeManagedTargetFixture(t)
	holdConnectorStateFile(t, target, windows.GENERIC_READ|windows.GENERIC_WRITE, 0)
	previousSleep := connectorStateReadSleep
	connectorStateReadSleep = func(time.Duration) {}
	t.Cleanup(func() { connectorStateReadSleep = previousSleep })

	data, info, err := readManagedTarget(target)
	if err == nil || data != nil || info != nil {
		t.Fatalf("readManagedTarget() = %q, %v, %v; want the lock reported", data, info, err)
	}
}

// The shared open keeps the non-regular refusal: a directory in place of the
// vendor file is reported at once, not read as empty or as absent.
func TestReadManagedTargetRefusesDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "agent")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	data, info, err := readManagedTarget(dir)
	if err == nil || !strings.Contains(err.Error(), "not a regular file") || data != nil || info != nil {
		t.Fatalf("readManagedTarget(dir) = %q, %v, %v; want a not-a-regular-file error", data, info, err)
	}
}

// A missing target is still (nil, nil, nil).
func TestReadManagedTargetMissingIsAbsent(t *testing.T) {
	data, info, err := readManagedTarget(filepath.Join(t.TempDir(), "absent.json"))
	if err != nil || data != nil || info != nil {
		t.Fatalf("readManagedTarget(missing) = %q, %v, %v; want nil, nil, nil", data, info, err)
	}
}

// Every managed-backup read of the target waits for a transient holder: the
// first capture, the drift check and the capture of a later Setup, the
// read-back after the patch and the restore inspection of Teardown.
func TestManagedBackupReadsWaitForTransientExclusiveHolder(t *testing.T) {
	t.Run("first capture", func(t *testing.T) {
		dataDir, target := writeManagedTargetFixture(t)
		holdExclusivelyFor(t, target, 300*time.Millisecond)
		if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
			t.Fatalf("captureManagedFileBackup() = %v, want it to wait for the holder", err)
		}
	})

	t.Run("later setup, read-back and teardown", func(t *testing.T) {
		dataDir, target := writeManagedTargetFixture(t)
		if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
			t.Fatal(err)
		}
		if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
			t.Fatal(err)
		}

		holdExclusivelyFor(t, target, 300*time.Millisecond)
		drifted, err := managedFileBackupDrifted(dataDir, "cursor", "config", target)
		if err != nil || drifted {
			t.Fatalf("managedFileBackupDrifted() = %v, %v; want false, nil", drifted, err)
		}

		holdExclusivelyFor(t, target, 300*time.Millisecond)
		if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
			t.Fatalf("later captureManagedFileBackup() = %v, want it to wait for the holder", err)
		}

		holdExclusivelyFor(t, target, 300*time.Millisecond)
		if err := updateManagedFileBackupPostHash(dataDir, "cursor", "config", target); err != nil {
			t.Fatalf("updateManagedFileBackupPostHash() = %v, want it to wait for the holder", err)
		}

		holdExclusivelyFor(t, target, 300*time.Millisecond)
		restored, err := restoreManagedFileBackupIfUnchanged(dataDir, "cursor", "config", target)
		if err != nil || !restored {
			t.Fatalf("restoreManagedFileBackupIfUnchanged() = %v, %v; want true, nil", restored, err)
		}
	})
}
