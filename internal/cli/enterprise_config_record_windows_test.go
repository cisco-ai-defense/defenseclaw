//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// GAP-0646: the guardian leaves config.yaml to a lifecycle run that holds
// lifecycle.lock or whose install transaction is pending, and while it
// records an edit it holds lifecycle.lock itself, so no run starts writing
// in between.
func TestClaimWindowsEnterpriseConfigFromLifecycle(t *testing.T) {
	dir := t.TempDir()
	etc := filepath.Join(dir, "etc")
	lock := filepath.Join(dir, "lifecycle", "lifecycle.lock")
	for _, folder := range []string{etc, filepath.Dir(lock), filepath.Join(dir, "install")} {
		if err := os.MkdirAll(folder, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	layoutOf := func() (managed.StandaloneLayout, error) {
		return managed.StandaloneLayout{ConfigPath: filepath.Join(etc, "config.yaml"), ConfigDir: etc}, nil
	}

	release, owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf)
	if owner != "" || release == nil {
		t.Fatalf("free lifecycle: owner %q", owner)
	}
	if other, err := tryWindowsEnterpriseLifecycleLock(lock); err == nil {
		other()
		t.Fatal("a lifecycle run took lifecycle.lock while the guardian recorded")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) {
		t.Fatalf("lifecycle.lock during the record: %v, want a sharing violation", err)
	}
	release()

	held, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	if _, owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf); !strings.Contains(owner, "holds lifecycle.lock") {
		t.Fatalf("held lifecycle.lock: owner %q", owner)
	}
	held()

	pending := filepath.Join(dir, "install", "pending.json")
	if err := os.WriteFile(pending, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, owner := claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf); !strings.Contains(owner, "transaction is pending") {
		t.Fatalf("pending transaction: owner %q", owner)
	}
	if again, err := tryWindowsEnterpriseLifecycleLock(lock); err != nil {
		t.Fatalf("the pending check kept lifecycle.lock: %v", err)
	} else {
		again()
	}
	if err := os.Remove(pending); err != nil {
		t.Fatal(err)
	}

	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	release, owner = claimWindowsEnterpriseConfigFromLifecycle(lock, layoutOf)
	if owner != "" || release == nil {
		t.Fatalf("no lock file: owner %q", owner)
	}
	release()
}

// GAP-0646: a Go lifecycle step waits for the guardian's short hold of
// lifecycle.lock, and still reads a run that keeps the lock as busy.
func TestAcquireWindowsEnterpriseLifecycleLockWaitsForAShortHold(t *testing.T) {
	lock := filepath.Join(t.TempDir(), "lifecycle.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	saved := windowsEnterpriseLifecycleLockWait
	t.Cleanup(func() { windowsEnterpriseLifecycleLockWait = saved })

	windowsEnterpriseLifecycleLockWait = 3 * time.Second
	held, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	time.AfterFunc(300*time.Millisecond, held)
	release, err := acquireWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatalf("after a short hold: %v", err)
	}
	release()

	kept, err := tryWindowsEnterpriseLifecycleLock(lock)
	if err != nil {
		t.Fatal(err)
	}
	defer kept()
	windowsEnterpriseLifecycleLockWait = 300 * time.Millisecond
	start := time.Now()
	if release, err := acquireWindowsEnterpriseLifecycleLock(lock); err == nil {
		release()
		t.Fatal("took lifecycle.lock from a run that keeps it")
	} else if !errors.Is(err, windows.ERROR_SHARING_VIOLATION) || time.Since(start) < 250*time.Millisecond {
		t.Fatalf("a kept lock: %v after %s, want a sharing violation after the wait", err, time.Since(start))
	}
}
