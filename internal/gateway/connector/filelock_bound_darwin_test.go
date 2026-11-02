//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func captureLockMarkers(t *testing.T) func() []string {
	t.Helper()
	var mu sync.Mutex
	var markers []string
	previous := managed.ReportResilienceEvent
	managed.ReportResilienceEvent = func(marker string, fields map[string]string) {
		mu.Lock()
		defer mu.Unlock()
		markers = append(markers, marker+" "+fields["reason"]+" "+fields["path"])
	}
	t.Cleanup(func() { managed.ReportResilienceEvent = previous })
	return func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), markers...)
	}
}

func holdFlock(t *testing.T, path string) func() {
	t.Helper()
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		t.Fatal(err)
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		file.Close()
	}
}

func TestBoundedLocksTimeOutAsLockBusy(t *testing.T) {
	previousWait := userLockWait
	userLockWait = 200 * time.Millisecond
	t.Cleanup(func() { userLockWait = previousWait })
	markers := captureLockMarkers(t)
	lockBusyStreaks.Lock()
	lockBusyStreaks.last = map[string]time.Time{}
	lockBusyStreaks.Unlock()

	dir := t.TempDir()
	lifecycle := filepath.Join(dir, ".codex-lifecycle.lock")
	release := holdFlock(t, lifecycle)
	defer release()
	config := filepath.Join(dir, "settings.json")
	releaseConfig := holdFlock(t, config+".lock")
	defer releaseConfig()

	for name, lock := range map[string]func(func() error) error{
		"owned":  func(fn func() error) error { return withOwnedFileLock(lifecycle, fn) },
		"config": func(fn func() error) error { return withFileLock(config, fn) },
	} {
		ran := false
		start := time.Now()
		err := lock(func() error { ran = true; return nil })
		if !errors.Is(err, ErrLockBusy) {
			t.Fatalf("%s: err = %v, want lock_busy", name, err)
		}
		if ran {
			t.Fatalf("%s: callback ran without the lock", name)
		}
		if elapsed := time.Since(start); elapsed > 5*time.Second {
			t.Fatalf("%s: wait was not bounded: %s", name, elapsed)
		}
	}
	// The held config lock file is never unlinked by a waiter.
	if _, err := os.Stat(config + ".lock"); err != nil {
		t.Fatalf("held lock file was removed: %v", err)
	}
	got := markers()
	if len(got) != 2 {
		t.Fatalf("want one lock_busy skip per lock, got %v", got)
	}
	// Same streak: no new line.
	_ = withOwnedFileLock(lifecycle, func() error { return nil })
	if len(markers()) != 2 {
		t.Fatalf("lock_busy logged twice in one streak: %v", markers())
	}

	release()
	ran := false
	if err := withOwnedFileLock(lifecycle, func() error { ran = true; return nil }); err != nil || !ran {
		t.Fatalf("released lock: err=%v ran=%v", err, ran)
	}
}

func TestOwnedLockRepairsLooserMode(t *testing.T) {
	markers := captureLockMarkers(t)
	lock := filepath.Join(t.TempDir(), ".codex-lifecycle.lock")
	if err := os.WriteFile(lock, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(lock, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := withOwnedFileLock(lock, func() error { return nil }); err != nil {
		t.Fatalf("lock with drifted mode: %v", err)
	}
	info, err := os.Stat(lock)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("mode = %o, want 600", info.Mode().Perm())
	}
	if len(markers()) != 1 {
		t.Fatalf("want one repair marker, got %v", markers())
	}
}
