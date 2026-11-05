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
	pinSecureClientTokenTest(t)
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

func TestAcquireFlockRetriesShareOneDeadline(t *testing.T) {
	pinSecureClientTokenTest(t)
	path := filepath.Join(t.TempDir(), "cfg.lock")
	release := holdFlock(t, path)
	defer release()
	file, err := os.OpenFile(path, os.O_RDWR, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// A retry after a replaced lock file carries the first attempt's
	// deadline: once it has passed, the retry gives up at once instead of
	// starting a fresh userLockWait.
	deadline := time.Now().Add(-time.Second)
	start := time.Now()
	if err := acquireFlock(file, path, &deadline); !errors.Is(err, ErrLockBusy) {
		t.Fatalf("err = %v, want lock_busy", err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("a retry past the shared deadline waited %s", elapsed)
	}
}

func TestR108MAINREVP3PerUserLockWaitsForHeldLock(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	previousWait := userLockWait
	userLockWait = 40 * time.Millisecond
	t.Cleanup(func() { userLockWait = previousWait })

	path := filepath.Join(t.TempDir(), "settings.json")
	release := holdFlock(t, path+".lock")
	released := make(chan struct{})
	go func() {
		time.Sleep(120 * time.Millisecond)
		release()
		close(released)
	}()
	ran := false
	start := time.Now()
	err := withFileLock(path, func() error { ran = true; return nil })
	<-released
	if err != nil || !ran || time.Since(start) < userLockWait {
		t.Fatalf("per-user lock: err=%v callback=%v elapsed=%s", err, ran, time.Since(start))
	}
}

func TestR108MAINREVP3OrdinaryAgedHeldLockWaits(t *testing.T) {
	for _, profile := range []struct {
		name       string
		deployment string
		enterprise string
	}{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
	} {
		t.Run(profile.name, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, profile.deployment)
			t.Setenv(managed.EnterpriseProfileEnv, profile.enterprise)
			previousWait := userLockWait
			userLockWait = 40 * time.Millisecond
			t.Cleanup(func() { userLockWait = previousWait })

			path := filepath.Join(t.TempDir(), "settings.json")
			lockPath := path + ".lock"
			release := holdFlock(t, lockPath)
			defer release()
			aged := time.Now().Add(-2 * time.Hour)
			if err := os.Chtimes(lockPath, aged, aged); err != nil {
				t.Fatal(err)
			}
			original, err := os.Stat(lockPath)
			if err != nil {
				t.Fatal(err)
			}

			contended := make(chan struct{}, 1)
			hook := func(string) { contended <- struct{}{} }
			fileLockContendedHookForTest.Store(&hook)
			t.Cleanup(func() { fileLockContendedHookForTest.Store(nil) })
			result := make(chan error, 1)
			ran := make(chan struct{}, 1)
			go func() {
				result <- withFileLock(path, func() error { ran <- struct{}{}; return nil })
			}()
			select {
			case <-contended:
			case err := <-result:
				t.Fatalf("writer returned before waiting: %v", err)
			case <-time.After(5 * time.Second):
				t.Fatal("writer did not reach the held lock")
			}
			current, err := os.Stat(lockPath)
			if err != nil || !os.SameFile(original, current) {
				t.Fatalf("held lock sentinel changed: %v", err)
			}
			select {
			case err := <-result:
				t.Fatalf("writer returned while lock held: %v", err)
			case <-time.After(3 * userLockWait):
			}
			release()
			if err := <-result; err != nil {
				t.Fatalf("writer after release: %v", err)
			}
			select {
			case <-ran:
			default:
				t.Fatal("writer callback did not run")
			}
		})
	}
}

func TestR108MAINREVP3OrdinarySentinelBaseVerdicts(t *testing.T) {
	for _, profile := range []struct {
		name       string
		deployment string
		enterprise string
	}{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
	} {
		t.Run(profile.name, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, profile.deployment)
			t.Setenv(managed.EnterpriseProfileEnv, profile.enterprise)
			for _, mode := range []os.FileMode{0o400, 0o200, 0o600} {
				t.Run(mode.String(), func(t *testing.T) {
					path := filepath.Join(t.TempDir(), "settings.json")
					lockPath := path + ".lock"
					if err := os.WriteFile(lockPath, nil, 0o600); err != nil {
						t.Fatal(err)
					}
					if err := os.Chmod(lockPath, mode); err != nil {
						t.Fatal(err)
					}
					aged := time.Now().Add(-2 * time.Hour)
					if err := os.Chtimes(lockPath, aged, aged); err != nil {
						t.Fatal(err)
					}
					ran := false
					err := withFileLock(path, func() error { ran = true; return nil })
					if mode == 0o600 {
						if err != nil || !ran {
							t.Fatalf("owner-private sentinel: err=%v ran=%v", err, ran)
						}
						return
					}
					if !errors.Is(err, os.ErrPermission) || ran {
						t.Fatalf("owner-only sentinel mode %04o: err=%v ran=%v", mode, err, ran)
					}
				})
			}
		})
	}
}

func TestR108MAINREVP3SecureClientLockWaitTwin(t *testing.T) {
	pinSecureClientTokenTest(t)
	previousWait := userLockWait
	userLockWait = 40 * time.Millisecond
	t.Cleanup(func() { userLockWait = previousWait })

	path := filepath.Join(t.TempDir(), "settings.json")
	release := holdFlock(t, path+".lock")
	defer release()
	ran := false
	if err := withFileLock(path, func() error { ran = true; return nil }); !errors.Is(err, ErrLockBusy) || ran {
		t.Fatalf("Secure Client lock: err=%v callback=%v, want bounded wait", err, ran)
	}
}

func TestR108MAINREVP3OrdinaryReplacedPersistentLock(t *testing.T) {
	for _, profile := range []struct {
		name       string
		deployment string
		enterprise string
	}{
		{"per-user", "", ""},
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone},
	} {
		t.Run(profile.name, func(t *testing.T) {
			t.Setenv(managed.DeploymentModeEnv, profile.deployment)
			t.Setenv(managed.EnterpriseProfileEnv, profile.enterprise)
			lockPath := filepath.Join(t.TempDir(), ".token.lock")
			releaseOld := holdFlock(t, lockPath)
			oldReleased := false
			defer func() {
				if !oldReleased {
					releaseOld()
				}
			}()
			waiter, err := os.OpenFile(lockPath, os.O_RDWR, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer waiter.Close()
			result := make(chan error, 1)
			go func() {
				var deadline time.Time
				result <- acquireFlock(waiter, lockPath, &deadline)
			}()

			if err := os.Remove(lockPath); err != nil {
				t.Fatal(err)
			}
			releaseNew := holdFlock(t, lockPath)
			defer releaseNew()
			releaseOld()
			oldReleased = true
			select {
			case err := <-result:
				if !errors.Is(err, errLockReplaced) {
					t.Fatalf("replaced persistent lock: got %v, want errLockReplaced", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("waiter did not finish after old lock released")
			}
		})
	}
}

func TestR108MAINREVP3OrdinaryReleasedPersistentLockTwin(t *testing.T) {
	t.Setenv(managed.DeploymentModeEnv, "")
	t.Setenv(managed.EnterpriseProfileEnv, "")
	lockPath := filepath.Join(t.TempDir(), ".token.lock")
	release := holdFlock(t, lockPath)
	released := false
	defer func() {
		if !released {
			release()
		}
	}()
	waiter, err := os.OpenFile(lockPath, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer waiter.Close()
	result := make(chan error, 1)
	go func() {
		var deadline time.Time
		result <- acquireFlock(waiter, lockPath, &deadline)
	}()
	release()
	released = true
	select {
	case err := <-result:
		if err != nil {
			t.Fatalf("released persistent lock: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("waiter did not finish after lock released")
	}
	if !lockStillNamesFile(waiter, lockPath) {
		t.Fatal("released persistent lock no longer names the acquired inode")
	}
	_ = syscall.Flock(int(waiter.Fd()), syscall.LOCK_UN)
}
