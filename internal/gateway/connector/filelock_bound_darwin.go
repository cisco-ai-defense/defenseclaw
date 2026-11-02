//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"fmt"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// boundedUserLocks: the root guardian takes these locks inside folders the
// target user owns, so a user holding one must never stall the guardian for
// every other user. A lock is waited for up to userLockWait, then the
// caller fails for this user only and retries on the next tick.
const boundedUserLocks = true

// ErrLockBusy reports a per-user lock still held after the bounded wait.
var ErrLockBusy = errors.New("lock_busy")

// userLockWait is replaced in tests.
var userLockWait = 10 * time.Second

var lockBusyStreaks = struct {
	sync.Mutex
	last map[string]time.Time
}{last: map[string]time.Time{}}

// lockBusyStreakGap: a lock reported busy again within this gap belongs to
// the same streak and is not logged again.
const lockBusyStreakGap = 10 * time.Minute

// acquireFlock takes an exclusive flock on file with LOCK_NB and a bounded
// retry. It confirms afterwards that lockPath still names the locked inode,
// so a lock file unlinked and recreated by another writer is never trusted.
func acquireFlock(file *os.File, lockPath string) error {
	deadline := time.Now().Add(userLockWait)
	delay := 25 * time.Millisecond
	for {
		err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if err == nil {
			if lockStillNamesFile(file, lockPath) {
				return nil
			}
			_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
			return errLockReplaced
		}
		if !errors.Is(err, syscall.EWOULDBLOCK) && !errors.Is(err, syscall.EINTR) {
			return err
		}
		if time.Now().After(deadline) {
			reportLockBusy(lockPath)
			return fmt.Errorf("%w: %s held by another process for %s", ErrLockBusy, lockPath, userLockWait)
		}
		time.Sleep(delay)
		if delay < 500*time.Millisecond {
			delay *= 2
		}
	}
}

// errLockReplaced asks the caller to reopen the lock file and try again.
var errLockReplaced = errors.New("lock file was replaced while waiting")

func lockStillNamesFile(file *os.File, lockPath string) bool {
	opened, err := file.Stat()
	if err != nil {
		return false
	}
	current, err := os.Lstat(lockPath)
	if err != nil || current.Mode()&os.ModeSymlink != 0 {
		return false
	}
	return os.SameFile(opened, current)
}

func reportLockBusy(lockPath string) {
	lockBusyStreaks.Lock()
	last := lockBusyStreaks.last[lockPath]
	now := time.Now()
	lockBusyStreaks.last[lockPath] = now
	lockBusyStreaks.Unlock()
	if !last.IsZero() && now.Sub(last) < lockBusyStreakGap+userLockWait {
		return
	}
	managed.EmitResilienceEvent(managed.MarkerSkip, map[string]string{
		"unit":   "lock",
		"path":   lockPath,
		"reason": "lock_busy",
		"detail": fmt.Sprintf("held by another process for %s; retried every reconcile", userLockWait),
	})
}

// ownedLockPermCheck accepts a lock file at 0600 or tighter and repairs a
// looser mode: a lock carries no data, so only group or other access is
// drift.
func ownedLockPermCheck(path string, file *os.File, info os.FileInfo) error {
	perm := info.Mode().Perm()
	if perm&^0o600 == 0 {
		return nil
	}
	if err := file.Chmod(0o600); err != nil {
		return fmt.Errorf("DefenseClaw lock %s has mode %o and could not be repaired: %w", path, perm, err)
	}
	managed.EmitResilienceEvent(managed.MarkerRepair, map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("lock mode %04o is looser than 0600", perm),
	})
	return nil
}
