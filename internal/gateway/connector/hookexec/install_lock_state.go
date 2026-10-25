// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The install-lock owner record. install.sh and install.ps1 write the
// installer's pid, its start time and a deadline (Unix seconds) into the
// lock folder right after they make it.
const (
	// InstallLockNoPIDWait is how long a lock without a readable pid is
	// still an installer's that has not written it yet.
	InstallLockNoPIDWait = 10 * time.Minute
	// InstallLockMaxAge is the latest deadline of any lock: no install runs
	// this long, so a pid that names a process again (a reused pid) or an
	// interrupted install's kept lock no longer holds past it.
	InstallLockMaxAge = 6 * time.Hour
)

// InstallLockRecoveryRecords are the interrupted-install records install.sh
// and install.ps1 keep the lock for, on purpose, after the installer exits:
// the next run takes the lock over and finishes or undoes that install.
var InstallLockRecoveryRecords = []string{"previous.new", ".repair", ".rollback-hold", ".lifecycle-txn.json"}

// installLockStale is the one stale-lock rule of every per-user hook (this
// package, hook-outage-mode, the shell hooks, the OpenCode and Amp plugins)
// and of `defenseclaw doctor`: a lock folder in home is no lock once its
// deadline has passed (the deadline it records, never later than
// InstallLockMaxAge after it was made), or, before that, when no
// interrupted-install record sits beside it and its owner is proven gone:
// its pid names no process, or it has had no valid pid for
// InstallLockNoPIDWait. A live or uncertain owner holds it: a running pid,
// a pid that cannot be checked, a record or pid that cannot be read, a lock
// that is not a folder.
func installLockStale(lstat func(string) (fs.FileInfo, error), home string, info fs.FileInfo, now time.Time) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	lock := filepath.Join(home, ".install.lock")
	made := info.ModTime()
	deadline := made.Add(InstallLockMaxAge)
	recorded, recordState := installLockNumber(lstat, filepath.Join(lock, "deadline"))
	if at := time.Unix(recorded, 0); recordState == lockNumberValid && at.Before(deadline) {
		deadline = at
	}
	if now.After(deadline) {
		return true
	}
	if recordState == lockNumberUnreadable {
		return false
	}
	for _, name := range InstallLockRecoveryRecords {
		if _, err := lstat(filepath.Join(home, name)); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	pid, state := installLockNumber(lstat, filepath.Join(lock, "pid"))
	switch state {
	case lockNumberUnreadable:
		return false
	case lockNumberValid:
		if pid > 2147483647 {
			return now.Sub(made) > InstallLockNoPIDWait
		}
		if int(pid) == os.Getpid() {
			return false
		}
		return installLockOwnerGone(int(pid))
	default:
		return now.Sub(made) > InstallLockNoPIDWait
	}
}

type lockNumberState int

const (
	lockNumberAbsent lockNumberState = iota
	lockNumberValid
	lockNumberUnreadable
)

// installLockNumber reads one decimal number of the owner record: absent
// (missing, empty or not a positive number), valid, or unreadable (not a
// regular small file, or a read error but its absence).
func installLockNumber(lstat func(string) (fs.FileInfo, error), path string) (int64, lockNumberState) {
	info, err := lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, lockNumberAbsent
		}
		return 0, lockNumberUnreadable
	}
	if !info.Mode().IsRegular() || info.Size() > 64 {
		return 0, lockNumberUnreadable
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, lockNumberAbsent
		}
		return 0, lockNumberUnreadable
	}
	text := strings.TrimSpace(string(raw))
	if text == "" || len(text) > 12 || text[0] < '1' || text[0] > '9' {
		return 0, lockNumberAbsent
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, lockNumberAbsent
	}
	return value, lockNumberValid
}
