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

// The install-lock owner record: install.sh and install.ps1 write the
// installer's pid into the lock folder right after they make it, as 1.0.2
// and 1.0.3 did, so every release's lock follows the same rule.
const (
	// InstallLockNoPIDWait is how long a lock without a readable pid is
	// still an installer's that has not written it yet.
	InstallLockNoPIDWait = 10 * time.Minute
	// InstallLockStartSlack is how much later than the lock's pid file a
	// process with that pid may have started and still be the installer
	// that wrote it (clock resolution, a small clock step). A process that
	// started later has a reused pid: the installer is gone.
	InstallLockStartSlack = time.Minute
	// InstallLockIdentityName is the owner record install.sh writes beside
	// pid on Linux: the installer's boot id and kernel start, "<boot_id>
	// <starttime>" (processIdentityOf). Linux counts a process start from
	// boot, so only that record, compared as it is, tells a reused pid from
	// a live owner across a wall-clock step.
	InstallLockIdentityName = "proc-start"
)

// InstallLockRecoveryRecords are the interrupted-install records install.sh
// and install.ps1 keep the lock for, on purpose, after the installer exits:
// the next run takes the lock over and finishes or undoes that install.
var InstallLockRecoveryRecords = []string{"previous.new", ".repair", ".rollback-hold", ".lifecycle-txn.json"}

// installLockStale is the one stale-lock rule of every per-user hook (this
// package, hook-outage-mode, the shell hooks, the OpenCode and Amp plugins)
// and of `defenseclaw doctor`: a lock folder in home is no lock only when no
// interrupted-install record sits beside it and its owner is proven gone:
// its pid names no process, or this reader's own process (no reader writes
// a lock), or another process than the one its InstallLockIdentityName
// record names, or, without that record off Linux, a process that started
// after the pid was written (a reused pid, InstallLockStartSlack), or it has
// had no valid pid for InstallLockNoPIDWait. On Linux a lock without that
// record (1.0.2, 1.0.3) holds while its pid names a process: a start Linux
// counts from boot is a time only through the wall clock now. A live owner holds it for as long as it
// runs, with no deadline; so does an uncertain one: a pid whose process
// start cannot be read, a pid that cannot be read, a lock that is not a
// folder. A deadline file an earlier 1.0.4 build wrote is not read.
func installLockStale(lstat func(string) (fs.FileInfo, error), home string, info fs.FileInfo, now time.Time) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	for _, name := range InstallLockRecoveryRecords {
		if _, err := lstat(filepath.Join(home, name)); err == nil || !errors.Is(err, fs.ErrNotExist) {
			return false
		}
	}
	made := info.ModTime()
	pid, written, state := installLockPID(lstat, filepath.Join(home, ".install.lock", "pid"))
	switch state {
	case lockNumberUnreadable:
		return false
	case lockNumberValid:
		if pid > 2147483647 {
			return now.Sub(made) > InstallLockNoPIDWait
		}
		if int(pid) == os.Getpid() {
			// A live installer's pid names no other process, and no
			// reader writes a lock: this pid was reused.
			return true
		}
		return installLockOwnerGone(lstat, filepath.Join(home, ".install.lock"), int(pid), written, now)
	default:
		return now.Sub(made) > InstallLockNoPIDWait
	}
}

// installLockOwnerGone reports an installer proven gone: pid names no
// process, or another process than the lock's identity record names, or,
// without that record where a process start is a fixed time (not Linux), a
// process the system says started more than InstallLockStartSlack after
// written, when the lock's pid was written. A record that cannot be read or
// compared holds.
func installLockOwnerGone(lstat func(string) (fs.FileInfo, error), lock string, pid int, written, now time.Time) bool {
	if installLockOwnerExited(pid) {
		return true
	}
	switch recorded, state := installLockIdentity(lstat, filepath.Join(lock, InstallLockIdentityName)); state {
	case lockNumberValid:
		current, known := processIdentityOf(pid)
		return known && current != recorded
	case lockNumberUnreadable:
		return false
	}
	if !processStartIsAbsolute {
		return false
	}
	started, known := processStartTimeOf(pid, now)
	return known && started.After(written.Add(InstallLockStartSlack))
}

// installLockIdentity reads the lock's identity record: its trimmed text and
// whether it is absent, valid, or unreadable (not a small regular file,
// empty, or a read error but its absence).
func installLockIdentity(lstat func(string) (fs.FileInfo, error), path string) (string, lockNumberState) {
	info, err := lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return "", lockNumberAbsent
		}
		return "", lockNumberUnreadable
	}
	if !info.Mode().IsRegular() || info.Size() > 128 {
		return "", lockNumberUnreadable
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return "", lockNumberUnreadable
	}
	text := strings.TrimSpace(string(raw))
	if text == "" {
		return "", lockNumberUnreadable
	}
	return text, lockNumberValid
}

type lockNumberState int

const (
	lockNumberAbsent lockNumberState = iota
	lockNumberValid
	lockNumberUnreadable
)

// installLockPID reads the lock's pid file: its decimal number and when it
// was written, and whether it is absent (missing, empty or not a positive
// number), valid, or unreadable (not a regular small file, or a read error
// but its absence).
func installLockPID(lstat func(string) (fs.FileInfo, error), path string) (int64, time.Time, lockNumberState) {
	info, err := lstat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, time.Time{}, lockNumberAbsent
		}
		return 0, time.Time{}, lockNumberUnreadable
	}
	if !info.Mode().IsRegular() || info.Size() > 64 {
		return 0, time.Time{}, lockNumberUnreadable
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return 0, time.Time{}, lockNumberAbsent
		}
		return 0, time.Time{}, lockNumberUnreadable
	}
	text := strings.TrimSpace(string(raw))
	if text == "" || len(text) > 12 || text[0] < '1' || text[0] > '9' {
		return 0, time.Time{}, lockNumberAbsent
	}
	value, err := strconv.ParseInt(text, 10, 64)
	if err != nil {
		return 0, time.Time{}, lockNumberAbsent
	}
	return value, info.ModTime(), lockNumberValid
}
