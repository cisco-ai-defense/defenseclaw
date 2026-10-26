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

	"github.com/defenseclaw/defenseclaw/internal/procidentity"
)

// InstallLockIdentityName is the owner record install.sh and install.ps1
// write beside the lock's pid: the installer's own process identity as the
// system names it (procidentity.Of: the boot id and kernel start on Linux,
// the creation second on macOS, the creation FILETIME on Windows). Compared
// as it is, it tells the installer from a later process that got its pid,
// and no clock step changes the answer.
const InstallLockIdentityName = "proc-start"

// installLockStale is the one stale-lock rule of every per-user hook (this
// package, hook-outage-mode, the shell hooks, the OpenCode and Amp plugins)
// and of `defenseclaw doctor`. It reads only the owner's identity, never a
// clock: a lock folder in home is no lock only when its owner is proven
// gone: its pid names no
// process, or this reader's own process (no reader writes a lock), or a
// process whose identity is not the one its InstallLockIdentityName record
// holds (a reused pid). Everything else holds, for as long as it lasts: a
// live owner however long it runs, a lock without a valid pid (an installer
// that has not written it yet), a lock without an identity record whose pid
// names a live process (1.0.2, 1.0.3), a record or identity that cannot be
// read, a lock that is not a folder. A deadline file an earlier 1.0.4
// build wrote is not read. An interrupted-install record beside the lock
// (previous.new, .repair, .rollback-hold, .lifecycle-txn.json) does not hold
// it once its installer is gone: a failed upgrade waiting for the next
// installer run no longer closes every hook until then; doctor names the
// recovery step (GAP-1024).
func installLockStale(lstat func(string) (fs.FileInfo, error), home string, info fs.FileInfo) bool {
	if info == nil || !info.IsDir() {
		return false
	}
	lock := filepath.Join(home, ".install.lock")
	pid, state := installLockPID(lstat, filepath.Join(lock, "pid"))
	if state != lockNumberValid || pid > 2147483647 {
		return false
	}
	if int(pid) == os.Getpid() {
		// A live installer's pid names no other process, and no reader
		// writes a lock: this pid was reused.
		return true
	}
	return installLockOwnerGone(lstat, lock, int(pid))
}

// installLockOwnerGone reports an installer proven gone: pid names no
// process, or another process than the lock's identity record names. A
// lock without that record, or one whose record or process identity cannot
// be read, holds.
func installLockOwnerGone(lstat func(string) (fs.FileInfo, error), lock string, pid int) bool {
	if installLockOwnerExited(pid) {
		return true
	}
	recorded, state := installLockIdentity(lstat, filepath.Join(lock, InstallLockIdentityName))
	if state != lockNumberValid {
		return false
	}
	current, known := procidentity.Of(pid)
	return known && current != recorded
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

// installLockPID reads the lock's pid file: its decimal number and whether
// it is absent (missing, empty or not a positive number), valid, or
// unreadable (not a regular small file, or a read error but its absence).
func installLockPID(lstat func(string) (fs.FileInfo, error), path string) (int64, lockNumberState) {
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
