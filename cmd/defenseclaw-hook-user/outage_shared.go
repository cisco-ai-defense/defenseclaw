// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// A per-user call the gateway did not answer in time asks the gateway binary
// for the account outage mode (hook-outage-mode), and each such call started
// its own 140 MB gateway process. Under a burst every late call did it at
// once: on a 4-vCPU host at 50 calls a second about sixty of those processes
// ran together, took the CPU the gateway needed, and made more calls late
// (rel-1-0-6 GAP-0558, #1384). The calls of one account now share one look:
// the first takes a lock and runs it, the others wait for its answer, and an
// answer is reused only by calls that became late at most
// outageModeFreshness before that look started. The watchdog waits for the
// mode for lateOrdinaryTierWait (250 ms) and keeps the closed answer when
// none comes, as before.
const (
	outageModeFreshness = 250 * time.Millisecond
	// outageModeClockSkew bounds how far in the future a result may say it
	// started: a later one is no result (a clock step, a forged file). It is
	// no wider than the freshness window.
	outageModeClockSkew = outageModeFreshness
	outageModeWaitStep  = 5 * time.Millisecond
	outageModeWaitMax   = 3 * time.Second
)

// sharedOutageMode is outageMode for a call that became late at lateAt.
func sharedOutageMode(gateway, hookDir string, lateAt time.Time, look func() string) string {
	result := filepath.Join(hookDir, ".outage-mode.result")
	lock := filepath.Join(hookDir, ".outage-mode.lock")
	// A look answers for the config it read: a result taken under another
	// config.yaml (a fail mode or profile change since) is no result.
	stamp := outageConfigStamp(filepath.Dir(hookDir))
	deadline := time.Now().Add(outageModeWaitMax)
	for {
		if started, mode, ok := readOutageModeResult(result, stamp); ok && !started.Before(lateAt.Add(-outageModeFreshness)) {
			return mode
		}
		if unlock := takeOutageModeLock(lock); unlock != nil {
			// Look again under the lock: a look that finished while this call
			// waited for it may be fresh enough.
			if started, mode, ok := readOutageModeResult(result, stamp); ok && !started.Before(lateAt.Add(-outageModeFreshness)) {
				unlock()
				return mode
			}
			started := time.Now()
			mode := look()
			if mode == "" {
				// The look was stopped (hook-user is exiting): no result.
				unlock()
				return "closed"
			}
			writeOutageModeResult(result, started, mode, stamp)
			unlock()
			return mode
		}
		if time.Now().After(deadline) {
			return "closed"
		}
		time.Sleep(outageModeWaitStep)
	}
}

// takeOutageModeLock takes the account look lock: an advisory flock(2) on
// the lock file, which the kernel releases when the holder exits, so a look
// whose hook gave up and exited never leaves the lock held. It returns the
// release, or nil when another call holds the lock.
func takeOutageModeLock(lock string) func() {
	file, err := os.OpenFile(lock, os.O_RDWR|os.O_CREATE|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return nil
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || !ownedByMe(info) {
		_ = file.Close()
		return nil
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil
	}
	return func() {
		_ = syscall.Flock(int(file.Fd()), syscall.LOCK_UN)
		_ = file.Close()
	}
}

// readOutageModeResult reads "v2 <unix nanos> <open|closed> <config stamp>"
// from a regular file of this account, taken under the config.yaml of stamp;
// anything else is no result.
func readOutageModeResult(path, stamp string) (time.Time, string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64 || info.Mode().Perm()&0o022 != 0 || !ownedByMe(info) {
		return time.Time{}, "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 4 || fields[0] != "v2" || (fields[2] != "open" && fields[2] != "closed") || fields[3] != stamp {
		return time.Time{}, "", false
	}
	nanos, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}, "", false
	}
	started := time.Unix(0, nanos)
	if started.After(time.Now().Add(outageModeClockSkew)) {
		return time.Time{}, "", false
	}
	return started, fields[2], true
}

func writeOutageModeResult(path string, started time.Time, mode, stamp string) {
	// The file is written under the look lock, so one temporary name is
	// enough and none is left behind by a later look.
	tmp := path + ".tmp"
	_ = os.Remove(tmp)
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return
	}
	_, werr := fmt.Fprintf(file, "v2 %d %s %s\n", started.UnixNano(), mode, stamp)
	if cerr := file.Close(); werr != nil || cerr != nil {
		_ = os.Remove(tmp)
		return
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
	}
}

func ownedByMe(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && stat.Uid == uint32(os.Geteuid())
}

// outageConfigStamp names the config.yaml of the data folder as it is now
// (size and modification time, or "none"): the input of an outage-mode look.
func outageConfigStamp(dataDir string) string {
	info, err := os.Stat(filepath.Join(dataDir, "config.yaml"))
	if err != nil {
		return "none"
	}
	return fmt.Sprintf("%d.%d", info.Size(), info.ModTime().UnixNano())
}
