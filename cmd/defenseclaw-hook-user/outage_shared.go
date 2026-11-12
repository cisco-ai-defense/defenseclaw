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
	outageModeLockStale = 5 * time.Second
	outageModeWaitStep  = 5 * time.Millisecond
	outageModeWaitMax   = 3 * time.Second
)

// sharedOutageMode is outageMode for a call that became late at lateAt.
func sharedOutageMode(gateway, hookDir string, lateAt time.Time, look func() string) string {
	result := filepath.Join(hookDir, ".outage-mode.result")
	lock := filepath.Join(hookDir, ".outage-mode.lock")
	deadline := time.Now().Add(outageModeWaitMax)
	for {
		if started, mode, ok := readOutageModeResult(result); ok && !started.Before(lateAt.Add(-outageModeFreshness)) {
			return mode
		}
		if takeOutageModeLock(lock) {
			started := time.Now()
			mode := look()
			writeOutageModeResult(result, started, mode)
			_ = os.Remove(lock)
			return mode
		}
		if time.Now().After(deadline) {
			return "closed"
		}
		time.Sleep(outageModeWaitStep)
	}
}

func takeOutageModeLock(lock string) bool {
	file, err := os.OpenFile(lock, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err == nil {
		_ = file.Close()
		return true
	}
	// A lock left by a look that died is taken over once it is stale.
	if info, statErr := os.Lstat(lock); statErr == nil && info.Mode().IsRegular() &&
		time.Since(info.ModTime()) > outageModeLockStale && ownedByMe(info) {
		_ = os.Remove(lock)
	}
	return false
}

// readOutageModeResult reads "v1 <unix nanos> <open|closed>" from a regular
// file of this account; anything else is no result.
func readOutageModeResult(path string) (time.Time, string, bool) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 64 || info.Mode().Perm()&0o022 != 0 || !ownedByMe(info) {
		return time.Time{}, "", false
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}, "", false
	}
	fields := strings.Fields(string(data))
	if len(fields) != 3 || fields[0] != "v1" || (fields[2] != "open" && fields[2] != "closed") {
		return time.Time{}, "", false
	}
	nanos, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil || nanos <= 0 {
		return time.Time{}, "", false
	}
	return time.Unix(0, nanos), fields[2], true
}

func writeOutageModeResult(path string, started time.Time, mode string) {
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	file, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL|syscall.O_NOFOLLOW, 0o600)
	if err != nil {
		return
	}
	_, werr := fmt.Fprintf(file, "v1 %d %s\n", started.UnixNano(), mode)
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
