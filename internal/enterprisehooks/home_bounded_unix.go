//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"
)

// Bounded home probes. A hard-mounted network home whose server is gone
// blocks stat in the kernel; a Go goroutine stuck there pins an OS thread
// and cannot be cancelled. Every root-side home probe of the enumerator and
// guardian therefore runs through a per-path in-flight record: the caller
// waits at most the timeout, and while an earlier probe of the same path
// is still blocked no new blocking call is started, so a hung home costs
// one thread in total rather than one per row, pass and cycle.

// UnixHomeCheckTimeout bounds one home probe.
const UnixHomeCheckTimeout = 5 * time.Second

type unixHomeProbe struct {
	started time.Time
	done    chan struct{}
	result  any
}

var (
	unixHomeProbesMu sync.Mutex
	unixHomeProbes   = map[string]*unixHomeProbe{}

	// unixHomeCheckProbe and unixHomeLstatProbe are the blocking calls;
	// tests replace them.
	unixHomeCheckProbe = CheckUnixTargetHome
	unixHomeLstatProbe = os.Lstat
	// unixHomeProbeTimeout is the enumerator's bound; tests shorten it.
	unixHomeProbeTimeout = UnixHomeCheckTimeout
)

// boundedUnixHomeProbe runs probe for key, waiting at most timeout. ok is
// false when the probe (this one or a still-blocked earlier one) did not
// answer in time.
func boundedUnixHomeProbe(key string, timeout time.Duration, probe func() any) (any, bool) {
	unixHomeProbesMu.Lock()
	current, running := unixHomeProbes[key]
	if running && time.Since(current.started) >= timeout {
		// Already known to be hung: answer at once.
		unixHomeProbesMu.Unlock()
		return nil, false
	}
	if !running {
		current = &unixHomeProbe{started: time.Now(), done: make(chan struct{})}
		unixHomeProbes[key] = current
		go func(record *unixHomeProbe) {
			result := probe()
			unixHomeProbesMu.Lock()
			record.result = result
			if unixHomeProbes[key] == record {
				delete(unixHomeProbes, key)
			}
			unixHomeProbesMu.Unlock()
			close(record.done)
		}(current)
	}
	wait := timeout - time.Since(current.started)
	unixHomeProbesMu.Unlock()
	if wait <= 0 {
		return nil, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-current.done:
		return current.result, true
	case <-timer.C:
		return nil, false
	}
}

// BoundedCheckUnixTargetHome is CheckUnixTargetHome with a deadline: a
// home that does not answer within timeout (or whose earlier check is still
// blocked) is pending.
func BoundedCheckUnixTargetHome(home string, uid int, timeout time.Duration) HomeCheck {
	clean := filepath.Clean(home)
	check := unixHomeCheckProbe
	result, ok := boundedUnixHomeProbe("check\x00"+clean+"\x00"+strconv.Itoa(uid), timeout, func() any {
		return check(home, uid)
	})
	if answer, answered := result.(HomeCheck); ok && answered {
		return answer
	}
	return HomeCheck{State: HomePending, Reason: fmt.Sprintf("user home %s did not respond within %s", clean, timeout)}
}

type unixLstatResult struct {
	info os.FileInfo
	err  error
}

// BoundedLstat is os.Lstat with a deadline. A path that does not answer
// returns an error that PendingTargetError recognizes (ETIMEDOUT).
func BoundedLstat(path string, timeout time.Duration) (os.FileInfo, error) {
	clean := filepath.Clean(path)
	lstat := unixHomeLstatProbe
	result, ok := boundedUnixHomeProbe("lstat\x00"+clean, timeout, func() any {
		info, err := lstat(clean)
		return unixLstatResult{info: info, err: err}
	})
	if answer, answered := result.(unixLstatResult); ok && answered {
		return answer.info, answer.err
	}
	return nil, &os.PathError{Op: "lstat", Path: clean, Err: syscall.ETIMEDOUT}
}

type unixEntriesResult struct {
	has bool
	err error
}

// BoundedDirHasEntries reports whether the directory at path holds at least
// one entry, with a deadline. A directory that does not answer returns an
// error that PendingTargetError recognizes (ETIMEDOUT).
func BoundedDirHasEntries(path string, timeout time.Duration) (bool, error) {
	clean := filepath.Clean(path)
	result, ok := boundedUnixHomeProbe("entries\x00"+clean, timeout, func() any {
		dir, err := os.Open(clean)
		if err != nil {
			return unixEntriesResult{err: err}
		}
		defer dir.Close()
		names, err := dir.Readdirnames(1)
		if len(names) > 0 {
			return unixEntriesResult{has: true}
		}
		if errors.Is(err, io.EOF) {
			return unixEntriesResult{}
		}
		return unixEntriesResult{err: err}
	})
	if answer, answered := result.(unixEntriesResult); ok && answered {
		return answer.has, answer.err
	}
	return false, &os.PathError{Op: "readdir", Path: clean, Err: syscall.ETIMEDOUT}
}

// unixOwnedSubdirScanLimit bounds how many entries of a home root
// BoundedDirHasOwnedSubdir looks at.
const unixOwnedSubdirScanLimit = 4096

// BoundedDirHasOwnedSubdir reports whether the directory path holds a
// folder (not a symlink) owned by uid, other than the entry named except,
// within timeout. Within the first unixOwnedSubdirScanLimit entries only.
// A home root that does not answer in time is an error.
func BoundedDirHasOwnedSubdir(path string, uid int, except string, timeout time.Duration) (bool, error) {
	clean := filepath.Clean(path)
	result, ok := boundedUnixHomeProbe("owned\x00"+clean+"\x00"+strconv.Itoa(uid)+"\x00"+except, timeout, func() any {
		dir, err := os.Open(clean)
		if err != nil {
			return unixEntriesResult{err: err}
		}
		defer dir.Close()
		names, err := dir.Readdirnames(unixOwnedSubdirScanLimit)
		if err != nil && !errors.Is(err, io.EOF) {
			return unixEntriesResult{err: err}
		}
		for _, name := range names {
			if name == except {
				continue
			}
			info, err := os.Lstat(filepath.Join(clean, name))
			if err != nil || !info.IsDir() {
				continue
			}
			if st, ok := info.Sys().(*syscall.Stat_t); ok && int64(st.Uid) == int64(uid) {
				return unixEntriesResult{has: true}
			}
		}
		return unixEntriesResult{}
	})
	if answer, answered := result.(unixEntriesResult); ok && answered {
		return answer.has, answer.err
	}
	return false, &os.PathError{Op: "readdir", Path: clean, Err: syscall.ETIMEDOUT}
}
