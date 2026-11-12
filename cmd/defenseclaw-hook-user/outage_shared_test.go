// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Late calls of one account share one outage-mode look instead of each
// starting a gateway process (#1384).
func TestSharedOutageModeRunsOneLookForConcurrentLateCalls(t *testing.T) {
	dir := t.TempDir()
	var looks atomic.Int32
	look := func() string {
		looks.Add(1)
		time.Sleep(50 * time.Millisecond)
		return "open"
	}
	lateAt := time.Now()
	var wg sync.WaitGroup
	modes := make([]string, 20)
	for i := range modes {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			modes[i] = sharedOutageMode("gw", dir, lateAt, look)
		}(i)
	}
	wg.Wait()
	for i, m := range modes {
		if m != "open" {
			t.Fatalf("call %d got %q", i, m)
		}
	}
	if n := looks.Load(); n != 1 {
		t.Fatalf("%d looks for 20 concurrent late calls, want 1", n)
	}
}

// A result that started before the call could have seen the current state is
// not reused: the call looks again.
func TestSharedOutageModeIgnoresAnOldResult(t *testing.T) {
	dir := t.TempDir()
	writeOutageModeResult(filepath.Join(dir, ".outage-mode.result"), time.Now().Add(-time.Second), "open")
	var looks atomic.Int32
	got := sharedOutageMode("gw", dir, time.Now(), func() string { looks.Add(1); return "closed" })
	if got != "closed" || looks.Load() != 1 {
		t.Fatalf("old result reused: mode %q, looks %d", got, looks.Load())
	}
}

// A result file that is not a plain file of this account, or not in the
// format, is no result.
func TestSharedOutageModeRefusesAForeignResult(t *testing.T) {
	dir := t.TempDir()
	result := filepath.Join(dir, ".outage-mode.result")
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("v1 99999999999999999 open\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, result); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readOutageModeResult(result); ok {
		t.Fatal("a symlinked result was read")
	}
	_ = os.Remove(result)
	if err := os.WriteFile(result, []byte("v1 12 maybe\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, ok := readOutageModeResult(result); ok {
		t.Fatal("a malformed result was read")
	}
}

// A lock whose holder is gone (its process exited) is free: flock is
// released with the file, and a lock file left on disk does not block.
func TestSharedOutageModeLockFileLeftBehindDoesNotBlock(t *testing.T) {
	dir := t.TempDir()
	lock := filepath.Join(dir, ".outage-mode.lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if got := sharedOutageMode("gw", dir, time.Now(), func() string { return "open" }); got != "open" {
		t.Fatalf("left-behind lock file blocked the look: %q", got)
	}
}

// A held lock makes other calls wait for the result of its look.
func TestSharedOutageModeWaitsForTheHolder(t *testing.T) {
	dir := t.TempDir()
	unlock := takeOutageModeLock(filepath.Join(dir, ".outage-mode.lock"))
	if unlock == nil {
		t.Fatal("lock not taken")
	}
	lateAt := time.Now()
	go func() {
		time.Sleep(30 * time.Millisecond)
		writeOutageModeResult(filepath.Join(dir, ".outage-mode.result"), time.Now(), "closed")
		unlock()
	}()
	var looks atomic.Int32
	if got := sharedOutageMode("gw", dir, lateAt, func() string { looks.Add(1); return "open" }); got != "closed" || looks.Load() != 0 {
		t.Fatalf("got %q with %d own looks; want the holder result", got, looks.Load())
	}
}

// A result that says it started in the future is no result.
func TestSharedOutageModeRefusesAFutureResult(t *testing.T) {
	dir := t.TempDir()
	writeOutageModeResult(filepath.Join(dir, ".outage-mode.result"), time.Now().Add(time.Hour), "open")
	if _, _, ok := readOutageModeResult(filepath.Join(dir, ".outage-mode.result")); ok {
		t.Fatal("a future result was read")
	}
}
