// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package main

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// rel-1-0-10 GAP-0268: a look still running when hook-user exits is stopped
// with its process group and writes no result for the next calls.
func TestGAP0268StoppedLookLeavesNoOrphanAndNoResult(t *testing.T) {
	t.Cleanup(func() {
		outageLooks.Lock()
		outageLooks.exiting = false
		outageLooks.Unlock()
	})
	dir := t.TempDir()
	hookDir := filepath.Join(dir, "hooks")
	if err := os.MkdirAll(hookDir, 0o700); err != nil {
		t.Fatal(err)
	}
	gateway := filepath.Join(dir, "defenseclaw-gateway")
	// A slow look: the gateway binary stand-in starts a child and waits.
	if err := os.WriteFile(gateway, []byte("#!/bin/sh\nsleep 30\necho open\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	modes := make(chan string, 1)
	go func() {
		modes <- sharedOutageMode(gateway, hookDir, time.Now(), func() string { return outageMode(gateway, hookDir) })
	}()
	pgid := 0
	for deadline := time.Now().Add(5 * time.Second); pgid == 0 && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
		outageLooks.Lock()
		for cmd := range outageLooks.running {
			pgid = cmd.Process.Pid
		}
		outageLooks.Unlock()
	}
	if pgid == 0 {
		t.Fatal("the look never started")
	}
	time.Sleep(100 * time.Millisecond) // the stand-in has started its child
	stopOutageLooks()
	select {
	case mode := <-modes:
		if mode != "closed" {
			t.Fatalf("stopped look gave %q, want closed", mode)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the stopped look did not end")
	}
	gone := false
	for deadline := time.Now().Add(3 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		if err := syscall.Kill(-pgid, 0); errors.Is(err, syscall.ESRCH) {
			gone = true
			break
		}
	}
	if !gone {
		t.Fatal("a process of the stopped look outlived it")
	}
	if _, err := os.Lstat(filepath.Join(hookDir, ".outage-mode.result")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a stopped look wrote a result: %v", err)
	}
	// While exiting no new look starts.
	if mode := outageMode(gateway, hookDir); mode != "" {
		t.Fatalf("a look after the stop gave %q, want none", mode)
	}
}
