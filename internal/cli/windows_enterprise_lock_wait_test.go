// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

var errTestLockBusy = errors.New("held by another run")

// fakeWindowsLockClock replaces the clock of acquireWindowsLockWithin: sleep
// advances now and never blocks.
func fakeWindowsLockClock(t *testing.T) *time.Time {
	t.Helper()
	now := time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC)
	savedNow, savedSleep := windowsLockWaitNow, windowsLockWaitSleep
	t.Cleanup(func() { windowsLockWaitNow, windowsLockWaitSleep = savedNow, savedSleep })
	windowsLockWaitNow = func() time.Time { return now }
	windowsLockWaitSleep = func(ctx context.Context, d time.Duration) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		now = now.Add(d)
		return nil
	}
	return &now
}

// busyFor returns a try that reports busy until the clock reaches free.
func busyFor(now *time.Time, free time.Time, tries *int) func() (func(), error) {
	return func() (func(), error) {
		*tries++
		if now.Before(free) {
			return nil, errTestLockBusy
		}
		return func() {}, nil
	}
}

func isTestLockBusy(err error) bool { return errors.Is(err, errTestLockBusy) }

func TestWindowsLockWaitZeroTriesOnce(t *testing.T) {
	now := fakeWindowsLockClock(t)
	tries := 0
	_, err := acquireWindowsLockWithin(context.Background(), 0, busyFor(now, now.Add(time.Hour), &tries), isTestLockBusy)
	if !errors.Is(err, errTestLockBusy) || tries != 1 {
		t.Fatalf("no --lock-wait: err %v after %d tries, want busy after 1", err, tries)
	}
}

func TestWindowsLockWaitTakesTheLockOnceFree(t *testing.T) {
	now := fakeWindowsLockClock(t)
	start := *now
	tries := 0
	release, err := acquireWindowsLockWithin(context.Background(), 10*time.Second, busyFor(now, start.Add(time.Second), &tries), isTestLockBusy)
	if err != nil || release == nil {
		t.Fatalf("lock freed after 1s within a 10s wait: %v", err)
	}
	if waited := now.Sub(start); waited < time.Second || waited > time.Second+windowsLockPoll {
		t.Fatalf("waited %s for a lock freed after 1s", waited)
	}
}

func TestWindowsLockWaitExpiresBusy(t *testing.T) {
	now := fakeWindowsLockClock(t)
	start := *now
	tries := 0
	_, err := acquireWindowsLockWithin(context.Background(), 2*time.Second, busyFor(now, start.Add(time.Hour), &tries), isTestLockBusy)
	if !errors.Is(err, errTestLockBusy) {
		t.Fatalf("held lock: %v, want the busy error", err)
	}
	if waited := now.Sub(start); waited != 2*time.Second {
		t.Fatalf("gave up after %s, want exactly the 2s wait", waited)
	}
}

func TestWindowsLockWaitStopsOnOtherErrorsAndCancel(t *testing.T) {
	now := fakeWindowsLockClock(t)
	broken := errors.New("access denied")
	tries := 0
	_, err := acquireWindowsLockWithin(context.Background(), time.Minute, func() (func(), error) { tries++; return nil, broken }, isTestLockBusy)
	if !errors.Is(err, broken) || tries != 1 {
		t.Fatalf("a non-busy failure must not be retried: %v after %d tries", err, tries)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	tries = 0
	_, err = acquireWindowsLockWithin(ctx, time.Minute, busyFor(now, now.Add(time.Hour), &tries), isTestLockBusy)
	if !errors.Is(err, errTestLockBusy) || tries != 1 {
		t.Fatalf("a cancelled run must stop waiting with the busy error: %v after %d tries", err, tries)
	}
}

func TestCheckWindowsLockWaitRange(t *testing.T) {
	newCmd := func(typed string) (*cobra.Command, time.Duration) {
		var wait time.Duration
		cmd := &cobra.Command{Use: "set"}
		addLockWaitFlag(cmd.Flags(), &wait)
		if err := cmd.Flags().Parse([]string{"--lock-wait", typed}); err != nil {
			t.Fatal(err)
		}
		return cmd, wait
	}
	for _, typed := range []string{"0", "30s", "15m"} {
		cmd, wait := newCmd(typed)
		if err := checkWindowsLockWait(cmd, wait); err != nil {
			t.Fatalf("--lock-wait %s: %v", typed, err)
		}
	}
	cmd, wait := newCmd("1h")
	if err := checkWindowsLockWait(cmd, wait); err == nil || !strings.Contains(err.Error(), "--lock-wait takes at most 15m, not 1h") {
		t.Fatalf("--lock-wait 1h: %v", err)
	}
	cmd, wait = newCmd("-1s")
	if err := checkWindowsLockWait(cmd, wait); err == nil || !strings.Contains(err.Error(), "--lock-wait takes a duration from 0 to 15m, not -1s") {
		t.Fatalf("--lock-wait -1s: %v", err)
	}
}
