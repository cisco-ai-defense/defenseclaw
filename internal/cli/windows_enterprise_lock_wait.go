// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

const (
	// windowsMaxLockWait bounds --lock-wait on Windows, as
	// enterpriseunix.MaxLockWait does on Linux and macOS.
	windowsMaxLockWait = 15 * time.Minute
	// windowsLockPoll is how often a waiting caller tries the lock again,
	// the 100 ms the installer polls with.
	windowsLockPoll = 100 * time.Millisecond
)

var (
	// windowsLockWaitNow and windowsLockWaitSleep are the clock of
	// acquireWindowsLockWithin (tests use a fake one).
	windowsLockWaitNow   = time.Now
	windowsLockWaitSleep = func(ctx context.Context, d time.Duration) error {
		timer := time.NewTimer(d)
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
			return nil
		}
	}
)

// acquireWindowsLockWithin calls try until it returns the lock, fails with an
// error busy does not accept, wait has passed or ctx ends. A wait of 0 tries
// once, which is what every caller did before --lock-wait was honoured on
// Windows. On expiry it returns try's last busy error.
func acquireWindowsLockWithin(ctx context.Context, wait time.Duration, try func() (func(), error), busy func(error) bool) (func(), error) {
	if ctx == nil {
		ctx = context.Background()
	}
	deadline := windowsLockWaitNow().Add(wait)
	for {
		release, err := try()
		if err == nil || !busy(err) {
			return release, err
		}
		remaining := deadline.Sub(windowsLockWaitNow())
		if remaining <= 0 {
			return nil, err
		}
		if sleepErr := windowsLockWaitSleep(ctx, min(windowsLockPoll, remaining)); sleepErr != nil {
			return nil, err
		}
	}
}

// formatWindowsLockWait prints a whole number of minutes as "10m", not
// "10m0s", as enterpriseunix.FormatLockWait does.
func formatWindowsLockWait(wait time.Duration) string {
	if wait >= time.Minute && wait%time.Minute == 0 {
		return fmt.Sprintf("%dm", int(wait/time.Minute))
	}
	return wait.String()
}

// checkWindowsLockWait refuses a --lock-wait outside 0..15m with the words
// and the usage line of checkLockWait (Linux and macOS) and the Windows
// invalid-arguments exit code, 1639.
func checkWindowsLockWait(cmd *cobra.Command, wait time.Duration) error {
	if wait >= 0 && wait <= windowsMaxLockWait {
		return nil
	}
	limit := formatWindowsLockWait(windowsMaxLockWait)
	typed := typedLockWait(cmd, wait)
	if typed == "" {
		typed = formatWindowsLockWait(wait)
	}
	msg := fmt.Sprintf("--lock-wait takes at most %s, not %s", limit, typed)
	if wait < 0 {
		msg = fmt.Sprintf("--lock-wait takes a duration from 0 to %s, not %s", limit, typed)
	}
	return lifecycleFlagError(cmd, errors.New(msg))
}
