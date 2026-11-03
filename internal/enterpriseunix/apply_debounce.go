// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"time"
)

// A path-triggered ensure plans once a pair of config pushes five seconds
// apart has settled. Every new config write starts another quiet window.
const applyTriggerQuietWindow = 6 * time.Second
const applyTriggerSampleInterval = 200 * time.Millisecond
const applyTriggerMaxWait = 15 * time.Second

func debounceApplyTrigger(ctx context.Context, configPath string) error {
	return waitForApplyTriggerQuiet(ctx, configPath, time.Now, waitApplyTriggerSample, os.Lstat)
}

func waitApplyTriggerSample(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func waitForApplyTriggerQuiet(
	ctx context.Context, path string, now func() time.Time,
	wait func(context.Context, time.Duration) error,
	stat func(string) (os.FileInfo, error),
) error {
	previous, previousErr := stat(path)
	start := now()
	limit := start.Add(applyTriggerMaxWait)
	deadline := start.Add(applyTriggerQuietWindow)
	for now().Before(deadline) {
		interval := min(applyTriggerSampleInterval, deadline.Sub(now()), limit.Sub(now()))
		if interval <= 0 {
			break
		}
		if err := wait(ctx, interval); err != nil {
			return err
		}
		current, currentErr := stat(path)
		if !sameApplyTriggerFile(previous, previousErr, current, currentErr) {
			deadline = now().Add(applyTriggerQuietWindow)
			if deadline.After(limit) {
				deadline = limit
			}
		}
		previous, previousErr = current, currentErr
	}
	return ctx.Err()
}

func sameApplyTriggerFile(before os.FileInfo, beforeErr error, after os.FileInfo, afterErr error) bool {
	if beforeErr != nil || afterErr != nil {
		return errors.Is(beforeErr, os.ErrNotExist) && errors.Is(afterErr, os.ErrNotExist)
	}
	return os.SameFile(before, after) && before.Size() == after.Size() && before.ModTime().Equal(after.ModTime()) && before.Mode() == after.Mode()
}
