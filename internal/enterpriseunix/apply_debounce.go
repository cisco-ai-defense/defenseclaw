// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"errors"
	"os"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// A path-triggered ensure plans once a pair of config pushes five seconds
// apart has settled. Every new config write starts another quiet window.
const applyTriggerQuietWindow = 6 * time.Second
const applyTriggerSampleInterval = 200 * time.Millisecond
const applyTriggerMaxWait = 15 * time.Second

func (l *lifecycle) hasApplyTriggerDebounce() bool {
	return l.opts.Action == ActionEnsure && l.opts.Reason == ApplyTriggerReason &&
		l.opts.ConfigFile == "" && l.env.ApplyTriggerDebounce != nil
}

// pathTriggerNeedsQuiet distinguishes a path event for the applied inputs
// from a change that needs the quiet window. The caller holds the lifecycle
// lock for this check and releases it before waiting, without publishing the
// lifecycle marker while the gateway remains active.
func (l *lifecycle) pathTriggerNeedsQuiet(ctx context.Context) bool {
	if !l.hasApplyTriggerDebounce() {
		return false
	}
	if l.opts.Bundle != "" || l.opts.BundleInbox || l.opts.Mutate != nil {
		return true
	}
	if l.env.bundleMode() {
		entries, err := os.ReadDir(l.env.bundleInboxDir())
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return true
		}
		if len(entries) != 0 {
			return true
		}
	}
	record, err := l.env.loadDeployment()
	if err != nil || record == nil {
		return true
	}
	l.restoreUnchangedConfigMetadata(ctx, record)
	probe := &lifecycle{
		env: l.env, opts: l.opts,
		result: enterprisestatus.New(l.opts.Action, l.result.Profile, l.env.GOOS, l.env.ProductVersion),
	}
	noop, _ := probe.ensureNoop(ctx, record)
	return !noop
}

func (l *lifecycle) waitForApplyTriggerBeforeLock(ctx context.Context) bool {
	waitCtx, stop := l.untilInterrupted(ctx)
	err := l.env.ApplyTriggerDebounce(waitCtx, l.env.P(l.env.Layout.ConfigPath))
	stop()
	if err == nil {
		return true
	}
	if l.interrupted() || errors.Is(err, context.Canceled) {
		l.result.AddError(codeInterrupted, "the run stopped while it waited for the config push to settle; nothing was changed")
	} else {
		l.result.AddError(codeState, "wait for config push: "+err.Error())
	}
	return false
}

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
