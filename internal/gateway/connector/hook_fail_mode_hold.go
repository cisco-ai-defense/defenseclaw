// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Polling and lock-touch periods of HoldHookFailModes.
const (
	hookFailModeHoldPoll  = 100 * time.Millisecond
	hookFailModeHoldTouch = 5 * time.Second
)

// HoldHookFailModes is RefreshHookFailModes for an upgrade that stops a
// running gateway. It takes the hook sidecar lock (withHookFailModeLock),
// refreshes, calls held, and keeps the lock until running reports the old
// gateway gone or timeout passes. It refreshes again before it lets go.
//
// An earlier gateway can render its hooks again while it runs or shuts
// down (a 1.0.x Windows Codex registration check rewrites the open it
// resolved for the sidecar it finds changed). Its writer waits on the lock,
// so it can no longer record that open, and dies waiting when the gateway
// exits: no hook reads it while the gateway is down. A connector script or
// adapter it renders outside the lock is closed by the second refresh.
//
// The lock file's time is kept current: an earlier Unix writer removes a
// lock file older than a minute (withFileLockMode). The returned error is
// the timeout when the gateway is still running at the deadline; the
// second refresh has run then too.
func HoldHookFailModes(
	hookDir string,
	mode func(connector string) string,
	held func(HookFailModeRefresh),
	running func() bool,
	timeout time.Duration,
) (HookFailModeRefresh, error) {
	var out HookFailModeRefresh
	var waitErr error
	locked := false
	err := withHookFailModeLock(hookDir, func() error {
		locked = true
		first, err := refreshHookFailModesLocked(hookDir, mode)
		if err != nil {
			return err
		}
		out = first
		if held != nil {
			held(first)
		}
		lockPath := filepath.Join(hookDir, hookConfigSidecarName+".lock")
		deadline := time.Now().Add(timeout)
		touched := time.Now()
		for running() {
			if !time.Now().Before(deadline) {
				waitErr = fmt.Errorf("the gateway was still running after %s", timeout)
				break
			}
			if time.Since(touched) >= hookFailModeHoldTouch {
				touched = time.Now()
				_ = os.Chtimes(lockPath, touched, touched)
			}
			time.Sleep(hookFailModeHoldPoll)
		}
		second, err := refreshHookFailModesLocked(hookDir, mode)
		if err != nil {
			return err
		}
		out.Scripts = appendMissing(out.Scripts, second.Scripts)
		return nil
	})
	if err != nil {
		return out, err
	}
	if !locked && held != nil {
		// No hook directory: nothing to hold.
		held(out)
	}
	return out, waitErr
}

func appendMissing(into, from []string) []string {
	seen := make(map[string]bool, len(into))
	for _, name := range into {
		seen[name] = true
	}
	for _, name := range from {
		if !seen[name] {
			seen[name] = true
			into = append(into, name)
		}
	}
	return into
}
