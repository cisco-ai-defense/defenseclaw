// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"bytes"
	"context"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winsession"
)

// A sign-in forwarded through internal/winsession arms one settle window and
// runs one extra cycle when it fires, instead of waiting for the interval
// tick. Sign-ins the loop receives while the window is armed join it; one
// that joined late gets one more window for the rest of its settle time.
func TestEnterpriseWindowsEnumerateIntervalRunsACycleOnSignIn(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousSettleAfter := enterpriseWindowsEnumerateSessionSettleAfter
	previousNow := enterpriseWindowsEnumerateSessionNow
	t.Cleanup(func() {
		enterpriseWindowsEnumerateSessionNow = previousNow
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateSessionSettleAfter = previousSettleAfter
	})
	// The settle window fires only when the test sends on settle, and every
	// arming is recorded, so the debounce is observed through events.
	armed := make(chan time.Duration, 8)
	settle := make(chan time.Time, 1)
	enterpriseWindowsEnumerateSessionSettleAfter = func(d time.Duration) <-chan time.Time {
		armed <- d
		return settle
	}
	// The loop reads the clock at each sign-in and when a window fires: the
	// second sign-in arrives 10 s into the 15 s window, and the follow-up
	// window fires once that sign-in has had its full settle time.
	start := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	readings := []time.Time{
		start, start.Add(10 * time.Second),
		start.Add(enterpriseWindowsEnumerateSessionSettle), start.Add(25 * time.Second),
	}
	var reads atomic.Int32
	enterpriseWindowsEnumerateSessionNow = func() time.Time {
		return readings[min(int(reads.Add(1))-1, len(readings)-1)]
	}
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	var cycles atomic.Int32
	started := make(chan int32, 8)
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		started <- cycles.Add(1)
		return enterprisehooks.Manifest{Version: 1, Targets: []enterprisehooks.ManifestTarget{}}, nil
	}
	enterpriseWindowsEnumerateManifestWriter = func(string, enterprisehooks.Manifest) (bool, error) { return false, nil }
	for {
		select {
		case <-winsession.Logons():
			continue
		default:
		}
		break
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- runEnterpriseWindowsEnumerateInterval(ctx, new(bytes.Buffer), &enterpriseWindowsEnumerateOptions{
			manifestPath: manifest,
			interval:     time.Hour,
			initialDelay: time.Millisecond,
		}, manifest)
	}()
	if n := <-started; n != 1 {
		t.Fatalf("first cycle = %d, want initial cycle", n)
	}
	winsession.NotifyLogon()
	select {
	case d := <-armed:
		if d != enterpriseWindowsEnumerateSessionSettle {
			t.Fatalf("settle window = %v, want %v", d, enterpriseWindowsEnumerateSessionSettle)
		}
	case n := <-started:
		t.Fatalf("cycle %d ran on sign-in before the settle window fired", n)
	}
	// The loop is the only receiver: an empty channel means it took the
	// second sign-in while the window was armed.
	winsession.NotifyLogon()
	for len(winsession.Logons()) != 0 {
		runtime.Gosched()
	}
	settle <- time.Now()
	if n := <-started; n != 2 {
		t.Fatalf("sign-in cycle = %d, want 2", n)
	}
	if d := <-armed; d != 10*time.Second {
		t.Fatalf("late sign-in window = %v, want the 10 s it has left", d)
	}
	settle <- time.Now()
	if n := <-started; n != 3 {
		t.Fatalf("late sign-in cycle = %d, want 3", n)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("interval loop: %v", err)
	}
	if got := cycles.Load(); got != 3 {
		t.Fatalf("two sign-ins ran %d cycles in total, want 3", got)
	}
	if extra := len(armed); extra != 0 {
		t.Fatalf("two sign-ins armed %d extra windows, want 0", extra)
	}
}
