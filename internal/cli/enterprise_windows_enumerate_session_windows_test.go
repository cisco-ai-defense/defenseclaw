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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winsession"
)

// A sign-in forwarded through internal/winsession runs one extra enumeration
// cycle after the settle delay instead of waiting for the interval tick.
func TestEnterpriseWindowsEnumerateIntervalRunsACycleOnSignIn(t *testing.T) {
	manifest := filepath.Join(t.TempDir(), "targets.yaml")
	previousConfig := enterpriseWindowsEnumerateConfigLoader
	previousEnumerator := enterpriseWindowsEnumerateProfileEnumerator
	previousWriter := enterpriseWindowsEnumerateManifestWriter
	previousSettle := enterpriseWindowsEnumerateSessionSettle
	t.Cleanup(func() {
		enterpriseWindowsEnumerateConfigLoader = previousConfig
		enterpriseWindowsEnumerateProfileEnumerator = previousEnumerator
		enterpriseWindowsEnumerateManifestWriter = previousWriter
		enterpriseWindowsEnumerateSessionSettle = previousSettle
	})
	enterpriseWindowsEnumerateSessionSettle = 10 * time.Millisecond
	enterpriseWindowsEnumerateConfigLoader = func() (*config.Config, error) {
		return &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}, nil
	}
	// Each cycle reports its start; the first one is held until the sign-in
	// burst has been delivered, so the burst lands while the loop is busy and
	// must coalesce into exactly one pending sign-in.
	var cycles atomic.Int32
	started := make(chan int32, 8)
	releaseFirst := make(chan struct{})
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		n := cycles.Add(1)
		started <- n
		if n == 1 {
			<-releaseFirst
		}
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
	winsession.NotifyLogon()
	close(releaseFirst)
	if n := <-started; n != 2 {
		t.Fatalf("sign-in cycle = %d, want 2", n)
	}
	// The hourly ticker cannot fire here, and a session cycle needs a pending
	// sign-in. With the burst consumed and the channel empty, no further cycle
	// can start, so the count is final.
	if pending := len(winsession.Logons()); pending != 0 {
		t.Fatalf("a burst of sign-ins left %d pending notifications, want 0", pending)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("interval loop: %v", err)
	}
	if got := cycles.Load(); got != 2 {
		t.Fatalf("a burst of sign-ins ran %d cycles in total, want 2", got)
	}
}
