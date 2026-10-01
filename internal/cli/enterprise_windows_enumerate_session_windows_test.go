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
	var cycles atomic.Int32
	enterpriseWindowsEnumerateProfileEnumerator = func(context.Context, *config.Config, enterprisehooks.EnumerateOptions) (enterprisehooks.Manifest, error) {
		cycles.Add(1)
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
	waitForCycles := func(want int32) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for cycles.Load() < want {
			if time.Now().After(deadline) {
				t.Fatalf("cycles = %d, want %d", cycles.Load(), want)
			}
			time.Sleep(5 * time.Millisecond)
		}
	}
	waitForCycles(1)
	winsession.NotifyLogon()
	winsession.NotifyLogon()
	waitForCycles(2)
	time.Sleep(50 * time.Millisecond)
	if got := cycles.Load(); got != 2 {
		t.Fatalf("a burst of sign-ins ran %d cycles in total, want 2", got)
	}
	cancel()
	if err := <-done; err != nil {
		t.Fatalf("interval loop: %v", err)
	}
}
