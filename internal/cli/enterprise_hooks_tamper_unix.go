// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterpriseunix"
)

// The standalone Unix guardian notices, between lifecycle runs, a missing
// hook binary (an antivirus quarantine) and an edited or deleted DefenseClaw
// machine-policy drop-in. Its sandbox cannot write either, so it starts the
// lifecycle's config-apply job, whose ensure puts them back, and logs each
// find as a tamper (GAP-1178, GAP-1217). Before, a missing hook binary left
// every agent running tool calls without DefenseClaw, and a changed drop-in
// left the hooks off for every user, until an administrator ran repair.

// unixTamperCheckInterval is how often the guardian checks between
// reconciles. While the same files stay tampered after a restore was
// started (a drop-in another tool holds with chattr +i, say), the next start
// waits unixTamperRetry, doubling up to unixTamperMaxRetry: an ensure that
// cannot restore a drop-in applies a transaction, which restarts the
// services, and must not do so every half minute.
var (
	unixTamperCheckInterval = 5 * time.Second
	unixTamperRetry         = 30 * time.Second
	unixTamperMaxRetry      = 15 * time.Minute
)

// unixTamperEnv is the lifecycle environment; tests replace it.
var unixTamperEnv = func() (unixTamperHost, error) {
	return enterpriseunix.NewEnv(runtime.GOOS, appVersion)
}

// unixTamperHost is what the check needs from the lifecycle environment.
type unixTamperHost interface {
	TamperedFiles() []string
	RequestTamperRestore(ctx context.Context) error
	RepairCommand() string
}

var unixTamper struct {
	sync.Mutex
	files     string
	requested time.Time
	wait      time.Duration
}

func init() {
	previous := enterpriseHookBeforeWatchReconcile
	enterpriseHookBeforeWatchReconcile = func(stderr io.Writer) {
		previous(stderr)
		checkUnixStandaloneTamper(context.Background(), stderr, time.Now())
	}
}

// watchUnixStandaloneTamper runs the check every unixTamperCheckInterval for
// the life of the guardian watch loop.
func watchUnixStandaloneTamper(ctx context.Context, stderr io.Writer) {
	if !enterpriseHooksStandaloneUnixActive() {
		return
	}
	ticker := time.NewTicker(unixTamperCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			checkUnixStandaloneTamper(ctx, stderr, now)
		}
	}
}

// checkUnixStandaloneTamper starts the lifecycle's restore when it finds
// tampered files, backing off while the same files stay tampered.
func checkUnixStandaloneTamper(ctx context.Context, stderr io.Writer, now time.Time) {
	if !enterpriseHooksStandaloneUnixActive() || os.Geteuid() != 0 {
		return
	}
	host, err := unixTamperEnv()
	if err != nil {
		return
	}
	files := strings.Join(host.TamperedFiles(), ", ")
	unixTamper.Lock()
	defer unixTamper.Unlock()
	if files == "" {
		unixTamper.files, unixTamper.requested, unixTamper.wait = "", time.Time{}, 0
		return
	}
	if files == unixTamper.files {
		if now.Sub(unixTamper.requested) < unixTamper.wait {
			return
		}
		unixTamper.wait = min(unixTamper.wait*2, unixTamperMaxRetry)
	} else {
		unixTamper.wait = unixTamperRetry
	}
	unixTamper.files, unixTamper.requested = files, now
	if err := host.RequestTamperRestore(ctx); err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: %s changed or removed since the last lifecycle run; starting the lifecycle's restore failed: %v; run `%s`\n", files, err, host.RepairCommand())
		return
	}
	fmt.Fprintf(stderr, "[hook-guardian] tamper: %s changed or removed since the last lifecycle run; started the lifecycle's config-apply job, which puts it back\n", files)
}
