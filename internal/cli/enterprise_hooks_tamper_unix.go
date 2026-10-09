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
// hook binary (an antivirus quarantine). Its sandbox cannot write the
// install root, so it starts the lifecycle's config-apply job, whose ensure
// puts it back, and logs each find as a tamper (GAP-1217). Before, a missing
// hook binary left every agent running tool calls without DefenseClaw until
// an administrator reinstalled the package.

// unixTamperCheckInterval is how often the guardian checks between
// reconciles; unixTamperRetry is how long it waits before it starts the
// restore again for the same files.
var (
	unixTamperCheckInterval = 5 * time.Second
	unixTamperRetry         = 30 * time.Second
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
// tampered files, at most once per unixTamperRetry for the same files.
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
		unixTamper.files, unixTamper.requested = "", time.Time{}
		return
	}
	if files == unixTamper.files && now.Sub(unixTamper.requested) < unixTamperRetry {
		return
	}
	unixTamper.files, unixTamper.requested = files, now
	if err := host.RequestTamperRestore(ctx); err != nil {
		fmt.Fprintf(stderr, "[hook-guardian] tamper: %s changed or removed since the last lifecycle run; starting the lifecycle's restore failed: %v; run `%s`\n", files, err, host.RepairCommand())
		return
	}
	fmt.Fprintf(stderr, "[hook-guardian] tamper: %s changed or removed since the last lifecycle run; started the lifecycle's config-apply job, which puts it back\n", files)
}
