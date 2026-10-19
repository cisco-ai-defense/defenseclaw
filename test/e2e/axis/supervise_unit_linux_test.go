//go:build linux

// Copyright 2026 Cisco Systems, Inc.
// SPDX-License-Identifier: Apache-2.0

package axis

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestSupervisorPreservesExitAndOutput(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	result, err := supervise(ctx, "/bin/sh", []string{"-c", "printf probe-out; printf probe-err >&2; exit 23"}, t.TempDir(), []string{"PATH=/usr/bin:/bin"})
	if err != nil || result.exitCode != 23 || result.timedOut || result.stdout != "probe-out" || result.stderr != "probe-err" {
		t.Fatalf("exit/output custody failed: result=%+v error=%v", result, err)
	}
}

func TestSupervisorBoundsTimeout(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	result, err := supervise(ctx, "/bin/sleep", []string{"60"}, t.TempDir(), []string{"PATH=/usr/bin:/bin"})
	if !result.timedOut || result.exitCode == 0 {
		t.Fatalf("timeout was not reported: result=%+v error=%v", result, err)
	}
	if err != nil && !strings.Contains(err.Error(), "context deadline exceeded") {
		t.Fatal(err)
	}
}
