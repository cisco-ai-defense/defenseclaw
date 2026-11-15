// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

// GAP-0289: a stalled task is stopped whole: a tool the agent started in a
// session of its own does not outlive it.
func TestStalledTaskLeavesNoDetachedTool(t *testing.T) {
	pidFile := filepath.Join(t.TempDir(), "tool.pid")
	var log eventLog
	o := HeadlessOptions{Stall: time.Second, Tick: 100 * time.Millisecond, Usage: flat}
	end := runWithin(t, 30*time.Second, func() TaskEnd {
		return RunHeadless(context.Background(), stallConfig(`setsid sleep 300 & echo $! > `+pidFile+`; exec sleep 300`), TaskRequest{Prompt: "p"}, o, log.emit)
	})
	if !end.Stalled {
		t.Fatalf("end %+v", end)
	}
	b, err := os.ReadFile(pidFile)
	if err != nil {
		t.Fatal(err)
	}
	pid, _ := strconv.Atoi(strings.TrimSpace(string(b)))
	for i := 0; i < 50; i++ {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		if st, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/stat"); err == nil && strings.Contains(string(st), ") Z ") {
			return // killed, not yet reaped by init
		}
		time.Sleep(100 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("the detached tool %d outlived the stalled task", pid)
}
