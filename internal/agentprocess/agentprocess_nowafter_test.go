// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package agentprocess

import (
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

// GAP-0381: the guardian records a removal before the file changes with a
// mark ahead of now, so an agent process that starts before the removal is
// done (or before a guardian that ended mid-removal could record it) is
// denied too.
func TestNowAfterCoversProcessesThatStartWithinTheBound(t *testing.T) {
	now, ahead := Now(), NowAfter(time.Minute)
	if now == "" || ahead == "" {
		if runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
			t.Skip("no process clock on this host")
		}
		return
	}
	parts := strings.Split(now, ":")
	started := func(offset time.Duration) string {
		boot, clock, _ := currentClock()
		return parts[0] + ":" + boot + ":1:" + strconv.FormatInt(clock+int64(offset.Seconds()*float64(clockUnitsPerSecond)), 10)
	}
	if !StartedBefore(started(30*time.Second), ahead) {
		t.Fatal("a process that starts within the bound must count as started before the mark")
	}
	if StartedBefore(started(2*time.Minute), ahead) {
		t.Fatal("a process that starts after the bound must not")
	}
	if StartedBefore(started(time.Second), now) {
		t.Fatal("a process that starts after now is not covered by now")
	}
}
