// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package attach

import (
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"testing"
	"time"
)

// TestMCPBridgeCloseWaitsForTheCmdExeGrandchild (GAP-1016): the shape the
// documented `npx ...` example has, with the real cmd.exe /d /c as the direct
// child and the helper as its grandchild. Close ends the tree through Kill,
// and the presence record must go only after the grandchild has exited. The
// grandchild leaves the job's process list before it has exited, so the
// record used to go while it was still running (10 of 10 cycles).
func TestMCPBridgeCloseWaitsForTheCmdExeGrandchild(t *testing.T) {
	t.Setenv("DC_MCP_HELPER", "echo")
	spec := MCPSpec{Name: "helper", Argv: []string{
		filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe"), "/d", "/c", os.Args[0],
	}}
	f := newFakeStream(t)
	c, s := f.dial()
	frames := pump(s)
	var grandPID atomic.Int64
	var aliveAtRemove atomic.Int64
	removed := make(chan time.Time, 16)
	startServe(t, c, MCPServe{Spec: spec, KillGrace: 2 * time.Second,
		OnChild: func(int) func() {
			return func() {
				if g := grandPID.Load(); g != 0 && pidAlive(int(g)) {
					aliveAtRemove.Add(1)
				}
				removed <- time.Now()
			}
		}})
	const cycles = 10
	var closeLatency []time.Duration
	for i := 0; i < cycles; i++ {
		sendCtl(t, s, "open")
		grand := startedPID(t, next(t, frames, "open"))
		t.Cleanup(func() { killPID(grand) })
		grandPID.Store(int64(grand))
		start := time.Now()
		sendCtl(t, s, "close")
		select {
		case at := <-removed:
			closeLatency = append(closeLatency, at.Sub(start))
		case <-time.After(treeLimit * 3):
			t.Fatalf("cycle %d: the presence record was not removed", i)
		}
		if pidAlive(grand) {
			t.Errorf("cycle %d: the grandchild %d still runs after the record went", i, grand)
		}
		for drained := false; !drained; { // the bridge's closing frames
			select {
			case <-frames:
			case <-time.After(30 * time.Millisecond):
				drained = true
			}
		}
	}
	if n := aliveAtRemove.Load(); n != 0 {
		t.Errorf("the presence record was removed while the grandchild still ran in %d of %d cycles", n, cycles)
	}
	sort.Slice(closeLatency, func(i, j int) bool { return closeLatency[i] < closeLatency[j] })
	t.Logf("close -> record removed: p50 %v max %v (%d cycles)", closeLatency[len(closeLatency)/2], closeLatency[len(closeLatency)-1], cycles)
}
