// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package manager

import (
	"context"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

const testHookScript = "/usr/local/lib/defenseclaw/hooks/claude-code-hook.sh"

// hookCallSample is a ps answer of a Claude Code sandbox; with call, a
// sample that landed in one of its hook calls (the TS r5 shape: the launch
// shell under claude, the hook script, its forks, one orphaned to the
// supervisor's subreaper, and its curl), and a workload process started in
// the same seconds.
func hookCallSample(call bool) *string {
	lines := []string{
		"P 1 0 1000 10", "Pc 1 openshell-sandb", "Pa 1 /opt/openshell/bin/openshell-sandbox",
		"P 95 1 1000 20", "Pc 95 python3", "Pa 95 /usr/bin/python3", "Pa 95 dc_supervisor.py",
		"P 100 95 1000 30", "Pc 100 claude", "Pa 100 /usr/local/bin/claude",
	}
	if call {
		lines = append(lines,
			"P 1059 100 1000 150", "Pc 1059 sh", "Pa 1059 /bin/sh", "Pa 1059 -c", "Pa 1059 "+testHookScript,
			"P 1060 1059 1000 151", "Pc 1060 claude-code-hoo", "Pa 1060 /bin/bash", "Pa 1060 -p", "Pa 1060 "+testHookScript,
			"P 1080 1060 1000 152", "Pc 1080 claude-code-hoo", "Pa 1080 /bin/bash", "Pa 1080 -p", "Pa 1080 "+testHookScript,
			"P 1082 1080 1000 152", "Pc 1082 claude-code-hoo",
			"P 1084 1082 1000 152",
			"P 1085 95 1000 152", "Pc 1085 claude-code-hoo",
			"P 1865 1082 1000 153", "Pc 1865 curl", "Pa 1865 curl", "Pa 1865 -X", "Pa 1865 POST",
			"P 1200 100 1000 152", "Pc 1200 sleep", "Pa 1200 sleep", "Pa 1200 30",
		)
	}
	return psAnswer(lines...)
}

// foldedHookFrames are the frames the feed sends for the call when it ends:
// the verified script's exec and its exit with the tool count.
func foldedHookFrames(id string, start, end time.Time) (sandboxfeed.Frame, sandboxfeed.Frame) {
	exec := execFrame(id, "hook-1060", "launch-1059", 9500, 1060, testHookScript, testHookScript+" -p "+testHookScript, start)
	exec.Hook, exec.PPID = true, 1059
	exit := exitFrame(id, "hook-1060", 9500, 0, end)
	exit.Hook, exit.HookTools = true, 12
	return exec, exit
}

func streamingKernelBox(t *testing.T, name string, sample *atomic.Pointer[string]) (*harnessEnv, *box, string) {
	t.Helper()
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	e, b, id := kernelBox(t, name, sample)
	e.m.kfeed.up(sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: "1.2.3", Tetragon: sandboxfeed.TetragonConnected})
	return e, b, id
}

func sampleNow(t *testing.T, e *harnessEnv, b *box) {
	t.Helper()
	time.Sleep(2 * time.Millisecond)
	if _, ok := e.m.sampleProcesses(context.Background(), b); !ok {
		t.Fatal("no sample")
	}
}

// checkFoldedCall: the call is one row (the script, an exit record only),
// none of its other processes is listed or recorded, and the workload's
// process the same sample saw is listed and recorded once each way.
func checkFoldedCall(t *testing.T, e *harnessEnv, name string) {
	t.Helper()
	folded := map[int]bool{1059: true, 1080: true, 1082: true, 1084: true, 1085: true, 1865: true}
	events := map[int][]string{}
	for _, r := range processRecords(e, name) {
		if folded[r.PID] {
			t.Errorf("a process of the folded hook call was recorded: %+v", r)
		}
		events[r.PID] = append(events[r.PID], r.Event)
		if r.PID == 1060 && (r.Source != audit.SandboxProcessSourceTetragon || r.Name != "claude-code-hook.sh") {
			t.Errorf("hook record = %+v", r)
		}
	}
	for pid, want := range map[int][]string{
		1:    {audit.SandboxProcessStart},
		100:  {audit.SandboxProcessStart},
		1060: {audit.SandboxProcessExit},
		1200: {audit.SandboxProcessStart, audit.SandboxProcessExit},
	} {
		if got := events[pid]; len(got) != len(want) || got[0] != want[0] || got[len(got)-1] != want[len(want)-1] {
			t.Errorf("records of pid %d = %v, want %v", pid, got, want)
		}
	}
	list, err := e.m.Processes(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Processes) != 3 {
		t.Errorf("live = %+v, want init, the supervisor and claude", list.Processes)
	}
	var exited []int
	for _, p := range list.Exited {
		exited = append(exited, p.PID)
		if folded[p.PID] {
			t.Errorf("a process of the folded hook call is listed: %+v", p)
		}
		if p.PID == 1060 && (!p.Hook || p.HookTools != 12 || p.Source != audit.SandboxProcessSourceTetragon) {
			t.Errorf("hook row = %+v", p)
		}
	}
	if len(exited) != 2 {
		t.Errorf("exited = %v, want the hook call and the workload's sleep", exited)
	}
}

// GAP-0095 (TS r5): a 5-second sample that landed in a hook call the kernel
// feed folds recorded the call's launch shell, the script's forks and its
// curl as sample processes, about five rows per call it caught, in sandbox
// ps and in the audit trail. The feed reports a folded call only when it
// ends, so while it streams a process only the sample shows is recorded one
// sample later, and the call's processes are dropped when the call ends.
func TestSampleDoesNotReaddAFoldedHookCall(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, id := streamingKernelBox(t, "foldbox", &sample)
	ctx := context.Background()
	sample.Store(hookCallSample(false))
	sampleNow(t, e, b)
	start := time.Now()
	sample.Store(hookCallSample(true))
	sampleNow(t, e, b)
	exec, exit := foldedHookFrames(id, start, time.Now())
	e.m.observeKernelFrame(ctx, b, exec)
	e.m.observeKernelFrame(ctx, b, exit)
	sample.Store(hookCallSample(false))
	sampleNow(t, e, b)
	checkFoldedCall(t, e, "foldbox")
}

// The feed may report the call before the sample that caught it is merged
// (the sample's exec outlasted the call): the call is remembered, and the
// sample's copy of the script is dropped as well.
func TestSampleMergedAfterTheFoldedCallEnded(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, id := streamingKernelBox(t, "latebox", &sample)
	ctx := context.Background()
	sample.Store(hookCallSample(false))
	sampleNow(t, e, b)
	start := time.Now()
	time.Sleep(2 * time.Millisecond)
	exec, exit := foldedHookFrames(id, start, time.Now())
	e.m.observeKernelFrame(ctx, b, exec)
	e.m.observeKernelFrame(ctx, b, exit)
	sample.Store(hookCallSample(true))
	sampleNow(t, e, b)
	sample.Store(hookCallSample(false))
	sampleNow(t, e, b)
	checkFoldedCall(t, e, "latebox")
}

// Without the feed's stream nothing waits: the sample records what it sees.
func TestSampleRecordsAtOnceWithoutTheFeed(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, _ := kernelBox(t, "nofeedbox", &sample)
	sample.Store(hookCallSample(true))
	sampleNow(t, e, b)
	if n := len(processRecords(e, "nofeedbox")); n != 11 {
		t.Fatalf("records = %d, want a start for each of the 11 processes", n)
	}
}
