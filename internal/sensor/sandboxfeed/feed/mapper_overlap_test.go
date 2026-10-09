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

package feed

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// parentProc is fakeProc with the parent pids of /proc.
type parentProc struct {
	fakeProc
	parents map[int]int
}

func (p parentProc) PPid(pid int) (int, bool) {
	ppid, ok := p.parents[pid]
	return ppid, ok
}

// GAP-0099 (TS r5): Claude starts several hooks for one event at once. A
// tool two forks below one call's script ($(printf ... | jq ...)) was
// counted to the newest running call, so overlapping calls of 12 tools each
// said [hook tools: 5] and [hook tools: 26]. The fork's ancestry in /proc
// names its own call; without it the newest call keeps the count.
func TestMapperCountsOverlappingHookCallsApart(t *testing.T) {
	init := proc{pid: 9500, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	agent := proc{pid: 9501, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	launcherA := proc{pid: 9502, ktime: 3e8, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	scriptA := proc{pid: 9503, ktime: 3e8 + 1e6, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcherA}
	launcherB := proc{pid: 9504, ktime: 3e8 + 2e6, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	scriptB := proc{pid: 9505, ktime: 3e8 + 3e6, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcherB}
	// A's command substitution and its pipeline stage, seen only at their
	// exits, and the jq the stage runs.
	outerA := proc{pid: 9506, ktime: 3e8 + 4e6, docker: workload, binary: sandboxClaudeHook, args: scriptA.args, parent: &scriptA}
	stageA := proc{pid: 9507, ktime: 3e8 + 5e6, docker: workload, binary: sandboxClaudeHook, args: scriptA.args, parent: &outerA}
	jqA := proc{pid: 9508, ktime: 3e8 + 6e6, docker: workload, binary: "/usr/bin/jq", args: "-r .hook_event_name", parent: &stageA}
	curlB := proc{pid: 9509, ktime: 3e8 + 7e6, docker: workload, binary: "/usr/bin/curl", args: "-q -s", parent: &scriptB}
	// After B ended, the substitution runs tail: its parent fork is known by
	// then, so it takes the call that fork was placed on (TS r5: one tail
	// was flagged hook_subtree_unexpected under the call that had ended).
	tailA := proc{pid: 9510, ktime: 3e8 + 9e6, docker: workload, binary: "/usr/bin/tail", args: "-1", parent: &outerA}
	run := func(t *testing.T, procs ProcReader) (toolsA, toolsB, shown int) {
		t.Helper()
		m := NewMapper(MapperConfig{Containers: testContainers(), Proc: procs})
		ctx := context.Background()
		for _, p := range []proc{init, agent, launcherA, scriptA, launcherB, scriptB} {
			m.Map(ctx, execOf(p))
		}
		summary := func(script proc) int {
			got := m.Map(ctx, exitOf(script, 0, ""))
			if len(got) != 2 || got[0].Frame.Kind != sandboxfeed.FrameExec || !got[1].Frame.Hook {
				t.Fatalf("summary of %d = %+v", script.pid, got)
			}
			return got[1].Frame.HookTools
		}
		for _, response := range [][]Item{m.Map(ctx, execOf(jqA)), m.Map(ctx, execOf(curlB)), m.Map(ctx, exitOf(curlB, 0, ""))} {
			shown += len(response)
		}
		toolsB = summary(scriptB)
		for _, response := range [][]Item{m.Map(ctx, execOf(tailA)), m.Map(ctx, exitOf(tailA, 0, "")),
			m.Map(ctx, exitOf(jqA, 0, "")), m.Map(ctx, exitOf(stageA, 0, "")), m.Map(ctx, exitOf(outerA, 0, ""))} {
			shown += len(response)
		}
		return summary(scriptA), toolsB, shown
	}
	nsOnly := fakeProc{init.pid: {ns: 1, ticks: ticksAt(init.ktime)}}
	withParents := parentProc{fakeProc: nsOnly, parents: map[int]int{
		stageA.pid: outerA.pid, outerA.pid: scriptA.pid, scriptA.pid: launcherA.pid, launcherA.pid: agent.pid,
	}}
	if a, b, shown := run(t, withParents); a != 2 || b != 1 || shown != 0 {
		t.Fatalf("hook tools: call A %d, call B %d, %d frames shown; want 2, 1 and none", a, b, shown)
	}
	// The fork ended before /proc was read: the newest call keeps it, and a
	// later tool of the same fork is shown, the safe direction.
	if _, _, shown := run(t, nsOnly); shown == 0 {
		t.Fatal("without /proc a tool under an ended call was folded")
	}
}

func TestHostProcReadsTheParentPid(t *testing.T) {
	root := t.TempDir()
	writeProc(t, root, 4100, "bash", "5", "NSpid:\t4100\t12\nPPid:\t4099\n")
	writeProc(t, root, 4101, "odd", "5", "")
	p := HostProc{Root: root}
	if ppid, ok := p.PPid(4100); !ok || ppid != 4099 {
		t.Fatalf("4100's parent = %d %v", ppid, ok)
	}
	for _, pid := range []int{4101, 999, 0} {
		if _, ok := p.PPid(pid); ok {
			t.Fatalf("pid %d read", pid)
		}
	}
}
