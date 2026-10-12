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
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"
	"google.golang.org/protobuf/types/known/wrapperspb"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
	pb "github.com/defenseclaw/defenseclaw/third_party/tetragon/api/v1/tetragon"
)

// Test containers: the workload and supervisor of one sandbox of uid 1000, a
// sandbox of uid 1001, and a container that is not an OpenShell sandbox.
const (
	workload   = "e323c06c37041c0c6e72d9d8d0d8786"
	supervisor = "23f7ebb0e93ee786a75d0c26267e465"
	otherUser  = "aaaabbbbccccddddeeeeffff0000111"
	plain      = "0123456789abcdef0123456789abcde"
)

type fakeContainers map[string]Container

func (f fakeContainers) Resolve(_ context.Context, id string) (Container, bool) {
	c, ok := f[id]
	return c, ok
}

func testContainers() fakeContainers {
	return fakeContainers{
		workload:   {ID: workload + "0", SandboxID: "sb-1", SandboxName: "myapp-claude", Role: sandboxfeed.RoleSandbox, Owner: 1000},
		supervisor: {ID: supervisor + "0", SandboxID: "sb-1", SandboxName: "myapp-claude", Role: sandboxfeed.RoleSupervisor, Owner: 1000},
		otherUser:  {ID: otherUser + "0", SandboxID: "sb-2", SandboxName: "theirs", Role: sandboxfeed.RoleSandbox, Owner: 1001},
	}
}

// fakeProc answers NSpid for the processes it holds.
type fakeProc map[int]struct {
	ns    int
	ticks int64
}

func (f fakeProc) NSPid(pid int) (int, int64, bool) {
	p, ok := f[pid]
	return p.ns, p.ticks, ok
}

// execID is Tetragon's id of an image started ktime nanoseconds after boot.
func execID(ktime int64, pid int) string {
	return base64.StdEncoding.EncodeToString(fmt.Appendf(nil, "dccert-node:%d:%d", ktime, pid))
}

type proc struct {
	pid      int
	ktime    int64
	docker   string
	binary   string
	args     string
	parent   *proc
	injected bool
}

func (p proc) id() string { return execID(p.ktime, p.pid) }

func (p proc) pb() *pb.Process {
	out := &pb.Process{
		ExecId: p.id(), Pid: wrapperspb.UInt32(uint32(p.pid)), Uid: wrapperspb.UInt32(1000), Cwd: "/work/myapp",
		Binary: p.binary, Arguments: p.args, Docker: p.docker, StartTime: timestamppb.New(time.Unix(1_800_000_000, p.ktime)),
		InInitTree: wrapperspb.Bool(!p.injected),
	}
	if p.parent != nil {
		out.ParentExecId = p.parent.id()
	}
	return out
}

func execOf(p proc) *pb.GetEventsResponse {
	exec := &pb.ProcessExec{Process: p.pb()}
	if p.parent != nil {
		exec.Parent = p.parent.pb()
	}
	return &pb.GetEventsResponse{Event: &pb.GetEventsResponse_ProcessExec{ProcessExec: exec}, Time: timestamppb.New(time.Unix(1_800_000_000, p.ktime))}
}

func exitOf(p proc, status uint32, signal string) *pb.GetEventsResponse {
	return &pb.GetEventsResponse{Event: &pb.GetEventsResponse_ProcessExit{ProcessExit: &pb.ProcessExit{Process: p.pb(), Status: status, Signal: signal}}}
}

// ticksAt is a /proc start, in clock ticks, of a process started ktime.
func ticksAt(ktime int64) int64 { return ktime / nsPerTick }

func one(t *testing.T, items []Item) Item {
	t.Helper()
	if len(items) != 1 {
		t.Fatalf("items = %+v, want one", items)
	}
	return items[0]
}

func TestMapperForwardsWorkloadExecsWithTheirSandboxPid(t *testing.T) {
	shell := proc{pid: 4200, ktime: 5_000_000_000, docker: workload, binary: "/bin/bash", args: "-c claude"}
	curl := proc{pid: 4242, ktime: 6_000_000_000, docker: workload, binary: "/usr/bin/curl",
		args: "--token=dccertsecretvalue https://example.invalid", parent: &shell}
	m := NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{
		4200: {ns: 7, ticks: ticksAt(shell.ktime)}, 4242: {ns: 9, ticks: ticksAt(curl.ktime)},
	}})
	ctx := context.Background()
	first := one(t, m.Map(ctx, execOf(shell)))
	if first.Owner != 1000 || first.Frame.PID != 7 || first.Frame.SandboxID != "sb-1" || first.Frame.Role != sandboxfeed.RoleSandbox {
		t.Fatalf("shell = %+v", first)
	}
	item := one(t, m.Map(ctx, execOf(curl)))
	f := item.Frame
	if f.Kind != sandboxfeed.FrameExec || f.PID != 9 || f.PPID != 7 || f.HostPID != 4242 || f.ParentHostPID != 4200 ||
		f.ExecID != curl.id() || f.ParentExecID != shell.id() || f.Binary != "/usr/bin/curl" || f.Cwd != "/work/myapp" ||
		f.UID == nil || *f.UID != 1000 || f.Injected || f.Collector || f.StartNS == 0 {
		t.Fatalf("curl = %+v", f)
	}
	// The command line is redacted before it leaves the feed.
	if strings.Contains(f.Cmdline, "dccertsecretvalue") || !strings.HasPrefix(f.Cmdline, "/usr/bin/curl ") {
		t.Fatalf("cmdline = %q", f.Cmdline)
	}
	exit := one(t, m.Map(ctx, exitOf(curl, 3, ""))).Frame
	if exit.Kind != sandboxfeed.FrameExit || exit.PID != 9 || exit.ExitCode == nil || *exit.ExitCode != 3 || exit.Signal != "" {
		t.Fatalf("exit = %+v", exit)
	}
	killed := one(t, m.Map(ctx, exitOf(shell, 0, "SIGKILL"))).Frame
	if killed.ExitCode != nil || killed.Signal != "SIGKILL" {
		t.Fatalf("killed = %+v", killed)
	}
	if s := m.Stats(); s.Execs != 2 || s.Pinned != 2 || s.Reused != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// A pid read after its process ended may name another process by then: one
// that started after the exec is not the exec's, and no pid is guessed.
func TestMapperNeverTakesAReusedPid(t *testing.T) {
	gone := proc{pid: 5000, ktime: 9_000_000_000, docker: workload, binary: "/usr/bin/cat", args: "dccert-block-marker"}
	reused := proc{pid: 5001, ktime: 9_000_000_000, docker: workload, binary: "/usr/bin/true"}
	m := NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{
		// 5001 now runs a process that started a second after the exec.
		5001: {ns: 30, ticks: ticksAt(reused.ktime + int64(time.Second))},
	}})
	ctx := context.Background()
	if f := one(t, m.Map(ctx, execOf(gone))).Frame; f.PID != 0 || f.HostPID != 5000 || f.ExecID != gone.id() {
		t.Fatalf("a process gone before its pid was read = %+v", f)
	}
	if f := one(t, m.Map(ctx, execOf(reused))).Frame; f.PID != 0 {
		t.Fatalf("a reused pid was taken: %+v", f)
	}
	if s := m.Stats(); s.Execs != 2 || s.Pinned != 0 || s.Reused != 1 {
		t.Fatalf("stats = %+v", s)
	}
	// An exec id of another shape cannot be tied to the process at its pid.
	odd := gone
	odd.pid = 5002
	response := execOf(odd)
	response.GetProcessExec().Process.ExecId = "not-base64"
	m = NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{5002: {ns: 4, ticks: 1}}})
	if f := one(t, m.Map(ctx, response)).Frame; f.PID != 0 {
		t.Fatalf("an undecodable exec id took a pid: %+v", f)
	}
}

// The supervisor's exec loop is counted per sandbox and summarized; other
// containers and host processes are not forwarded at all.
func TestMapperSummarizesTheSupervisorAndDropsOthers(t *testing.T) {
	m := NewMapper(MapperConfig{Containers: testContainers()})
	ctx := context.Background()
	for i := range 5 {
		loop := proc{pid: 6000 + i, ktime: int64(i+1) * 1e9, docker: supervisor, binary: "/openshell-supervisor", args: "health --socket /run/openshell/health.sock", injected: true}
		if items := m.Map(ctx, execOf(loop)); len(items) != 0 {
			t.Fatalf("a supervisor exec was forwarded: %+v", items)
		}
		if items := m.Map(ctx, exitOf(loop, 0, "")); len(items) != 0 {
			t.Fatalf("a supervisor exit was forwarded: %+v", items)
		}
	}
	for _, other := range []proc{
		{pid: 7000, ktime: 1e9, docker: plain, binary: "/usr/bin/claude"},
		{pid: 7001, ktime: 1e9, binary: "/usr/bin/claude"},
	} {
		if items := m.Map(ctx, execOf(other)); len(items) != 0 {
			t.Fatalf("%s was forwarded: %+v", other.docker, items)
		}
	}
	now := time.Unix(1_800_000_100, 0)
	summary := one(t, m.Summaries(now))
	if summary.Owner != 1000 || summary.Frame.Kind != sandboxfeed.FrameSummary || summary.Frame.SandboxID != "sb-1" ||
		summary.Frame.Execs != 5 || summary.Frame.Role != sandboxfeed.RoleSupervisor {
		t.Fatalf("summary = %+v", summary)
	}
	if again := m.Summaries(now); len(again) != 0 {
		t.Fatalf("the window did not restart: %+v", again)
	}
	if s := m.Stats(); s.Supervisor != 5 || s.Other != 2 || s.Execs != 0 {
		t.Fatalf("stats = %+v", s)
	}
}

// DefenseClaw's collector, exec'd into the sandbox, is marked with its
// children and the images its pid runs next; a workload process with the
// same command is not (it is in the container's init tree, and not a child of
// the container's pid 1).
func TestMapperMarksTheCollector(t *testing.T) {
	collectorArgs := "-i PATH=/usr/bin:/bin HOME=/sandbox LC_ALL=C /bin/bash -p -c \"export LC_ALL=C mode=$1\" defenseclaw-collect ps 1"
	timeout := proc{pid: 8000, ktime: 1e9, docker: workload, binary: "/usr/bin/timeout", args: "10 /usr/bin/env " + collectorArgs, injected: true}
	env := proc{pid: 8001, ktime: 2e9, docker: workload, binary: "/usr/bin/env", args: collectorArgs, parent: &timeout, injected: true}
	bash := proc{pid: 8001, ktime: 2e9 + 1000, docker: workload, binary: "/bin/bash", args: "-p -c script defenseclaw-collect ps", parent: &timeout, injected: true}
	find := proc{pid: 8002, ktime: 3e9, docker: workload, binary: "/usr/bin/find", args: "/proc -mindepth 2", parent: &bash, injected: true}
	user := proc{pid: 8100, ktime: 4e9, docker: workload, binary: "/usr/bin/env", args: collectorArgs}
	exec := proc{pid: 8200, ktime: 5e9, docker: workload, binary: "/usr/bin/ls", args: "-la", injected: true}
	m := NewMapper(MapperConfig{Containers: testContainers()})
	ctx := context.Background()
	for _, p := range []proc{timeout, env, bash, find} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; !f.Collector || !f.Injected {
			t.Fatalf("%s is not marked as the collector: %+v", p.binary, f)
		}
	}
	if f := one(t, m.Map(ctx, exitOf(find, 0, ""))).Frame; !f.Collector {
		t.Fatalf("the collector's exit is not marked: %+v", f)
	}
	if f := one(t, m.Map(ctx, execOf(user))).Frame; f.Collector {
		t.Fatalf("a workload process was taken for the collector: %+v", f)
	}
	if f := one(t, m.Map(ctx, execOf(exec))).Frame; f.Collector || !f.Injected {
		t.Fatalf("another injected process = %+v", f)
	}
}

// OpenShell's exec starts the collector as a child of the container's pid 1
// (its supervisor), inside a shell and under timeout(1), in the init tree
// (GAP-0024). It is marked with its own programs; a program the collector
// never runs stays in the tree, and the same command line started by the
// workload is not taken.
func TestMapperMarksTheCollectorOpenShellStarts(t *testing.T) {
	script := `"export LC_ALL=C mode=$1 max=$2" defenseclaw-collect ps 4096 64`
	envArgs := "-i PATH=/usr/bin:/bin HOME=/sandbox LC_ALL=C /bin/bash -p -c " + script
	init := proc{pid: 7000, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	shell := proc{pid: 7100, ktime: 1e9, docker: workload, binary: "/bin/bash", parent: &init,
		args: `-c "timeout -k 5 10 /usr/bin/env -i 'PATH=/usr/bin:/bin' 'HOME=/sandbox' 'LC_ALL=C' /bin/bash -p -c ` + script + `"`}
	timeout := proc{pid: 7100, ktime: 1e9 + 500, docker: workload, binary: "/usr/bin/timeout", args: "-k 5 10 /usr/bin/env " + envArgs, parent: &shell}
	env := proc{pid: 7101, ktime: 2e9, docker: workload, binary: "/usr/bin/env", args: envArgs, parent: &timeout}
	bash := proc{pid: 7101, ktime: 2e9 + 500, docker: workload, binary: "/bin/bash", args: "-p -c " + script, parent: &env}
	find := proc{pid: 7102, ktime: 3e9, docker: workload, binary: "/usr/bin/find", args: "/proc -mindepth 2", parent: &bash}
	tr := proc{pid: 7103, ktime: 3e9 + 50, docker: workload, binary: "/usr/bin/tr", args: `\n\0 \001\n`, parent: &bash}
	curl := proc{pid: 7104, ktime: 3e9 + 100, docker: workload, binary: "/usr/bin/curl", args: "https://example.invalid", parent: &bash}
	agent := proc{pid: 7200, ktime: 4e9, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	mimic := proc{pid: 7201, ktime: 5e9, docker: workload, binary: shell.binary, args: shell.args, parent: &agent}
	m := NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{
		7000: {ns: 1}, 7100: {ns: 50}, 7101: {ns: 51}, 7102: {ns: 52}, 7103: {ns: 53}, 7104: {ns: 54}, 7200: {ns: 60}, 7201: {ns: 61},
	}})
	ctx := context.Background()
	for _, p := range []proc{shell, timeout, env, bash, find, tr} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; !f.Collector || f.Injected {
			t.Fatalf("%s %s is not marked as the collector: %+v", p.binary, p.args, f)
		}
	}
	if f := one(t, m.Map(ctx, exitOf(find, 0, ""))).Frame; !f.Collector {
		t.Fatalf("the collector's exit is not marked: %+v", f)
	}
	if f := one(t, m.Map(ctx, execOf(curl))).Frame; f.Collector {
		t.Fatalf("a program the collector never runs was left out of the tree: %+v", f)
	}
	for _, p := range []proc{agent, mimic} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; f.Collector {
			t.Fatalf("a workload process was taken for the collector: %+v", f)
		}
	}
}

// The collector's script forks a subshell for each pipeline stage. The fork
// never execs: it has an exec id and an exit, but no exec event, so its child
// (tr) and its exit were forwarded every 5 s and filled the exited list
// (GAP-0050). Both are the collector's now; the workload's own forks, and a
// program the collector never runs below a fork, stay in the tree.
func TestMapperMarksTheCollectorsForkedPipelineStages(t *testing.T) {
	script := `"export LC_ALL=C mode=$1 max=$2" defenseclaw-collect ps 4096 64`
	envArgs := "-i PATH=/usr/bin:/bin HOME=/sandbox LC_ALL=C /bin/bash -p -c " + script
	init := proc{pid: 7000, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	shell := proc{pid: 7100, ktime: 1e9, docker: workload, binary: "/bin/bash", parent: &init,
		args: `-c "timeout -k 5 10 /usr/bin/env -i 'PATH=/usr/bin:/bin' 'HOME=/sandbox' 'LC_ALL=C' /bin/bash -p -c ` + script + `"`}
	timeout := proc{pid: 7100, ktime: 1e9 + 500, docker: workload, binary: "/usr/bin/timeout", args: "-k 5 10 /usr/bin/env " + envArgs, parent: &shell}
	env := proc{pid: 7101, ktime: 2e9, docker: workload, binary: "/usr/bin/env", args: envArgs, parent: &timeout}
	bash := proc{pid: 7101, ktime: 2e9 + 500, docker: workload, binary: "/bin/bash", args: "-p -c " + script, parent: &env}
	fork := proc{pid: 7105, ktime: 3e9, docker: workload, binary: "/bin/bash", args: "-p -c " + script, parent: &bash}
	tr := proc{pid: 7106, ktime: 3e9 + 10, docker: workload, binary: "/usr/bin/tr", args: `\n\0 \001\n`, parent: &fork}
	idle := proc{pid: 7107, ktime: 3e9 + 20, docker: workload, binary: "/bin/bash", args: "-p -c " + script, parent: &bash}
	curl := proc{pid: 7108, ktime: 3e9 + 30, docker: workload, binary: "/usr/bin/curl", args: "https://example.invalid", parent: &fork}
	agent := proc{pid: 7200, ktime: 4e9, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	agentFork := proc{pid: 7201, ktime: 4e9 + 10, docker: workload, binary: "/usr/local/bin/claude", parent: &agent}
	userTr := proc{pid: 7202, ktime: 4e9 + 20, docker: workload, binary: "/usr/bin/tr", args: "a-z A-Z", parent: &agentFork}
	m := NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{
		7000: {ns: 1}, 7100: {ns: 50}, 7101: {ns: 51}, 7105: {ns: 55}, 7106: {ns: 56}, 7107: {ns: 57}, 7108: {ns: 58},
		7200: {ns: 60}, 7201: {ns: 61}, 7202: {ns: 62},
	}})
	ctx := context.Background()
	for _, p := range []proc{shell, timeout, env, bash} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; !f.Collector {
			t.Fatalf("%s is not marked as the collector: %+v", p.binary, f)
		}
	}
	if f := one(t, m.Map(ctx, execOf(tr))).Frame; !f.Collector {
		t.Fatalf("the pipeline stage below the collector's fork is not marked: %+v", f)
	}
	if f := one(t, m.Map(ctx, execOf(curl))).Frame; f.Collector {
		t.Fatalf("a program the collector never runs, below its fork, was left out: %+v", f)
	}
	for _, p := range []proc{tr, fork, idle} {
		if f := one(t, m.Map(ctx, exitOf(p, 0, ""))).Frame; !f.Collector {
			t.Fatalf("the exit of %d (%s) is not marked: %+v", p.pid, p.binary, f)
		}
	}
	for _, p := range []proc{agent, userTr} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; f.Collector {
			t.Fatalf("a workload process was taken for the collector: %+v", f)
		}
	}
	if f := one(t, m.Map(ctx, exitOf(agentFork, 0, ""))).Frame; f.Collector {
		t.Fatalf("a workload fork's exit was taken for the collector's: %+v", f)
	}
}

// hookMapper is a mapper that reads init's pid in the sandbox as 1: the
// sandbox's supervisor, where a hook-folding agent's ancestry must end.
func hookMapper(init proc) *Mapper {
	return NewMapper(MapperConfig{Containers: testContainers(), Proc: fakeProc{init.pid: {ns: 1, ticks: ticksAt(init.ktime)}}})
}

func TestMapperFoldsVerifiedClaudeHookTools(t *testing.T) {
	const hook = sandboxClaudeHook
	if connector.SandboxHookDir+"/claude-code-hook.sh" != hook {
		t.Fatal("feed hook path differs from the image's rendered hook path")
	}
	init := proc{pid: 8000, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	agent := proc{pid: 8001, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	launcher := proc{pid: 8002, ktime: 3e8, docker: workload, binary: "/bin/sh", args: "-c " + hook, parent: &agent}
	script := proc{pid: 8003, ktime: 4e8, docker: workload, binary: hook, args: "-p " + hook, parent: &launcher}
	fork := proc{pid: 8004, ktime: 5e8, docker: workload, binary: hook, args: script.args, parent: &script}
	find := proc{pid: 8005, ktime: 6e8, docker: workload, binary: "/usr/bin/find", parent: &script}
	jq := proc{pid: 8006, ktime: 7e8, docker: workload, binary: "/usr/bin/jq", parent: &fork}
	work := proc{pid: 8007, ktime: 8e8, docker: workload, binary: "/usr/bin/python3", parent: &agent}
	unexpected := proc{pid: 8008, ktime: 9e8, docker: workload, binary: "/tmp/find", parent: &script}
	m := hookMapper(init)
	ctx := context.Background()
	m.Map(ctx, execOf(init))
	m.Map(ctx, execOf(agent))
	if got := m.Map(ctx, execOf(launcher)); len(got) != 0 {
		t.Fatalf("hook launcher forwarded before verification: %+v", got)
	}
	if got := m.Map(ctx, execOf(script)); len(got) != 0 {
		t.Fatalf("hook emitted before its subtree was known: %+v", got)
	}
	for _, p := range []proc{find, jq} {
		if got := m.Map(ctx, execOf(p)); len(got) != 0 {
			t.Fatalf("known hook tool visible: %+v", got)
		}
	}
	if f := one(t, m.Map(ctx, execOf(work))).Frame; f.HookTool || f.Hook {
		t.Fatalf("workload hidden: %+v", f)
	}
	got := m.Map(ctx, exitOf(script, 0, ""))
	if len(got) != 2 || !got[0].Frame.Hook || !got[1].Frame.Hook || got[1].Frame.HookTools != 2 {
		t.Fatalf("hook summary = %+v", got)
	}
	if got := m.Map(ctx, exitOf(launcher, 0, "")); len(got) != 0 {
		t.Fatalf("verified launcher exit forwarded: %+v", got)
	}
	// A second call with an unexpected executable releases every event
	// already held for that call, including the launcher and known tool.
	launcher2 := launcher
	launcher2.pid, launcher2.ktime = 8012, 13e8
	script2 := script
	script2.pid, script2.ktime, script2.parent = 8013, 14e8, &launcher2
	find2 := find
	find2.pid, find2.ktime, find2.parent = 8014, 15e8, &script2
	unexpected.parent = &script2
	m.Map(ctx, execOf(launcher2))
	m.Map(ctx, execOf(script2))
	m.Map(ctx, execOf(find2))
	got = m.Map(ctx, execOf(unexpected))
	if len(got) != 4 {
		t.Fatalf("unexpected subtree released %d events, want launcher, script, tool and child: %+v", len(got), got)
	}
	for _, item := range got {
		if item.Frame.Hook || item.Frame.HookTool {
			t.Fatalf("unexpected subtree still summarized: %+v", item.Frame)
		}
	}
	if !got[3].Frame.HookUnexpected {
		t.Fatalf("unexpected child not flagged: %+v", got[3].Frame)
	}
}

func TestMapperLeavesHookLookalikesVisible(t *testing.T) {
	// The processes a case's agent may run below. A tool call's shell is a
	// child of the agent (Claude Code runs each command as bash -c); an MCP
	// server is one the agent starts directly; a program named like the
	// supervisor is not the sandbox's pid 1.
	init := proc{pid: 8500, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	outer := proc{pid: 8505, ktime: 15e7, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	toolShell := proc{pid: 8501, ktime: 2e8, docker: workload, binary: "/bin/bash", args: `-c "eval 'claude -p hi'"`, parent: &outer}
	mcpServer := proc{pid: 8506, ktime: 2e8 + 1, docker: workload, binary: "/usr/bin/node", args: "/sandbox/work/myapp/mcp.js", parent: &outer}
	unseen := proc{pid: 8507, ktime: 5e7, docker: workload, binary: "/bin/bash", args: "-l"}
	fakeInit := proc{pid: 8508, ktime: 2e8 + 2, docker: workload, binary: "/tmp/openshell-sandbox", parent: &unseen}
	for _, tc := range []struct {
		name, command, script string
		agentParent           *proc
		before                []proc
		noPID                 bool
	}{
		{"different path", "-c " + sandboxClaudeHook, "/tmp/claude-code-hook.sh", &init, []proc{init}, false},
		{"environment wrapper", "-c env X=1 " + sandboxClaudeHook, sandboxClaudeHook, &init, []proc{init}, false},
		{"tool shell", "-c " + sandboxClaudeHook, sandboxClaudeHook, &toolShell, []proc{init, outer, toolShell}, false},
		{"agent an agent started", "-c " + sandboxClaudeHook, sandboxClaudeHook, &mcpServer, []proc{init, outer, mcpServer}, false},
		{"program named like the supervisor", "-c " + sandboxClaudeHook, sandboxClaudeHook, &fakeInit, []proc{fakeInit}, false},
		{"supervisor not seen", "-c " + sandboxClaudeHook, sandboxClaudeHook, &init, nil, false},
		{"supervisor pid not read", "-c " + sandboxClaudeHook, sandboxClaudeHook, &init, []proc{init}, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			m := hookMapper(init)
			if tc.noPID {
				m = NewMapper(MapperConfig{Containers: testContainers()})
			}
			for _, p := range tc.before {
				m.Map(ctx, execOf(p))
			}
			agent := proc{pid: 8502, ktime: 3e8, docker: workload, binary: "/usr/local/bin/claude", parent: tc.agentParent}
			launcher := proc{pid: 8503, ktime: 4e8, docker: workload, binary: "/bin/sh", args: tc.command, parent: &agent}
			script := proc{pid: 8504, ktime: 5e8, docker: workload, binary: tc.script, args: "-p " + tc.script, parent: &launcher}
			m.Map(ctx, execOf(agent))
			m.Map(ctx, execOf(launcher))
			if f := one(t, m.Map(ctx, execOf(script))).Frame; f.Hook || f.HookTool {
				t.Fatalf("lookalike script was summarized: %+v", f)
			}
			if got := m.Map(ctx, exitOf(launcher, 0, "")); len(got) == 0 {
				t.Fatal("lookalike launcher exit was hidden")
			}
		})
	}
}

// A real sandbox's Claude Code (TS r4, GAP-0063): the supervisor starts it
// through its launch shell, bash -c "cd ... && claudecode-launch ...", and
// claudecode-launch, the supervisor script and env, each replacing the last
// in its pid; the hook script runs its tools directly and in the forks of
// its command substitutions. That launch shell was taken for a tool call's
// shell, so no hook call of a real sandbox was folded.
func TestMapperFoldsHooksOfTheClaudeTheSandboxStarted(t *testing.T) {
	init := proc{pid: 9100, ktime: 1e8, docker: workload, binary: "/.openshell/runtime/openshell-sandbox", args: "--bootstrap /.openshell/channel/sandbox/bootstrap.json"}
	launch := proc{pid: 9195, ktime: 2e8, docker: workload, binary: "/bin/bash", parent: &init,
		args: `-c "cd /sandbox/work/myapp && /usr/local/lib/defenseclaw/bin/claudecode-launch --dangerously-skip-permissions"`}
	claudeLaunch := proc{pid: 9195, ktime: 2e8 + 1e6, docker: workload, binary: "/usr/local/lib/defenseclaw/bin/claudecode-launch", parent: &launch,
		args: "-p /usr/local/lib/defenseclaw/bin/claudecode-launch --dangerously-skip-permissions"}
	supervisor := proc{pid: 9195, ktime: 2e8 + 2e6, docker: workload, binary: "/usr/bin/python3", parent: &claudeLaunch,
		args: "-I -S /usr/local/lib/defenseclaw/bin/dc_supervisor.py /usr/bin/env -u BASH_ENV /usr/local/bin/claude --dangerously-skip-permissions"}
	env := proc{pid: 9200, ktime: 3e8, docker: workload, binary: "/usr/bin/env", args: "-u BASH_ENV /usr/local/bin/claude --dangerously-skip-permissions", parent: &supervisor}
	agent := proc{pid: 9200, ktime: 3e8 + 1e6, docker: workload, binary: "/usr/local/bin/claude", args: "--dangerously-skip-permissions", parent: &env}
	launcher := proc{pid: 9232, ktime: 4e8, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	script := proc{pid: 9233, ktime: 4e8 + 1e6, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcher}
	find := proc{pid: 9234, ktime: 4e8 + 2e6, docker: workload, binary: "/usr/bin/find", args: "/usr/local/lib/defenseclaw -mindepth 1", parent: &script}
	subst := proc{pid: 9235, ktime: 4e8 + 3e6, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &script}
	curl := proc{pid: 9236, ktime: 4e8 + 4e6, docker: workload, binary: "/usr/bin/curl", args: "-q -s", parent: &subst}
	// $(printf ... | jq ...): jq's parent is the pipeline's fork, whose parent,
	// the command substitution's fork, the feed sees only at its exit.
	outer := proc{pid: 9237, ktime: 4e8 + 5e6, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &script}
	stage := proc{pid: 9238, ktime: 4e8 + 6e6, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &outer}
	printf := proc{pid: 9239, ktime: 4e8 + 7e6, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &outer}
	jq := proc{pid: 9242, ktime: 4e8 + 8e6, docker: workload, binary: "/usr/bin/jq", args: "-r .hook_event_name", parent: &stage}
	tool := proc{pid: 9240, ktime: 5e8, docker: workload, binary: "/bin/bash", args: `-c "eval '/bin/true ts4-user-marker'"`, parent: &agent}
	marker := proc{pid: 9241, ktime: 5e8 + 1e6, docker: workload, binary: "/usr/bin/true", args: "ts4-user-marker", parent: &tool}

	m := hookMapper(init)
	ctx := context.Background()
	for _, p := range []proc{init, launch, claudeLaunch, supervisor, env, agent} {
		one(t, m.Map(ctx, execOf(p)))
	}
	for _, p := range []proc{launcher, script, find, curl} {
		if got := m.Map(ctx, execOf(p)); len(got) != 0 {
			t.Fatalf("hook process %s forwarded: %+v", p.binary, got)
		}
	}
	for _, p := range []proc{tool, marker} {
		if f := one(t, m.Map(ctx, execOf(p))).Frame; f.Hook || f.HookTool {
			t.Fatalf("the workload was folded: %+v", f)
		}
	}
	if got := m.Map(ctx, exitOf(printf, 0, "")); len(got) != 0 {
		t.Fatalf("a pipeline fork's exit forwarded: %+v", got)
	}
	if got := m.Map(ctx, execOf(jq)); len(got) != 0 {
		t.Fatalf("jq in a command substitution's pipeline forwarded: %+v", got)
	}
	for _, p := range []proc{curl, subst, find, jq, stage, outer} {
		if got := m.Map(ctx, exitOf(p, 0, "")); len(got) != 0 {
			t.Fatalf("hook process %s exit forwarded: %+v", p.binary, got)
		}
	}
	got := m.Map(ctx, exitOf(script, 0, ""))
	if len(got) != 2 || got[0].Frame.Kind != sandboxfeed.FrameExec || got[0].Frame.Binary != sandboxClaudeHook ||
		!got[0].Frame.Hook || !got[1].Frame.Hook || got[1].Frame.HookTools != 3 {
		t.Fatalf("hook summary = %+v", got)
	}
	if got := m.Map(ctx, exitOf(launcher, 0, "")); len(got) != 0 {
		t.Fatalf("verified launcher exit forwarded: %+v", got)
	}
	if f := one(t, m.Map(ctx, exitOf(marker, 0, ""))).Frame; f.Hook || f.HookTool {
		t.Fatalf("the workload's exit was folded: %+v", f)
	}
}

// A fork of the hook script whose parent fork was not seen joins the
// running verified call only while no other run of the script of that
// container and user is live: a run the workload started could be its
// origin, so its tools stay visible.
func TestMapperLeavesNestedHookForksVisibleBesideAnotherRun(t *testing.T) {
	init := proc{pid: 9400, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	agent := proc{pid: 9401, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	launcher := proc{pid: 9402, ktime: 3e8, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	script := proc{pid: 9403, ktime: 4e8, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcher}
	toolShell := proc{pid: 9404, ktime: 5e8, docker: workload, binary: "/bin/bash", args: `-c "eval 'claude-code-hook.sh < x'"`, parent: &agent}
	ownRun := proc{pid: 9405, ktime: 6e8, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &toolShell}
	outer := proc{pid: 9406, ktime: 7e8, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &ownRun}
	stage := proc{pid: 9407, ktime: 8e8, docker: workload, binary: sandboxClaudeHook, args: script.args, parent: &outer}
	jq := proc{pid: 9408, ktime: 9e8, docker: workload, binary: "/usr/bin/jq", parent: &stage}
	m := hookMapper(init)
	ctx := context.Background()
	for _, p := range []proc{init, agent, launcher, script, toolShell, ownRun} {
		m.Map(ctx, execOf(p))
	}
	if f := one(t, m.Map(ctx, execOf(jq))).Frame; f.Hook || f.HookTool {
		t.Fatalf("a tool below an unverified run was folded: %+v", f)
	}
	if f := one(t, m.Map(ctx, exitOf(jq, 0, ""))).Frame; f.Hook || f.HookTool {
		t.Fatalf("its exit was folded: %+v", f)
	}
}

// The ancestry table holds running processes: an ended process and the
// images it replaced leave it, so hook folding is still on after more
// processes than the table holds (GAP-0063: it filled after about 16k and
// turned folding off for as long as the stream lasted).
func TestMapperForgetsEndedProcessesAndKeepsFolding(t *testing.T) {
	init := proc{pid: 9300, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	agent := proc{pid: 9301, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	m := hookMapper(init)
	ctx := context.Background()
	m.Map(ctx, execOf(init))
	m.Map(ctx, execOf(agent))
	for i := range tracked + 100 {
		pid := 10_000 + i
		shell := proc{pid: pid, ktime: 3e8 + int64(i)*10, docker: workload, binary: "/bin/bash", args: `-c "eval 'git status'"`, parent: &agent}
		git := proc{pid: pid, ktime: shell.ktime + 1, docker: workload, binary: "/usr/bin/git", args: "status", parent: &shell}
		m.Map(ctx, execOf(shell))
		m.Map(ctx, execOf(git))
		m.Map(ctx, exitOf(git, 0, ""))
	}
	if !m.hookTrust || len(m.hookProcs.m) != 2 {
		t.Fatalf("after %d processes: hook folding %v, %d table entries (want init and the agent)", tracked+100, m.hookTrust, len(m.hookProcs.m))
	}
	launcher := proc{pid: 9302, ktime: 9e9, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	script := proc{pid: 9303, ktime: 9e9 + 1, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcher}
	m.Map(ctx, execOf(launcher))
	if got := m.Map(ctx, execOf(script)); len(got) != 0 {
		t.Fatalf("hook call not folded after many processes: %+v", got)
	}
	if got := m.Map(ctx, exitOf(script, 0, "")); len(got) != 2 || !got[1].Frame.Hook {
		t.Fatalf("hook summary = %+v", got)
	}
	m.Map(ctx, exitOf(launcher, 0, ""))
	if len(m.hookProcs.m) != 2 {
		t.Fatalf("a finished hook call stayed in the table: %d entries", len(m.hookProcs.m))
	}
}

func TestMapperReleasesUnfinishedHookOnStreamEnd(t *testing.T) {
	ctx := context.Background()
	init := proc{pid: 8600, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	m := hookMapper(init)
	agent := proc{pid: 8601, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	launcher := proc{pid: 8602, ktime: 3e8, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	script := proc{pid: 8603, ktime: 4e8, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcher}
	tool := proc{pid: 8604, ktime: 5e8, docker: workload, binary: "/usr/bin/jq", parent: &script}
	for _, p := range []proc{init, agent, launcher, script, tool} {
		m.Map(ctx, execOf(p))
	}
	got := m.DisableHooks()
	if len(got) != 3 {
		t.Fatalf("stream end released %d events, want launcher, script and tool", len(got))
	}
	for _, item := range got {
		if item.Frame.Hook || item.Frame.HookTool || item.Owner != 1000 {
			t.Fatalf("stream end kept a hidden event: %+v", item)
		}
	}
	if again := m.DisableHooks(); len(again) != 0 {
		t.Fatalf("stream end duplicated events: %+v", again)
	}
	later := proc{pid: 8605, ktime: 6e8, docker: workload, binary: "/usr/bin/find", parent: &script}
	if f := one(t, m.Map(ctx, execOf(later))).Frame; f.HookTool || f.Hook {
		t.Fatalf("process after stream loss was hidden: %+v", f)
	}
}

func TestMapperReleasesHookBeforeAncestryEviction(t *testing.T) {
	ctx := context.Background()
	init := proc{pid: 8700, ktime: 1e8, docker: workload, binary: "/usr/local/bin/openshell-sandbox"}
	m := hookMapper(init)
	agent := proc{pid: 8701, ktime: 2e8, docker: workload, binary: "/usr/local/bin/claude", parent: &init}
	launcher := proc{pid: 8702, ktime: 3e8, docker: workload, binary: "/bin/sh", args: "-c " + sandboxClaudeHook, parent: &agent}
	script := proc{pid: 8703, ktime: 4e8, docker: workload, binary: sandboxClaudeHook, args: "-p " + sandboxClaudeHook, parent: &launcher}
	tool := proc{pid: 8704, ktime: 5e8, docker: workload, binary: "/usr/bin/jq", parent: &script}
	for _, p := range []proc{init, agent, launcher, script, tool} {
		m.Map(ctx, execOf(p))
	}
	for i := len(m.hookProcs.m); i < tracked-1; i++ {
		m.hookProcs.put(fmt.Sprintf("unrelated-%d", i), &hookProcess{})
	}
	work := proc{pid: 8705, ktime: 6e8, docker: workload, binary: "/bin/true", parent: &agent}
	got := m.Map(ctx, execOf(work))
	if len(got) != 4 || m.hookTrust {
		t.Fatalf("capacity fallback released %d events, trust=%v", len(got), m.hookTrust)
	}
	for _, item := range got {
		if item.Frame.Hook || item.Frame.HookTool {
			t.Fatalf("capacity fallback hid %+v", item.Frame)
		}
	}
}

// A Codex notify program's arguments (the turn's JSON) never leave the feed.
func TestMapperWithholdsNotifyArguments(t *testing.T) {
	notify := proc{pid: 9000, ktime: 1e9, docker: workload, binary: "/sandbox/.defenseclaw/notify-bridge.sh",
		args: `{"type":"agent-turn-complete","last-assistant-message":"dccert-payload-marker"}`}
	f := one(t, NewMapper(MapperConfig{Containers: testContainers()}).Map(context.Background(), execOf(notify))).Frame
	if strings.Contains(f.Cmdline, "dccert-payload-marker") || !strings.Contains(f.Cmdline, redaction.WithheldArgv) {
		t.Fatalf("notify cmdline = %q", f.Cmdline)
	}
}

func TestExecKtime(t *testing.T) {
	if ktime, pid, ok := execKtime(execID(4121774088780, 217400)); !ok || ktime != 4121774088780 || pid != 217400 {
		t.Fatalf("decoded %d %d %v", ktime, pid, ok)
	}
	for _, bad := range []string{"", "!!!", base64.StdEncoding.EncodeToString([]byte("node:x:1")),
		base64.StdEncoding.EncodeToString([]byte("node:5")), base64.StdEncoding.EncodeToString([]byte("node:5:-1"))} {
		if _, _, ok := execKtime(bad); ok {
			t.Errorf("%q decoded", bad)
		}
	}
}

func TestBoundedMapForgetsInsteadOfGrowing(t *testing.T) {
	b := newBoundedMap[int, int](8)
	for i := range 100 {
		b.put(i, i)
	}
	if len(b.m) > 8 {
		t.Fatalf("holds %d entries", len(b.m))
	}
	if v, ok := b.get(99); !ok || v != 99 {
		t.Fatal("the newest entry is gone")
	}
}

// The container runtime's init, which starts every exec into the container,
// is counted, not forwarded; the command that replaces it is.
func TestMapperLeavesOutTheRuntimesInit(t *testing.T) {
	runc := proc{pid: 8300, ktime: 1e9, docker: workload, binary: "/proc/self/fd/6", args: "init", injected: true}
	ls := proc{pid: 8300, ktime: 1e9 + 500, docker: workload, binary: "/usr/bin/ls", args: "-la", injected: true}
	m := NewMapper(MapperConfig{Containers: testContainers()})
	ctx := context.Background()
	if items := m.Map(ctx, execOf(runc)); len(items) != 0 {
		t.Fatalf("runc init was forwarded: %+v", items)
	}
	if f := one(t, m.Map(ctx, execOf(ls))).Frame; f.Binary != "/usr/bin/ls" || !f.Injected {
		t.Fatalf("the exec's command = %+v", f)
	}
	// Its exit is left out too, so exits match execs (GAP-0026).
	if items := m.Map(ctx, exitOf(runc, 0, "")); len(items) != 0 {
		t.Fatalf("runc init's exit was forwarded: %+v", items)
	}
	if f := one(t, m.Map(ctx, exitOf(ls, 0, ""))).Frame; f.Kind != sandboxfeed.FrameExit || f.Binary != "/usr/bin/ls" {
		t.Fatalf("the command's exit = %+v", f)
	}
	// The workload's own process named like it is forwarded: only an exec
	// into the container is the runtime's.
	own := runc
	own.pid, own.injected = 8301, false
	if items := m.Map(ctx, execOf(own)); len(items) != 1 {
		t.Fatalf("a workload process was left out: %+v", items)
	}
	if s := m.Stats(); s.Runtime != 1 || s.Execs != 2 {
		t.Fatalf("stats = %+v", s)
	}
}
