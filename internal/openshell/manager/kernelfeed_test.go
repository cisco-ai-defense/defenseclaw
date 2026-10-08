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
	"encoding/base64"
	"errors"
	"io"
	"runtime"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// feedID is a Tetragon-shaped exec id.
func feedID(name string) string {
	return base64.StdEncoding.EncodeToString([]byte("dccert-node:" + name))
}

// sampleHandler answers the process sample with *sample, as treeEnv's does.
func sampleHandler(sample *atomic.Pointer[string]) openshelltest.ExecHandler {
	return func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isCollect(call) && call.Command[10] == "ps" {
			if s := sample.Load(); s != nil {
				return openshelltest.ExecResponse{Stdout: []byte(*s)}
			}
		}
		return openshelltest.ExecResponse{}
	}
}

// kernelBox is a running manager with one ready docker sandbox whose
// process tree is on, and its OpenShell id. Its feed connection waits
// forever, so the test drives the frames and the feed's state itself.
func kernelBox(t *testing.T, name string, sample *atomic.Pointer[string]) (*harnessEnv, *box, string) {
	t.Helper()
	e := newEnv(t, nil)
	e.handleExec(sampleHandler(sample))
	withKernelFeed(e, func(ctx context.Context) (KernelFeedStream, error) {
		<-ctx.Done()
		return nil, ctx.Err()
	})
	e.live(sandboxapi.CreateRequest{Name: name, ProcessTree: true})
	b := e.boxOf(name)
	return e, b, sandboxIDOf(e, b)
}

// sandboxIDOf is the box's OpenShell sandbox id, which the feed names it by
// (the fake gateway gives its sandboxes none, so the test does).
func sandboxIDOf(e *harnessEnv, b *box) string {
	e.m.mu.Lock()
	defer e.m.mu.Unlock()
	if b.rec.ID == "" {
		b.rec.ID = "0adf0c94-" + b.rec.Name
	}
	return b.rec.ID
}

func execFrame(sandboxID, exec, parent string, hostPID, pid int, binary, cmdline string, at time.Time) sandboxfeed.Frame {
	uid := 1000
	return sandboxfeed.Frame{Kind: sandboxfeed.FrameExec, At: at, SandboxID: sandboxID, Role: sandboxfeed.RoleSandbox,
		ExecID: feedID(exec), ParentExecID: parentID(parent), HostPID: hostPID, PID: pid, UID: &uid,
		Binary: binary, Cmdline: cmdline, Cwd: "/sandbox/work/myapp", StartNS: at.UnixNano()}
}

func parentID(name string) string {
	if name == "" {
		return ""
	}
	return feedID(name)
}

func exitFrame(sandboxID, exec string, hostPID, code int, at time.Time) sandboxfeed.Frame {
	return sandboxfeed.Frame{Kind: sandboxfeed.FrameExit, At: at, SandboxID: sandboxID, ExecID: feedID(exec), HostPID: hostPID, ExitCode: &code}
}

func processRecords(e *harnessEnv, name string) []audit.SandboxProcessEvent {
	return where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool { return ev.Sandbox.Name == name })
}

// Every exec and exit the feed reports joins the tree with Tetragon's ids:
// a process with its in-sandbox pid among the live ones, one without by its
// exec id and host pid only, recorded either way; DefenseClaw's own
// collector is left out.
func TestKernelFeedFramesJoinTheTree(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, id := kernelBox(t, "feedbox", &sample)
	ctx := context.Background()
	now := time.Now().Add(-time.Second)
	e.m.observeKernelFrame(ctx, b, execFrame(id, "bash", "", 9100, 7, "/bin/bash", "/bin/bash -l", now))
	e.m.observeKernelFrame(ctx, b, execFrame(id, "cat", "bash", 9101, 0, "/usr/bin/cat",
		"/usr/bin/cat --password=dccertvalue dccert-block-marker", now.Add(time.Millisecond)))
	collector := execFrame(id, "collect", "", 9200, 30, "/usr/bin/env", "/usr/bin/env -i PATH=/usr/bin:/bin", now)
	collector.Collector, collector.Injected = true, true
	e.m.observeKernelFrame(ctx, b, collector)
	e.m.observeKernelFrame(ctx, b, exitFrame(id, "cat", 9101, 0, now.Add(3*time.Millisecond)))
	e.m.observeKernelFrame(ctx, b, sandboxfeed.Frame{Kind: sandboxfeed.FrameSummary, SandboxID: id, Execs: 180})

	list, err := e.m.Processes(ctx, "feedbox")
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Processes) != 1 {
		t.Fatalf("live = %+v, want the pinned bash only", list.Processes)
	}
	bash := list.Processes[0]
	if bash.PID != 7 || bash.HostPID != 9100 || bash.Source != audit.SandboxProcessSourceTetragon || bash.Comm != "bash" ||
		bash.Exe != "/bin/bash" || bash.Cwd != "/sandbox/work/myapp" || bash.UID != 1000 {
		t.Fatalf("bash = %+v", bash)
	}
	if len(list.Exited) != 1 {
		t.Fatalf("exited = %+v", list.Exited)
	}
	cat := list.Exited[0]
	if cat.PID != 0 || cat.HostPID != 9101 || cat.PPID != 7 || cat.ExitCode == nil || *cat.ExitCode != 0 ||
		strings.Contains(cat.Cmdline, "dccertvalue") {
		t.Fatalf("cat = %+v", cat)
	}

	records := processRecords(e, "feedbox")
	if len(records) != 3 {
		t.Fatalf("records = %+v", records)
	}
	for _, r := range records {
		if r.Source != audit.SandboxProcessSourceTetragon || r.HostPID == 0 || r.ExecID == "" {
			t.Fatalf("record = %+v", r)
		}
	}
	if catStart := records[1]; catStart.PID != 0 || catStart.HostPID != 9101 || !slices.Equal(catStart.Lineage, []string{"bash"}) {
		t.Fatalf("cat start = %+v", catStart)
	}
	if catExit := records[2]; catExit.Event != audit.SandboxProcessExit || catExit.ExitCode == nil {
		t.Fatalf("cat exit = %+v", catExit)
	}

	// The feed's counts show once it is connected.
	if list.Kernel != nil {
		t.Fatalf("a feed nobody connected to is in the list: %+v", list.Kernel)
	}
	e.m.kfeed.up(sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: "1.2.3", Tetragon: sandboxfeed.TetragonConnected})
	list, _ = e.m.Processes(ctx, "feedbox")
	if k := list.Kernel; k == nil || !k.Connected || k.Execs != 2 || k.Pinned != 1 || k.CollectorExecs != 1 ||
		k.SupervisorExecs != 180 || k.Source != audit.SandboxProcessSourceTetragon {
		t.Fatalf("kernel = %+v", list.Kernel)
	}
	// A duplicate exec changes nothing.
	e.m.observeKernelFrame(ctx, b, execFrame(id, "bash", "", 9100, 7, "/bin/bash", "/bin/bash -l", now))
	if n := len(processRecords(e, "feedbox")); n != 3 {
		t.Fatalf("a duplicate exec was recorded (%d records)", n)
	}
}

// The sample and the feed name the same process once: the sample fills in
// a process the feed reported, the feed names one the sample saw first, and
// a new image at a host pid ends the one it replaced.
func TestKernelFeedAndTheSampleAgree(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init", "P 42 1 1000 20", "Pc 42 claude", "L /proc/42 exe /usr/bin/claude"))
	e, b, id := kernelBox(t, "agreebox", &sample)
	ctx := context.Background()
	if _, ok := e.m.sampleProcesses(ctx, b); !ok {
		t.Fatal("no sample")
	}
	now := time.Now()
	e.m.observeKernelFrame(ctx, b, execFrame(id, "claude", "", 9300, 42, "/usr/bin/claude", "/usr/bin/claude", now))
	e.m.observeKernelFrame(ctx, b, execFrame(id, "bash", "claude", 9301, 43, "/bin/bash", "/bin/bash -c ls", now))
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init", "P 42 1 1000 20", "Pc 42 claude", "P 43 42 1000 30", "Pc 43 bash",
		"L /proc/42 exe /usr/bin/claude", "L /proc/43 exe /bin/bash"))
	time.Sleep(time.Millisecond)
	e.m.sampleProcesses(ctx, b)
	starts := func() map[int]int {
		out := map[int]int{}
		for _, r := range processRecords(e, "agreebox") {
			if r.Event == audit.SandboxProcessStart {
				out[r.PID]++
			}
		}
		return out
	}
	if s := starts(); s[42] != 1 || s[43] != 1 || s[1] != 1 {
		t.Fatalf("starts by pid = %v, want each once", s)
	}
	list, _ := e.m.Processes(ctx, "agreebox")
	byPID := map[int]sandboxapi.Process{}
	for _, p := range list.Processes {
		byPID[p.PID] = p
	}
	if p := byPID[42]; p.Source != audit.SandboxProcessSourceSample || p.HostPID != 9300 {
		t.Fatalf("claude = %+v, want the sample's, named by the feed", p)
	}
	if p := byPID[43]; p.Source != audit.SandboxProcessSourceTetragon || p.PPID != 42 || p.StartedAt.IsZero() {
		t.Fatalf("bash = %+v, want the feed's, filled in by the sample", p)
	}
	// bash execs python3 in place (same pids): bash ends, python3 starts.
	e.m.observeKernelFrame(ctx, b, execFrame(id, "python3", "claude", 9301, 43, "/usr/bin/python3", "/usr/bin/python3 -V", now.Add(time.Second)))
	list, _ = e.m.Processes(ctx, "agreebox")
	if len(list.Exited) != 1 || list.Exited[0].Exe != "/bin/bash" {
		t.Fatalf("exited = %+v", list.Exited)
	}
	for _, p := range list.Processes {
		if p.PID == 43 && p.Exe != "/usr/bin/python3" {
			t.Fatalf("pid 43 runs %q", p.Exe)
		}
	}
}

// The ProcessLookup join key: (sandbox, in-sandbox pid, executable). A pid
// the sandbox reused names the process that ran the record's binary, not
// whatever holds the pid now.
func TestKernelLineageJoinKeyKeepsAReusedPidApart(t *testing.T) {
	var sample atomic.Pointer[string]
	e, b, id := kernelBox(t, "keybox", &sample)
	ctx := context.Background()
	now := time.Now()
	e.m.observeKernelFrame(ctx, b, execFrame(id, "bash", "", 9400, 5, "/bin/bash", "/bin/bash", now))
	e.m.observeKernelFrame(ctx, b, execFrame(id, "curl", "bash", 9401, 77, "/usr/bin/curl", "/usr/bin/curl https://example.org", now))
	e.m.observeKernelFrame(ctx, b, exitFrame(id, "curl", 9401, 0, now.Add(time.Second)))
	e.m.observeKernelFrame(ctx, b, execFrame(id, "python3", "", 9402, 77, "/usr/bin/python3", "/usr/bin/python3 app.py", now.Add(2*time.Second)))

	if l := e.m.LineageFor("keybox", 77, "/usr/bin/curl"); len(l) != 2 || l[0].Exe != "/usr/bin/curl" || l[1].PID != 5 || l[1].Comm != "bash" {
		t.Fatalf("curl's lineage = %+v", l)
	}
	if l := e.m.LineageFor("keybox", 77, "/usr/bin/python3"); len(l) != 1 || l[0].Exe != "/usr/bin/python3" {
		t.Fatalf("python3's lineage = %+v", l)
	}
	if l := e.m.LineageFor("keybox", 77, "/usr/bin/wget"); l != nil {
		t.Fatalf("a binary no process at the pid ran = %+v", l)
	}
	if l := e.m.Lineage("keybox", 77); len(l) != 1 || l[0].Exe != "/usr/bin/python3" {
		t.Fatalf("without the binary = %+v", l)
	}
	// The destinations view passes the connecting record's binary.
	e.ocsf("keybox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(77) -> example.org:443/tcp [policy:allow_example engine:opa]", time.Now())
	row, ok := destinationKinds(t, e, "keybox")["example.org"]
	if !ok {
		t.Fatal("no example.org destination")
	}
	if l := row.Lineage; len(l) != 2 || l[0].Exe != "/usr/bin/curl" || l[1].Comm != "bash" {
		t.Fatalf("destination lineage = %+v", row.Lineage)
	}
}

// fakeFeedStream is a connected feed whose frames the test sends.
type fakeFeedStream struct {
	header sandboxfeed.Header
	frames chan sandboxfeed.Frame
	closed chan struct{}
}

func newFakeFeedStream() *fakeFeedStream {
	return &fakeFeedStream{
		header: sandboxfeed.Header{Protocol: sandboxfeed.ProtocolVersion, Build: "1.2.3", Tetragon: sandboxfeed.TetragonConnected},
		frames: make(chan sandboxfeed.Frame, 16), closed: make(chan struct{}),
	}
}

func (f *fakeFeedStream) Header() sandboxfeed.Header { return f.header }

func (f *fakeFeedStream) Next() (sandboxfeed.Frame, error) {
	select {
	case frame := <-f.frames:
		return frame, nil
	case <-f.closed:
		return sandboxfeed.Frame{}, io.EOF
	}
}

func (f *fakeFeedStream) Close() error {
	select {
	case <-f.closed:
	default:
		close(f.closed)
	}
	return nil
}

// withKernelFeed replaces the manager's feed before it runs, fast-paced.
func withKernelFeed(e *harnessEnv, dial KernelFeedDialer) *kernelFeed {
	k := newKernelFeed(dial, "1.2.3", e.t.Logf)
	k.poll, k.idle, k.retry, k.skewRetry = 10*time.Millisecond, time.Hour, 20*time.Millisecond, 20*time.Millisecond
	e.m.kfeed = k
	return k
}

// The manager holds the feed while a docker sandbox has its tree on and
// routes the frames to it by OpenShell id.
func TestKernelFeedConnectionFeedsTheTree(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	e := newEnv(t, nil)
	stream := newFakeFeedStream()
	var dials atomic.Int32
	k := withKernelFeed(e, func(context.Context) (KernelFeedStream, error) {
		dials.Add(1)
		return stream, nil
	})
	e.live(sandboxapi.CreateRequest{Name: "connbox", ProcessTree: true})
	eventually(t, "the feed to connect", func() bool { v := k.view(); return v != nil && v.Connected })
	id := sandboxIDOf(e, e.boxOf("connbox"))
	stream.frames <- execFrame(id, "node", "", 9500, 12, "/usr/bin/node", "/usr/bin/node test.js", time.Now())
	stream.frames <- execFrame("another-sandbox", "x", "", 9501, 13, "/usr/bin/x", "/usr/bin/x", time.Now())
	stream.frames <- sandboxfeed.Frame{Kind: sandboxfeed.FrameStatus, Tetragon: sandboxfeed.TetragonConnected, Dropped: 4}
	eventually(t, "the exec in the tree", func() bool {
		list, _ := e.m.Processes(context.Background(), "connbox")
		return list.Kernel != nil && list.Kernel.Execs == 1 && list.Kernel.Dropped == 4
	})
	if n := len(processRecords(e, "connbox")); n != 1 {
		t.Fatalf("records = %d, want only connbox's exec", n)
	}
	if dials.Load() != 1 {
		t.Fatalf("dialled %d times", dials.Load())
	}
}

// A feed speaking another protocol is not read: the tree stays the
// sample's, and the list says why and how to update the feed.
func TestKernelFeedVersionSkewFallsBackToTheSample(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init"))
	e := newEnv(t, nil)
	e.handleExec(sampleHandler(&sample))
	k := withKernelFeed(e, func(context.Context) (KernelFeedStream, error) {
		return nil, &sandboxfeed.SkewError{Server: sandboxfeed.ProtocolVersion + 1, Client: sandboxfeed.ProtocolVersion, Build: "9.0.0"}
	})
	e.live(sandboxapi.CreateRequest{Name: "skewbox", ProcessTree: true})
	eventually(t, "the skew to be noted", func() bool { v := k.view(); return v != nil && v.Reason == sandboxfeed.ReasonVersionSkew })
	b := e.boxOf("skewbox")
	if _, ok := e.m.sampleProcesses(context.Background(), b); !ok {
		t.Fatal("the sample does not run")
	}
	list, _ := e.m.Processes(context.Background(), "skewbox")
	if k := list.Kernel; k == nil || k.Connected || k.Reason != sandboxfeed.ReasonVersionSkew || k.Build != "9.0.0" ||
		!strings.Contains(k.UpdateCommand, "sandbox kernel-feed install") {
		t.Fatalf("kernel = %+v", list.Kernel)
	}
	if len(list.Processes) != 1 || list.Processes[0].Source != audit.SandboxProcessSourceSample {
		t.Fatalf("processes = %+v", list.Processes)
	}
}

// GAP-0033: after a version skew the feed is dialled again as soon as its
// socket is replaced (the printed install restarts it), not after the skew
// pause.
func TestKernelFeedRetriesOnceTheSocketIsReplaced(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	e := newEnv(t, nil)
	stream := newFakeFeedStream()
	var updated atomic.Bool
	var dials atomic.Int32
	k := withKernelFeed(e, func(context.Context) (KernelFeedStream, error) {
		dials.Add(1)
		if !updated.Load() {
			return nil, &sandboxfeed.SkewError{Server: sandboxfeed.ProtocolVersion + 1, Client: sandboxfeed.ProtocolVersion, Build: "9.0.0"}
		}
		return stream, nil
	})
	k.skewRetry = time.Hour
	k.socketID = func() string {
		if updated.Load() {
			return "the updated feed's socket"
		}
		return "the old feed's socket"
	}
	e.live(sandboxapi.CreateRequest{Name: "updatebox", ProcessTree: true})
	eventually(t, "the skew to be noted", func() bool { v := k.view(); return v != nil && v.Reason == sandboxfeed.ReasonVersionSkew })
	before := dials.Load()
	updated.Store(true)
	eventually(t, "the updated feed to be read", func() bool { v := k.view(); return v != nil && v.Connected })
	if dials.Load() != before+1 {
		t.Fatalf("dials %d after the skew, want one more", dials.Load()-before)
	}
}

// No sandbox with its tree on: no connection. A missing feed is not in the
// list at all; one this account may not read is.
func TestKernelFeedIsDialledOnlyWhenWanted(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("the kernel feed is Linux only")
	}
	e := newEnv(t, nil)
	var dials atomic.Int32
	k := withKernelFeed(e, func(context.Context) (KernelFeedStream, error) {
		dials.Add(1)
		return nil, sandboxfeed.ErrNotInstalled
	})
	e.live(sandboxapi.CreateRequest{Name: "plainbox"})
	time.Sleep(100 * time.Millisecond)
	if dials.Load() != 0 {
		t.Fatalf("dialled %d times with no process tree on", dials.Load())
	}
	if k.view() != nil {
		t.Fatalf("view = %+v", k.view())
	}
	k.down(errors.Join(sandboxfeed.ErrNotPermitted))
	if v := k.view(); v == nil || v.Reason != sandboxfeed.ReasonNotPermitted {
		t.Fatalf("not permitted = %+v", v)
	}
}

// The feed marks DefenseClaw's collector by the command the manager runs.
func TestCollectorCommandIsRecognizedByTheFeed(t *testing.T) {
	argv := collectArgv("ps", 1, []string{"O", "argv"})
	if !sandboxfeed.IsCollectorCommand(argv) || !slices.Contains(argv, sandboxfeed.CollectorName) {
		t.Fatalf("collectArgv %q is not what the feed recognizes", argv[:10])
	}
}

// The vm driver's guest kernel is not the host's: no feed there.
func TestKernelFeedAppliesToDockerSandboxesOnly(t *testing.T) {
	b := &box{}
	b.rec.Driver = "vm"
	if kernelFeedApplies(b) {
		t.Fatal("the feed applies to a vm sandbox")
	}
	b.rec.Driver = ""
	if got := kernelFeedApplies(b); got != (runtime.GOOS == "linux") {
		t.Fatalf("docker sandbox applies = %v on %s", got, runtime.GOOS)
	}
}
