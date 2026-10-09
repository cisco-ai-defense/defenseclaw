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
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/openshelltest"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// sampleOf is a ps-mode collector answer of the processes given as
// "pid ppid start comm args...".
func sampleOf(procs ...string) *collection {
	lines := []string{"T 100 1700000000"}
	for _, p := range procs {
		f := strings.Fields(p)
		lines = append(lines, fmt.Sprintf("P %s %s 1000 %s", f[0], f[1], f[2]), "Pc "+f[0]+" "+f[3])
		for _, a := range f[3:] {
			lines = append(lines, "Pa "+f[0]+" "+a)
		}
	}
	c, err := parseCollection(answerOf(append(lines, collectEnd)...), false, newCollectScope(), 1)
	if err != nil {
		panic(err)
	}
	return c
}

func TestProcessTreeMergesSamples(t *testing.T) {
	tree := newProcTree()
	t0 := time.Now()
	started, exited := tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 30 bash"), t0, t0, false)
	if len(started) != 3 || len(exited) != 0 {
		t.Fatalf("first sample started %d exited %d", len(started), len(exited))
	}
	// 43 ended, and its pid now runs another process (another start time).
	t1 := t0.Add(5 * time.Second)
	started, exited = tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 99 python3"), t1, t1, false)
	if len(started) != 1 || started[0].Comm != "python3" || len(exited) != 1 || exited[0].Comm != "bash" {
		t.Fatalf("second sample started %+v exited %+v", started, exited)
	}
	// A process OpenShell reported after the sample was taken is not gone
	// for missing from it.
	t2 := t1.Add(5 * time.Second)
	tree.mu.Lock()
	tree.live[77] = &procNode{PID: 77, Comm: "late", FirstSeen: t2.Add(time.Second), Source: audit.SandboxProcessSourceOCSF}
	tree.mu.Unlock()
	_, exited = tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 99 python3"), t2, t2.Add(2*time.Second), false)
	if len(exited) != 0 {
		t.Fatalf("exited %+v, want the late process kept", exited)
	}
	if names := tree.ancestryLocked(tree.live[43]); len(names) != 3 || names[0] != "python3" || names[1] != "claude" || names[2] != "init" {
		t.Fatalf("lineage = %v", names)
	}
}

// Only a complete sample ends the live processes it lacks: one cut at the
// stream's bound, without its end or stopped at the process bound may just
// not have reached them.
func TestProcessTreeKeepsLiveProcessesOnAPartialSample(t *testing.T) {
	tree := newProcTree()
	t0 := time.Now()
	tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 30 node", "44 42 40 python3"), t0, t0, false)
	head := collectSchema + "\nT 100 1700000000\nP 1 0 1000 10\nPc 1 init\nP 42 1 1000 20\nPc 42 claude\n"
	partial := map[string]func() (*collection, error){
		"cut": func() (*collection, error) {
			return parseCollection([]byte(head+"P 43 42 10"), true, newCollectScope(), 1)
		},
		"no end": func() (*collection, error) { return parseCollection([]byte(head), false, newCollectScope(), 1) },
		"capped": func() (*collection, error) {
			return parseCollection([]byte(head+"Q processes\n"+collectEnd+"\n"), false, newCollectScope(), 1)
		},
	}
	for name, parse := range partial {
		c, err := parse()
		if err != nil {
			t.Fatal(err)
		}
		at := time.Now()
		if _, exited := tree.merge(c, at, at, false); len(exited) != 0 || !tree.truncated {
			t.Fatalf("%s sample: exited %+v truncated %v, want none ended", name, exited, tree.truncated)
		}
	}
	at := time.Now()
	if _, exited := tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "44 42 40 python3"), at, at, false); len(exited) != 1 || exited[0].PID != 43 || tree.truncated {
		t.Fatalf("complete sample: exited %+v, want 43", exited)
	}
}

func TestProcessTreeIsBounded(t *testing.T) {
	tree := newProcTree()
	var procs []string
	for i := range procTreeMaxLive + 500 {
		procs = append(procs, fmt.Sprintf("%d 1 %d p%d", i+2, i+1, i))
	}
	now := time.Now()
	started, _ := tree.merge(sampleOf(procs...), now, now, false)
	if len(started) != procTreeMaxLive || len(tree.live) != procTreeMaxLive || !tree.truncated {
		t.Fatalf("live = %d started = %d truncated = %v, want the bound of %d", len(tree.live), len(started), tree.truncated, procTreeMaxLive)
	}
	_, exited := tree.merge(sampleOf("1 0 1 init"), now.Add(time.Second), now.Add(time.Second), false)
	if len(exited) != procTreeMaxLive || len(tree.exited) != procTreeMaxExited {
		t.Fatalf("exited %d kept %d, want the last %d kept", len(exited), len(tree.exited), procTreeMaxExited)
	}
}

// The bound holds across samples that end nothing: the new processes of
// partial samples join only while the tree has room, and a complete sample
// ends the ones it lacks before it adds its own.
func TestProcessTreeStaysBoundedAcrossPartialSamples(t *testing.T) {
	tree := newProcTree()
	now := time.Now()
	for round := range 3 {
		lines := []string{"T 100 1700000000"}
		for i := range 3000 {
			pid := 2 + round*3000 + i
			lines = append(lines, fmt.Sprintf("P %d 1 1000 %d", pid, pid), fmt.Sprintf("Pc %d p%d", pid, pid))
		}
		// No end line: the sample may not show every process.
		c, err := parseCollection(answerOf(lines...), false, newCollectScope(), 1)
		if err != nil {
			t.Fatal(err)
		}
		at := now.Add(time.Duration(round) * time.Second)
		started, exited := tree.merge(c, at, at, false)
		if len(tree.live) > procTreeMaxLive || len(exited) != 0 || !tree.truncated {
			t.Fatalf("round %d: live = %d started = %d exited = %d truncated = %v, want at most %d live",
				round, len(tree.live), len(started), len(exited), tree.truncated, procTreeMaxLive)
		}
	}
	if len(tree.live) != procTreeMaxLive {
		t.Fatalf("live = %d, want the bound of %d", len(tree.live), procTreeMaxLive)
	}
	at := now.Add(time.Minute)
	started, exited := tree.merge(sampleOf("1 0 1 init", "90000 1 5 claude"), at, at, false)
	if len(started) != 2 || len(exited) != procTreeMaxLive || len(tree.live) != 2 || tree.truncated {
		t.Fatalf("complete sample: started %d exited %d live %d truncated %v", len(started), len(exited), len(tree.live), tree.truncated)
	}
}

// treeEnv is a running manager with one ready sandbox whose process tree is
// on and whose ps samples answer *sample.
func treeEnv(t *testing.T, name string, sample *atomic.Pointer[string]) *harnessEnv {
	t.Helper()
	e := newEnv(t, nil)
	e.handleExec(func(_ context.Context, call openshelltest.ExecCall) openshelltest.ExecResponse {
		if isCollect(call) && call.Command[10] == "ps" {
			if s := sample.Load(); s != nil {
				return openshelltest.ExecResponse{Stdout: []byte(*s)}
			}
		}
		return openshelltest.ExecResponse{}
	})
	e.live(sandboxapi.CreateRequest{Name: name, ProcessTree: true})
	return e
}

// psAnswer is a ps answer of a sandbox that booted two seconds ago, so its
// processes started just before now.
func psAnswer(lines ...string) *string {
	return psAnswerBoot(time.Now().Add(-2*time.Second), lines...)
}

func psAnswerBoot(boot time.Time, lines ...string) *string {
	s := string(answerOf(append(append([]string{fmt.Sprintf("T 100 %d", boot.Unix())}, lines...), collectEnd)...))
	return &s
}

// TestDestinationLineageByProgram (GAP-0139, GAP-0133): OpenShell names pid 0
// for every connection on both drivers, so a destination never had a
// lineage although its program was in the tree. The one process of that
// program running when the host was seen gives it; two copies give none.
func TestDestinationLineageByProgram(t *testing.T) {
	var sample atomic.Pointer[string]
	tree := []string{"P 1 0 1000 10", "Pc 1 init", "P 124 1 1000 20", "Pc 124 claude", "P 521 124 1000 30", "Pc 521 bash",
		"P 526 521 1000 40", "Pc 526 curl", "L /proc/526 exe /usr/bin/curl"}
	sample.Store(psAnswer(tree...))
	e := treeEnv(t, "linbox", &sample)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("linbox")); !ok {
		t.Fatal("no sample")
	}
	e.ocsf("linbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> pypi.org:443/tcp [policy:allow_pypi engine:opa]", time.Now())
	d, err := e.m.Destinations(context.Background(), "linbox")
	if err != nil || len(d.Destinations) != 1 || len(d.Destinations[0].Lineage) != 4 || d.Destinations[0].Lineage[0].PID != 526 ||
		d.Destinations[0].Lineage[1].Comm != "bash" || d.Destinations[0].Lineage[2].Comm != "claude" {
		t.Fatalf("destinations = %+v, %v", d.Destinations, err)
	}
	sample.Store(psAnswer(append(tree, "P 530 521 1000 50", "Pc 530 curl", "L /proc/530 exe /usr/bin/curl")...))
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("linbox")); !ok {
		t.Fatal("no sample")
	}
	if d, _ = e.m.Destinations(context.Background(), "linbox"); len(d.Destinations[0].Lineage) != 0 {
		t.Fatalf("two copies of the program ran: lineage %+v", d.Destinations[0].Lineage)
	}
}

// TestDestinationLineageWithoutExe (GAP-0139): the workload's processes are
// not dumpable, so a live sample has no executable for them; the program's
// name (its first argument or comm) finds the process instead. A process
// whose executable is known to be another program is not taken.
func TestDestinationLineageWithoutExe(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 1000 10", "Pc 1 init", "P 124 1 1000 20", "Pc 124 claude", "P 521 124 1000 30", "Pc 521 bash",
		"P 526 521 1000 40", "Pc 526 curl", "Pa 526 curl", "Pa 526 -s",
		"P 527 521 1000 41", "Pc 527 curl", "L /proc/527 exe /opt/other/curl"))
	e := treeEnv(t, "noexe", &sample)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("noexe")); !ok {
		t.Fatal("no sample")
	}
	e.ocsf("noexe", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> pypi.org:443/tcp [policy:allow_pypi engine:opa]", time.Now())
	d, err := e.m.Destinations(context.Background(), "noexe")
	if err != nil || len(d.Destinations) != 1 || len(d.Destinations[0].Lineage) != 4 || d.Destinations[0].Lineage[0].PID != 526 ||
		d.Destinations[0].Lineage[2].Comm != "claude" {
		t.Fatalf("destinations = %+v, %v", d.Destinations, err)
	}
}

// TestDestinationLineageNeedsARecentStart (GAP-0174): a program too short for
// a sample (a quick curl, a `sandbox exec`) is not in the tree, so a copy of
// it that started long before and still runs (a slow download) is not
// credited with its connection; the copy that started just before one is.
func TestDestinationLineageNeedsARecentStart(t *testing.T) {
	var sample atomic.Pointer[string]
	now := time.Now()
	// curl 526 started a minute ago; curl 530 starts in 29 seconds.
	sample.Store(psAnswerBoot(now.Add(-60*time.Second), "P 1 0 1000 10", "Pc 1 init", "P 124 1 1000 20", "Pc 124 claude",
		"P 521 124 1000 30", "Pc 521 bash", "P 526 521 1000 100", "Pc 526 curl", "Pa 526 curl",
		"P 530 521 1000 8900", "Pc 530 curl", "Pa 530 curl"))
	e := treeEnv(t, "slowbox", &sample)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("slowbox")); !ok {
		t.Fatal("no sample")
	}
	e.ocsf("slowbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> example.net:443/tcp [policy:allow_example engine:opa]", now)
	e.ocsf("slowbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(0) -> example.org:443/tcp [policy:allow_example engine:opa]", now.Add(30*time.Second))
	rows := destinationKinds(t, e, "slowbox")
	if l := rows["example.net"].Lineage; len(l) != 0 {
		t.Fatalf("example.net lineage %+v, want none: the only curl then started a minute before", l)
	}
	if l := rows["example.org"].Lineage; len(l) != 4 || l[0].PID != 530 || l[1].Comm != "bash" {
		t.Fatalf("example.org lineage %+v, want curl 530's", l)
	}
}

func TestSampleProcessesRecordsTheTree(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init", "P 42 1 1000 20", "Pc 42 claude", "Pa 42 claude", "Pa 42 --token=dccertvalue",
		"L /proc/42 exe /usr/bin/node", "L /proc/42 cwd /sandbox/work/repo"))
	e := treeEnv(t, "treebox", &sample)
	b := e.boxOf("treebox")
	if _, ok := e.m.sampleProcesses(context.Background(), b); !ok {
		t.Fatal("no sample")
	}
	list, err := e.m.Processes(context.Background(), "treebox")
	if err != nil || !list.Enabled || len(list.Processes) != 2 {
		t.Fatalf("processes = %+v, %v", list, err)
	}
	claude := list.Processes[1]
	if claude.PID != 42 || claude.PPID != 1 || claude.Exe != "/usr/bin/node" || claude.Cwd != "/sandbox/work/repo" ||
		strings.Contains(claude.Cmdline, "dccertvalue") || claude.Source != audit.SandboxProcessSourceSample {
		t.Fatalf("process = %+v", claude)
	}
	if lineage := e.m.Lineage("treebox", 42); len(lineage) != 2 || lineage[0].Comm != "claude" || lineage[1].PID != 1 {
		t.Fatalf("lineage = %+v", lineage)
	}
	// On docker a slow sample keeps the pace; on the vm driver it sets the
	// slower one for the rest of the session, and the list says so.
	if d, slow := e.m.paceSamples(b, 2*time.Second, true, false, openshell.DriverDocker); d != processSampleInterval || slow {
		t.Fatalf("docker pace = %s, %v", d, slow)
	}
	if d, slow := e.m.paceSamples(b, 100*time.Millisecond, true, false, openshell.DriverVM); d != processSampleInterval || slow {
		t.Fatalf("vm pace after a fast sample = %s, %v", d, slow)
	}
	if list, _ := e.m.Processes(context.Background(), "treebox"); list.IntervalSeconds != 5 {
		t.Fatalf("interval = %d", list.IntervalSeconds)
	}
	if d, slow := e.m.paceSamples(b, 2*time.Second, true, false, openshell.DriverVM); d != processSampleIntervalVM || !slow {
		t.Fatalf("vm pace after a slow sample = %s, %v", d, slow)
	}
	if d, slow := e.m.paceSamples(b, 0, false, true, openshell.DriverVM); d != processSampleIntervalVM || !slow {
		t.Fatalf("vm pace stays slow = %s, %v", d, slow)
	}
	if list, _ := e.m.Processes(context.Background(), "treebox"); list.IntervalSeconds != 15 {
		t.Fatalf("interval = %d", list.IntervalSeconds)
	}
	// 42 ended between the samples.
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init"))
	time.Sleep(time.Millisecond)
	e.m.sampleProcesses(context.Background(), b)
	list, _ = e.m.Processes(context.Background(), "treebox")
	if len(list.Processes) != 1 || len(list.Exited) != 1 || list.Exited[0].PID != 42 {
		t.Fatalf("after the exit: %+v", list)
	}
	var starts, exits int
	for _, ev := range where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool { return ev.Sandbox.Name == "treebox" }) {
		switch ev.Event {
		case audit.SandboxProcessStart:
			starts++
		case audit.SandboxProcessExit:
			exits++
			if ev.PID == 42 && (len(ev.Lineage) != 1 || ev.Lineage[0] != "init") {
				t.Fatalf("exit lineage = %v", ev.Lineage)
			}
		}
	}
	if starts < 2 || exits < 1 {
		t.Fatalf("records: %d starts, %d exits", starts, exits)
	}
}

// TestLineageNamesTheProgramInFull (GAP-0172): the kernel keeps 15 bytes of a
// process's name, so a lineage, a process record's name and the dashboard's
// top programs said openshell-sandb for openshell-sandbox; its first
// argument gives the name in full. A shorter comm stays as it is.
func TestLineageNamesTheProgramInFull(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 1000 10", "Pc 1 openshell-sandb", "Pa 1 /.openshell/runtime/openshell-sandbox",
		"P 42 1 1000 20", "Pc 42 bash", "Pa 42 -bash", "P 43 42 1000 30", "Pc 43 curl", "Pa 43 curl"))
	e := treeEnv(t, "namebox", &sample)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("namebox")); !ok {
		t.Fatal("no sample")
	}
	if l := e.m.Lineage("namebox", 43); len(l) != 3 || l[1].Comm != "bash" || l[2].Comm != "openshell-sandbox" {
		t.Fatalf("lineage = %+v", l)
	}
	names := map[int]string{}
	var lineage []string
	for _, ev := range where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool { return ev.Sandbox.Name == "namebox" }) {
		names[ev.PID] = ev.Name
		if ev.PID == 43 {
			lineage = ev.Lineage
		}
	}
	if names[1] != "openshell-sandbox" || names[42] != "bash" || strings.Join(lineage, ",") != "bash,openshell-sandbox" {
		t.Fatalf("records: names %v, lineage of 43 %v", names, lineage)
	}
}

func TestOCSFProcessRecordsJoinTheTree(t *testing.T) {
	var sample atomic.Pointer[string]
	e := treeEnv(t, "ocsfbox", &sample)
	now := time.Now()
	e.ocsf("ocsfbox", "PROC:LAUNCH [INFO] python3(4242) [cmd:python3 /app/main.py --password dccertvalue]", now)
	list, _ := e.m.Processes(context.Background(), "ocsfbox")
	if len(list.Processes) != 1 || list.Processes[0].Source != audit.SandboxProcessSourceOCSF || strings.Contains(list.Processes[0].Cmdline, "dccertvalue") {
		t.Fatalf("after the launch: %+v", list)
	}
	e.ocsf("ocsfbox", "PROC:TERMINATE [INFO] python3(4242) [exit:3]", now.Add(time.Second))
	list, _ = e.m.Processes(context.Background(), "ocsfbox")
	if len(list.Processes) != 0 || len(list.Exited) != 1 || list.Exited[0].ExitCode == nil || *list.Exited[0].ExitCode != 3 {
		t.Fatalf("after the terminate: %+v", list)
	}
}

// With the process tree on, a destination names the lineage of the process
// that connected, from the tree (the process first).
func TestDestinationsNameTheProcessTreesLineage(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init", "P 42 1 1000 20", "Pc 42 bash", "P 77 42 1000 30", "Pc 77 curl",
		"L /proc/77 exe /usr/bin/curl"))
	e := treeEnv(t, "linbox", &sample)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("linbox")); !ok {
		t.Fatal("no sample")
	}
	// Its process records carry the binding and the launching user, like
	// every sandbox record.
	binding := e.binding("linbox").ID
	recs := where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool { return ev.Sandbox.Name == "linbox" })
	if len(recs) != 3 || recs[0].Sandbox.BindingID != binding || recs[0].UserID != "1000" || recs[0].UserName != "dev" {
		t.Fatalf("process records = %+v", recs)
	}
	e.ocsf("linbox", "NET:OPEN [INFO] ALLOWED /usr/bin/curl(77) -> example.org:443/tcp [policy:allow_example engine:opa]", time.Now())
	row, ok := destinationKinds(t, e, "linbox")["example.org"]
	if !ok {
		t.Fatal("no example.org destination")
	}
	if l := row.Lineage; row.PID != 77 || len(l) != 3 || l[0].PID != 77 || l[0].Comm != "curl" || l[0].Exe != "/usr/bin/curl" ||
		l[1].PID != 42 || l[1].Comm != "bash" || l[2].PID != 1 {
		t.Fatalf("row %+v, lineage %+v", row, row.Lineage)
	}
}

// A process record copies its process while it holds the tree: a sample or
// an OpenShell record may update or end the process at the same time (run
// with -race). A start record carries no exit status.
func TestProcessRecordsCopyTheirProcess(t *testing.T) {
	var sample atomic.Pointer[string]
	lines := []string{"P 1 0 0 10", "Pc 1 init"}
	for i := range 20 {
		pid := 5000 + i
		lines = append(lines, fmt.Sprintf("P %d 1 1000 %d", pid, pid), fmt.Sprintf("Pc %d sampled", pid))
	}
	sample.Store(psAnswer(lines...))
	e := treeEnv(t, "racebox", &sample)
	b := e.boxOf("racebox")
	// Launches of processes the samples show and of ones they do not.
	var launches []ocsf.Record
	for i := range 20 {
		for _, pid := range []int{5000 + i, 6000 + i} {
			launches = append(launches, *parseOCSF(t, fmt.Sprintf("PROC:LAUNCH [INFO] python3(%d) [cmd:python3 main.py]", pid)))
		}
	}
	ctx := context.Background()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for range 20 {
			e.m.sampleProcesses(ctx, b)
		}
	}()
	go func() {
		defer wg.Done()
		for _, r := range launches {
			e.m.ocsfEvent(ctx, b, r, time.Now())
		}
	}()
	wg.Wait()
	e.deleteBox("racebox", sandboxapi.DeleteRequest{})
	var starts, exits int
	for _, ev := range where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool { return ev.Sandbox.Name == "racebox" }) {
		switch ev.Event {
		case audit.SandboxProcessStart:
			starts++
			if ev.ExitCode != nil {
				t.Fatalf("start record with an exit status: %+v", ev)
			}
		case audit.SandboxProcessExit:
			exits++
		}
	}
	if starts == 0 || starts != exits {
		t.Fatalf("records: %d starts, %d exits, want every start ended", starts, exits)
	}
}

// Off by default: no sample runs, OpenShell's PROC records are not kept,
// and the API says the tree is off.
func TestProcessTreeIsOffByDefault(t *testing.T) {
	e := liveEnv(t, "plainbox", nil)
	if _, ok := e.m.sampleProcesses(context.Background(), e.boxOf("plainbox")); ok {
		t.Fatal("a sandbox without the process tree was sampled")
	}
	e.ocsf("plainbox", "PROC:LAUNCH [INFO] python3(4242) [cmd:python3]", time.Now())
	list, err := e.m.Processes(context.Background(), "plainbox")
	if err != nil || list.Enabled || len(list.Processes) != 0 || e.m.Lineage("plainbox", 4242) != nil {
		t.Fatalf("processes = %+v, %v", list, err)
	}
	if sb := e.get("plainbox"); sb.ProcessTree {
		t.Fatal("the view says the process tree is on")
	}
	// Its destinations name the connecting process, without a lineage.
	e.ocsf("plainbox", "NET:OPEN [INFO] ALLOWED /usr/bin/python3(4242) -> example.org:443/tcp [policy:allow_example engine:opa]", time.Now())
	if row := destinationKinds(t, e, "plainbox")["example.org"]; row.PID != 4242 || row.Lineage != nil {
		t.Fatalf("row %+v", row)
	}
}

// A stop ends every live process of the tree.
func TestStopEndsTheProcessTree(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init"))
	e := treeEnv(t, "stopbox", &sample)
	e.m.sampleProcesses(context.Background(), e.boxOf("stopbox"))
	e.stopBox("stopbox")
	list, _ := e.m.Processes(context.Background(), "stopbox")
	if len(list.Processes) != 0 || len(list.Exited) != 1 {
		t.Fatalf("after the stop: %+v", list)
	}
}

// A delete of a running sandbox ends its processes too: every start has
// its exit.
func TestDeleteEndsTheProcessTree(t *testing.T) {
	var sample atomic.Pointer[string]
	sample.Store(psAnswer("P 1 0 0 10", "Pc 1 init", "P 42 1 1000 20", "Pc 42 claude"))
	e := treeEnv(t, "delbox", &sample)
	e.m.sampleProcesses(context.Background(), e.boxOf("delbox"))
	e.deleteBox("delbox", sandboxapi.DeleteRequest{})
	count := func(event string) int {
		return len(where(&e.tel.mu, &e.tel.processes, func(ev audit.SandboxProcessEvent) bool {
			return ev.Sandbox.Name == "delbox" && ev.Event == event
		}))
	}
	if starts, exits := count(audit.SandboxProcessStart), count(audit.SandboxProcessExit); starts != 2 || exits != 2 {
		t.Fatalf("records: %d starts, %d exits, want every start ended", starts, exits)
	}
}
