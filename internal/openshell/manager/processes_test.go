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
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
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
	started, exited := tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 30 bash"), t0, t0)
	if len(started) != 3 || len(exited) != 0 {
		t.Fatalf("first sample started %d exited %d", len(started), len(exited))
	}
	// 43 ended, and its pid now runs another process (another start time).
	t1 := t0.Add(5 * time.Second)
	started, exited = tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 99 python3"), t1, t1)
	if len(started) != 1 || started[0].Comm != "python3" || len(exited) != 1 || exited[0].Comm != "bash" {
		t.Fatalf("second sample started %+v exited %+v", started, exited)
	}
	// A process OpenShell reported after the sample was taken is not gone
	// for missing from it.
	t2 := t1.Add(5 * time.Second)
	tree.mu.Lock()
	tree.live[77] = &procNode{PID: 77, Comm: "late", FirstSeen: t2.Add(time.Second), Source: audit.SandboxProcessSourceOCSF}
	tree.mu.Unlock()
	_, exited = tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 99 python3"), t2, t2.Add(2*time.Second))
	if len(exited) != 0 {
		t.Fatalf("exited %+v, want the late process kept", exited)
	}
	if names := tree.lineageNamesLocked(43); len(names) != 3 || names[0] != "python3" || names[1] != "claude" || names[2] != "init" {
		t.Fatalf("lineage = %v", names)
	}
}

// Only a complete sample ends the live processes it lacks: one cut at the
// stream's bound, without its end or stopped at the process bound may just
// not have reached them.
func TestProcessTreeKeepsLiveProcessesOnAPartialSample(t *testing.T) {
	tree := newProcTree()
	t0 := time.Now()
	tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "43 42 30 node", "44 42 40 python3"), t0, t0)
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
		if _, exited := tree.merge(c, at, at); len(exited) != 0 || !tree.truncated {
			t.Fatalf("%s sample: exited %+v truncated %v, want none ended", name, exited, tree.truncated)
		}
	}
	at := time.Now()
	if _, exited := tree.merge(sampleOf("1 0 10 init", "42 1 20 claude", "44 42 40 python3"), at, at); len(exited) != 1 || exited[0].PID != 43 || tree.truncated {
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
	started, _ := tree.merge(sampleOf(procs...), now, now)
	if len(started) != procTreeMaxLive || len(tree.live) != procTreeMaxLive || !tree.truncated {
		t.Fatalf("live = %d started = %d truncated = %v, want the bound of %d", len(tree.live), len(started), tree.truncated, procTreeMaxLive)
	}
	_, exited := tree.merge(sampleOf("1 0 1 init"), now.Add(time.Second), now.Add(time.Second))
	if len(exited) != procTreeMaxLive || len(tree.exited) != procTreeMaxExited {
		t.Fatalf("exited %d kept %d, want the last %d kept", len(exited), len(tree.exited), procTreeMaxExited)
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

func psAnswer(lines ...string) *string {
	s := string(answerOf(append(append([]string{"T 100 1700000000"}, lines...), collectEnd)...))
	return &s
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
