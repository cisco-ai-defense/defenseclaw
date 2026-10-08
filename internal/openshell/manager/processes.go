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

package manager

import (
	"context"
	"maps"
	"path"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/sensor/sandboxfeed"
)

// The process tree (opt-in: the pack's observe.process_tree, or `sandbox run
// --process-tree`). While a sandbox with it on is ready, the collector
// samples its /proc every processSampleInterval (one exec; on the vm driver
// every processSampleIntervalVM once a sample is slow): the pid, parent,
// uid, start time, comm, executable, working folder and first arguments of
// every process. OpenShell's PROC LAUNCH and TERMINATE records join the tree
// as they arrive (they name a process and its binary, not its parent; the
// next sample fills that in). On a Linux docker sandbox whose host runs the
// sandbox kernel feed (kernelfeed.go), every exec and exit Tetragon saw
// joins it too, with Tetragon's exec ids: a process that lives for
// milliseconds is still recorded. Such a process is in the tree by its
// in-sandbox pid only when the feed could read that pid at the exec (most
// short-lived ones are gone by then); otherwise it is there by its exec id
// and host pid alone, never under a pid of another namespace. The tree is
// bounded (procTreeMaxLive live processes, the procTreeMaxExited most
// recently ended ones), every process that joins it is recorded once as
// started and once as exited (sandbox.process_tree, at most
// sandboxapi.ProcessRecordBurst at once and sandboxapi.ProcessRecordRate a
// second per sandbox; the list counts the records not sent),
// and Lineage walks it for the egress destinations. Without the feed its
// limits are those of sampling: a process that starts and ends between two
// samples, and that OpenShell does not report, is never seen. Every field
// is the agent's to choose (its arguments, its comm, its executable path):
// display text, never a decision.

const (
	processSampleInterval   = 5 * time.Second
	processSampleIntervalVM = 15 * time.Second
	// processSampleSlow is the sample time past which the vm driver's
	// sandboxes are sampled every processSampleIntervalVM.
	processSampleSlow    = time.Second
	processSampleTimeout = 10 * time.Second
	procTreeMaxLive      = 4096
	procTreeMaxExited    = 1024
	maxLineageDepth      = 32
	maxCmdlineBytes      = 1024
	// commBytes is how much of a program's name the kernel keeps as a
	// process's comm (TASK_COMM_LEN less its NUL).
	commBytes = 15
	// lineageStartWindow is how long before its connection a process of the
	// program may have started for PIDOf to credit it with the connection,
	// and lineageClockSlack how long after: the sandbox's clock and its boot
	// time (whole seconds) may be off by that much (GAP-0174).
	lineageStartWindow = 5 * time.Second
	lineageClockSlack  = time.Second
	// hookCallMemory is how long a hook call the kernel feed folded is
	// remembered after it ended: a sample taken during the call can be
	// merged up to processSampleTimeout later. maxHookCalls bounds them.
	hookCallMemory = processSampleTimeout + processSampleInterval
	maxHookCalls   = 64
)

// procNode is one process of the tree. startTicks is its start in clock
// ticks since boot, 0 while only OpenShell or the kernel feed reported it.
type procNode struct {
	PID, PPID, UID int
	startTicks     int64
	Start          time.Time
	Comm, Exe, Cwd string
	Cmdline        string
	Source         string
	FirstSeen      time.Time
	ExitedAt       time.Time
	ExitCode       *int
	// ExecID and ParentExecID are Tetragon's ids of the image and of its
	// parent's, and HostPID the host's pid, for a process the kernel feed
	// reported. PID is 0 for one whose in-sandbox pid was not captured.
	ExecID, ParentExecID string
	HostPID              int
	Hook                 bool
	HookTools            int
	HookUnexpected       bool
	// held marks a process only a sample saw while the kernel feed streams,
	// whose start is not recorded yet: it may belong to a hook call the
	// feed folds, which the feed reports only when the call ends (hookCall).
	held bool
}

// procTree is one sandbox's process tree.
type procTree struct {
	mu        sync.Mutex
	live      map[int]*procNode
	exited    []*procNode
	sampledAt time.Time
	truncated bool
	// gate paces the tree's records; heldAt is when the log last said how
	// many it held back, notSent how many it held back in all.
	gate    *rateGate
	heldAt  time.Time
	notSent int64
	// interval is how often the sandbox is sampled now (0 until a sample).
	interval time.Duration
	// byExec holds every process the kernel feed reported that is still in
	// the tree, live or among the ended ones kept; byHost the live ones by
	// host pid. kernel counts what the feed brought.
	byExec map[string]*procNode
	byHost map[int]*procNode
	kernel kernelCounts
	// held are the processes whose start waits one sample (procNode.held),
	// in the order the samples found them; calls are the hook calls the
	// feed folded in the last hookCallMemory.
	held  []*procNode
	calls []hookCall
}

// hookCall is one call of DefenseClaw's hook script the kernel feed folded
// into one row: its in-sandbox pid and parent's (the launch shell), its
// user, its program's comm as a sample reads it, and when it ran.
type hookCall struct {
	pid, ppid, uid int
	comm           string
	start, end     time.Time
}

// kernelCounts are what one sandbox's tree took from the kernel feed: execs
// (pinned: with the in-sandbox pid), its supervisor's summarized execs, and
// DefenseClaw's own collector's execs, which are left out.
type kernelCounts struct {
	execs, pinned, supervisor, collector int64
}

func newProcTree() *procTree {
	return &procTree{
		live: map[int]*procNode{}, gate: newRateGate(sandboxapi.ProcessRecordBurst, sandboxapi.ProcessRecordRate),
		byExec: map[string]*procNode{}, byHost: map[int]*procNode{},
	}
}

// processTreeOn reports whether the box's policy has the process tree on.
// Callers hold Manager.mu.
func (b *box) processTreeOn() bool {
	return b.eff != nil && b.eff.ProcessTree
}

// tree returns the box's process tree, making it on first use. Callers hold
// Manager.mu.
func (b *box) tree() *procTree {
	if b.procs == nil {
		b.procs = newProcTree()
	}
	return b.procs
}

// setSampleInterval records how often the observer samples the sandbox now,
// for the process list.
func (m *Manager) setSampleInterval(b *box, d time.Duration) {
	m.mu.Lock()
	t := b.procs
	m.mu.Unlock()
	if t != nil {
		t.mu.Lock()
		t.interval = d
		t.mu.Unlock()
	}
}

// sampleProcesses takes one sample of a ready sandbox whose process tree is
// on, and records the processes that started and exited since the last
// one. It reports how long the exec took and whether it ran.
func (m *Manager) sampleProcesses(ctx context.Context, b *box) (time.Duration, bool) {
	m.mu.Lock()
	on := b.processTreeOn() && b.phase == audit.SandboxPhaseReady && !b.deleted && !b.retained
	name := b.rec.Name
	hold := on && kernelFeedApplies(b)
	m.mu.Unlock()
	if !on {
		return 0, false
	}
	// The feed's lock is not taken under Manager.mu.
	hold = hold && m.kfeed.streaming()
	gw, err := m.gateway(ctx)
	if err != nil {
		return 0, false
	}
	start := m.now()
	execStart := time.Now()
	res, err := m.ownExec(ctx, gw, name, collectArgv("ps", 1, []string{"O", "argv", "O", "cwd"}), openshell.ExecOptions{
		Timeout: processSampleTimeout, Attempts: 1, MaxOutputBytes: collectStreamBytes,
	})
	took := time.Since(execStart)
	if err != nil {
		m.dropGateway(gw, err)
		if ctx.Err() == nil {
			m.logf("sandbox %s: process sample: %v", name, err)
		}
		return took, false
	}
	col, err := parseCollection(res.Stdout, res.Truncated, newCollectScope(), 1)
	if err != nil {
		m.logf("sandbox %s: process sample: %v", name, err)
		return took, true
	}
	m.mu.Lock()
	t := b.tree()
	id := b.identity()
	m.mu.Unlock()
	started, exited := t.merge(col, start, m.now(), hold)
	m.recordProcesses(ctx, b, id, t, started, exited)
	return took, true
}

// merge folds one sample, taken from sampledAt on, into the tree and returns
// the processes that started and exited. A pid the sample shows with
// another start time is a new process; a live process a complete sample
// lacks has exited, unless it joined the tree after the sample was taken.
// A sample cut short, without its end, or stopped at a process bound does
// not show every process: it ends none. Whatever the samples, the tree holds
// at most procTreeMaxLive live processes: a new one past the bound is left
// out (the tree says it is truncated) until others end.
//
// With hold (the kernel feed streams this sandbox's execs), a process only
// the sample shows is recorded one sample later: the feed reports a hook
// call it folds only when the call ends, and the sample may have caught the
// call's launch shell, forks and tools meanwhile (GAP-0095). The processes
// of such a call are dropped (foldLocked); the others are recorded at the
// next sample, with the time they were first seen.
func (t *procTree) merge(c *collection, sampledAt, now time.Time, hold bool) (started, exited []*procNode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sampledAt = now
	// What the previous sample held has waited a sample: record it now
	// (before an exit this sample finds).
	for _, node := range t.held {
		node.held = false
		started = append(started, node)
	}
	t.held = nil
	complete := c.Ended && !c.ProcessesCapped && len(c.Processes) <= procTreeMaxLive
	t.truncated = !complete
	if complete {
		// The processes a complete sample lacks end first, so they do not
		// hold room the ones it shows need.
		seen := make(map[int]bool, len(c.Processes))
		for _, p := range c.Processes {
			seen[p.PID] = true
		}
		for pid, node := range t.live {
			// The sandbox's init, pid 1 of its pid namespace, ends only with
			// the sandbox, which ends the whole tree: a sample without it
			// missed it (GAP-0100: an idle sandbox recorded its pid 1 ending
			// and starting again, about once an hour). Another process at
			// pid 1 has another start and ends it below.
			if !seen[pid] && pid != 1 && node.FirstSeen.Before(sampledAt) {
				exited = append(exited, t.exitLocked(node, now, nil))
			}
		}
	}
	for _, p := range c.Processes {
		node := t.live[p.PID]
		if node != nil && node.startTicks != 0 && node.startTicks != p.StartTicks {
			exited = append(exited, t.exitLocked(node, now, nil))
			node = nil
		}
		fresh := node == nil
		if fresh {
			if len(t.live) >= procTreeMaxLive {
				t.truncated = true
				continue
			}
			node = &procNode{PID: p.PID, FirstSeen: now, Source: audit.SandboxProcessSourceSample, held: hold}
			t.live[p.PID] = node
		}
		node.PPID, node.UID, node.startTicks, node.Start = p.PPID, p.UID, p.StartTicks, c.started(p)
		if p.Comm != "" {
			node.Comm = p.Comm
		}
		if p.Exe != "" {
			node.Exe = p.Exe
		}
		node.Cwd = p.Cwd
		if len(p.Args) > 0 {
			node.Cmdline = redaction.CommandLine(p.Args, maxCmdlineBytes)
		}
		switch {
		case fresh && node.held:
			t.held = append(t.held, node)
		case fresh:
			started = append(started, node)
		}
	}
	// A call that ended before this sample was merged was taken while the
	// call ran.
	t.calls = slices.DeleteFunc(t.calls, func(call hookCall) bool { return now.Sub(call.end) > hookCallMemory })
	for _, call := range t.calls {
		t.foldLocked(call)
	}
	return started, exited
}

// releaseLocked records a held process now: it is the kernel feed's, ended
// otherwise than by a sample, or its tree ends. It reports whether the
// process was held. Callers hold t.mu.
func (t *procTree) releaseLocked(node *procNode) bool {
	if !node.held {
		return false
	}
	node.held = false
	t.held = slices.DeleteFunc(t.held, func(n *procNode) bool { return n == node })
	return true
}

// foldLocked drops the held processes that belong to a hook call the kernel
// feed folded (GAP-0095): the call itself (a sample merged after the feed
// reported it), its launch shell (the call's parent), every process under
// it, and a fork of the hook script that the same sample found orphaned
// (its parent ended while the sample read /proc, so the kernel moved it to
// a subreaper among the call's ancestors). Each one was first seen while
// the call ran, by a user's sample of the call's own user. A held process
// was never recorded, so nothing recorded is withdrawn; anything else is
// recorded at the next sample. Callers hold t.mu.
func (t *procTree) foldLocked(call hookCall) {
	if len(t.held) == 0 || call.pid <= 0 {
		return
	}
	during := func(n *procNode) bool {
		return n.UID == call.uid && !n.FirstSeen.Before(call.start.Add(-lineageClockSlack)) && !n.FirstSeen.After(call.end.Add(hookCallMemory))
	}
	held := make(map[int]*procNode, len(t.held))
	for _, n := range t.held {
		held[n.PID] = n
	}
	under := func(n *procNode) bool {
		for p, depth := n, 0; p != nil && depth < maxLineageDepth; depth++ {
			if p.PPID == call.pid {
				return true
			}
			p = held[p.PPID]
		}
		return false
	}
	ancestors := map[int]bool{1: true}
	for pid, depth := call.ppid, 0; pid > 0 && depth < maxLineageDepth && !ancestors[pid]; depth++ {
		ancestors[pid] = true
		node := t.byPIDLocked(pid, "")
		if node == nil {
			break
		}
		pid = node.PPID
	}
	fold := map[*procNode]bool{}
	samples := map[time.Time]bool{}
	for _, n := range t.held {
		if during(n) && (n.PID == call.pid || n.PID == call.ppid || under(n)) {
			fold[n] = true
			samples[n.FirstSeen] = true
		}
	}
	for _, n := range t.held {
		if !fold[n] && during(n) && samples[n.FirstSeen] && call.comm != "" && n.Comm == call.comm && ancestors[n.PPID] {
			fold[n] = true
		}
	}
	if len(fold) == 0 {
		return
	}
	t.held = slices.DeleteFunc(t.held, func(n *procNode) bool { return fold[n] })
	for n := range fold {
		n.held = false
		if t.live[n.PID] == n {
			delete(t.live, n.PID)
		}
	}
}

// exitLocked moves a live process to the exited ones, the least recently
// ended dropped past procTreeMaxExited. A process already ended stays as it
// was. Callers hold t.mu.
func (t *procTree) exitLocked(node *procNode, at time.Time, code *int) *procNode {
	if !node.ExitedAt.IsZero() {
		return node
	}
	if node.PID > 0 && t.live[node.PID] == node {
		delete(t.live, node.PID)
	}
	if node.HostPID > 0 && t.byHost[node.HostPID] == node {
		delete(t.byHost, node.HostPID)
	}
	node.ExitedAt, node.ExitCode = at, code
	t.exited = append(t.exited, node)
	if over := len(t.exited) - procTreeMaxExited; over > 0 {
		for _, old := range t.exited[:over] {
			if old.ExecID != "" && t.byExec[old.ExecID] == old {
				delete(t.byExec, old.ExecID)
			}
		}
		t.exited = slices.Delete(t.exited, 0, over)
	}
	return node
}

// observeOCSFProcess indexes an OpenShell PROC record of a sandbox whose
// process tree is on: a launch joins the tree, a terminate ends the process
// with its exit status.
func (m *Manager) observeOCSFProcess(ctx context.Context, b *box, r ocsf.Record, at time.Time) {
	// A record from before this daemon started is OpenShell replaying its
	// stream: the process it names may be long gone.
	if !r.HasPID || r.PID <= 0 || at.Before(m.startedAt) {
		return
	}
	m.mu.Lock()
	if !b.processTreeOn() {
		m.mu.Unlock()
		return
	}
	t := b.tree()
	id := b.identity()
	m.mu.Unlock()
	var started, exited []*procNode
	t.mu.Lock()
	node := t.live[r.PID]
	switch strings.ToUpper(r.Activity) {
	case "LAUNCH":
		if node == nil && len(t.live) < procTreeMaxLive {
			node = &procNode{PID: r.PID, FirstSeen: at, Source: audit.SandboxProcessSourceOCSF}
			binary := collectText(r.Binary, collectMaxPathBytes)
			node.Comm, node.Exe = collectText(path.Base(binary), collectMaxCommBytes), binary
			if r.CmdLine != "" {
				node.Cmdline = redaction.CommandLine(strings.Fields(r.CmdLine), maxCmdlineBytes)
			}
			t.live[r.PID] = node
			started = append(started, node)
		}
	case "TERMINATE":
		if node != nil {
			if t.releaseLocked(node) {
				started = append(started, node)
			}
			exited = append(exited, t.exitLocked(node, at, r.ExitCode))
		}
	}
	t.mu.Unlock()
	m.recordProcesses(ctx, b, id, t, started, exited)
}

// observeKernelFrame adds an exec, or ends a process, the sandbox kernel
// feed reported for a sandbox whose process tree is on.
func (m *Manager) observeKernelFrame(ctx context.Context, b *box, f sandboxfeed.Frame) {
	at := f.At
	if now := m.now(); at.IsZero() || at.After(now) {
		at = now
	}
	m.mu.Lock()
	if !b.processTreeOn() || b.deleted {
		m.mu.Unlock()
		return
	}
	t := b.tree()
	id := b.identity()
	m.mu.Unlock()
	var started, exited []*procNode
	t.mu.Lock()
	switch f.Kind {
	case sandboxfeed.FrameExec:
		started, exited = t.kernelExecLocked(f, at)
	case sandboxfeed.FrameExit:
		exited = t.kernelExitLocked(f, at)
	case sandboxfeed.FrameSummary:
		t.kernel.supervisor += max(f.Execs, 0)
	}
	t.mu.Unlock()
	m.recordProcesses(ctx, b, id, t, started, exited)
}

// kernelExecLocked adds one exec. A new image at a host pid ends the image it
// replaced (an exec without a fork); one at an in-sandbox pid ends the other
// process the tree had there, unless that is this same process as the sample
// or OpenShell saw it first, which it then names. DefenseClaw's own
// collector is counted and left out. Callers hold t.mu.
func (t *procTree) kernelExecLocked(f sandboxfeed.Frame, at time.Time) (started, exited []*procNode) {
	if f.ExecID == "" || t.byExec[f.ExecID] != nil {
		return nil, nil
	}
	if f.Collector {
		t.kernel.collector++
		return nil, nil
	}
	if f.HookTool {
		return nil, nil
	}
	binary := collectText(f.Binary, collectMaxPathBytes)
	if f.HostPID > 0 {
		if previous := t.byHost[f.HostPID]; previous != nil {
			exited = append(exited, t.exitLocked(previous, at, nil))
		}
	}
	var node *procNode
	claimed := false
	if f.PID > 0 {
		if current := t.live[f.PID]; current != nil {
			if current.ExecID == "" && (current.Exe == "" || current.Exe == binary || !current.FirstSeen.Before(at.Add(-time.Second))) {
				node = current
				// A sample's process not recorded yet is the feed's: it is
				// recorded as the feed names it.
				if claimed = t.releaseLocked(current); claimed {
					node.Source = audit.SandboxProcessSourceTetragon
				}
			} else {
				if t.releaseLocked(current) {
					started = append(started, current)
				}
				exited = append(exited, t.exitLocked(current, at, nil))
			}
		}
	}
	fresh := node == nil
	if fresh {
		if len(t.byHost) >= procTreeMaxLive || (f.PID > 0 && len(t.live) >= procTreeMaxLive) {
			t.truncated = true
			return started, exited
		}
		node = &procNode{PID: max(f.PID, 0), FirstSeen: at, Source: audit.SandboxProcessSourceTetragon}
		if node.PID > 0 {
			t.live[node.PID] = node
		}
	}
	node.ExecID, node.ParentExecID, node.HostPID = f.ExecID, f.ParentExecID, max(f.HostPID, 0)
	node.Hook, node.HookUnexpected = f.Hook, f.HookUnexpected
	if parent := t.byExec[f.ParentExecID]; f.PPID <= 0 && parent != nil && parent.PID > 0 {
		node.PPID = parent.PID
	} else if f.PPID > 0 {
		node.PPID = f.PPID
	}
	if f.UID != nil {
		node.UID = *f.UID
	}
	if node.Start.IsZero() && f.StartNS > 0 {
		node.Start = time.Unix(0, f.StartNS)
	}
	if binary != "" {
		node.Exe = binary
		if fresh || node.Comm == "" {
			node.Comm = collectText(path.Base(binary), collectMaxCommBytes)
		}
	}
	// The feed redacted the command line before it left the root process;
	// the same rules run again here, so an older feed cannot pass less.
	if f.Cmdline != "" {
		node.Cmdline = redaction.CommandLine(strings.Fields(f.Cmdline), maxCmdlineBytes)
	}
	if f.Cwd != "" {
		node.Cwd = collectText(f.Cwd, collectMaxPathBytes)
	}
	t.byExec[f.ExecID] = node
	if node.HostPID > 0 {
		t.byHost[node.HostPID] = node
	}
	t.kernel.execs++
	if node.PID > 0 {
		t.kernel.pinned++
	}
	if fresh || claimed {
		started = append(started, node)
	}
	return started, exited
}

// kernelExitLocked ends the process an exit names: by its exec id, or the
// latest image of its host pid. Callers hold t.mu.
func (t *procTree) kernelExitLocked(f sandboxfeed.Frame, at time.Time) []*procNode {
	if f.Collector || f.HookTool {
		return nil
	}
	node := t.byExec[f.ExecID]
	if node == nil && f.HostPID > 0 {
		node = t.byHost[f.HostPID]
	}
	if node == nil || !node.ExitedAt.IsZero() {
		return nil
	}
	if f.Hook {
		node.Hook, node.HookTools = true, max(f.HookTools, 0)
		if node.PID > 0 {
			call := hookCall{pid: node.PID, ppid: node.PPID, uid: node.UID, start: node.Start, end: at}
			if call.start.IsZero() || call.start.After(node.FirstSeen) {
				call.start = node.FirstSeen
			}
			if node.Exe != "" {
				call.comm = truncate(path.Base(node.Exe), commBytes)
			}
			t.foldLocked(call)
			if t.calls = append(t.calls, call); len(t.calls) > maxHookCalls {
				t.calls = slices.Delete(t.calls, 0, len(t.calls)-maxHookCalls)
			}
		}
	}
	return []*procNode{t.exitLocked(node, at, f.ExitCode)}
}

// endProcessTree ends every live process of a sandbox that stopped or was
// deleted.
func (m *Manager) endProcessTree(b *box) {
	m.mu.Lock()
	t := b.procs
	id := b.identity()
	m.mu.Unlock()
	if t == nil {
		return
	}
	now := m.now()
	t.mu.Lock()
	started := t.held
	for _, node := range started {
		node.held = false
	}
	t.held = nil
	var exited []*procNode
	for _, node := range t.live {
		exited = append(exited, t.exitLocked(node, now, nil))
	}
	for _, node := range t.byHost {
		exited = append(exited, t.exitLocked(node, now, nil))
	}
	t.mu.Unlock()
	if ctx := m.running(); ctx != nil {
		m.recordProcesses(ctx, b, id, t, started, exited)
	}
}

// recordProcesses records the processes that started and exited, within the
// tree's record rate; the log says once a minute how many it held back.
func (m *Manager) recordProcesses(ctx context.Context, b *box, id audit.SandboxIdentity, t *procTree, started, exited []*procNode) {
	emit := func(node *procNode, event string) {
		// The record copies the process while it holds the tree: a sample,
		// an OpenShell record or a kernel feed frame may update the process
		// meanwhile.
		t.mu.Lock()
		ev := audit.SandboxProcessEvent{
			Sandbox: id, Event: event, Source: node.Source, PID: node.PID, ParentPID: node.PPID,
			HostPID: node.HostPID, ExecID: node.ExecID,
			Executable: node.Exe, Name: node.name(), CommandLine: node.displayCmdline(), WorkingDirectory: node.Cwd,
			Lineage: t.ancestryLocked(t.parentLocked(node)), Timestamp: node.FirstSeen,
		}
		if event == audit.SandboxProcessExit {
			ev.ExitCode, ev.Timestamp = node.ExitCode, node.ExitedAt
		}
		if node.Hook {
			if event == audit.SandboxProcessStart {
				t.mu.Unlock()
				return
			}
		}
		t.mu.Unlock()
		if t.gate.take(processGateKey, ev.Timestamp) {
			m.tel.RecordSandboxProcess(ctx, ev)
			return
		}
		t.mu.Lock()
		t.notSent++
		t.mu.Unlock()
	}
	for _, node := range started {
		emit(node, audit.SandboxProcessStart)
	}
	for _, node := range exited {
		emit(node, audit.SandboxProcessExit)
	}
	now := m.now()
	t.mu.Lock()
	report := now.Sub(t.heldAt) >= time.Minute
	if report {
		t.heldAt = now
	}
	t.mu.Unlock()
	if !report {
		return
	}
	for _, held := range t.gate.drain(now) {
		m.logf("sandbox %s: %d process records were not sent: the sandbox starts processes faster than %d a second", id.Name, held.n, sandboxapi.ProcessRecordRate)
	}
}

// processGateKey is the one key of a tree's record gate.
const processGateKey = "processes"

// parentLocked is a process's parent in the tree: by exec id for one the
// kernel feed reported, else by pid, live first, then the most recently
// ended. Callers hold t.mu.
func (t *procTree) parentLocked(node *procNode) *procNode {
	if node == nil {
		return nil
	}
	if node.ParentExecID != "" {
		if parent := t.byExec[node.ParentExecID]; parent != nil {
			return parent
		}
	}
	if node.PPID > 0 && node.PPID != node.PID {
		return t.byPIDLocked(node.PPID, "")
	}
	return nil
}

// byPIDLocked is the process the tree has at in-sandbox pid, live first,
// then the most recently ended. With exe, a process the kernel feed reported
// matches only when it ran exe: that is the join key of a lookup (sandbox,
// pid, executable), which keeps a pid the sandbox reused from naming
// another process's lineage. Callers hold t.mu.
func (t *procTree) byPIDLocked(pid int, exe string) *procNode {
	if pid <= 0 {
		return nil
	}
	matches := func(n *procNode) bool { return exe == "" || n.ExecID == "" || n.Exe == exe }
	if node := t.live[pid]; node != nil && matches(node) {
		return node
	}
	for i := len(t.exited) - 1; i >= 0; i-- {
		if node := t.exited[i]; node.PID == pid && matches(node) {
			return node
		}
	}
	return nil
}

// ancestryLocked is the name of node and of each of its ancestors, at most
// maxLineageDepth of them. Callers hold t.mu.
func (t *procTree) ancestryLocked(node *procNode) []string {
	var out []string
	seen := map[*procNode]bool{}
	for node != nil && len(out) < maxLineageDepth && !seen[node] {
		seen[node] = true
		out = append(out, node.name())
		node = t.parentLocked(node)
	}
	return out
}

// Lineage returns the process pid of sandbox sandboxName and its ancestors,
// nearest first, from the sandbox's process tree; nil while the tree is
// off or does not hold the process. It implements ProcessLookup.
func (m *Manager) Lineage(sandboxName string, pid int) []ProcessRef {
	return m.LineageFor(sandboxName, pid, "")
}

// LineageFor is Lineage for the process at pid that runs exe (the binary
// the record that names the pid reported): a process the kernel feed
// reported is taken only when its executable is exe.
func (m *Manager) LineageFor(sandboxName string, pid int, exe string) []ProcessRef {
	m.mu.Lock()
	b := m.boxes[sandboxName]
	var t *procTree
	if b != nil {
		t = b.procs
	}
	m.mu.Unlock()
	if t == nil || pid <= 0 {
		return nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	var out []ProcessRef
	seen := map[*procNode]bool{}
	for node := t.byPIDLocked(pid, exe); node != nil && len(out) < maxLineageDepth && !seen[node]; node = t.parentLocked(node) {
		seen[node] = true
		out = append(out, ProcessRef{PID: node.PID, PPID: node.PPID, Comm: node.name(), Exe: node.Exe, Start: node.Start})
	}
	return out
}

// PIDOf is the pid of the one process of sandbox sandboxName that runs exe
// (runs), started at most lineageStartWindow before at (when the program was
// seen connecting) and was not seen exiting before then, from the sandbox's
// process tree; 0 while the tree is off, or when it holds no such process or
// several. A program shorter than a sample interval (a quick curl, a
// `sandbox exec`) is not in the tree, so a copy of it that started earlier
// and still runs (a slow download) cannot be told from it and is not taken
// (GAP-0174); a program that connects long after it started has no lineage
// either. It implements ProcessLookup.
func (m *Manager) PIDOf(sandboxName, exe string, at time.Time) int {
	m.mu.Lock()
	b := m.boxes[sandboxName]
	var t *procTree
	if b != nil {
		t = b.procs
	}
	m.mu.Unlock()
	if t == nil || exe == "" || at.IsZero() {
		return 0
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	startOf := func(n *procNode) time.Time {
		if n.Start.IsZero() {
			// Only OpenShell's launch record named it so far.
			return n.FirstSeen
		}
		return n.Start
	}
	var candidates []*procNode
	for _, nodes := range [][]*procNode{slices.Collect(maps.Values(t.live)), t.exited} {
		for _, n := range nodes {
			start := startOf(n)
			if !n.runs(exe) || n.PID <= 0 || start.Before(at.Add(-lineageStartWindow)) || start.After(at.Add(lineageClockSlack)) ||
				(!n.ExitedAt.IsZero() && n.ExitedAt.Before(at)) {
				continue
			}
			candidates = append(candidates, n)
		}
	}
	if pid := onePID(candidates); pid != 0 || len(candidates) == 0 {
		return pid
	}
	// Several copies. The slack allows for a sample's coarse start, so a
	// copy that started just after the connection is a candidate too. The
	// kernel feed's processes carry their exact exec and exit, so when every
	// candidate is one, the copy running when the program was seen
	// connecting is the one (GAP-0022: on tg a curl every 0.4 s made every
	// row ambiguous). A sampled copy keeps the rule: two give none.
	var running []*procNode
	for _, n := range candidates {
		if n.ExecID == "" {
			return 0
		}
		if !startOf(n).After(at) {
			running = append(running, n)
		}
	}
	return onePID(running)
}

// onePID is the pid the nodes share, or 0 for none or several.
func onePID(nodes []*procNode) int {
	pid := 0
	for _, n := range nodes {
		switch {
		case pid == 0:
			pid = n.PID
		case n.PID != pid:
			return 0
		}
	}
	return pid
}

// runs reports whether the process runs program exe. A sample seldom has a
// workload process's executable (the workload's processes are not dumpable,
// so the exec cannot read their exe link; GAP-0139): without one, the name
// of its first argument or its comm (the kernel keeps 15 bytes of the
// program's name) stands for it.
func (n *procNode) runs(exe string) bool {
	if n.Exe != "" {
		return n.Exe == exe
	}
	name := path.Base(exe)
	if argv0, _, _ := strings.Cut(n.Cmdline, " "); argv0 != "" && path.Base(argv0) == name {
		return true
	}
	return n.Comm != "" && n.Comm == truncate(name, commBytes)
}

// name is the process's name in a lineage: its comm, unless that is the
// kernel's cut of a longer name its executable or first argument gives in
// full (openshell-sandb of openshell-sandbox; GAP-0172).
func (n *procNode) name() string {
	if len(n.Comm) != commBytes {
		return n.Comm
	}
	argv0, _, _ := strings.Cut(n.Cmdline, " ")
	for _, p := range []string{n.Exe, strings.Trim(argv0, `'"`)} {
		if base := path.Base(p); len(base) > commBytes && strings.HasPrefix(base, n.Comm) {
			return base
		}
	}
	return n.Comm
}

var _ ProcessLookup = (*Manager)(nil)

// Processes returns a sandbox's process tree (GET
// /sandboxes/{name}/processes): its live processes by in-sandbox pid, and
// the ones that ended most recently. A live process the kernel feed
// reported without its in-sandbox pid is not listed among the live ones
// (they are keyed by that pid); it is listed once it ended, with its host
// pid.
func (m *Manager) Processes(_ context.Context, name string) (*sandboxapi.ProcessList, error) {
	b, err := m.box(name)
	if err != nil {
		return nil, err
	}
	m.mu.Lock()
	out := &sandboxapi.ProcessList{Name: b.rec.Name, Enabled: b.processTreeOn(), Processes: []sandboxapi.Process{}}
	t := b.procs
	if out.Enabled {
		out.IntervalSeconds = int(processSampleInterval / time.Second)
	}
	kernel := out.Enabled && kernelFeedApplies(b)
	m.mu.Unlock()
	if kernel {
		out.Kernel = m.kfeed.view()
	}
	if t == nil {
		return out, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out.SampledAt, out.Truncated, out.RecordsNotSent = t.sampledAt, t.truncated, t.notSent
	if t.interval > 0 {
		out.IntervalSeconds = int(t.interval / time.Second)
	}
	if out.Kernel != nil {
		out.Kernel.Execs, out.Kernel.Pinned = t.kernel.execs, t.kernel.pinned
		out.Kernel.SupervisorExecs, out.Kernel.CollectorExecs = t.kernel.supervisor, t.kernel.collector
	}
	for _, node := range t.live {
		out.Processes = append(out.Processes, node.view())
	}
	for i := len(t.exited) - 1; i >= 0 && len(out.Exited) < sandboxapi.MaxExitedProcesses; i-- {
		out.Exited = append(out.Exited, t.exited[i].view())
	}
	slices.SortFunc(out.Processes, func(a, b sandboxapi.Process) int { return a.PID - b.PID })
	return out, nil
}

func (n *procNode) view() sandboxapi.Process {
	return sandboxapi.Process{
		PID: n.PID, PPID: n.PPID, UID: n.UID, StartedAt: n.Start, ExitedAt: n.ExitedAt, ExitCode: n.ExitCode,
		Comm: sandboxapi.DisplayText(n.Comm), Exe: sandboxapi.DisplayText(n.Exe), Cwd: sandboxapi.DisplayText(n.Cwd),
		Cmdline: sandboxapi.DisplayText(n.displayCmdline()), Source: n.Source, HostPID: n.HostPID,
		Hook: n.Hook, HookTools: n.HookTools, HookSubtreeUnexpected: n.HookUnexpected,
	}
}

func (n *procNode) displayCmdline() string {
	line := n.Cmdline
	if n.Hook {
		line += " [hook tools: " + strconv.Itoa(n.HookTools) + "]"
	}
	if n.HookUnexpected {
		line += " [hook_subtree_unexpected]"
	}
	return line
}
