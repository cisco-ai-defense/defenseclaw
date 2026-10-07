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
	"regexp"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// The process tree (opt-in: the pack's observe.process_tree, or `sandbox run
// --process-tree`). While a sandbox with it on is ready, the collector
// samples its /proc every processSampleInterval (one exec; on the vm driver
// every processSampleIntervalVM once a sample is slow): the pid, parent,
// uid, start time, comm, executable, working folder and first arguments of
// every process. OpenShell's PROC LAUNCH and TERMINATE records join the tree
// as they arrive (they name a process and its binary, not its parent; the
// next sample fills that in). The tree is bounded (procTreeMaxLive live
// processes, the procTreeMaxExited most recently ended ones), every process
// that joins it is recorded once as started and once as exited
// (sandbox.process_tree, at most processRecordBurst at once and
// processRecordRate a second per sandbox), and Lineage walks it for the
// egress destinations. Its limits are those of sampling: a process that
// starts and ends between two samples, and that OpenShell does not report,
// is never seen; and every field is the agent's to choose (its arguments,
// its comm, its executable path): display text, never a decision.

const (
	processSampleInterval   = 5 * time.Second
	processSampleIntervalVM = 15 * time.Second
	// processSampleSlow is the sample time past which the vm driver's
	// sandboxes are sampled every processSampleIntervalVM.
	processSampleSlow    = time.Second
	processSampleTimeout = 10 * time.Second
	procTreeMaxLive      = 4096
	procTreeMaxExited    = 1024
	processRecordBurst   = 200
	processRecordRate    = 10
	maxLineageDepth      = 32
	maxCmdlineBytes      = 1024
)

// procNode is one process of the tree. startTicks is its start in clock
// ticks since boot, 0 while only OpenShell reported it.
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
}

// procTree is one sandbox's process tree.
type procTree struct {
	mu        sync.Mutex
	live      map[int]*procNode
	exited    []*procNode
	sampledAt time.Time
	truncated bool
	// gate paces the tree's records; heldAt is when the log last said how
	// many it held back.
	gate   *rateGate
	heldAt time.Time
	// interval is how often the sandbox is sampled now (0 until a sample).
	interval time.Duration
}

func newProcTree() *procTree {
	return &procTree{live: map[int]*procNode{}, gate: newRateGate(processRecordBurst, processRecordRate)}
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
	m.mu.Unlock()
	if !on {
		return 0, false
	}
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
	started, exited := t.merge(col, start, m.now())
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
func (t *procTree) merge(c *collection, sampledAt, now time.Time) (started, exited []*procNode) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.sampledAt = now
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
			if !seen[pid] && node.FirstSeen.Before(sampledAt) {
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
			node = &procNode{PID: p.PID, FirstSeen: now, Source: audit.SandboxProcessSourceSample}
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
			node.Cmdline = processCmdline(p.Args)
		}
		if fresh {
			started = append(started, node)
		}
	}
	return started, exited
}

// exitLocked moves a live process to the exited ones, the least recently
// ended dropped past procTreeMaxExited. Callers hold t.mu.
func (t *procTree) exitLocked(node *procNode, at time.Time, code *int) *procNode {
	delete(t.live, node.PID)
	node.ExitedAt, node.ExitCode = at, code
	t.exited = append(t.exited, node)
	if over := len(t.exited) - procTreeMaxExited; over > 0 {
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
				node.Cmdline = processCmdline(strings.Fields(r.CmdLine))
			}
			t.live[r.PID] = node
			started = append(started, node)
		}
	case "TERMINATE":
		if node != nil {
			exited = append(exited, t.exitLocked(node, at, r.ExitCode))
		}
	}
	t.mu.Unlock()
	m.recordProcesses(ctx, b, id, t, started, exited)
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
	var exited []*procNode
	for _, node := range t.live {
		exited = append(exited, t.exitLocked(node, now, nil))
	}
	t.mu.Unlock()
	if ctx := m.running(); ctx != nil {
		m.recordProcesses(ctx, b, id, t, nil, exited)
	}
}

// recordProcesses records the processes that started and exited, within the
// tree's record rate; the log says once a minute how many it held back.
func (m *Manager) recordProcesses(ctx context.Context, b *box, id audit.SandboxIdentity, t *procTree, started, exited []*procNode) {
	emit := func(node *procNode, event string) {
		// The record copies the process while it holds the tree: a sample
		// or an OpenShell record may update the process meanwhile.
		t.mu.Lock()
		ev := audit.SandboxProcessEvent{
			Sandbox: id, Event: event, Source: node.Source, PID: node.PID, ParentPID: node.PPID,
			Executable: node.Exe, Name: node.Comm, CommandLine: node.Cmdline, WorkingDirectory: node.Cwd,
			Lineage: t.lineageNamesLocked(node.PPID), Timestamp: node.FirstSeen,
		}
		if event == audit.SandboxProcessExit {
			ev.ExitCode, ev.Timestamp = node.ExitCode, node.ExitedAt
		}
		t.mu.Unlock()
		if t.gate.take(processGateKey, ev.Timestamp) {
			m.tel.RecordSandboxProcess(ctx, ev)
		}
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
		m.logf("sandbox %s: %d process records were not sent: the sandbox starts processes faster than %d a second", id.Name, held.n, processRecordRate)
	}
}

// processGateKey is the one key of a tree's record gate.
const processGateKey = "processes"

// lineageNamesLocked is the comm of each ancestor from pid up, at most
// maxLineageDepth of them. Callers hold t.mu.
func (t *procTree) lineageNamesLocked(pid int) []string {
	var out []string
	seen := map[int]bool{}
	for pid > 0 && len(out) < maxLineageDepth && !seen[pid] {
		seen[pid] = true
		node := t.live[pid]
		if node == nil {
			break
		}
		out = append(out, node.Comm)
		pid = node.PPID
	}
	return out
}

// Lineage returns the process pid of sandbox sandboxName and its ancestors,
// nearest first, from the sandbox's process tree; nil while the tree is
// off or does not hold the process. It implements ProcessLookup.
func (m *Manager) Lineage(sandboxName string, pid int) []ProcessRef {
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
	seen := map[int]bool{}
	for pid > 0 && len(out) < maxLineageDepth && !seen[pid] {
		seen[pid] = true
		node := t.live[pid]
		if node == nil {
			for i := len(t.exited) - 1; i >= 0; i-- {
				if t.exited[i].PID == pid {
					node = t.exited[i]
					break
				}
			}
		}
		if node == nil {
			break
		}
		out = append(out, ProcessRef{PID: node.PID, PPID: node.PPID, Comm: node.Comm, Exe: node.Exe, Start: node.Start})
		pid = node.PPID
	}
	return out
}

// PIDOf is the pid of the one process of sandbox sandboxName that runs exe
// (runs) and that ran at at (started by then, not seen exiting
// before), from the sandbox's process tree; 0 while the tree is off, or when
// it holds no such process or several. A program shorter than a sample
// interval is not in the tree. It implements ProcessLookup.
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
	pid := 0
	for _, nodes := range [][]*procNode{slices.Collect(maps.Values(t.live)), t.exited} {
		for _, n := range nodes {
			if !n.runs(exe) || n.Start.After(at) || (!n.ExitedAt.IsZero() && n.ExitedAt.Before(at)) || n.PID == pid {
				continue
			}
			if pid != 0 {
				return 0
			}
			pid = n.PID
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
	return n.Comm != "" && n.Comm == truncate(name, 15)
}

var _ ProcessLookup = (*Manager)(nil)

// Processes returns a sandbox's process tree (GET
// /sandboxes/{name}/processes): its live processes, and the ones that
// ended most recently.
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
	m.mu.Unlock()
	if t == nil {
		return out, nil
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	out.SampledAt, out.Truncated = t.sampledAt, t.truncated
	if t.interval > 0 {
		out.IntervalSeconds = int(t.interval / time.Second)
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
		Cmdline: sandboxapi.DisplayText(n.Cmdline), Source: n.Source,
	}
}

// secretArg is an argument that names a secret (--token=…, api_key=…), and
// secretFlag a flag whose next argument is one (--password value).
var (
	secretArg  = regexp.MustCompile(`(?i)^(-{0,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*[=:])(.+)$`)
	secretFlag = regexp.MustCompile(`(?i)^-{1,2}[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*$`)
	// longToken is a bare argument shaped like a key: 32 or more letters,
	// digits and key punctuation with both letters and digits.
	longToken = regexp.MustCompile(`^[A-Za-z0-9_\-+/=.]{32,}$`)
	// userFlag is a flag whose next argument may be user:password (curl -u,
	// --user, --proxy-user, -U), and userArg one with it attached.
	userFlag = regexp.MustCompile(`^(?:-u|-U|--user|--proxy-user)$`)
	userArg  = regexp.MustCompile(`^(-u|-U|--user=|--proxy-user=)([^:]*:)(.+)$`)
	// urlPassword is the password of a URL's userinfo
	// (scheme://user:password@host).
	urlPassword = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://[^/@:\s]*:)([^/@\s]+)@`)
	// secretKey is a word that names a secret and ends where its value, the
	// next word, starts (a header: "Authorization: Bearer …", "X-Api-Key: …");
	// authScheme the scheme word an Authorization value starts with.
	secretKey  = regexp.MustCompile(`(?i)^[a-z0-9_.-]*(?:token|secret|passw(?:or)?d|api[_-]?key|auth|credential|private[_-]?key)[a-z0-9_.-]*[=:]$`)
	authScheme = regexp.MustCompile(`(?i)^(?:bearer|basic|token|digest|negotiate)$`)
	// word is one word of an argument that holds several (a script).
	word = regexp.MustCompile(`\S+`)
)

// processCmdline is a process's argument vector as the process tree keeps
// and shows it: joined, the values of arguments that name secrets,
// key-shaped arguments, URL passwords, the password of a user:password
// argument (curl -u) and a MySQL client's attached -pPASSWORD replaced by
// redaction placeholders, at most maxCmdlineBytes. An argument of several
// words (the script of sh -c '…' or eval '…', a header value) has its
// words redacted the same way (GAP-0107). Telemetry destinations redact it
// again by their own profile (it is content).
func processCmdline(args []string) string {
	return truncate(strings.Join(redactArgs(args), " "), maxCmdlineBytes)
}

// redactArgs redacts an argument vector, or the words of one argument, for
// processCmdline. A word keeps the quotes around it.
func redactArgs(args []string) []string {
	out := make([]string, 0, len(args))
	mysql := len(args) > 0 && mysqlClient(strings.Trim(args[0], `'"`))
	hideNext, userNext := false, false
	for _, arg := range args {
		user := userNext
		userNext = false
		pre, a, post := unquote(arg)
		switch {
		case hideNext && authScheme.MatchString(a):
			// The scheme of "Authorization: Bearer …" stays; its value goes.
		case hideNext:
			a, hideNext = redaction.ForSinkEntity(a), false
		case strings.ContainsAny(a, " \t\r\n"):
			a = redactWords(a)
		case secretKey.MatchString(a):
			hideNext = true
		case user && !strings.HasPrefix(a, "-") && strings.Contains(a, ":"):
			name, password, _ := strings.Cut(a, ":")
			a = name + ":" + redaction.ForSinkEntity(password)
		case secretArg.MatchString(a):
			m := secretArg.FindStringSubmatch(a)
			a = m[1] + redaction.ForSinkEntity(m[2])
		case secretFlag.MatchString(a):
			hideNext = true
		case userFlag.MatchString(a):
			userNext = true
		case userArg.MatchString(a):
			m := userArg.FindStringSubmatch(a)
			a = m[1] + m[2] + redaction.ForSinkEntity(m[3])
		case mysql && len(a) > 2 && strings.HasPrefix(a, "-p"):
			a = "-p" + redaction.ForSinkEntity(a[2:])
		case longToken.MatchString(a) && strings.ContainsAny(a, "0123456789") && strings.IndexFunc(a, isLetter) >= 0 && !strings.Contains(a, "/"):
			a = redaction.ForSinkEntity(a)
		}
		a = urlPassword.ReplaceAllStringFunc(a, func(m string) string {
			sub := urlPassword.FindStringSubmatch(m)
			return sub[1] + redaction.ForSinkEntity(sub[2]) + "@"
		})
		out = append(out, pre+a+post)
	}
	return out
}

// redactWords redacts the words of an argument that holds several, keeping
// the space between them.
func redactWords(s string) string {
	at := word.FindAllStringIndex(s, -1)
	words := make([]string, len(at))
	for i, r := range at {
		words[i] = s[r[0]:r[1]]
	}
	red := redactArgs(words)
	var b strings.Builder
	last := 0
	for i, r := range at {
		b.WriteString(s[last:r[0]])
		b.WriteString(red[i])
		last = r[1]
	}
	b.WriteString(s[last:])
	return b.String()
}

// unquote splits the shell quotes, their backslash escapes (a script nested
// in another, GAP-0144) and brackets around a word from it.
func unquote(s string) (pre, core, post string) {
	core = strings.TrimLeft(s, `\'"($`+"`")
	pre = s[:len(s)-len(core)]
	trimmed := strings.TrimRight(core, `\'");`+"`")
	return pre, trimmed, core[len(trimmed):]
}

// mysqlClient reports a MySQL or MariaDB client, which takes its password
// attached to -p.
func mysqlClient(argv0 string) bool {
	name := path.Base(argv0)
	return strings.HasPrefix(name, "mysql") || strings.HasPrefix(name, "mariadb")
}

func isLetter(r rune) bool { return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') }
