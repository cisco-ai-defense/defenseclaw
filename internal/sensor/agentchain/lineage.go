// Copyright 2026 Cisco Systems, Inc. and its affiliates
// Copyright (c) 2026 Mike Storm. All rights reserved.
//
// Derived from ShadowClaw -- Universal Shadow AI Detector, by Mike Storm,
// Distinguished Engineer, CCIE Security 13847. Reimplemented in Go and
// absorbed into the DefenseClaw gateway; see NOTICE for the modifications.
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

package agentchain

import (
	"sort"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

const (
	// lineageTTL is how long a dead process stays in the ancestry table. A
	// chain routinely refers to a child that has already exited -- that is the
	// normal case for cat and base64 -- so forgetting immediately would break
	// attribution for exactly the events worth attributing.
	lineageTTL = 30 * time.Minute

	// maxTrackedProcesses bounds the table so a fork bomb cannot grow it
	// without limit.
	maxTrackedProcesses = 40000

	// maxRetiredProcesses bounds the records kept only by exec id after a
	// newer process took their pid.
	maxRetiredProcesses = 10000

	// maxAncestryWalk bounds a single ancestry walk. A pid table can contain a
	// cycle after pid reuse, and an unbounded walk would hang the poll.
	maxAncestryWalk = 64

	// reseedWindow is how far apart two exec events of one live process may
	// put its start. Tetragon re-announces every running process after it
	// restarts, under a new exec id and with the start time it reads from
	// procfs; that differs from the start its exec event carried by the
	// fork-to-exec gap, which is milliseconds. A new image at the pid (the
	// number reused, or a later exec) is further apart than this.
	reseedWindow = 100 * time.Millisecond

	// pollStartTolerance is how far a process-table row's start (fork time,
	// in clock ticks) may sit from the kernel exec record of the same process
	// (exec time) before the row is taken to be another process.
	pollStartTolerance = 2 * time.Second

	// maxAliases bounds the exec ids one process can collect through
	// repeated backend restarts.
	maxAliases = 4
)

type processRecord struct {
	pid            int
	ppid           int
	responsiblePID int
	name           string
	exe            string
	cmdline        string
	user           string
	uid, auid      *int
	// execID is the backend's identity of this process image (Tetragon's
	// exec_id); aliases are the further ids it gave the same live process
	// when it re-announced it. parentExecID is the parent's, which survives
	// the parent's pid being reused.
	execID       string
	aliases      []string
	parentExecID string
	startNS      int64
	agent        tactics.AgentRoot
	agentName    string
	via          string
	exitedAt     time.Time
	lastSeen     time.Time
	// retired is set once a newer process took this pid. The record is then
	// reachable only by exec id -- for the children that name it as their
	// parent -- until the TTL.
	retired bool
}

func (r *processRecord) hasExecID(id string) bool {
	if id == "" {
		return false
	}
	if r.execID == id {
		return true
	}
	for _, alias := range r.aliases {
		if alias == id {
			return true
		}
	}
	return false
}

// ProcessFacts is what the tracker holds about one process.
type ProcessFacts struct {
	PID     int
	ExecID  string
	Name    string
	Exe     string
	Cmdline string
	User    string
	// UID and AUID are nil when the backend did not report them.
	UID     *int
	AUID    *int
	StartNS int64
	// Agent is set on a process recognised as an agent.
	Agent tactics.AgentRoot
}

func (r *processRecord) facts() ProcessFacts {
	if r == nil {
		return ProcessFacts{}
	}
	return ProcessFacts{
		PID: r.pid, ExecID: r.execID, Name: r.name, Exe: r.exe, Cmdline: r.cmdline,
		User: r.user, UID: copyInt(r.uid), AUID: copyInt(r.auid), StartNS: r.startNS,
		Agent: r.agent,
	}
}

func copyInt(value *int) *int {
	if value == nil {
		return nil
	}
	copied := *value
	return &copied
}

// Tracker keeps process ancestry so an observation about a short-lived
// descendant can be attributed to the agent that spawned it.
//
// Lineage comes from exec events where they are available -- authoritative,
// and they catch the eight-millisecond cat that polling a process table never
// sees -- and falls back to parent pids from the process table when the sensor
// is unprivileged.
//
// A backend that names process images (Tetragon's exec_id) replaces the
// guesswork about pid reuse: a child names its parent's image, so a reused
// parent pid is never mistaken for the parent, and a pid whose image changed
// is a new record rather than a renamed old one. Backends without it (cn_proc,
// Endpoint Security, ETW, process-table polls) keep the name-change rule.
type Tracker struct {
	mu      sync.RWMutex
	records map[int]*processRecord
	// byExec indexes records by exec id and alias, including retired ones.
	byExec map[string]*processRecord
	// retiredQueue holds the retired records, oldest first.
	retiredQueue []*processRecord
	ttl          time.Duration
	now          func() time.Time
	// exited counts records whose process has gone. It is the only thing
	// eviction can reclaim, so keeping the count lets a full table of live
	// processes skip the scan entirely instead of walking every record to
	// discover there is nothing to drop -- which, under sustained process
	// churn, is a full-table scan for every new pid, on the poll path.
	exited int
}

// NewTracker returns an empty tracker using the real clock.
func NewTracker() *Tracker { return newTracker(lineageTTL, time.Now) }

func newTracker(ttl time.Duration, now func() time.Time) *Tracker {
	return &Tracker{
		records: make(map[int]*processRecord), byExec: make(map[string]*processRecord),
		ttl: ttl, now: now,
	}
}

// ExecObservation is one exec as a kernel event backend reported it. Fields a
// backend cannot supply stay zero.
type ExecObservation struct {
	PID            int
	PPID           int
	ResponsiblePID int
	Name           string
	// Exe is the resolved executable path.
	Exe     string
	Cmdline string
	User    string
	UID     *int
	AUID    *int
	// ExecID and ParentExecID are the backend's image identities.
	ExecID       string
	ParentExecID string
	// StartNS is the process start in Unix nanoseconds.
	StartNS int64
}

// ObserveExec records an exec event. This is the authoritative source: it
// carries the parent at the moment of exec, which a later process-table poll
// cannot recover once the parent has exited and the child is reparented.
func (t *Tracker) ObserveExec(pid, ppid, responsiblePID int, name, cmdline string) {
	t.ObserveExecEvent(ExecObservation{
		PID: pid, PPID: ppid, ResponsiblePID: responsiblePID, Name: name, Cmdline: cmdline,
	})
}

// ObserveExecEvent records an exec event with everything the backend said
// about the process.
func (t *Tracker) ObserveExecEvent(e ExecObservation) {
	if e.PID <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	if e.ExecID != "" {
		if known, ok := t.byExec[e.ExecID]; ok {
			// The same image announced again: a duplicate delivery adds
			// facts at most.
			known.lastSeen = now
			fillRecord(known, e)
			return
		}
	}
	existing, ok := t.records[e.PID]
	switch {
	case !ok:
		t.insertLocked(e, now, nil)
	case existing.execID != "" && e.ExecID != "" && existing.exitedAt.IsZero() &&
		startsAgree(existing.startNS, e.StartNS, reseedWindow):
		// The live process re-announced under a new exec id (Tetragon
		// restarted). Same process: it keeps its identity and its children.
		t.aliasLocked(existing, e, now)
	case existing.execID != "":
		// Another image at this pid. When both sides carry exec ids, they and
		// not the name say so, and nothing of the old identity carries over.
		// A native exec cannot name the image, so the name rule decides as it
		// does on the native backend.
		var carry *processRecord
		if e.ExecID == "" && existing.exitedAt.IsZero() && existing.name == e.Name {
			carry = existing
		}
		t.retireLocked(existing, now)
		t.insertLocked(e, now, carry)
	default:
		t.updateLocked(existing, e, now)
	}
}

// ObserveProcessTable records a poll of the live process table. It is the
// unprivileged fallback for ObserveExec and is lossy in exactly one way worth
// naming: a process that started and exited between two polls is never seen.
func (t *Tracker) ObserveProcessTable(rows []ProcessRow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	for _, row := range rows {
		t.observeRowLocked(row, now)
	}
}

// ProcessRow is one row of a process-table poll.
type ProcessRow struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
	// StartNS is the process start in Unix nanoseconds, 0 when unknown.
	StartNS int64
}

func (t *Tracker) observeRowLocked(row ProcessRow, now time.Time) {
	if row.PID <= 0 {
		return
	}
	e := ExecObservation{
		PID: row.PID, PPID: row.PPID, ResponsiblePID: row.PPID,
		Name: row.Name, Cmdline: row.Cmdline, StartNS: row.StartNS,
	}
	existing, ok := t.records[row.PID]
	switch {
	case !ok:
		t.insertLocked(e, now, nil)
	case existing.execID != "" && existing.exitedAt.IsZero() &&
		!startsDisagree(existing.startNS, row.StartNS, pollStartTolerance):
		// The kernel's exec record is the authority on this process. A poll
		// only says it is still there; its name (comm, cut at 15 bytes) must
		// not rename the image the kernel described.
		existing.lastSeen = now
		if existing.ppid <= 0 {
			existing.ppid = row.PPID
		}
	case existing.execID != "":
		t.retireLocked(existing, now)
		t.insertLocked(e, now, nil)
	default:
		t.updateLocked(existing, e, now)
	}
}

// insertLocked adds a record for a pid the table does not hold. carry is the
// process it replaced, when that was the same program (the name rule), so its
// agent identity survives an exec that does not restate it.
func (t *Tracker) insertLocked(e ExecObservation, now time.Time, carry *processRecord) {
	if len(t.records) >= maxTrackedProcesses {
		// Full. Drop the oldest exited record rather than refusing to
		// learn: a table that stops updating attributes new work to stale
		// ancestry, which is worse than forgetting a dead pid.
		t.evictOldestExitedLocked()
		if len(t.records) >= maxTrackedProcesses {
			return
		}
	}
	record := &processRecord{pid: e.PID, lastSeen: now}
	setRecord(record, e)
	t.records[e.PID] = record
	if e.ExecID != "" {
		t.byExec[e.ExecID] = record
	}
	t.identifyLocked(record, true)
	if record.agentName == "" && carry != nil && carry.agentName != "" {
		record.agent, record.agentName, record.via = carry.agent, carry.agentName, carry.via
	}
}

// updateLocked is an exec or poll of a pid whose record carries no exec id.
func (t *Tracker) updateLocked(existing *processRecord, e ExecObservation, now time.Time) {
	// A pid that has already exited, or that now reports a different image,
	// is a different process: the kernel recycled the number, or the process
	// exec'd into something else. Either way the identity recorded before
	// belongs to a process that is gone.
	recycled := !existing.exitedAt.IsZero() || existing.name != e.Name
	if !existing.exitedAt.IsZero() {
		t.exited--
	}
	if recycled {
		setRecord(existing, e)
	} else {
		existing.ppid, existing.responsiblePID = e.PPID, e.ResponsiblePID
		existing.cmdline = e.Cmdline
		fillRecord(existing, e)
	}
	if e.ExecID != "" {
		existing.execID = e.ExecID
		t.byExec[e.ExecID] = existing
	}
	existing.lastSeen = now
	existing.exitedAt = time.Time{}
	// Clear rather than carry forward on a recycled pid. The lineage gate is
	// the whole false-positive control for the host plane, so a stale agent
	// name on a recycled pid turns ordinary developer activity -- in this
	// process and in every descendant of it -- into scored findings.
	t.identifyLocked(existing, recycled)
}

// aliasLocked records a further exec id for a live process.
func (t *Tracker) aliasLocked(existing *processRecord, e ExecObservation, now time.Time) {
	if len(existing.aliases) >= maxAliases {
		if t.byExec[existing.aliases[0]] == existing {
			delete(t.byExec, existing.aliases[0])
		}
		existing.aliases = existing.aliases[1:]
	}
	existing.aliases = append(existing.aliases, e.ExecID)
	t.byExec[e.ExecID] = existing
	existing.lastSeen = now
	// The newest description wins where it says something.
	if e.Name != "" {
		existing.name = e.Name
	}
	if e.Exe != "" {
		existing.exe = e.Exe
	}
	if e.Cmdline != "" {
		existing.cmdline = e.Cmdline
	}
	if e.PPID > 0 {
		existing.ppid, existing.responsiblePID = e.PPID, e.ResponsiblePID
	}
	if e.ParentExecID != "" {
		existing.parentExecID = e.ParentExecID
	}
	fillRecord(existing, e)
	t.identifyLocked(existing, false)
}

// retireLocked takes a record out of the pid table because a newer process
// holds its pid. A record with an exec id stays reachable through it.
func (t *Tracker) retireLocked(record *processRecord, now time.Time) {
	delete(t.records, record.pid)
	if record.exitedAt.IsZero() {
		record.exitedAt = now
	} else {
		t.exited--
	}
	if record.execID == "" {
		return
	}
	record.retired = true
	t.retiredQueue = append(t.retiredQueue, record)
	for len(t.retiredQueue) > maxRetiredProcesses {
		t.forgetLocked(t.retiredQueue[0])
		t.retiredQueue = t.retiredQueue[1:]
	}
}

// forgetLocked drops every exec id that leads to record.
func (t *Tracker) forgetLocked(record *processRecord) {
	for _, id := range append([]string{record.execID}, record.aliases...) {
		if id != "" && t.byExec[id] == record {
			delete(t.byExec, id)
		}
	}
}

// identifyLocked recomputes a record's agent identity. clearOnMiss drops the
// identity it had when the record no longer reads as an agent.
func (t *Tracker) identifyLocked(record *processRecord, clearOnMiss bool) {
	if root := tactics.IdentifyAgent(record.exe, record.name, record.cmdline); root.Name != "" {
		record.agent, record.agentName = root, root.Name
		record.via = "cmdline"
		if root.Basis == tactics.BasisExecutable || root.Basis == tactics.BasisInstallPath {
			record.via = "process"
		}
		return
	}
	if clearOnMiss {
		record.agent, record.agentName, record.via = tactics.AgentRoot{}, "", ""
	}
}

// setRecord replaces everything a record says about its process.
func setRecord(record *processRecord, e ExecObservation) {
	record.ppid, record.responsiblePID = e.PPID, e.ResponsiblePID
	record.name, record.exe, record.cmdline, record.user = e.Name, e.Exe, e.Cmdline, e.User
	record.uid, record.auid = copyInt(e.UID), copyInt(e.AUID)
	record.execID, record.parentExecID, record.startNS = e.ExecID, e.ParentExecID, e.StartNS
	record.aliases = nil
}

// fillRecord adds the facts a record lacks.
func fillRecord(record *processRecord, e ExecObservation) {
	if record.exe == "" {
		record.exe = e.Exe
	}
	if record.user == "" {
		record.user = e.User
	}
	if record.uid == nil {
		record.uid = copyInt(e.UID)
	}
	if record.auid == nil {
		record.auid = copyInt(e.AUID)
	}
	if record.parentExecID == "" {
		record.parentExecID = e.ParentExecID
	}
	if record.startNS == 0 {
		record.startNS = e.StartNS
	}
}

// startsAgree reports two known start times within window of each other.
func startsAgree(a, b int64, window time.Duration) bool {
	if a == 0 || b == 0 {
		return false
	}
	delta := a - b
	if delta < 0 {
		delta = -delta
	}
	return delta <= int64(window)
}

// startsDisagree reports two known start times further apart than window.
// Unknown is never a disagreement.
func startsDisagree(a, b int64, window time.Duration) bool {
	return a != 0 && b != 0 && !startsAgree(a, b, window)
}

func (t *Tracker) evictOldestExitedLocked() {
	if t.exited == 0 {
		// Nothing to reclaim. Without this the table walks all
		// maxTrackedProcesses records on every new pid once it is full and
		// every process in it is alive.
		return
	}
	var victim *processRecord
	for _, record := range t.records {
		if record.exitedAt.IsZero() {
			continue
		}
		if victim == nil || record.exitedAt.Before(victim.exitedAt) {
			victim = record
		}
	}
	if victim != nil {
		delete(t.records, victim.pid)
		t.forgetLocked(victim)
		t.exited--
	}
}

// ObserveExit marks a pid as gone. The record is kept for the TTL so an
// observation about the process can still be attributed after it exits.
func (t *Tracker) ObserveExit(pid int) { t.ObserveExitEvent(pid, "") }

// ObserveExitEvent marks a process as gone. With an exec id it marks exactly
// that image, even when a newer process already holds the pid.
func (t *Tracker) ObserveExitEvent(pid int, execID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	record := t.lookupLocked(pid, execID)
	if record == nil {
		return
	}
	if record.exitedAt.IsZero() && !record.retired {
		t.exited++
	}
	if !record.retired || record.exitedAt.IsZero() {
		record.exitedAt = t.now()
	}
}

// lookupLocked finds the record of a process by its exec id, else its pid.
// A pid whose record names another image is not that process.
func (t *Tracker) lookupLocked(pid int, execID string) *processRecord {
	if execID != "" {
		if record, ok := t.byExec[execID]; ok {
			return record
		}
	}
	record, ok := t.records[pid]
	if !ok {
		return nil
	}
	if execID != "" && record.execID != "" && !record.hasExecID(execID) {
		return nil
	}
	return record
}

// Reap drops exited records past the TTL and returns how many were removed.
func (t *Tracker) Reap() int {
	t.mu.Lock()
	defer t.mu.Unlock()
	cutoff := t.now().Add(-t.ttl)
	removed := 0
	for pid, record := range t.records {
		if !record.exitedAt.IsZero() && record.exitedAt.Before(cutoff) {
			delete(t.records, pid)
			t.forgetLocked(record)
			t.exited--
			removed++
		}
	}
	kept := t.retiredQueue[:0]
	for _, record := range t.retiredQueue {
		if record.exitedAt.Before(cutoff) {
			t.forgetLocked(record)
			removed++
			continue
		}
		kept = append(kept, record)
	}
	for index := len(kept); index < len(t.retiredQueue); index++ {
		t.retiredQueue[index] = nil
	}
	t.retiredQueue = kept
	return removed
}

// Attribute walks a pid's ancestry to the agent answerable for it, or reports
// false when there is no agent above it.
//
// This is the gate: no host-plane signal fires for a process without an AI
// agent in its lineage. A developer running sudo produces nothing; the same
// sudo as a descendant of claude produces a signal.
func (t *Tracker) Attribute(pid int) (Attribution, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	found, ok := t.walkLocked(t.records[pid])
	return found.Attribution, ok
}

// Lineage is an attribution together with the processes it runs through.
type Lineage struct {
	Attribution
	// Root is the agent process the attribution names (RootPID).
	Root ProcessFacts
	// SessionRoot is the outermost ancestor of Root that carries Root's
	// agent identity, so the forks and self-execs of one agent share it.
	SessionRoot ProcessFacts
	// Child is Root's direct child on the path down to the process -- the
	// process an agent started for a tool call -- or the zero value when the
	// process is the agent itself.
	Child ProcessFacts
}

// Lineage attributes the process named by execID (when the backend gave one)
// or pid, and returns the processes the attribution runs through.
func (t *Tracker) Lineage(pid int, execID string) (Lineage, bool) {
	t.mu.RLock()
	defer t.mu.RUnlock()
	found, ok := t.walkLocked(t.lookupLocked(pid, execID))
	if !ok {
		return Lineage{}, false
	}
	session := found.root
	if found.Depth > 0 {
		session = t.outermostSameAgentLocked(found.root)
	}
	return Lineage{
		Attribution: found.Attribution, Root: found.root.facts(),
		SessionRoot: session.facts(), Child: found.child.facts(),
	}, true
}

// walk is an attribution with the records it names.
type walk struct {
	Attribution
	root, child *processRecord
}

func (t *Tracker) walkLocked(record *processRecord) (walk, bool) {
	if record == nil {
		return walk{}, false
	}
	if record.agentName != "" {
		// The process is itself an agent. Walk to the outermost ancestor
		// carrying the same agent identity before calling it the root.
		//
		// This matters for any agent that is a shell script or a supervisor:
		// its forked children inherit its argv, so each one independently
		// looks like the agent. Rooting each at itself would split one agent
		// session into one session per command it ran -- which is exactly the
		// fragmentation this package exists to prevent, since the sequence is
		// the finding.
		root := t.outermostSameAgentLocked(record)
		return walk{Attribution: Attribution{
			RootPID: root.pid, AgentName: record.agentName, Depth: 0,
			Via: record.via, State: StateAttributed,
		}, root: root}, true
	}
	// The parent chain is authoritative; the responsible pid is a fallback.
	//
	// Both are needed and the order matters. On macOS a shell an agent
	// spawned can be reparented away, and then only the responsible pid
	// still points back at the agent -- so it cannot be ignored. But the
	// responsible pid is a TCC concept meaning "the process answerable for
	// this one's permissions", which on a normal host is the session leader
	// for everything in the session. Measured live: an agent at 77949 and
	// both of its children reported responsible=75745, the login session.
	// Preferring it walked straight past the agent to the session leader,
	// found no agent there, and gated every tactic the agent had performed.
	//
	// So: walk parents first, and only fall back to the responsible chain
	// when that finds nothing.
	if found, ok := t.walkAncestryLocked(record, false); ok {
		return found, true
	}
	return t.walkAncestryLocked(record, true)
}

// walkAncestryLocked climbs from record looking for an agent.
//
// preferResponsible selects which edge to follow when a process has both a
// parent and a distinct responsible process.
func (t *Tracker) walkAncestryLocked(record *processRecord, preferResponsible bool) (walk, bool) {
	for depth, current := 1, record; depth <= maxAncestryWalk; depth++ {
		parent, viaResponsible := t.parentLocked(current, preferResponsible)
		if parent == nil {
			return walk{}, false
		}
		if parent.agentName != "" {
			// Which edge was actually taken to reach this parent, recorded
			// from the step that took it. Reading it off the parent's own
			// responsiblePID asked the wrong record and always said
			// "ancestry", hiding the reparenting case this exists to cover.
			via := "ancestry"
			if viaResponsible {
				via = "responsible"
			}
			return walk{Attribution: Attribution{
				RootPID: parent.pid, AgentName: parent.agentName, Depth: depth,
				Via: via, State: StateAttributed,
			}, root: parent, child: current}, true
		}
		current = parent
	}
	return walk{}, false
}

// parentLocked is one step up the tree: the responsible process when
// preferred and known, else the parent image the backend named, else the
// process at the parent pid -- unless the child named its parent's image and
// the pid now holds another one, which is the kernel having reused the
// number. viaResponsible reports that the responsible edge was taken.
func (t *Tracker) parentLocked(current *processRecord, preferResponsible bool) (*processRecord, bool) {
	if preferResponsible && current.responsiblePID > 0 && current.responsiblePID != current.pid {
		if parent, ok := t.records[current.responsiblePID]; ok {
			if current.responsiblePID == InitPID {
				return nil, false
			}
			return parent, current.responsiblePID != current.ppid
		}
	}
	if current.parentExecID != "" {
		if parent, ok := t.byExec[current.parentExecID]; ok {
			if parent == current || parent.pid <= 0 || parent.pid == InitPID {
				return nil, false
			}
			return parent, false
		}
	}
	next := current.ppid
	if next <= 0 || next == InitPID || next == current.pid {
		return nil, false
	}
	parent, ok := t.records[next]
	if !ok {
		return nil, false
	}
	if current.parentExecID != "" && parent.execID != "" && !parent.hasExecID(current.parentExecID) {
		return nil, false
	}
	return parent, false
}

// outermostSameAgentLocked walks up from record while each ancestor carries
// the same agent name, and returns the last one that does.
//
// It prefers the responsible pid for the same reason attribution does: on
// macOS a shell an agent spawned is reparented away, so its ppid is launchd
// and only the responsible pid still points at the agent. Following ppid
// alone stopped at that reparenting and rooted the child at itself, splitting
// one agent session into one per fork -- the exact fragmentation this walk
// exists to prevent. Bounded by the same walk limit as attribution, because a
// pid table can contain a cycle after pid reuse.
func (t *Tracker) outermostSameAgentLocked(record *processRecord) *processRecord {
	root, current := record, record
	for depth := 0; depth < maxAncestryWalk; depth++ {
		parent, _ := t.parentLocked(current, true)
		if parent == nil || parent.agentName != record.agentName {
			return root
		}
		root, current = parent, parent
	}
	return root
}

// AttributionState classifies a pid that has no agent above it, so the absence
// is described rather than merely reported as "no finding".
func (t *Tracker) AttributionState(pid int) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	record, ok := t.records[pid]
	if _, attributed := t.walkLocked(record); attributed {
		return StateAttributed
	}
	if !ok {
		return StateOrphaned
	}
	if record.ppid == InitPID {
		return StateBootPersistent
	}
	return StateOrphaned
}

// RunningAgents lists the live agent processes, pid-ordered.
func (t *Tracker) RunningAgents() []Attribution {
	t.mu.RLock()
	defer t.mu.RUnlock()
	agents := make([]Attribution, 0, 8)
	for pid, record := range t.records {
		if record.agentName == "" || !record.exitedAt.IsZero() {
			continue
		}
		agents = append(agents, Attribution{
			RootPID: pid, AgentName: record.agentName, Depth: 0,
			Via: record.via, State: StateAttributed,
		})
	}
	sort.Slice(agents, func(i, j int) bool { return agents[i].RootPID < agents[j].RootPID })
	return agents
}

// Tracked is how many process records are held.
func (t *Tracker) Tracked() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records)
}
