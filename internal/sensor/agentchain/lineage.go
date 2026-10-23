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
	"strings"
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
	// newer process instance took their pid.
	maxRetiredProcesses = 10000

	// maxAncestryWalk bounds a single ancestry walk. A pid table can contain a
	// cycle after pid reuse, and an unbounded walk would hang the poll.
	maxAncestryWalk = 64

	// startTolerance allows for rounding between kernel start-time sources.
	// Exec time is not a process start time: a process may exec long after
	// fork. Two known starts further apart than this on one pid are two
	// processes.
	startTolerance = 2 * time.Second

	// reseedWindow is how far apart two exec events of one live process may
	// put its start for the second to be a re-announce of the first.
	// Tetragon re-announces every running process after it restarts, under a
	// new exec id and with the start time it reads from procfs; that differs
	// from the start its exec event carried by the fork-to-exec gap, which is
	// milliseconds.
	reseedWindow = 100 * time.Millisecond

	// pollStartTolerance is how far a process-table row's start may sit from
	// the start a kernel exec record (one with an exec id) carries before
	// the row is taken to be another process. The two are derived
	// independently -- the row from /proc/stat's boot time (whole seconds,
	// recomputed from the current clock) plus clock ticks, the exec record
	// from the backend's own boot-time conversion -- so a clock step since
	// boot moves one and not the other. Wide on purpose: a row that wrongly
	// replaced a kernel record would cost the process its exec-derived
	// identity on every poll. It still catches a reused pid whose
	// predecessor's exit was lost.
	pollStartTolerance = 5 * time.Minute

	// maxAliases bounds the further exec ids one process instance can
	// collect through re-announces and later images.
	maxAliases = 4
)

// processRecord is one process instance. Its identity is the pid and the
// kernel start time (with instance telling generations apart when the start
// is unknown); an exec id is never part of it. Exec ids are an alias layer:
// they name the instance, so an event or a child that carries one finds it
// even after a newer instance took the pid.
type processRecord struct {
	pid int
	// start is the kernel creation time when known. keyStart is the first
	// observed start used for the session key, zero when the first source
	// could not say. It stays fixed when a later poll refines or fills start.
	start    time.Time
	keyStart time.Time
	// firstSeen is when this instance was first observed. A process cannot
	// be observed before it was created, so a start learnt later that falls
	// after it belongs to another process that took the pid.
	firstSeen time.Time
	// bornAt is when the creation or exec event that started this instance
	// was logged, zero when a poll found it first, and ownerSID the account
	// that event named, empty when it named none. They tie what the
	// instance did to it and not to a later process on the pid (GAP-1464).
	bornAt         time.Time
	ownerSID       string
	instance       uint64
	ppid           int
	responsiblePID int
	// parentInstance and responsibleInstance are the instances ppid and
	// responsiblePID named when the edge was learnt, zero when the tracker
	// had no record of them then. They confirm an edge when a start is
	// unknown: exec events carry none.
	parentInstance      uint64
	responsibleInstance uint64
	name                string
	exe                 string
	cmdline             string
	user                string
	uid, auid           *int
	// execID is the backend's id of the instance's current image (Tetragon's
	// exec_id); aliases are the further ids it gave the same instance, by
	// re-announcing it or for an earlier image. parentExecID is the parent's,
	// which survives the parent's pid being reused.
	execID       string
	aliases      []string
	parentExecID string
	agent        tactics.AgentRoot
	agentName    string
	via          string
	exitedAt     time.Time
	lastSeen     time.Time
	// retired is set once a newer instance took this pid. The record is then
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
	facts := ProcessFacts{
		PID: r.pid, ExecID: r.execID, Name: r.name, Exe: r.exe, Cmdline: r.cmdline,
		User: r.user, UID: copyInt(r.uid), AUID: copyInt(r.auid), Agent: r.agent,
	}
	if !r.start.IsZero() {
		facts.StartNS = r.start.UnixNano()
	}
	return facts
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
// A process instance is its pid and kernel start time. A backend that names
// process images (Tetragon's exec_id) adds aliases to that identity and
// nothing else: a child that names its parent's image reaches the parent even
// after the parent's pid was reused, and a re-announce under a new exec id
// stays the same instance. Backends without exec ids (cn_proc, Endpoint
// Security, ETW, process-table polls) never touch the alias layer.
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
	exited       int
	nextInstance uint64
}

// NewTracker returns an empty tracker using the real clock.
func NewTracker() *Tracker { return newTracker(lineageTTL, time.Now) }

func newTracker(ttl time.Duration, now func() time.Time) *Tracker {
	return &Tracker{
		records: make(map[int]*processRecord), byExec: make(map[string]*processRecord),
		ttl: ttl, now: now,
	}
}

// Creation is what an exec or process-creation event says about the
// process beyond its image: when the event was logged, and the SID of the
// account it names for the process, empty when it names none.
type Creation struct {
	At  time.Time
	SID string
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
	// ExecID and ParentExecID are the backend's image identities, aliases of
	// the process instance and of its parent.
	ExecID       string
	ParentExecID string
	// StartNS is the start the backend reported, in Unix nanoseconds, 0 when
	// it reported none. Only a backend that also names the image (ExecID)
	// reports one.
	StartNS int64
	// Created is when the event was logged and the account it named.
	Created Creation
}

// ObserveExec records an exec event. This is the authoritative source: it
// carries the parent at the moment of exec, which a later process-table poll
// cannot recover once the parent has exited and the child is reparented.
// The event's time is not the kernel creation time: a process may exec long
// after it forked.
func (t *Tracker) ObserveExec(pid, ppid, responsiblePID int, name, cmdline string, created Creation) {
	t.ObserveExecEvent(ExecObservation{
		PID: pid, PPID: ppid, ResponsiblePID: responsiblePID, Name: name, Cmdline: cmdline, Created: created,
	})
}

// ObserveExecEvent records an exec event with everything the backend said
// about the process. Without an exec id it is exactly ObserveExec. With one,
// the event first resolves the process instance from its pid and start: an
// exec id seen before is a duplicate delivery, a live instance re-announced
// under a new one gains an alias, and anything else is recorded by the pid and
// start rules, the exec id becoming an alias of the instance they resolve.
func (t *Tracker) ObserveExecEvent(e ExecObservation) {
	if e.PID <= 0 {
		return
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	start := startOf(e.StartNS)
	if e.ExecID != "" {
		if known, ok := t.byExec[e.ExecID]; ok {
			// The same image announced again: a duplicate delivery adds
			// facts at most.
			known.lastSeen = now
			fillRecord(known, e)
			return
		}
		if existing, ok := t.records[e.PID]; ok && existing.execID != "" && existing.exitedAt.IsZero() {
			if startsAgree(existing.start, start, reseedWindow) && sameReseedIdentity(existing, e) {
				// The live process re-announced under a new exec id
				// (Tetragon restarted). The alias changes; the instance and
				// its key do not.
				t.aliasLocked(existing, e, now)
				return
			}
			if existing.hasExecID(e.ParentExecID) {
				// Tetragon names the image a process exec'd from as the
				// parent of the image it exec'd into, at the same pid: the
				// same instance in a new image. Its start is the exec's, not
				// the process's, and must not split the instance, and the
				// instance keeps its own parent.
				start = time.Time{}
				e.ParentExecID = existing.parentExecID
				if e.PPID <= 0 || e.PPID == e.PID {
					e.PPID, e.ResponsiblePID = existing.ppid, existing.responsiblePID
				}
			}
		}
	}
	t.recordLocked(e, start, false)
}

// instanceLocked is the instance recorded under pid, zero when there is none.
func (t *Tracker) instanceLocked(pid int) uint64 {
	if record, ok := t.records[pid]; ok {
		return record.instance
	}
	return 0
}

// ObserveProcessTable records a poll of the live process table. It is the
// unprivileged fallback for ObserveExec and is lossy in exactly one way worth
// naming: a process that started and exited between two polls is never seen.
func (t *Tracker) ObserveProcessTable(rows []ProcessRow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := t.now()
	learnt := make([]*processRecord, 0, len(rows))
	for _, row := range rows {
		if row.PID <= 0 {
			continue
		}
		if existing, ok := t.records[row.PID]; ok && existing.execID != "" && existing.exitedAt.IsZero() &&
			!startsDisagree(existing.start, row.Start, pollStartTolerance) {
			// The kernel's exec record is the authority on this process. A
			// poll only says it is still there; its name (comm, cut at 15
			// bytes) must not rename the image the kernel described.
			existing.lastSeen = now
			if existing.ppid <= 0 {
				existing.ppid = row.PPID
			}
			if existing.start.IsZero() && !row.Start.IsZero() {
				existing.start = row.Start
			}
			continue
		}
		e := ExecObservation{PID: row.PID, PPID: row.PPID, Name: row.Name, Cmdline: row.Cmdline}
		if record := t.recordLocked(e, row.Start, true); record != nil {
			learnt = append(learnt, record)
		}
	}
	// A parent listed after its child in the same poll was unknown, or still
	// an earlier holder of its pid, when the edge was learnt. Both rows
	// describe the table at one moment, so the edge names the parent row's
	// instance.
	polled := make(map[int]bool, len(learnt))
	for _, record := range learnt {
		polled[record.pid] = true
	}
	for _, record := range learnt {
		if record.parentInstance == 0 || polled[record.ppid] {
			record.parentInstance = t.instanceLocked(record.ppid)
		}
		if record.responsiblePID == record.ppid && (record.responsibleInstance == 0 || polled[record.ppid]) {
			record.responsibleInstance = record.parentInstance
		}
	}
}

// ProcessRow is one row of a process-table poll.
type ProcessRow struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
	// Start is when the kernel created the process, zero when unknown.
	Start time.Time
}

// recordLocked records one observation and returns the record when it learnt
// a new parent edge for it, nil otherwise.
//
// inferResponsible marks a process-table row, which has no responsible pid:
// the ppid stands in for it only while none is known. A responsible pid
// already learnt for this instance is kept, because once the child is
// reparented to launchd it is the only link left to the agent.
func (t *Tracker) recordLocked(e ExecObservation, start time.Time, inferResponsible bool) *processRecord {
	pid, ppid, responsiblePID, created := e.PID, e.PPID, e.ResponsiblePID, e.Created
	if pid <= 0 {
		return nil
	}
	now := t.now()
	existing, ok := t.records[pid]
	if !ok {
		if len(t.records) >= maxTrackedProcesses {
			// Full. Drop the oldest exited record rather than refusing to
			// learn: a table that stops updating attributes new work to stale
			// ancestry, which is worse than forgetting a dead pid.
			t.evictOldestExitedLocked()
			if len(t.records) >= maxTrackedProcesses {
				return nil
			}
		}
		existing = &processRecord{pid: pid}
		t.records[pid] = existing
	}
	// Exec replaces an image, not a process. Only an observed exit or a
	// different kernel start means the pid names a new process instance.
	// A start after the instance was first seen is the same evidence for an
	// instance first seen without one, and so is a creation that names
	// another account: a Windows 4688 carries no creation time, so with the
	// earlier holder's exit unseen it is all that tells them apart (GAP-1464).
	recycled := !existing.exitedAt.IsZero() || differentStart(existing.start, start) ||
		(existing.instance != 0 && existing.start.IsZero() && !start.IsZero() &&
			start.After(existing.firstSeen.Add(startTolerance))) ||
		(created.SID != "" && existing.ownerSID != "" && !strings.EqualFold(created.SID, existing.ownerSID))
	reimaged := existing.name != e.Name
	if !existing.exitedAt.IsZero() {
		t.exited--
	}
	if recycled && existing.execID != "" {
		// The instance had exec ids: it stays reachable through them, for
		// the children that name it, and the new instance gets a record of
		// its own. Without exec ids nothing can reach it again.
		t.retireLocked(existing, now)
		existing = &processRecord{pid: pid}
		t.records[pid] = existing
	}
	fresh := existing.instance == 0 || recycled
	if fresh {
		t.nextInstance++
		existing.instance = t.nextInstance
		existing.start = start
		existing.keyStart = start
		existing.firstSeen = now
		existing.bornAt, existing.ownerSID = created.At, created.SID
		existing.exe, existing.user = e.Exe, e.User
		existing.uid, existing.auid = copyInt(e.UID), copyInt(e.AUID)
		existing.execID, existing.aliases, existing.parentExecID = "", nil, ""
	} else {
		if existing.start.IsZero() && !start.IsZero() {
			// Learn the real start without changing the key of a live
			// session first seen while its creation time was unavailable.
			existing.start = start
		}
		if existing.bornAt.IsZero() {
			existing.bornAt = created.At
		}
		if existing.ownerSID == "" {
			existing.ownerSID = created.SID
		}
		// What a later exec says about the instance replaces what an
		// earlier one said. A poll row names no path, so for it only a new
		// image clears the old image's.
		if reimaged || e.Exe != "" {
			existing.exe = e.Exe
		}
		if e.User != "" {
			existing.user = e.User
		}
		if e.UID != nil {
			existing.uid = copyInt(e.UID)
		}
		if e.AUID != nil {
			existing.auid = copyInt(e.AUID)
		}
	}
	if e.ExecID != "" {
		if existing.execID != "" && existing.execID != e.ExecID {
			// A later image of the same instance: the new id leads, and the
			// old one still names this instance for its children.
			t.addAliasLocked(existing, existing.execID)
		}
		existing.execID = e.ExecID
		t.byExec[e.ExecID] = existing
		if e.ParentExecID != "" {
			existing.parentExecID = e.ParentExecID
		}
	}
	if inferResponsible {
		responsiblePID = ppid
		if !fresh && existing.responsiblePID > 0 {
			responsiblePID = existing.responsiblePID
		}
	}
	var learnt *processRecord
	if fresh || existing.ppid != ppid {
		existing.parentInstance = t.instanceLocked(ppid)
		learnt = existing
	}
	if fresh || existing.responsiblePID != responsiblePID {
		existing.responsibleInstance = t.instanceLocked(responsiblePID)
	}
	existing.ppid = ppid
	existing.responsiblePID = responsiblePID
	existing.name = e.Name
	existing.cmdline = e.Cmdline
	existing.lastSeen = now
	existing.exitedAt = time.Time{}
	// Clear rather than carry forward on a recycled pid or a new image. The
	// lineage gate is the whole false-positive control for the host plane,
	// so a stale agent name on a recycled pid turns ordinary developer
	// activity -- in this process and in every descendant of it -- into
	// scored findings.
	t.identifyLocked(existing, fresh || reimaged)
	return learnt
}

// sameReseedIdentity refuses a new image that merely received a reused PID
// within the restart window. A real Tetragon re-seed should describe the same
// executable, command, uid and parent; if a field changed, a fresh record is
// safer than inheriting an old agent's lineage.
func sameReseedIdentity(existing *processRecord, e ExecObservation) bool {
	if existing.exe == "" || e.Exe == "" || existing.exe != e.Exe ||
		existing.name != e.Name || existing.ppid != e.PPID {
		return false
	}
	if existing.cmdline != e.Cmdline {
		return false
	}
	if (existing.uid == nil) != (e.UID == nil) {
		return false
	}
	return existing.uid == nil || *existing.uid == *e.UID
}

// addAliasLocked records a further exec id for the instance, dropping the
// oldest alias past maxAliases.
func (t *Tracker) addAliasLocked(r *processRecord, id string) {
	if id == "" {
		return
	}
	for _, alias := range r.aliases {
		if alias == id {
			return
		}
	}
	if len(r.aliases) >= maxAliases {
		if t.byExec[r.aliases[0]] == r {
			delete(t.byExec, r.aliases[0])
		}
		r.aliases = r.aliases[1:]
	}
	r.aliases = append(r.aliases, id)
	t.byExec[id] = r
}

// aliasLocked records a re-announce of a live instance under a new exec id.
// The instance, its start and its key stay as they were.
func (t *Tracker) aliasLocked(existing *processRecord, e ExecObservation, now time.Time) {
	t.addAliasLocked(existing, e.ExecID)
	existing.lastSeen = now
	// The newest description wins where it says something.
	if e.Cmdline != "" {
		existing.cmdline = e.Cmdline
	}
	if e.ResponsiblePID > 0 && e.ResponsiblePID != existing.responsiblePID {
		existing.responsiblePID = e.ResponsiblePID
		existing.responsibleInstance = t.instanceLocked(e.ResponsiblePID)
	}
	if e.ParentExecID != "" {
		existing.parentExecID = e.ParentExecID
	}
	fillRecord(existing, e)
	t.identifyLocked(existing, false)
}

// retireLocked takes a record out of the pid table because a newer instance
// holds its pid. A record with an exec id stays reachable through it. The
// exited count no longer includes it: the caller has already taken an
// exited record out of it.
func (t *Tracker) retireLocked(record *processRecord, now time.Time) {
	if t.records[record.pid] == record {
		delete(t.records, record.pid)
	}
	if record.exitedAt.IsZero() {
		record.exitedAt = now
	}
	record.retired = true
	t.retiredQueue = append(t.retiredQueue, record)
	for len(t.retiredQueue) > maxRetiredProcesses {
		t.forgetLocked(t.retiredQueue[0])
		t.retiredQueue[0] = nil
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
	if record.start.IsZero() && e.StartNS != 0 {
		record.start = startOf(e.StartNS)
	}
}

// startOf is a backend's Unix-nanosecond start, zero when it gave none.
func startOf(ns int64) time.Time {
	if ns == 0 {
		return time.Time{}
	}
	return time.Unix(0, ns)
}

// startsAgree reports two known start times within window of each other.
func startsAgree(a, b time.Time, window time.Duration) bool {
	if a.IsZero() || b.IsZero() {
		return false
	}
	delta := a.Sub(b)
	if delta < 0 {
		delta = -delta
	}
	return delta <= window
}

// startsDisagree reports two known start times further apart than window.
// Unknown is never a disagreement.
func startsDisagree(a, b time.Time, window time.Duration) bool {
	return !a.IsZero() && !b.IsZero() && !startsAgree(a, b, window)
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
// the instance that id names, even when a newer instance already holds the
// pid.
func (t *Tracker) ObserveExitEvent(pid int, execID string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	record := t.lookupLocked(pid, execID)
	if record == nil {
		return
	}
	if record.retired {
		// Already out of the pid table; only its exit time is news.
		return
	}
	if record.exitedAt.IsZero() {
		t.exited++
	}
	record.exitedAt = t.now()
}

// lookupLocked finds the instance an exec id names, else the one at the pid.
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

// Instance names the process instance the tracker records under a pid.
type Instance struct {
	// Start is when the kernel created it and Born when the event that
	// started it was logged, each zero when unknown.
	Start, Born time.Time
	// ID tells the tracker's instances apart, zero when it has no record.
	ID uint64
}

// InstanceOf is the process instance now recorded under pid.
func (t *Tracker) InstanceOf(pid int) Instance { return t.InstanceOfProcess(pid, "") }

// InstanceOfProcess is the process instance an exec id names (when the
// backend gave one), else the one now recorded under pid. A late event of an
// instance whose pid was reused still names that instance.
func (t *Tracker) InstanceOfProcess(pid int, execID string) Instance {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if record := t.lookupLocked(pid, execID); record != nil {
		return Instance{Start: record.start, Born: record.bornAt, ID: record.instance}
	}
	return Instance{}
}

// differentStart reports two known start times too far apart to be one
// process.
func differentStart(recorded, observed time.Time) bool {
	return startsDisagree(recorded, observed, startTolerance)
}

// confirmedParent reports whether parent is still the process the edge from
// child named, link being the instance recorded with that edge. An edge that
// recorded another instance names an earlier holder of the pid, whatever the
// starts say: a process that took the pid within startTolerance after the
// child started is not its parent (GAP-1495). Otherwise two known starts
// decide by order: a parent younger than its child is a later process on the
// pid. With either start unknown only the instance can confirm it, so an
// unknown start is unverified rather than a match: an exec-only child of an
// agent that exited would otherwise take the identity of whatever now holds
// that pid.
func confirmedParent(parent, child *processRecord, link uint64) bool {
	if link != 0 && link != parent.instance {
		return false
	}
	if !parent.start.IsZero() && !child.start.IsZero() {
		return !parent.start.After(child.start.Add(startTolerance))
	}
	return link != 0 && link == parent.instance
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

// attributionOf is the attribution to root, the record the walk stopped at.
func attributionOf(root *processRecord, agentName string, depth int, via string) Attribution {
	return Attribution{
		RootPID: root.pid, RootStart: root.start, RootKeyStart: root.keyStart, RootBorn: root.bornAt,
		RootInstance: root.instance, RootName: root.name, AgentName: agentName, Depth: depth,
		Via: via, State: StateAttributed,
	}
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
		return walk{Attribution: attributionOf(root, record.agentName, 0, record.via), root: root}, true
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
			return walk{Attribution: attributionOf(parent, parent.agentName, depth, via), root: parent, child: current}, true
		}
		current = parent
	}
	return walk{}, false
}

// parentLocked is one step up the tree: the responsible process when
// preferred and known, else the parent image the child named by exec id,
// else the process instance at the parent pid. The pid edges are confirmed
// against the instance they named (confirmedParent), and a parent pid that
// now holds an image other than the one the child named is the kernel
// having reused the number. viaResponsible reports that the responsible edge
// was taken.
func (t *Tracker) parentLocked(current *processRecord, preferResponsible bool) (*processRecord, bool) {
	if preferResponsible && current.responsiblePID > 0 && current.responsiblePID != current.pid {
		if parent, ok := t.records[current.responsiblePID]; ok {
			if current.responsiblePID == InitPID || !confirmedParent(parent, current, current.responsibleInstance) {
				return nil, false
			}
			return parent, current.responsiblePID != current.ppid
		}
	}
	if current.parentExecID != "" {
		if parent, ok := t.byExec[current.parentExecID]; ok {
			// The exec id names the parent instance exactly, retired or not.
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
	if !confirmedParent(parent, current, current.parentInstance) {
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
