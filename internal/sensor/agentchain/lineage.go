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

	// maxAncestryWalk bounds a single ancestry walk. A pid table can contain a
	// cycle after pid reuse, and an unbounded walk would hang the poll.
	maxAncestryWalk = 64

	// startTolerance allows for rounding between kernel start-time sources.
	// Exec time is not a process start time: a process may exec long after
	// fork. Two known starts further apart than this on one pid are two
	// processes.
	startTolerance = 2 * time.Second
)

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
	cmdline             string
	agentName           string
	via                 string
	exitedAt            time.Time
	lastSeen            time.Time
}

// Tracker keeps process ancestry so an observation about a short-lived
// descendant can be attributed to the agent that spawned it.
//
// Lineage comes from exec events where they are available -- authoritative,
// and they catch the eight-millisecond cat that polling a process table never
// sees -- and falls back to parent pids from the process table when the sensor
// is unprivileged.
type Tracker struct {
	mu      sync.RWMutex
	records map[int]*processRecord
	ttl     time.Duration
	now     func() time.Time
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
	return &Tracker{records: make(map[int]*processRecord), ttl: ttl, now: now}
}

// Creation is what an exec or process-creation event says about the
// process beyond its image: when the event was logged, and the SID of the
// account it names for the process, empty when it names none.
type Creation struct {
	At  time.Time
	SID string
}

// ObserveExec records an exec event. This is the authoritative source: it
// carries the parent at the moment of exec, which a later process-table poll
// cannot recover once the parent has exited and the child is reparented.
// The event's time is not the kernel creation time: a process may exec long
// after it forked.
func (t *Tracker) ObserveExec(pid, ppid, responsiblePID int, name, cmdline string, created Creation) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recordLocked(pid, ppid, responsiblePID, false, name, cmdline, time.Time{}, created)
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
	learnt := make([]*processRecord, 0, len(rows))
	for _, row := range rows {
		if record := t.recordLocked(row.PID, row.PPID, 0, true, row.Name, row.Cmdline, row.Start, Creation{}); record != nil {
			learnt = append(learnt, record)
		}
	}
	// A parent listed after its child in the same poll was unknown when the
	// edge was learnt. Both rows describe the table at one moment.
	for _, record := range learnt {
		if record.parentInstance == 0 {
			record.parentInstance = t.instanceLocked(record.ppid)
		}
		if record.responsibleInstance == 0 && record.responsiblePID == record.ppid {
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
func (t *Tracker) recordLocked(
	pid, ppid, responsiblePID int, inferResponsible bool, name, cmdline string, start time.Time, created Creation,
) *processRecord {
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
	reimaged := existing.name != name
	if !existing.exitedAt.IsZero() {
		t.exited--
	}
	fresh := existing.instance == 0 || recycled
	if fresh {
		t.nextInstance++
		existing.instance = t.nextInstance
		existing.start = start
		existing.keyStart = start
		existing.firstSeen = now
		existing.bornAt, existing.ownerSID = created.At, created.SID
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
	existing.name = name
	existing.cmdline = cmdline
	existing.lastSeen = now
	existing.exitedAt = time.Time{}
	if agent := tactics.AgentIdentity(name, cmdline); agent != "" {
		existing.agentName = agent
		if tactics.IsAgentProcess(name) {
			existing.via = "process"
		} else {
			existing.via = "cmdline"
		}
		return learnt
	}
	if recycled || reimaged {
		// Clear rather than carry forward. The lineage gate is the whole
		// false-positive control for the host plane, so a stale agent name on
		// a recycled pid turns ordinary developer activity -- in this process
		// and in every descendant of it -- into scored findings.
		existing.agentName = ""
		existing.via = ""
	}
	return learnt
}

func (t *Tracker) evictOldestExitedLocked() {
	if t.exited == 0 {
		// Nothing to reclaim. Without this the table walks all
		// maxTrackedProcesses records on every new pid once it is full and
		// every process in it is alive.
		return
	}
	var oldestPID int
	var oldest time.Time
	for pid, record := range t.records {
		if record.exitedAt.IsZero() {
			continue
		}
		if oldest.IsZero() || record.exitedAt.Before(oldest) {
			oldest, oldestPID = record.exitedAt, pid
		}
	}
	if oldestPID != 0 {
		delete(t.records, oldestPID)
		t.exited--
	}
}

// ObserveExit marks a pid as gone. The record is kept for the TTL so an
// observation about the process can still be attributed after it exits.
func (t *Tracker) ObserveExit(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if record, ok := t.records[pid]; ok {
		if record.exitedAt.IsZero() {
			t.exited++
		}
		record.exitedAt = t.now()
	}
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
			t.exited--
			removed++
		}
	}
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
func (t *Tracker) InstanceOf(pid int) Instance {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if record, ok := t.records[pid]; ok {
		return Instance{Start: record.start, Born: record.bornAt, ID: record.instance}
	}
	return Instance{}
}

// differentStart reports two known start times too far apart to be one
// process.
func differentStart(recorded, observed time.Time) bool {
	if recorded.IsZero() || observed.IsZero() {
		return false
	}
	delta := recorded.Sub(observed)
	return delta > startTolerance || delta < -startTolerance
}

// confirmedParent reports whether parent is still the process the edge from
// child named, link being the instance recorded with that edge. Two known
// starts decide by order: a parent younger than its child is a later process
// on the pid. With either start unknown only the instance can confirm it, so
// an unknown start is unverified rather than a match: an exec-only child of an
// agent that exited would otherwise take the identity of whatever now holds
// that pid.
func confirmedParent(parent, child *processRecord, link uint64) bool {
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
	return t.attributeLocked(pid)
}

func (t *Tracker) attributeLocked(pid int) (Attribution, bool) {
	record, ok := t.records[pid]
	if !ok {
		return Attribution{}, false
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
		root := t.outermostSameAgentLocked(pid, record.agentName)
		return Attribution{
			RootPID: root, RootStart: t.records[root].start, RootKeyStart: t.records[root].keyStart,
			RootBorn: t.records[root].bornAt, RootInstance: t.records[root].instance, RootName: t.records[root].name,
			AgentName: record.agentName, Depth: 0,
			Via: record.via, State: StateAttributed,
		}, true
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
func (t *Tracker) walkAncestryLocked(
	record *processRecord, preferResponsible bool,
) (Attribution, bool) {
	for depth, current := 1, record; depth <= maxAncestryWalk; depth++ {
		next, link := current.ppid, current.parentInstance
		viaResponsible := false
		if preferResponsible &&
			current.responsiblePID > 0 && current.responsiblePID != current.pid {
			if _, ok := t.records[current.responsiblePID]; ok {
				next, link = current.responsiblePID, current.responsibleInstance
				viaResponsible = next != current.ppid
			}
		}
		if next <= 0 || next == InitPID || next == current.pid {
			return Attribution{}, false
		}
		parent, ok := t.records[next]
		if !ok || !confirmedParent(parent, current, link) {
			return Attribution{}, false
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
			return Attribution{
				RootPID: next, RootStart: parent.start, RootKeyStart: parent.keyStart, RootBorn: parent.bornAt,
				RootInstance: parent.instance, RootName: parent.name, AgentName: parent.agentName, Depth: depth,
				Via: via, State: StateAttributed,
			}, true
		}
		current = parent
	}
	return Attribution{}, false
}

// outermostSameAgentLocked walks up from pid while each ancestor carries the
// same agent name, and returns the last one that does.
//
// Bounded by the same walk limit as attribution, because a pid table can
// contain a cycle after pid reuse.
func (t *Tracker) outermostSameAgentLocked(pid int, agentName string) int {
	root := pid
	current, ok := t.records[pid]
	if !ok {
		return root
	}
	for depth := 0; depth < maxAncestryWalk; depth++ {
		// Prefer the responsible pid for the same reason attribution does: on
		// macOS a shell an agent spawned is reparented away, so its ppid is
		// launchd and only the responsible pid still points at the agent.
		// Following ppid alone stopped at that reparenting and rooted the
		// child at itself, splitting one agent session into one per fork --
		// the exact fragmentation this walk exists to prevent.
		next, link := current.ppid, current.parentInstance
		if current.responsiblePID > 0 && current.responsiblePID != current.pid {
			if _, ok := t.records[current.responsiblePID]; ok {
				next, link = current.responsiblePID, current.responsibleInstance
			}
		}
		if next <= 0 || next == InitPID || next == current.pid {
			return root
		}
		parent, ok := t.records[next]
		if !ok || parent.agentName != agentName || !confirmedParent(parent, current, link) {
			return root
		}
		root = next
		current = parent
	}
	return root
}

// AttributionState classifies a pid that has no agent above it, so the absence
// is described rather than merely reported as "no finding".
func (t *Tracker) AttributionState(pid int) string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if _, ok := t.attributeLocked(pid); ok {
		return StateAttributed
	}
	record, ok := t.records[pid]
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
