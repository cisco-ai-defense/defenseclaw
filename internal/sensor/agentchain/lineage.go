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

	// maxAncestryWalk bounds a single ancestry walk. A pid table can contain a
	// cycle after pid reuse, and an unbounded walk would hang the poll.
	maxAncestryWalk = 64
)

type processRecord struct {
	pid            int
	ppid           int
	responsiblePID int
	name           string
	cmdline        string
	agentName      string
	via            string
	exitedAt       time.Time
	lastSeen       time.Time
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
}

// NewTracker returns an empty tracker using the real clock.
func NewTracker() *Tracker { return newTracker(lineageTTL, time.Now) }

func newTracker(ttl time.Duration, now func() time.Time) *Tracker {
	return &Tracker{records: make(map[int]*processRecord), ttl: ttl, now: now}
}

// ObserveExec records an exec event. This is the authoritative source: it
// carries the parent at the moment of exec, which a later process-table poll
// cannot recover once the parent has exited and the child is reparented.
func (t *Tracker) ObserveExec(pid, ppid, responsiblePID int, name, cmdline string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.recordLocked(pid, ppid, responsiblePID, name, cmdline)
}

// ObserveProcessTable records a poll of the live process table. It is the
// unprivileged fallback for ObserveExec and is lossy in exactly one way worth
// naming: a process that started and exited between two polls is never seen.
func (t *Tracker) ObserveProcessTable(rows []ProcessRow) {
	t.mu.Lock()
	defer t.mu.Unlock()
	for _, row := range rows {
		t.recordLocked(row.PID, row.PPID, row.PPID, row.Name, row.Cmdline)
	}
}

// ProcessRow is one row of a process-table poll.
type ProcessRow struct {
	PID     int
	PPID    int
	Name    string
	Cmdline string
}

func (t *Tracker) recordLocked(pid, ppid, responsiblePID int, name, cmdline string) {
	if pid <= 0 {
		return
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
				return
			}
		}
		existing = &processRecord{pid: pid}
		t.records[pid] = existing
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
	}
}

func (t *Tracker) evictOldestExitedLocked() {
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
	}
}

// ObserveExit marks a pid as gone. The record is kept for the TTL so an
// observation about the process can still be attributed after it exits.
func (t *Tracker) ObserveExit(pid int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if record, ok := t.records[pid]; ok {
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
			removed++
		}
	}
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
		return Attribution{
			RootPID:   t.outermostSameAgentLocked(pid, record.agentName),
			AgentName: record.agentName, Depth: 0,
			Via: record.via, State: StateAttributed,
		}, true
	}
	// Prefer the responsible pid when the platform supplies one that differs
	// from the parent. On macOS a shell spawned by an agent is reparented, and
	// the responsible pid is what survives that.
	for depth, current := 1, record; depth <= maxAncestryWalk; depth++ {
		next := current.ppid
		if current.responsiblePID > 0 && current.responsiblePID != current.pid {
			if _, ok := t.records[current.responsiblePID]; ok {
				next = current.responsiblePID
			}
		}
		if next <= 0 || next == InitPID || next == current.pid {
			return Attribution{}, false
		}
		parent, ok := t.records[next]
		if !ok {
			return Attribution{}, false
		}
		if parent.agentName != "" {
			via := "ancestry"
			if parent.responsiblePID == next && next != parent.ppid {
				via = "responsible"
			}
			return Attribution{
				RootPID: next, AgentName: parent.agentName, Depth: depth,
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
		next := current.ppid
		if next <= 0 || next == InitPID || next == current.pid {
			return root
		}
		parent, ok := t.records[next]
		if !ok || parent.agentName != agentName {
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
