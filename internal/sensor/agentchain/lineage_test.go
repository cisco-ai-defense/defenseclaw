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
	"testing"
	"time"
)

// TestExitedCounterTracksTheTable pins the invariant the eviction shortcut
// rests on.
//
// evictOldestExitedLocked returns immediately when the counter says there is
// nothing to reclaim. If the counter ever drifts above the truth the scan is
// merely wasted; if it drifts below, a full table stops accepting new pids
// and the tracker silently stops learning ancestry -- which attributes new
// work to stale lineage, the failure this table exists to prevent.
func TestExitedCounterTracksTheTable(t *testing.T) {
	t.Parallel()
	now := time.Now()
	clock := func() time.Time { return now }
	tracker := newTracker(time.Minute, clock)

	countExited := func() int {
		exited := 0
		for _, record := range tracker.records {
			if !record.exitedAt.IsZero() {
				exited++
			}
		}
		return exited
	}
	check := func(step string) {
		t.Helper()
		if got, want := tracker.exited, countExited(); got != want {
			t.Fatalf("after %s: counter = %d, table holds %d exited", step, got, want)
		}
	}

	tracker.ObserveExec(10, 1, 0, "claude", "claude")
	tracker.ObserveExec(11, 10, 0, "bash", "bash -c id")
	check("two execs")

	tracker.ObserveExit(11)
	check("one exit")
	if tracker.exited != 1 {
		t.Fatalf("exited = %d, want 1", tracker.exited)
	}

	// Exiting the same pid twice must not double-count.
	tracker.ObserveExit(11)
	check("repeated exit")
	if tracker.exited != 1 {
		t.Fatalf("exited = %d after a repeated exit, want 1", tracker.exited)
	}

	// The kernel recycles the number: the record comes back to life.
	tracker.ObserveExec(11, 10, 0, "curl", "curl https://example.invalid")
	check("recycled pid")
	if tracker.exited != 0 {
		t.Fatalf("exited = %d after the pid was reused, want 0", tracker.exited)
	}

	tracker.ObserveExit(11)
	now = now.Add(2 * time.Minute)
	if removed := tracker.Reap(); removed != 1 {
		t.Fatalf("Reap removed %d, want 1", removed)
	}
	check("reap")
	if tracker.exited != 0 {
		t.Fatalf("exited = %d after reaping the only dead record, want 0", tracker.exited)
	}

	// The same invariant with exec ids: a reused pid retires the old record
	// (counted nowhere in exited) and an exit by exec id marks only that image.
	tracker.ObserveExecEvent(ExecObservation{PID: 20, PPID: 1, Name: "claude", ExecID: "x20", StartNS: 1})
	tracker.ObserveExitEvent(20, "x20")
	check("exit by exec id")
	tracker.ObserveExecEvent(ExecObservation{PID: 20, PPID: 1, Name: "vim", ExecID: "y20", StartNS: int64(time.Hour)})
	check("reuse retires the exited record")
	tracker.ObserveExitEvent(20, "x20")
	check("a late exit of the retired image")
	if record := tracker.records[20]; record == nil || !record.exitedAt.IsZero() {
		t.Fatal("the exit of the old image marked the process that now holds the pid")
	}
	now = now.Add(2 * time.Minute)
	tracker.Reap()
	check("reap of a retired record")
	if _, ok := tracker.byExec["x20"]; ok {
		t.Fatal("Reap kept the retired record's exec id past the TTL")
	}
	if len(tracker.retiredQueue) != 0 {
		t.Fatalf("retired queue holds %d after the TTL", len(tracker.retiredQueue))
	}
}

func intp(value int) *int { return &value }

// TestExecIDLineageSurvivesPidReuse is the case exec ids exist for. The agent
// exits and the kernel hands its pid to the developer's editor; a job the
// agent started before exiting still belongs to the agent, and the editor's
// children never do.
func TestExecIDLineageSurvivesPidReuse(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	start := int64(1_760_000_000) * int64(time.Second)
	tracker.ObserveExecEvent(ExecObservation{
		PID: 100, PPID: 50, Name: "claude", Exe: "/home/dev/.local/bin/claude",
		ExecID: "agent", StartNS: start, UID: intp(1001),
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 101, PPID: 100, Name: "bash", Exe: "/usr/bin/bash", Cmdline: "/usr/bin/bash -c nohup ./job.sh",
		ExecID: "shell", ParentExecID: "agent", StartNS: start + int64(time.Second),
	})
	tracker.ObserveExitEvent(100, "agent")
	tracker.ObserveExitEvent(101, "shell")
	// The pid is reused by an editor the developer opened.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 100, PPID: 60, Name: "vim", Exe: "/usr/bin/vim", ExecID: "editor",
		StartNS: start + int64(time.Minute),
	})

	// The detached job, reparented to init, still names its parent image.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 102, PPID: 1, Name: "job.sh", Exe: "/usr/bin/bash", ExecID: "job", ParentExecID: "shell",
		StartNS: start + 2*int64(time.Minute),
	})
	lineage, ok := tracker.Lineage(102, "job")
	if !ok || lineage.AgentName != "claude" || lineage.Depth != 2 {
		t.Fatalf("detached job: lineage = %+v ok=%v, want claude at depth 2", lineage, ok)
	}
	if lineage.Root.ExecID != "agent" || lineage.Child.ExecID != "shell" {
		t.Fatalf("root/child = %q/%q, want the exited agent image and its shell", lineage.Root.ExecID, lineage.Child.ExecID)
	}

	// A late child that names the agent's image directly, by its old pid.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 103, PPID: 100, Name: "curl", ExecID: "late", ParentExecID: "agent",
		StartNS: start + 2*int64(time.Minute),
	})
	if attribution, ok := tracker.Attribute(103); !ok || attribution.AgentName != "claude" {
		t.Fatalf("a child naming the agent's image: %+v ok=%v", attribution, ok)
	}

	// The editor's own child names the editor's image: not the agent's.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 104, PPID: 100, Name: "cat", ExecID: "editor-child", ParentExecID: "editor",
		StartNS: start + 3*int64(time.Minute),
	})
	if attribution, ok := tracker.Attribute(104); ok {
		t.Fatalf("the editor's child was attributed to %q through the reused pid", attribution.AgentName)
	}
	// A child naming a parent image the tracker never saw, at the reused pid:
	// the pid belongs to another image, so it is not the parent.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 105, PPID: 100, Name: "cat", ExecID: "orphan", ParentExecID: "never-seen",
	})
	if attribution, ok := tracker.Attribute(105); ok {
		t.Fatalf("a child of an unseen image was attributed to %q through the pid", attribution.AgentName)
	}
	if _, ok := tracker.Attribute(100); ok {
		t.Fatal("the editor at the reused pid is attributed to the agent")
	}
}

// TestReseededProcessKeepsItsIdentity pins the Tetragon restart case: the
// live agent is re-announced under a new exec id with nearly the same start,
// and stays the same process with both ids leading to it. A new image at the
// pid outside the window is a new process that inherits nothing.
func TestReseededProcessKeepsItsIdentity(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	start := int64(1_760_000_000) * int64(time.Second)
	tracker.ObserveExecEvent(ExecObservation{
		PID: 200, PPID: 50, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292",
		ExecID: "first", StartNS: start,
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 201, PPID: 200, Name: "bash", ExecID: "before", ParentExecID: "first", StartNS: start + 1,
	})
	// Tetragon restarted: the same process, re-seeded from procfs.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 200, PPID: 50, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292",
		ExecID: "reseeded", StartNS: start + int64(3*time.Millisecond),
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 202, PPID: 200, Name: "bash", ExecID: "after", ParentExecID: "reseeded", StartNS: start + 2,
	})
	for _, pid := range []int{201, 202} {
		if attribution, ok := tracker.Attribute(pid); !ok || attribution.RootPID != 200 || attribution.AgentName != "claude" {
			t.Fatalf("pid %d: %+v ok=%v, want claude at 200 under either exec id", pid, attribution, ok)
		}
	}
	if lineage, ok := tracker.Lineage(200, "reseeded"); !ok || lineage.Root.ExecID != "first" {
		t.Fatalf("Lineage by the alias = %+v ok=%v, want the original record", lineage, ok)
	}

	// Much later, another image at the pid (its exit was lost).
	tracker.ObserveExecEvent(ExecObservation{
		PID: 200, PPID: 70, Name: "bash", Exe: "/usr/bin/bash", ExecID: "new", StartNS: start + int64(10*time.Second),
	})
	if _, ok := tracker.Attribute(200); ok {
		t.Fatal("a new image at the pid inherited the agent identity")
	}
	tracker.ObserveExecEvent(ExecObservation{
		PID: 203, PPID: 200, Name: "cat", ExecID: "new-child", ParentExecID: "new", StartNS: start + int64(11*time.Second),
	})
	if attribution, ok := tracker.Attribute(203); ok {
		t.Fatalf("a child of the new image was attributed to %q", attribution.AgentName)
	}
	if attribution, ok := tracker.Attribute(202); !ok || attribution.AgentName != "claude" {
		t.Fatalf("the old agent's child lost its attribution: %+v ok=%v", attribution, ok)
	}
}

// TestProcessTablePollDoesNotRenameAKernelRecord pins that a poll row, whose
// name is the 15-byte comm, does not overwrite what the kernel's exec record
// said -- and that a row whose start shows another process does replace it.
func TestProcessTablePollDoesNotRenameAKernelRecord(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	start := int64(1_760_000_000) * int64(time.Second)
	tracker.ObserveExecEvent(ExecObservation{
		PID: 300, PPID: 50, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292",
		ExecID: "native", StartNS: start,
	})
	tracker.ObserveProcessTable([]ProcessRow{{PID: 300, PPID: 50, Name: "sh", StartNS: start + int64(10*time.Millisecond)}})
	if attribution, ok := tracker.Attribute(300); !ok || attribution.AgentName != "claude" {
		t.Fatalf("a same-process poll row renamed the agent: %+v ok=%v", attribution, ok)
	}
	tracker.ObserveProcessTable([]ProcessRow{{PID: 300, PPID: 50, Name: "sh", StartNS: start + int64(time.Hour)}})
	if _, ok := tracker.Attribute(300); ok {
		t.Fatal("a poll row of another process at the pid kept the agent identity")
	}
	if _, ok := tracker.byExec["native"]; !ok {
		t.Fatal("the replaced kernel record is no longer reachable by its exec id")
	}
}

// TestLineageNamesTheProcessesItRunsThrough pins the facts the host plane
// reads off an attribution: the nearest agent, the outermost process of that
// agent (one session for a supervisor and its sandbox wrapper), and the
// agent's direct child, which is the tool call a hook decision covers.
func TestLineageNamesTheProcessesItRunsThrough(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	tracker.ObserveExecEvent(ExecObservation{
		PID: 400, PPID: 50, Name: "codex", Exe: "/usr/lib/node_modules/@openai/codex/bin/codex",
		ExecID: "codex", UID: intp(1001), User: "dev",
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 401, PPID: 400, Name: "codex-linux-sandbox",
		Exe: "/usr/lib/node_modules/@openai/codex/bin/codex-linux-sandbox", ExecID: "sandbox", ParentExecID: "codex",
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 402, PPID: 401, Name: "bash", Exe: "/usr/bin/bash", Cmdline: `/usr/bin/bash -lc "cat notes.txt"`,
		ExecID: "tool", ParentExecID: "sandbox",
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 403, PPID: 402, Name: "cat", Exe: "/usr/bin/cat", ExecID: "cat", ParentExecID: "tool",
	})
	lineage, ok := tracker.Lineage(403, "cat")
	if !ok {
		t.Fatal("the tool's child was not attributed")
	}
	if lineage.Depth != 2 || lineage.Root.PID != 401 || lineage.SessionRoot.PID != 400 || lineage.Child.PID != 402 {
		t.Fatalf("lineage = depth %d root %d session %d child %d, want 2/401/400/402",
			lineage.Depth, lineage.Root.PID, lineage.SessionRoot.PID, lineage.Child.PID)
	}
	if lineage.SessionRoot.Agent.Connector != "codex" || lineage.SessionRoot.UID == nil || *lineage.SessionRoot.UID != 1001 {
		t.Fatalf("session root facts = %+v", lineage.SessionRoot)
	}
	if self, ok := tracker.Lineage(400, ""); !ok || self.Depth != 0 || self.Child.PID != 0 {
		t.Fatalf("the agent itself: %+v ok=%v, want depth 0 and no child", self, ok)
	}
}
