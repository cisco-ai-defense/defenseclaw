// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package agentchain

import (
	"testing"
	"time"
)

// The tests here pin how Tetragon's exec ids map onto the canonical process
// identity, the pid and kernel start: an exec id is an alias of an instance
// and never its key.

const aliasTestStart = int64(1_760_000_000) * int64(time.Second)

func TestExecIDResolvesToTheCanonicalInstance(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	tracker.ObserveExecEvent(ExecObservation{
		PID: 500, PPID: 50, Name: "claude", Exe: "/home/dev/.local/bin/claude", ExecID: "a", StartNS: aliasTestStart,
	})
	instance := tracker.InstanceOf(500)
	if instance.ID == 0 || !instance.Start.Equal(time.Unix(0, aliasTestStart)) {
		t.Fatalf("instance = %+v, want one started at the exec's start", instance)
	}
	if byID := tracker.InstanceOfProcess(0, "a"); byID != instance {
		t.Fatalf("by exec id = %+v, want %+v", byID, instance)
	}
	lineage, ok := tracker.Lineage(500, "a")
	if !ok || lineage.RootInstance != instance.ID || !lineage.RootKeyStart.Equal(instance.Start) || lineage.Root.ExecID != "a" {
		t.Fatalf("lineage = %+v ok=%v, want the canonical instance %d keyed on its start", lineage, ok, instance.ID)
	}
	// A poll row of the same process (procfs start, comm name) and a native
	// exec without an exec id resolve to the same instance.
	tracker.ObserveProcessTable([]ProcessRow{{
		PID: 500, PPID: 50, Name: "claude", Start: time.Unix(0, aliasTestStart+int64(time.Millisecond)),
	}})
	tracker.ObserveExec(500, 50, 50, "claude", "claude", Creation{})
	if got := tracker.InstanceOf(500); got.ID != instance.ID || !got.Start.Equal(instance.Start) {
		t.Fatalf("after a poll and a native exec: %+v, want %+v", got, instance)
	}
	if attribution, ok := tracker.Attribute(500); !ok || attribution.RootInstance != instance.ID {
		t.Fatalf("attribution = %+v ok=%v", attribution, ok)
	}
}

func TestPidReuseWithADifferentStartIsANewInstance(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	tracker.ObserveExecEvent(ExecObservation{
		PID: 600, PPID: 50, Name: "claude", Exe: "/home/dev/.local/bin/claude", ExecID: "agent", StartNS: aliasTestStart,
	})
	tracker.ObserveExecEvent(ExecObservation{
		PID: 601, PPID: 600, Name: "bash", Exe: "/usr/bin/bash", ExecID: "tool", ParentExecID: "agent",
		StartNS: aliasTestStart + int64(time.Second),
	})
	agent := tracker.InstanceOf(600)
	// The agent's exit was lost and the pid now holds another process.
	tracker.ObserveExecEvent(ExecObservation{
		PID: 600, PPID: 70, Name: "bash", Exe: "/usr/bin/bash", ExecID: "editor", StartNS: aliasTestStart + int64(10*time.Second),
	})
	editor := tracker.InstanceOf(600)
	if editor.ID == agent.ID || editor.Start.Equal(agent.Start) {
		t.Fatalf("the reused pid kept the agent's instance: agent %+v, now %+v", agent, editor)
	}
	if got := tracker.InstanceOfProcess(600, "agent"); got != agent {
		t.Fatalf("the agent's exec id names %+v, want the agent's instance %+v", got, agent)
	}
	if _, ok := tracker.Attribute(600); ok {
		t.Fatal("the process at the reused pid is attributed to the agent")
	}
	lineage, ok := tracker.Lineage(601, "tool")
	if !ok || lineage.RootInstance != agent.ID || lineage.RootPID != 600 || !lineage.RootKeyStart.Equal(agent.Start) {
		t.Fatalf("the agent's tool: %+v ok=%v, want the agent's own instance", lineage, ok)
	}

	// The same holds without exec ids: a poll row with another start on the
	// pid is a new instance, and the agent's child no longer reaches it.
	native := NewTracker()
	native.ObserveProcessTable([]ProcessRow{
		{PID: 700, PPID: 50, Name: "claude", Cmdline: "claude", Start: time.Unix(0, aliasTestStart)},
		{PID: 701, PPID: 700, Name: "bash", Start: time.Unix(0, aliasTestStart+int64(time.Second))},
	})
	before := native.InstanceOf(700)
	native.ObserveProcessTable([]ProcessRow{{PID: 700, PPID: 70, Name: "claude", Cmdline: "claude",
		Start: time.Unix(0, aliasTestStart+int64(time.Minute))}})
	if after := native.InstanceOf(700); after.ID == before.ID {
		t.Fatalf("a new start on the pid kept instance %d", after.ID)
	}
	if attribution, ok := native.Attribute(701); ok {
		t.Fatalf("the old child reached the new process at its parent pid: %+v", attribution)
	}
}

func TestReannounceDoesNotSplitOrMergeInstances(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	agent := func(pid int, execID string, start int64) ExecObservation {
		return ExecObservation{
			PID: pid, PPID: 50, Name: "2.1.292", Exe: "/home/dev/.local/share/claude/versions/2.1.292",
			Cmdline: "claude", UID: intp(1001), ExecID: execID, StartNS: start,
		}
	}
	tracker.ObserveExecEvent(agent(800, "x", aliasTestStart))
	tracker.ObserveExecEvent(agent(810, "y", aliasTestStart+int64(time.Millisecond)))
	first, second := tracker.InstanceOf(800), tracker.InstanceOf(810)
	if first.ID == second.ID {
		t.Fatal("two processes share an instance")
	}
	firstKey, _ := tracker.Lineage(800, "x")

	// Tetragon restarted: both are re-announced, a millisecond off the start
	// their exec carried, and one of the announcements is delivered twice.
	tracker.ObserveExecEvent(agent(800, "x2", aliasTestStart+int64(3*time.Millisecond)))
	tracker.ObserveExecEvent(agent(800, "x2", aliasTestStart+int64(3*time.Millisecond)))
	tracker.ObserveExecEvent(agent(810, "y2", aliasTestStart+int64(4*time.Millisecond)))
	if got := tracker.InstanceOf(800); got != first {
		t.Fatalf("the re-announce split the instance: %+v, was %+v", got, first)
	}
	if got := tracker.InstanceOf(810); got != second {
		t.Fatalf("the re-announce split the second instance: %+v, was %+v", got, second)
	}
	for _, id := range []string{"x", "x2"} {
		lineage, ok := tracker.Lineage(0, id)
		if !ok || lineage.RootInstance != first.ID || !lineage.RootKeyStart.Equal(firstKey.RootKeyStart) || lineage.RootPID != 800 {
			t.Fatalf("exec id %q: %+v ok=%v, want instance %d with its first key", id, lineage, ok, first.ID)
		}
	}
	if got := tracker.InstanceOfProcess(0, "y2"); got != second {
		t.Fatalf("the second process's re-announce named %+v, want %+v: two processes merged", got, second)
	}
	// Children named under either id belong to their own parent only.
	tracker.ObserveExecEvent(ExecObservation{PID: 801, PPID: 800, Name: "bash", ExecID: "c1", ParentExecID: "x2",
		StartNS: aliasTestStart + int64(time.Second)})
	tracker.ObserveExecEvent(ExecObservation{PID: 811, PPID: 810, Name: "bash", ExecID: "c2", ParentExecID: "y",
		StartNS: aliasTestStart + int64(time.Second)})
	if a, ok := tracker.Attribute(801); !ok || a.RootInstance != first.ID {
		t.Fatalf("child of the re-announced agent: %+v ok=%v", a, ok)
	}
	if a, ok := tracker.Attribute(811); !ok || a.RootInstance != second.ID {
		t.Fatalf("child of the second agent: %+v ok=%v", a, ok)
	}
}

// TestSelfExecKeepsTheInstance pins that an exec in the same process --
// Tetragon names the earlier image at the pid as the new image's parent -- is
// a new image of the instance, not a new instance, although Tetragon's start
// for it is the time of the later exec, and that the instance keeps its own
// parent.
func TestSelfExecKeepsTheInstance(t *testing.T) {
	t.Parallel()
	tracker := NewTracker()
	tracker.ObserveExecEvent(ExecObservation{PID: 900, PPID: 50, Name: "bash", Exe: "/usr/bin/bash",
		ExecID: "launcher", ParentExecID: "login", StartNS: aliasTestStart})
	tracker.ObserveExecEvent(ExecObservation{PID: 901, PPID: 900, Name: "cat", ExecID: "early", ParentExecID: "launcher",
		StartNS: aliasTestStart + int64(time.Second)})
	before := tracker.InstanceOf(900)
	tracker.ObserveExecEvent(ExecObservation{PID: 900, PPID: 900, Name: "claude", Exe: "/home/dev/.local/bin/claude",
		ExecID: "agent", ParentExecID: "launcher", StartNS: aliasTestStart + int64(30*time.Second)})
	if after := tracker.InstanceOf(900); after != before {
		t.Fatalf("an exec in the same process made a new instance: %+v, was %+v", after, before)
	}
	attribution, ok := tracker.Attribute(900)
	if !ok || attribution.AgentName != "claude" || attribution.RootInstance != before.ID {
		t.Fatalf("the re-imaged process: %+v ok=%v", attribution, ok)
	}
	if got := tracker.InstanceOfProcess(0, "launcher"); got != before {
		t.Fatalf("the earlier image's exec id names %+v, want the instance", got)
	}
	tracker.ObserveExecEvent(ExecObservation{PID: 50, PPID: 1, Name: "login", ExecID: "login", StartNS: aliasTestStart - int64(time.Hour)})
	tracker.ObserveExecEvent(ExecObservation{PID: 902, PPID: 900, Name: "cat", ExecID: "late", ParentExecID: "agent",
		StartNS: aliasTestStart + int64(31*time.Second)})
	if lineage, ok := tracker.Lineage(902, "late"); !ok || lineage.RootPID != 900 || lineage.Child.PID != 902 {
		t.Fatalf("the re-imaged agent's child: %+v ok=%v", lineage, ok)
	}
	tracker.mu.RLock()
	record := tracker.records[900]
	tracker.mu.RUnlock()
	if record.ppid != 50 || record.parentExecID != "login" {
		t.Fatalf("the re-imaged instance's parent is %d/%q, want 50/login", record.ppid, record.parentExecID)
	}
}
