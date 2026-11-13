// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package chainstate

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// The gateway's hook path for a structured action (Bash, Read) records its
// first step in the actor window with a prepare at PreToolUse and a resolve
// at PostToolUse, never an observe (agent_hook_chain.go). These tests make
// those calls through the real leader transport (R4's GAP-0179 proofs).

func (h *harness) prepare(actor Actor, p guardrail.ToolChainProjection, inv string) {
	h.t.Helper()
	id, fp := eventID(h.t)
	r, err := h.bind(actor, ScopeActor, "s1").PreparePending(context.Background(), audit.ToolChainPreparePendingInput{
		ToolInvocationDigest: inv, PreSemanticEventID: id, PreInputFingerprint: fp,
		RulesetFingerprint: ruleset, Projection: p})
	if err != nil || r.Status != audit.ToolChainPendingPrepared {
		h.t.Fatalf("prepare: %+v err=%v", r, err)
	}
}

func (h *harness) resolve(actor Actor, inv string, outcome audit.ToolChainPendingOutcome) {
	h.t.Helper()
	id, fp := eventID(h.t)
	r, err := h.bind(actor, ScopeActor, "s1").ResolvePending(context.Background(), audit.ToolChainResolvePendingInput{
		ToolInvocationDigest: inv, Outcome: outcome, RulesetFingerprint: ruleset,
		TerminalSemanticEventID: id, TerminalInputFingerprint: fp})
	if err != nil || r.Status != audit.ToolChainPendingResolved {
		h.t.Fatalf("resolve: %+v err=%v", r, err)
	}
}

// promote is a successful structured action: prepare, then resolve.
func (h *harness) promote(actor Actor, p guardrail.ToolChainProjection, inv string) {
	h.t.Helper()
	h.prepare(actor, p, inv)
	h.advance(time.Second)
	h.resolve(actor, inv, audit.ToolChainPendingOutcomeSuccess)
}

func (h *harness) egress(actor Actor) (EgressVerdict, error) {
	return h.svc.Egress(context.Background(), EgressRequest{Actor: actor, Host: "example.com", Method: "POST"})
}

// settle waits for the worker's queued jobs.
func (h *harness) settle() {
	h.svc.egress.stop()
	h.svc.startEgressWorker()
}

func secretRead(t *testing.T) guardrail.ToolChainProjection {
	return projection(t, guardrail.ToolChainSecretReadThenEgress, 1)
}

func TestPromotedSecretReadRefusesTheFirstEgressGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.promote(actorA, secretRead(t), strings.Repeat("c", 64))
	h.advance(time.Second)
	for i := 1; i <= 2; i++ {
		if v, err := h.egress(actorA); err != nil || !v.Deny || v.Rule != guardrail.ToolChainSecretReadThenEgress {
			t.Fatalf("egress %d after a promoted secret read: %+v %v", i, v, err)
		}
		h.settle()
	}
	// Another actor is not touched.
	if v, err := h.egress(actorB); err != nil || v.Deny {
		t.Fatalf("other actor: %+v %v", v, err)
	}
}

// A secret read counts from its PreToolUse: `curl -d @~/.aws/credentials`
// sends while it runs, before PostToolUse. A failed read never armed the
// chain, so its egress passes once the failure resolves.
func TestPreparedSecretReadCountsWhileItRunsGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	inv := strings.Repeat("a", 64)
	h.prepare(actorA, secretRead(t), inv)
	h.advance(time.Second)
	if v, err := h.egress(actorA); err != nil || !v.Deny {
		t.Fatalf("egress while the read runs: %+v %v", v, err)
	}
	h.resolve(actorA, inv, audit.ToolChainPendingOutcomeFailure)
	if v, err := h.egress(actorA); err != nil || v.Deny {
		t.Fatalf("egress after a failed read: %+v %v", v, err)
	}
	// A pending read past its expiry no longer counts.
	h.prepare(actorA, secretRead(t), strings.Repeat("b", 64))
	h.advance(guardrail.ToolChainMaxHorizon + time.Minute)
	if v, err := h.egress(actorA); err != nil || v.Deny {
		t.Fatalf("egress after the pending read expired: %+v %v", v, err)
	}
}

// An exact transport replay (the same semantic event) is one event in the
// store and in the memo: replays never age the secret read out.
func TestReplayedObserveDoesNotAgeTheChainGAP0179(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.hook(actorA, "s1", secretRead(t))
	h.advance(time.Second)
	id, fp := eventID(t)
	in := audit.ToolChainObserveInput{SemanticEventID: id, InputFingerprint: fp, RulesetFingerprint: ruleset,
		Projection: projection(t, reverseShell, 1), DenyEligible: true}
	b, err := h.client.Bind(actorA, ScopeActor, "claudecode", "s1", "PreToolUse")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		if _, err := b.Observe(context.Background(), in); err != nil {
			t.Fatalf("replay %d: %v", i, err)
		}
	}
	if v, err := h.egress(actorA); err != nil || !v.Deny {
		t.Fatalf("after 9 replays of one event: %+v %v", v, err)
	}
	// Eight distinct events do age it out, as in the store.
	for i := 0; i < 8; i++ {
		h.advance(time.Second)
		h.hook(actorA, "s1", projection(t, reverseShell, 1))
	}
	if v, err := h.egress(actorA); err != nil || v.Deny {
		t.Fatalf("after 8 distinct events: %+v %v", v, err)
	}
}

// Refused egress attempts sent nothing, so they are not egress steps:
// retrying never ages the secret read out of its event window.
func TestRefusedEgressDoesNotAgeTheChain(t *testing.T) {
	h := newHarness(t, t.TempDir(), Options{})
	h.promote(actorA, secretRead(t), strings.Repeat("e", 64))
	for i := 1; i <= 12; i++ {
		h.advance(time.Second)
		if v, err := h.egress(actorA); err != nil || !v.Deny {
			t.Fatalf("attempt %d: %+v %v", i, v, err)
		}
		h.settle()
	}
}

// A fork child's first egress, before any hook of its own, is checked
// against the parent's promoted read; and after the child's store opens
// (its first hook), against the copied windows.
func TestForkChildFirstEgressAfterParentsPromotedReadGAP0179(t *testing.T) {
	parents := map[string]string{actorB.UID: actorA.UID}
	h := newHarness(t, t.TempDir(), Options{ParentOf: func(_ context.Context, _, uid string) (string, error) {
		return parents[uid], nil
	}})
	h.promote(actorA, secretRead(t), strings.Repeat("f", 64))
	h.advance(time.Second)
	if v, err := h.egress(actorB); err != nil || !v.Deny {
		t.Fatalf("fork child, first egress: %+v %v", v, err)
	}
	h.settle()
	h.hook(actorB, "s1", projection(t, reverseShell, 1))
	if v, err := h.egress(actorB); err != nil || !v.Deny {
		t.Fatalf("fork child after its first hook: %+v %v", v, err)
	}
}

// A new leader on the volume answers from the saved memo: the promoted or
// observed secret read, with or without an egress before the restart.
func TestSecretReadSurvivesFailoverGAP0179(t *testing.T) {
	for _, tc := range []struct {
		name             string
		promoted, egress bool
	}{{"promoted", true, false}, {"promoted after an egress", true, true}, {"observed", false, false}, {"observed after an egress", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			h := newHarness(t, dir, Options{})
			if tc.promoted {
				h.promote(actorA, secretRead(t), strings.Repeat("9", 64))
			} else {
				h.hook(actorA, "s1", secretRead(t))
			}
			h.advance(time.Second)
			if tc.egress {
				if v, err := h.egress(actorA); err != nil || !v.Deny {
					t.Fatalf("leader 1: %+v %v", v, err)
				}
			}
			h.srv.Close()
			_ = h.svc.Close()
			h2 := newHarness(t, dir, Options{})
			h2.advance(10 * time.Second)
			for i := 1; i <= 2; i++ {
				if v, err := h2.egress(actorA); err != nil || !v.Deny {
					t.Fatalf("new leader, egress %d: %+v %v", i, v, err)
				}
				h2.settle()
			}
		})
	}
}
