// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// gap0337Resolve prepares a proposal that starts the secret-read chain and
// the privilege chain, resolves it with outcome and mayHaveRead, and
// reports which of the two chains an egress / elevation step then denies.
func gap0337Resolve(t *testing.T, outcome ToolChainPendingOutcome, mayHaveRead bool) (secretRead, privilege bool) {
	t.Helper()
	fixture := newToolChainFixture(t, ":memory:")
	secret, priv := guardrail.ToolChainSecretReadThenEgress, guardrail.ToolChainPrivilegeDiscoveryThenElevation
	pre := fixture.seed(t, "gap0337", correlationDigest("gap0337-pre"))
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  pre.ConnectorInstanceID,
		ToolInvocationDigest: correlationDigest("gap0337-invocation"),
		PreSemanticEventID:   pre.SemanticEventID,
		PreInputFingerprint:  pre.InputFingerprint,
		RulesetFingerprint:   pre.RulesetFingerprint,
		Projection:           toolChainProjection(t, []string{secret, priv}, 1, true),
	}
	if _, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "gap0337", correlationDigest("gap0337-terminal"))
	resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     prepare.ToolInvocationDigest,
		Outcome:                  outcome,
		RulesetFingerprint:       prepare.RulesetFingerprint,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
		UnsuccessfulMayHaveRead:  mayHaveRead,
	})
	if err != nil || resolved.Status != ToolChainPendingResolved {
		t.Fatalf("resolve=%#v err=%v", resolved, err)
	}
	var pending int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil || pending != 0 {
		t.Fatalf("pending after resolve=%d err=%v", pending, err)
	}
	for i, id := range []string{secret, priv} {
		fixture.now = fixture.now.Add(time.Second)
		final := fixture.seed(t, "gap0337", correlationDigest("gap0337-final-"+id))
		final.Projection = toolChainProjection(t, []string{id}, 2, true)
		final.DenyEligible = true
		matched, err := fixture.chain.Observe(t.Context(), final)
		if err != nil {
			t.Fatal(err)
		}
		bit, _ := guardrail.ToolChainResultMask(id)
		if i == 0 {
			secretRead = matched.DeniedMask&bit != 0
		} else {
			privilege = matched.DeniedMask&bit != 0
		}
	}
	return secretRead, privilege
}

// substrate-1 GAP-0337: a failed or unknown result that may have read
// promotes the proposal's secret-read step 1 alone; without the mark, and
// for any outcome without it, an unsuccessful result promotes nothing.
func TestToolChainUnsuccessfulMayHaveReadPromotesOnlyTheSecretRead(t *testing.T) {
	for _, tc := range []struct {
		outcome     ToolChainPendingOutcome
		mayHaveRead bool
		wantSecret  bool
	}{
		{ToolChainPendingOutcomeFailure, true, true},
		{ToolChainPendingOutcomeUnknown, true, true},
		{ToolChainPendingOutcomeFailure, false, false},
		{ToolChainPendingOutcomeUnknown, false, false},
		{ToolChainPendingOutcomeDenied, false, false},
	} {
		secret, privilege := gap0337Resolve(t, tc.outcome, tc.mayHaveRead)
		if secret != tc.wantSecret || privilege {
			t.Errorf("%s mayHaveRead=%v: secret-read=%v privilege=%v, want %v and false",
				tc.outcome, tc.mayHaveRead, secret, privilege, tc.wantSecret)
		}
	}
}

// A denied or cancelled call did not run: the mark is refused.
func TestToolChainMayHaveReadNeedsAFailedOrUnknownOutcome(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	seed := fixture.seed(t, "gap0337-validate", correlationDigest("fp"))
	for _, outcome := range []ToolChainPendingOutcome{ToolChainPendingOutcomeDenied, ToolChainPendingOutcomeCancelled, ToolChainPendingOutcomeSuccess} {
		err := validateToolChainResolvePendingInput(ToolChainResolvePendingInput{
			ConnectorInstanceID:      seed.ConnectorInstanceID,
			ToolInvocationDigest:     correlationDigest("x"),
			Outcome:                  outcome,
			RulesetFingerprint:       seed.RulesetFingerprint,
			TerminalSemanticEventID:  seed.SemanticEventID,
			TerminalInputFingerprint: seed.InputFingerprint,
			UnsuccessfulMayHaveRead:  true,
		})
		if err == nil {
			t.Errorf("%s with the mark was accepted", outcome)
		}
	}
}
