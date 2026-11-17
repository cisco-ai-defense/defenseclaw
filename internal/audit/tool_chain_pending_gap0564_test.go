// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestSubstrateGAP0564ResentProposalIsAReplay: substrate-1 GAP-0564. A hook client
// resends a PreToolUse it got no answer for, and a gateway replica that did
// not take the first delivery gives it its own semantic event id. The same
// call, session, body and projection is a replay: the first row stands and
// its result promotes it. Before, the resend read as a reused tool call id
// and both proposals were dropped. A different body under the same id is
// still a conflict.
func TestSubstrateGAP0564ResentProposalIsAReplay(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	chainID := guardrail.ToolChainSecretReadThenEgress
	invocation := correlationDigest("resent-invocation")
	body := correlationDigest("resent-body")

	first := fixture.seed(t, "resent-session", body)
	prepare := ToolChainPreparePendingInput{
		ConnectorInstanceID:  first.ConnectorInstanceID,
		ToolInvocationDigest: invocation,
		PreSemanticEventID:   first.SemanticEventID,
		PreInputFingerprint:  first.InputFingerprint,
		RulesetFingerprint:   first.RulesetFingerprint,
		Projection:           toolChainProjection(t, []string{chainID}, 1, true),
	}
	if r, err := fixture.chain.PreparePending(t.Context(), prepare); err != nil || r.Status != ToolChainPendingPrepared {
		t.Fatalf("first delivery=%#v err=%v", r, err)
	}
	resend := prepare
	resend.PreSemanticEventID = fixture.seed(t, "resent-session", body).SemanticEventID
	if r, err := fixture.chain.PreparePending(t.Context(), resend); err != nil || r.Status != ToolChainPendingReplay {
		t.Fatalf("resend under another event id=%#v err=%v, want a replay", r, err)
	}
	var pending int
	if err := fixture.store.db.QueryRow(`SELECT COUNT(*) FROM guardrail_chain_pending_actions`).Scan(&pending); err != nil || pending != 1 {
		t.Fatalf("pending rows after the resend=%d err=%v, want the first one", pending, err)
	}
	terminal := fixture.seed(t, "resent-session", correlationDigest("resent-terminal"))
	resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID:      terminal.ConnectorInstanceID,
		ToolInvocationDigest:     invocation,
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       prepare.RulesetFingerprint,
		TerminalSemanticEventID:  terminal.SemanticEventID,
		TerminalInputFingerprint: terminal.InputFingerprint,
	})
	if err != nil || resolved.Status != ToolChainPendingResolved {
		t.Fatalf("result of the resent call=%#v err=%v, want it resolved", resolved, err)
	}

	reused := prepare
	reused.ToolInvocationDigest = correlationDigest("reused-invocation")
	seeded := fixture.seed(t, "resent-session", correlationDigest("reused-body"))
	reused.PreSemanticEventID, reused.PreInputFingerprint = seeded.SemanticEventID, seeded.InputFingerprint
	if _, err := fixture.chain.PreparePending(t.Context(), reused); err != nil {
		t.Fatal(err)
	}
	other := fixture.seed(t, "resent-session", correlationDigest("another-body"))
	reused.PreSemanticEventID, reused.PreInputFingerprint = other.SemanticEventID, other.InputFingerprint
	if _, err := fixture.chain.PreparePending(t.Context(), reused); !errors.Is(err, ErrToolChainPendingConflict) {
		t.Fatalf("another body under the same id: err=%v, want the conflict", err)
	}
}
