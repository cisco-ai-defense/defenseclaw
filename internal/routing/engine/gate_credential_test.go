// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"strings"
	"testing"
)

// denyingGateAdmin is an admin whose Gate refuses the original request the
// way the real evaluator does for a request outside the allow list.
type denyingGateAdmin struct{ fakeAdmin }

func (denyingGateAdmin) Gate(AdminVerdict, GateTarget, bool) *DenyReason {
	return &DenyReason{Code: "routing_admin_denied", Message: "Your administrator does not allow this model for this request (rule r1)."}
}

// rel-1-0-10 GAP-0921: an allowed alias with no gateway credential made the
// request fall back to its own, disallowed model, and the refusal blamed the
// administrator. The refusal now says the credential is missing.
func TestGateNamesTheMissingCredentialOfAnAllowedAlias(t *testing.T) {
	admin := denyingGateAdmin{fakeAdmin{verdict: AdminVerdict{Bind: true, RuleIDs: []string{"r1"}, Policy: Policy{AllowedAliases: []string{"fast"}}}}}
	noKey := func(b Backend, _ Request) bool { return b.Alias != "fast" }
	e := mustEngine(t, testConfig(), Options{Managed: true, Admin: admin, CredentialOK: noKey})
	d := e.Decide(context.Background(), chat("refactor"))
	if d.Outcome != OutcomeFallback || len(d.NoCredential) != 1 || d.NoCredential[0] != "fast" {
		t.Fatalf("decision = %+v", d)
	}
	deny := e.Gate(d, GateTarget{Provider: "openai", Model: "gpt-x"})
	if deny == nil || deny.Code != "routing_admin_denied" || !strings.Contains(deny.Message, "fast") || !strings.Contains(deny.Message, "no gateway credential") || !strings.Contains(deny.Message, "(rule r1)") || strings.Contains(deny.Message, "do not fit") || strings.Contains(deny.Message, "does not allow") {
		t.Fatalf("deny = %+v", deny)
	}

	// With its credential the alias serves the call and nothing is refused.
	ok := mustEngine(t, testConfig(), Options{Managed: true, Admin: admin})
	d = ok.Decide(context.Background(), chat("refactor"))
	if d.Outcome != OutcomeApplied || len(d.NoCredential) != 0 {
		t.Fatalf("with a credential: %+v", d)
	}

	// A fallback with no credential problem keeps the administrator text.
	other := mustEngine(t, testConfig(), Options{Managed: true, Admin: admin})
	d = other.Decide(context.Background(), chat("refactor"))
	d.Outcome, d.NoCredential = OutcomeFallback, nil
	if deny := other.Gate(d, GateTarget{Provider: "openai", Model: "gpt-x"}); deny == nil || !strings.Contains(deny.Message, "does not allow") {
		t.Fatalf("plain deny rewritten: %+v", deny)
	}
}

// Another allowed model that failed for a reason other than a credential is
// said too: the credential is not the whole story.
func TestGateSaysWhenAnotherAllowedModelDoesNotFit(t *testing.T) {
	d := Decision{NoCredential: []string{"fast"}, OtherUnfit: true, verdict: AdminVerdict{RuleIDs: []string{"r1"}}}
	admin := denyingGateAdmin{fakeAdmin{verdict: AdminVerdict{Bind: true}}}
	e := mustEngine(t, testConfig(), Options{Managed: true, Admin: admin})
	deny := e.Gate(d, GateTarget{Provider: "openai", Model: "gpt-x"})
	if deny == nil || !strings.Contains(deny.Message, "Other models allowed for you do not fit") {
		t.Fatalf("deny = %+v", deny)
	}
}
