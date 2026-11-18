// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package extproc

import (
	"context"
	"slices"
	"strings"
	"testing"
)

// substrate-1 GAP-0339: a request whose chain check saw an incomplete window
// (an unrecorded tool step of the actor) is refused where unchecked egress
// is (chain.failure_mode closed, or auto on a managed install or for an
// unattended actor), and allowed with an alert elsewhere.
func TestGAP0339UnrecordedStepRefusedWhereUncheckedIs(t *testing.T) {
	ctx := context.Background()
	why := "the actor's hook contract routes no tool-call lifecycle event \"preToolUse\""
	checker := fakeChecker{v: ChainVerdict{Unrecorded: why}}
	attended := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = checker })
	v := attended.eng.DecideHeaders(ctx, req("x", "GET", "example.com", "/"))
	if !v.Allow || !v.Alert || !slices.ContainsFunc(v.Findings, func(f string) bool { return strings.HasPrefix(f, "chain_unrecorded:") }) {
		t.Fatalf("attended open source actor, GET: %+v, want allowed with a chain_unrecorded alert", v)
	}
	// A send is refused in every mode (GAP-0601).
	for _, mode := range []string{"", FailureOpen} {
		h := newHarness(t, func(c *Config, o *Options) {
			o.ChainChecker = checker
			if mode != "" {
				c.Chain.FailureMode = mode
			}
		})
		v = h.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/"))
		if v.Allow || v.Category != CategoryChainUnchecked || v.Rule != uncheckedUnrecorded || !v.Retryable ||
			!strings.Contains(v.Reason, why) || !strings.Contains(v.Reason, "carry data out") {
			t.Fatalf("attended open source actor, POST, mode %q: %+v, want refused chain_unchecked/unrecorded_step", mode, v)
		}
	}
	closed := newHarness(t, func(c *Config, o *Options) { o.ChainChecker = checker; c.Chain.FailureMode = FailureClosed })
	v = closed.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/"))
	if v.Allow || v.Category != CategoryChainUnchecked || !strings.Contains(v.Reason, why) {
		t.Fatalf("failure_mode closed: %+v, want refused chain_unchecked with the reason", v)
	}
	managed := newHarness(t, func(c *Config, o *Options) { o.ChainChecker = checker; c.Managed = true })
	if v := managed.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/")); v.Allow || v.Category != CategoryChainUnchecked {
		t.Fatalf("managed: %+v, want refused", v)
	}
}
