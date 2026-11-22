//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// TestSubstrateGAP0564KitRetryOnTheOtherReplicaKeepsTheActorChecked is substrate-1
// GAP-0564 (CERT-110 J43 on E5: two gateway replicas, 50 actors started at
// once). The leader was slow to create 50 new actor stores, so a PreToolUse
// ran past the kit's answer budget and the kit posted it again, the same
// body on a fresh connection. The other replica took the resend and minted
// its own semantic event id; the leader read that as a reused tool call id,
// dropped the call's proposal and answered "internal", the gateway marked
// the actor unrecorded, and the callout refused every egress of 16 of the
// 50 actors for the rest of the window. A resend is the same call: the
// actor stays checked, and a secret read that is resent still refuses the
// upload after it. A different call under a reused id is still refused.
func TestSubstrateGAP0564KitRetryOnTheOtherReplicaKeepsTheActorChecked(t *testing.T) {
	installCorrelationHMACForTest(t)
	installDefaultProfileConnector(t, "claudecode")
	svc, chains := newTestChainLeaderServiceWith(t, "")
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "claude"}})
	profiles := func(identity.Person, string, string, bool) (string, string, error) { return "eng", "eng-web", nil }
	r1 := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Profiles = chains, profiles })}
	r2 := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Chains, c.Profiles, c.Registrations = chains, profiles, r1.f.regs
	})}
	for _, r := range []chartReplica{r1, r2} {
		r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
	}
	r1.f.api.substrateState().cfg.Actions = chartTemplateActions(fake, attestedClaudeKit())
	rec := r1.f.do(t, r1.f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice",
		`{"template":"claude","connector":"claudecode","name":"alice-j43","unattended":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	a, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-j43"))
	if err != nil {
		t.Fatal(err)
	}
	uid := a.GetMetadata().GetUid()
	r1.admit("alice-j43", uid)
	r2.admit("alice-j43", uid)
	const tok = "tok-alice-j43"
	egress := func(when string) chainstate.EgressVerdict {
		t.Helper()
		v, err := svc.Egress(context.Background(), chainstate.EgressRequest{
			Actor: chainstate.Actor{Atespace: "eng-web", UID: uid}, Host: "t-sink.t.svc", Method: "GET"})
		if err != nil {
			t.Fatalf("%s: egress check: %v", when, err)
		}
		return v
	}
	unrecorded := func(got agentHookResponse) bool { return slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) }

	// The batch start: the call runs on replica 1, the kit's resend lands on
	// replica 2, the result on replica 1.
	run := claudeToolEvent("PreToolUse", "s1", "toolu_run", "python3 j43.py steady 1794952888 420")
	if got := r1.hook(t, tok, run); unrecorded(got) {
		t.Fatalf("first delivery: %+v", got)
	}
	if got := r2.hook(t, tok, run); unrecorded(got) {
		t.Fatalf("the kit's resend on the other replica was reported unrecorded: %+v", got)
	}
	r1.hook(t, tok, claudeToolResult("PostToolUse", "s1", "toolu_run"))
	if v := egress("after a resent benign call"); v.Deny || v.Unrecorded != "" {
		t.Fatalf("after a resent benign call: %+v, want the egress allowed (J43: no refusal)", v)
	}

	// A secret read that is resent still links to the upload after it.
	read := claudeToolEvent("PreToolUse", "s1", "toolu_read", "cat ~/.aws/credentials")
	r2.hook(t, tok, read)
	r1.hook(t, tok, read)
	r1.hook(t, tok, claudeToolResult("PostToolUse", "s1", "toolu_read"))
	if v := egress("after a resent secret read"); !v.Deny || v.Rule != guardrail.ToolChainSecretReadThenEgress {
		t.Fatalf("after a resent secret read: %+v, want the secret-read chain to refuse", v)
	}

	// Another call under a reused id is not a resend: both proposals stop
	// counting and the actor's egress is checked as unrecorded (closed).
	r1.hook(t, tok, claudeToolEvent("PreToolUse", "s1", "toolu_reused", "ls -la"))
	if got := r2.hook(t, tok, claudeToolEvent("PreToolUse", "s1", "toolu_reused", "ls -la /tmp")); !unrecorded(got) {
		t.Fatalf("a different call under a reused id: %+v, want %s", got, substrateChainUnrecordedRule)
	}
	if v := egress("after a reused id"); v.Unrecorded == "" {
		t.Fatalf("after a reused id: %+v, want the actor marked unrecorded", v)
	}
}
