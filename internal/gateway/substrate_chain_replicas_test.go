//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"net/http"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// chartReplica is one gateway replica of a chart install: its own audit
// store and actor listener, the shared registrations, and the leader's
// chain state over the leader RPC.
type chartReplica struct{ f *substrateFixture }

// substrateKitEnvelope is the envelope the kit hook posts: it names the hook
// contract the kit was built with (kit config HookContracts).
func substrateKitEnvelope(contract string, payload map[string]any) string {
	p, _ := json.Marshal(payload)
	b, _ := json.Marshal(map[string]any{"v": substrateEnvelopeVersion, "connector": "claudecode", "mode": "headless",
		"kit_version": "stk", "hook_contract": contract, "payload": json.RawMessage(p)})
	return string(b)
}

func (r chartReplica) hook(t *testing.T, token string, ev map[string]any) agentHookResponse {
	t.Helper()
	ev["cwd"] = "/work"
	rec := r.f.do(t, r.f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", token,
		substrateKitEnvelope("claudecode-hooks-v2", ev))
	if rec.Code != http.StatusOK {
		t.Fatalf("%s: %d %s", ev["hook_event_name"], rec.Code, rec.Body)
	}
	var out agentHookResponse
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out
}

// admit makes a created actor known to a replica's actor listener: its
// token and its live state, as the router and the Control API give them.
func (r chartReplica) admit(name, uid string) {
	toks := r.f.api.substrateState().cfg.Actors.(*fakeActorTokens)
	toks.mu.Lock()
	toks.tokens["tok-"+name] = identity.Actor{Atespace: "eng-web", Name: name, UID: uid, Subject: "actor/eng-web/" + name}
	toks.mu.Unlock()
	r.f.mu.Lock()
	r.f.live["eng-web/"+name] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
	r.f.mu.Unlock()
}

// TestSubstrateChartInstallSecretReadRefusedGAP0201 is a chart install's
// shape: two gateway replicas and a leader. The actor is created through
// the admin route from an attested template (as the launcher does), its
// PreToolUse for `cat ~/.aws/credentials` lands on one replica and its
// PostToolUse on the other, and the callout's chain check then refuses its
// next request. Before the fix the registration named no agent version, so
// the kit's pinned hook contract (claudecode-hooks-v2) resolved as unknown
// and the chain stage skipped the read silently on every replica.
func TestSubstrateChartInstallSecretReadRefusedGAP0201(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	svc, chains := newTestChainLeaderService(t)
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
		`{"template":"claude","connector":"claudecode","name":"alice-chart","unattended":true}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create: %d %s", rec.Code, rec.Body)
	}
	a, err := fake.GetActor(context.Background(), ateapi.Ref("eng-web", "alice-chart"))
	if err != nil {
		t.Fatal(err)
	}
	uid := a.GetMetadata().GetUid()
	reg, _, err := r1.f.regs.Get(context.Background(), "eng-web", uid)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("registration: harness %q, contract %q", reg.HarnessVersion, reg.HookContract)
	r1.admit("alice-chart", uid)
	r2.admit("alice-chart", uid)

	egress := chainstate.EgressRequest{Actor: chainstate.Actor{Atespace: "eng-web", UID: uid}, Host: "github.com", Method: "POST"}
	check := func(when string, wantDeny bool) {
		t.Helper()
		v, err := svc.Egress(context.Background(), egress)
		if err != nil || v.Deny != wantDeny || (wantDeny && v.Rule != guardrail.ToolChainSecretReadThenEgress) {
			t.Errorf("%s: egress %+v err=%v, want deny=%v", when, v, err, wantDeny)
		}
	}
	r2.hook(t, "tok-alice-chart", claudeToolEvent("PreToolUse", "s1", "list-1", "ls -la"))
	r1.hook(t, "tok-alice-chart", claudeToolResult("PostToolUse", "s1", "list-1"))
	check("after a benign command", false)
	r2.hook(t, "tok-alice-chart", claudeToolEvent("PreToolUse", "s1", "read-1", "cat ~/.aws/credentials"))
	check("while the secret read runs (PreToolUse on replica 2)", true)
	r1.hook(t, "tok-alice-chart", claudeToolResult("PostToolUse", "s1", "read-1"))
	check("after the secret read (PostToolUse on replica 1)", true)
}

// TestSubstrateUnrecordedChainStepIsNeverSilentGAP0201: a registration
// that names no agent version (made before GAP-0201, or from a template
// whose statement has none) while the kit pins claudecode-hooks-v2. The
// gateway can't resolve the hook lifecycle, so the step can't reach the
// actor window: the hook answers with an alert finding on the default
// pack, and a block on strict, instead of skipping it silently.
func TestSubstrateUnrecordedChainStepIsNeverSilentGAP0201(t *testing.T) {
	installCorrelationHMACForTest()
	installDefaultProfileConnector(t, "claudecode")
	_, chains := newTestChainLeaderService(t)
	r := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains = chains })}
	r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
	got := r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", "cat ~/.aws/credentials"))
	if !slices.Contains(got.RuleIDs, "SUBSTRATE-CHAIN-UNRECORDED") || got.Action == "allow" {
		t.Fatalf("default pack: %+v, want an alert naming SUBSTRATE-CHAIN-UNRECORDED", got)
	}
	r.f.api.scannerCfg.Guardrail.RulePackDir = strings.TrimSuffix(guardrailPoliciesRoot(t), "/") + "/strict"
	got = r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-2", "ls -la"))
	if got.Action != "block" {
		t.Fatalf("strict pack: %+v, want a block", got)
	}
	// A registration with the attested version records the step: no finding.
	if err := r.f.regs.Put(context.Background(), withHarness(t, r.f, "alice-1", kit.AgentVersion("claudecode", ""), "claudecode-hooks-v2")); err != nil {
		t.Fatal(err)
	}
	r.f.api.scannerCfg.Guardrail.RulePackDir = ""
	got = r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-3", "ls -la"))
	if slices.Contains(got.RuleIDs, "SUBSTRATE-CHAIN-UNRECORDED") {
		t.Fatalf("attested registration: %+v, want no unrecorded finding", got)
	}
}

// withHarness is a fixture registration with the agent version and hook
// contract an attested template names.
func withHarness(t *testing.T, f *substrateFixture, name, version, contract string) registry.Registration {
	t.Helper()
	uid := subUID1
	if name != "alice-1" {
		t.Fatalf("unknown fixture actor %s", name)
	}
	reg, ok, err := f.regs.Get(context.Background(), "eng-web", uid)
	if err != nil || !ok {
		t.Fatalf("registration %s: %v", name, err)
	}
	reg.HarnessVersion, reg.HookContract = version, contract
	return reg
}
