// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// The replica-independent call/result join of a Substrate actor (substrate-1
// GAP-0342) and its fail modes, from review rch3 (zz_rch3_342_test.go): the
// key is the verified actor's and session's, so another actor or session
// can't clear a read; a result the leader can't take, or one that arrives
// before its call, never clears it; and a result whose call reached no
// leader marks the actor unrecorded (R1).

// gap0342Pair is two gateway replicas sharing one leader, each with its own
// correlation HMAC key (as two pods derive theirs from their device keys):
// onA and onB select the replica whose key is active.
func gap0342Pair(t *testing.T) (a, b chartReplica, chains *chainstate.Client, onA, onB func()) {
	t.Helper()
	a, _, chains = substrateEgressReplicaWith(t, "default", false, "")
	b = chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, a.f.regs })}
	b.f.api.store, b.f.api.logger = testStoreAndV8Logger(t)
	keyA, keyB := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32)
	prev := gatewaylog.SwapTelemetryHMACKeyForTest(keyA)
	t.Cleanup(func() { gatewaylog.SwapTelemetryHMACKeyForTest(prev) })
	return a, b, chains, func() { gatewaylog.SwapTelemetryHMACKeyForTest(keyA) }, func() { gatewaylog.SwapTelemetryHMACKeyForTest(keyB) }
}

// gap0342DeadReplica is a replica whose leader is unreachable.
func gap0342DeadReplica(t *testing.T, a chartReplica) chartReplica {
	t.Helper()
	srv := httptest.NewServer(nil)
	url := srv.URL
	srv.Close()
	dead := &chainstate.Client{Leader: &leader.Client{BaseURL: url, HTTP: srv.Client(), Retry: time.Second}}
	r := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = dead, a.f.regs })}
	r.f.api.store, r.f.api.logger = testStoreAndV8Logger(t)
	return r
}

const gap0342CarolUID = "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c"

// gap0342AddCarol registers carol-1, another Claude Code actor, on rs.
func gap0342AddCarol(t *testing.T, a chartReplica, rs ...chartReplica) {
	t.Helper()
	ctx := context.Background()
	reg, ok, err := a.f.regs.Get(ctx, "eng-web", subUID1)
	if err != nil || !ok {
		t.Fatalf("alice registration: %v", err)
	}
	key, err := sandboxreg.SubstrateKey("eng-web", gap0342CarolUID)
	if err != nil {
		t.Fatal(err)
	}
	reg.Key, reg.Name, reg.UID = key, "carol-1", gap0342CarolUID
	if err := a.f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	for _, r := range rs {
		r.admit("carol-1", gap0342CarolUID)
	}
}

func gap0342Fail(session, id, cmd, text string) map[string]interface{} {
	post := claudeToolResult("PostToolUseFailure", session, id)
	delete(post, "tool_response")
	post["tool_input"] = map[string]interface{}{"command": cmd}
	post["error"] = "Exit code 1\n" + text
	return post
}

func gap0342OK(session, id, cmd, text string) map[string]interface{} {
	post := claudeToolResult("PostToolUse", session, id)
	post["tool_input"] = map[string]interface{}{"command": cmd}
	post["tool_response"] = map[string]interface{}{"stdout": text, "stderr": "", "interrupted": false, "isImage": false}
	return post
}

// gap0342Egress is the hook answer to an upload of uid's actor on r and the
// leader's egress verdict for it.
func gap0342Egress(t *testing.T, r chartReplica, chains *chainstate.Client, uid, tok, label string) (agentHookResponse, chainstate.EgressVerdict) {
	t.Helper()
	got := r.hook(t, tok, claudeToolEvent("PreToolUse", "s1", "send-"+label, substrateEgress))
	v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
		Actor: chainstate.Actor{Atespace: "eng-web", UID: uid}, Host: "github.com", Method: "POST"})
	if err != nil {
		t.Fatalf("%s: egress check: %v", label, err)
	}
	return got, v
}

func gap0342Refused(t *testing.T, label string, got agentHookResponse, v chainstate.EgressVerdict) {
	t.Helper()
	if !slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress) || got.Action != guardrailActionBlock || !v.Deny {
		t.Fatalf("%s: hook %q %v, callout %+v: want both refused by the chain", label, got.Action, got.RuleIDs, v)
	}
}

// Another actor's forged result with alice's session and call id clears
// nothing of alice's read; it is carol's own result with no call, so carol
// is marked unrecorded (R1), never refused by alice's chain.
func TestGAP0342KeyIsTheActorsOwn(t *testing.T) {
	a, b, chains, onA, onB := gap0342Pair(t)
	gap0342AddCarol(t, a, a, b)
	onA()
	a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", "cat .env"))
	onB()
	b.hook(t, "tok-carol-1", gap0342Fail("s1", "read-1", "cat .env", "cat: .env: No such file or directory"))
	b.hook(t, "tok-alice", gap0342OK("s1", "read-1", "cat .env", "API_KEY=canary-1"))
	got, v := gap0342Egress(t, b, chains, subUID1, "tok-alice", "alice")
	gap0342Refused(t, "alice after carol's forged result", got, v)
	_, cv := gap0342Egress(t, b, chains, gap0342CarolUID, "tok-carol-1", "carol")
	if cv.Deny {
		t.Fatalf("carol: %+v, want no chain refusal from alice's read", cv)
	}
	if cv.Unrecorded == "" {
		t.Fatalf("carol: %+v, want her result with no call marked unrecorded (R1)", cv)
	}
}

// A forged failure in another session of the same actor clears nothing.
func TestGAP0342KeyIsTheSessionsOwn(t *testing.T) {
	a, b, chains, onA, onB := gap0342Pair(t)
	onA()
	a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", "cat .env"))
	onB()
	b.hook(t, "tok-alice", gap0342Fail("s2", "read-1", "cat .env", "cat: .env: No such file or directory"))
	b.hook(t, "tok-alice", gap0342OK("s1", "read-1", "cat .env", "API_KEY=canary-1"))
	got, v := gap0342Egress(t, b, chains, subUID1, "tok-alice", "alice")
	gap0342Refused(t, "after a forged result in another session", got, v)
}

// A result the leader can't take never clears the read: the result's
// replica reports the step unrecorded, and the proposal stays in the
// actor's window, so the callout refuses.
func TestGAP0342LeaderDownAtTheResultFailsClosed(t *testing.T) {
	for _, row := range []struct {
		id, read, text string
		ok             bool
	}{
		{"missing-file", "cat .env.production", "cat: .env.production: No such file or directory", false},
		{"printed", "cat .env", "API_KEY=canary-1", true},
	} {
		t.Run(row.id, func(t *testing.T) {
			a, _, chains, onA, onB := gap0342Pair(t)
			dead := gap0342DeadReplica(t, a)
			onA()
			a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", row.read))
			onB()
			res := gap0342Fail("s1", "read-1", row.read, row.text)
			if row.ok {
				res = gap0342OK("s1", "read-1", row.read, row.text)
			}
			got := dead.hook(t, "tok-alice", res)
			if !slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
				t.Fatalf("result on the cut-off replica: %+v, want %s", got, substrateChainUnrecordedRule)
			}
			if _, v := gap0342Egress(t, a, chains, subUID1, "tok-alice", row.id); !v.Deny {
				t.Fatalf("callout: %+v, want refused (the read was never cleared)", v)
			}
		})
	}
}

// A result that arrives before its call clears nothing: the later proposal
// stays pending and the callout refuses (the safe side).
func TestGAP0342ResultBeforeTheCallFailsClosed(t *testing.T) {
	for _, row := range []struct {
		id, read, text string
		ok             bool
	}{
		{"missing-file", "cat .env.production", "cat: .env.production: No such file or directory", false},
		{"printed", "cat .env", "API_KEY=canary-1", true},
	} {
		t.Run(row.id, func(t *testing.T) {
			a, b, chains, onA, onB := gap0342Pair(t)
			onB()
			res := gap0342Fail("s1", "read-1", row.read, row.text)
			if row.ok {
				res = gap0342OK("s1", "read-1", row.read, row.text)
			}
			b.hook(t, "tok-alice", res)
			onA()
			a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", row.read))
			onB()
			if _, v := gap0342Egress(t, b, chains, subUID1, "tok-alice", row.id); !v.Deny && v.Unrecorded == "" {
				t.Fatalf("callout: %+v, want refused or unrecorded", v)
			}
		})
	}
}

// R1: the call reached no leader (its replica is cut off) and its printed
// result reaches a healthy replica: the actor is marked unrecorded, so the
// callout refuses where it refuses unchecked egress. A plain call's result
// with no proposal (no credentials read) marks nothing.
func TestGAP0342ResultOfACallThatReachedNoLeaderIsUnrecorded(t *testing.T) {
	a, b, chains, onA, onB := gap0342Pair(t)
	dead := gap0342DeadReplica(t, a)
	onA()
	dead.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", "cat .env"))
	onB()
	got := b.hook(t, "tok-alice", gap0342OK("s1", "read-1", "cat .env", "API_KEY=canary-1"))
	if !slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("result on the healthy replica: %+v, want %s", got, substrateChainUnrecordedRule)
	}
	if _, v := gap0342Egress(t, b, chains, subUID1, "tok-alice", "r1"); v.Unrecorded == "" {
		t.Fatalf("callout: %+v, want the unrecorded mark", v)
	}

	a2, b2, chains2, onA2, onB2 := gap0342Pair(t)
	dead2 := gap0342DeadReplica(t, a2)
	onA2()
	dead2.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls -la"))
	onB2()
	plain := b2.hook(t, "tok-alice", gap0342OK("s1", "list-1", "ls -la", "notes.txt"))
	if slices.Contains(plain.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("plain call's result: %+v, want no unrecorded mark", plain)
	}
	if _, v := gap0342Egress(t, b2, chains2, subUID1, "tok-alice", "plain"); v.Unrecorded != "" || v.Deny {
		t.Fatalf("callout after a plain call: %+v, want allowed and no mark", v)
	}
}
