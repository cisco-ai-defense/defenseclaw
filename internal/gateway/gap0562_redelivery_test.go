//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// substrate-1 GAP-0562: right after a gateway restart, a benign PreToolUse
// was answered "HIGH finding: Allowed but flagged by DefenseClaw policy".
// It was not a warm-up state. The hook was the same call delivered again (a
// kit retry, or the J15 probe's repeated payload) to a replica whose ledger
// had not seen it: a fresh pod after the restart, or the other replica. Each
// replica mints its own semantic event ID, so the leader read the second
// prepare of the same invocation as a reused invocation ID, voided the
// prepared proposal and answered an internal error; the gateway then
// reported the step SUBSTRATE-CHAIN-UNRECORDED (HIGH, no catalog title, so
// no rule named). The same call is now a replay on the leader.
func TestGAP0562SameCallOnAnotherReplicaIsNotFlagged(t *testing.T) {
	a, b, _, onA, onB := gap0342Pair(t)
	for _, tc := range []struct{ id, cmd string }{
		{"toolu_bash", "echo livegate-benign"},
		{"toolu_ls", "ls -la"},
	} {
		onA()
		if got := a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "lg555", tc.id, tc.cmd)); got.Action != "allow" || len(got.RuleIDs) != 0 {
			t.Fatalf("%s on replica A: %q %v", tc.cmd, got.Action, got.RuleIDs)
		}
		onB()
		got := b.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "lg555", tc.id, tc.cmd))
		if got.Action != "allow" || len(got.RuleIDs) != 0 || got.Reason != "" {
			t.Fatalf("%s delivered again on replica B: action %q severity %q rules %v reason %q, want the silent allow replica A gave",
				tc.cmd, got.Action, got.Severity, got.RuleIDs, got.Reason)
		}
		// Its result joins the call on either replica.
		if got := b.hook(t, "tok-alice", gap0342OK("lg555", tc.id, tc.cmd, "ok\n")); slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
			t.Fatalf("%s: the result of the call delivered twice is unrecorded: %v", tc.cmd, got.RuleIDs)
		}
	}
}

// A fresh replica (a pod started after the restart) gets the call again.
func TestGAP0562SameCallOnAFreshReplicaIsNotFlagged(t *testing.T) {
	a, _, chains, onA, _ := gap0342Pair(t)
	onA()
	a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "lg555", "toolu_read", "cat README.md"))
	fresh := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, a.f.regs })}
	fresh.f.api.store, fresh.f.api.logger = testStoreAndV8Logger(t)
	if got := fresh.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "lg555", "toolu_read", "cat README.md")); got.Action != "allow" || len(got.RuleIDs) != 0 {
		t.Fatalf("the same call on a fresh replica: action %q rules %v reason %q", got.Action, got.RuleIDs, got.Reason)
	}
}

// The security properties stay: a secret read delivered twice is still a
// read whose upload is refused, and a reused invocation ID with another
// command still voids the proposal and is reported unrecorded.
func TestGAP0562RedeliveryKeepsTheChainAndAReusedIDStaysFlagged(t *testing.T) {
	a, b, chains, onA, onB := gap0342Pair(t)
	read := "cat ~/.aws/credentials"
	onA()
	a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", read))
	onB()
	if got := b.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", read)); slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("the secret read delivered again is unrecorded: %v", got.RuleIDs)
	}
	onA()
	a.hook(t, "tok-alice", gap0342OK("s1", "read-1", read, "[default]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"))
	v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
		Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST"})
	if err != nil || !v.Deny {
		t.Fatalf("egress after the secret read delivered twice: %+v %v, want refused", v, err)
	}
	a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s2", "reuse-1", "echo first"))
	onB()
	if got := b.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s2", "reuse-1", "echo second")); !slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
		t.Fatalf("a reused invocation ID with another command: rules %v, want %s", got.RuleIDs, substrateChainUnrecordedRule)
	}
}
