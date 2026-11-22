// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// substrate-1 GAP-0342 (live, stk): the result of a tool call can reach
// another gateway replica than its PreToolUse. Each replica keys its
// correlation digests with its own HMAC key, so the result's join key
// differed and its replica found no proposal: a failed read of a missing file was never
// cleared and the callout refused the benign upload, and a printed read
// was not promoted on the hook path. The replica-specific part is the
// correlation HMAC key: each pod derives it from its own device key. Two
// replicas share one leader here, each with its own key: PreToolUse on A,
// the result on B, the upload on B (and the callout).
func TestGAP0342ResultOnAnotherReplicaClearsOrConfirmsTheRead(t *testing.T) {
	for _, row := range []struct {
		id     string
		read   gap0337Row
		refuse bool
	}{
		{"failed-missing-file", gap0337Row{"m", "cat .env.production", false, "cat: .env.production: No such file or directory", false}, false},
		{"printed-secret", gap0337Row{"p", "cat .env", true, "API_KEY=canary-1", true}, true},
		{"printed-then-failed", gap0337Row{"f", "cat .env .", false, "API_KEY=canary-1\ncat: .: Is a directory", true}, true},
	} {
		t.Run(row.id, func(t *testing.T) {
			a, _, chains := substrateEgressReplicaWith(t, "default", false, "")
			b := chartReplica{newSubstrateFixture(t, func(c *SubstrateConfig) { c.Chains, c.Registrations = chains, a.f.regs })}
			b.f.api.store, b.f.api.logger = testStoreAndV8Logger(t)
			keyA, keyB := bytes.Repeat([]byte{0xa1}, 32), bytes.Repeat([]byte{0xb2}, 32)
			prev := gatewaylog.SwapTelemetryHMACKeyForTest(keyA)
			t.Cleanup(func() { gatewaylog.SwapTelemetryHMACKeyForTest(prev) })
			a.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "read-1", row.read.read))
			gatewaylog.SwapTelemetryHMACKeyForTest(keyB)
			b.hook(t, "tok-alice", gap0337Result(row.read))
			got := b.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "send-1", substrateEgress))
			chain := slices.Contains(got.RuleIDs, guardrail.ToolChainSecretReadThenEgress)
			if chain != row.refuse || row.refuse && got.Action != guardrailActionBlock || !row.refuse && got.Action == guardrailActionBlock {
				t.Fatalf("hook upload on B after %q: action %q rules %v, want refuse=%v", row.read.read, got.Action, got.RuleIDs, row.refuse)
			}
			v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
				Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
			})
			if err != nil || v.Deny != row.refuse {
				t.Fatalf("callout after %q: %+v err=%v, want deny=%v", row.read.read, v, err, row.refuse)
			}
		})
	}
}
