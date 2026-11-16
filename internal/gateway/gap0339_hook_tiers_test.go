// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// substrate-1 GAP-0339, the 1.0.10 lead's ruling (STEER 2026-11-16): a tool
// step that can't be recorded in the actor's chain window is reported
// (SUBSTRATE-CHAIN-UNRECORDED) and, at the hook, alerts in the open source
// default and permissive packs and refuses only in managed and strict
// (balanced defaults). The leader keeps it for the callout, which refuses
// where it refuses unchecked egress.
func TestGAP0339UnrecordedStepAtTheHookAlertsInDefaultAndPermissive(t *testing.T) {
	for _, tc := range []struct {
		name, pack string
		managed    bool
		block      bool
	}{
		{"default", "default", false, false},
		{"permissive", "permissive", false, false},
		{"strict", "strict", false, true},
		{"managed", "default", true, true},
		{"managed-strict", "strict", true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, _, chains := substrateEgressReplicaWith(t, tc.pack, tc.managed, "")
			orig := toolChainRulesetFingerprint
			toolChainRulesetFingerprint = func(context.Context, string, connector.HookProfile) (string, error) {
				return "", errors.New("lifecycle not encodable")
			}
			t.Cleanup(func() { toolChainRulesetFingerprint = orig })
			got := r.hook(t, "tok-alice", claudeToolEvent("PreToolUse", "s1", "list-1", "ls -la"))
			if !slices.Contains(got.RuleIDs, substrateChainUnrecordedRule) {
				t.Fatalf("hook: %+v, want %s", got, substrateChainUnrecordedRule)
			}
			if blocked := got.Action == guardrailActionBlock; blocked != tc.block {
				t.Fatalf("hook action %q, want block=%v", got.Action, tc.block)
			}
			if !tc.block && got.Action != guardrailActionAlert {
				t.Fatalf("hook action %q, want alert", got.Action)
			}
			v, err := chains.CheckEgress(context.Background(), chainstate.EgressRequest{
				Actor: chainstate.Actor{Atespace: "eng-web", UID: subUID1}, Host: "github.com", Method: "POST",
			})
			if err != nil || !strings.Contains(v.Unrecorded, "fingerprinted") {
				t.Fatalf("callout verdict %+v err=%v, want the unrecorded step with its reason", v, err)
			}
		})
	}
}
