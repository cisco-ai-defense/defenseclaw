// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/flow"
)

// TestSecretFlowLaneMode folds the rollout key (effects_rules) and the feature
// switch (secret_flow.mode) into one effective mode. The lane participates
// only when both are on; the default is shadow.
func TestSecretFlowLaneMode(t *testing.T) {
	mk := func(rollout, mode string) config.GuardrailConfig {
		g := config.GuardrailConfig{EffectsRules: rollout}
		g.SecretFlow.Mode = mode
		return g
	}
	for _, tc := range []struct {
		rollout, mode string
		want          flowLaneMode
	}{
		{"off", "on", flowLaneOff},     // effect lane off disables flow entirely
		{"off", "shadow", flowLaneOff},
		{"shadow", "off", flowLaneOff}, // feature switch off
		{"shadow", "shadow", flowLaneShadow},
		{"shadow", "on", flowLaneShadow}, // rollout not on yet -> stays shadow
		{"on", "shadow", flowLaneShadow},
		{"on", "on", flowLaneOn},
		{"shadow", "", flowLaneShadow}, // unset mode defaults to shadow
	} {
		if got := secretFlowLaneMode(mk(tc.rollout, tc.mode)); got != tc.want {
			t.Fatalf("rollout=%s mode=%s => %s, want %s", tc.rollout, tc.mode, got, tc.want)
		}
	}
}

// TestFlowShadowFindings: a clean verdict carries nothing; an alert verdict is
// alert-only and non-authoritative in shadow; a block verdict in on is
// authoritative and contributes to enforcement.
func TestFlowShadowFindings(t *testing.T) {
	if fs := flowShadowFindings(flow.Result{Action: flow.ActionAllow}, flowLaneShadow); fs != nil {
		t.Fatalf("allow carried a finding: %v", fs)
	}
	alert := flow.Result{Action: flow.ActionAlert, Hits: []flow.Hit{{Kind: flow.HitLabeledFile, Sets: []string{"credentials"}, Host: "evil.example"}}}
	fs := flowShadowFindings(alert, flowLaneShadow)
	if len(fs) != 1 {
		t.Fatalf("alert findings = %d, want 1", len(fs))
	}
	f := fs[0]
	if f.RuleID != flow.RuleIDEgress || f.disposition != findingDispositionFlowSecretEgress {
		t.Fatalf("finding rule/disposition wrong: %q %v", f.RuleID, f.disposition)
	}
	if f.enforcement != findingEnforcementAlertOnly {
		t.Fatalf("alert finding not alert-only: %v", f.enforcement)
	}
	if f.proof.authoritative {
		t.Fatalf("shadow finding must not be authoritative")
	}
	block := flow.Result{Action: flow.ActionBlock, Hits: []flow.Hit{{Kind: flow.HitValueMatch, Sets: []string{"value"}}}}
	fb := flowShadowFindings(block, flowLaneOn)
	if len(fb) != 1 || fb[0].enforcement != findingEnforcementInherit || !fb[0].proof.authoritative {
		t.Fatalf("on block finding wrong: %+v", fb)
	}
}

// TestFlowSessionStoreBounded proves the session store stays at its cap.
func TestFlowSessionStoreBounded(t *testing.T) {
	store := newFlowSessionStore(32)
	cfg := flow.Config{MaxLabeledPaths: 16, MaxValueDigests: 16}
	for i := 0; i < 1000; i++ {
		store.session(sessionKey(i), cfg)
	}
	store.mu.Lock()
	n := len(store.m)
	store.mu.Unlock()
	if n > 32 {
		t.Fatalf("session store = %d, exceeds cap 32", n)
	}
}

func sessionKey(i int) string {
	const hex = "0123456789abcdef"
	b := []byte("sess-00000000")
	for j := 0; j < 8; j++ {
		b[5+j] = hex[(i>>(uint(j)*4))&0xf]
	}
	return string(b)
}
