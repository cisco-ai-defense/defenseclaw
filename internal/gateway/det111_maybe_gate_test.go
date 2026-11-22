// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

func TestDET111UnknownEffectTierNeverRaisesLiveFinding(t *testing.T) {
	res := EffectShadowResult{Tier: string(effectTierUnknown), Action: guardrailActionAlert,
		Known: true, Sets: []string{"credentials"}, Program: "multi-effect", Kind: "write", Reach: []string{"R-NAME"}}
	if findings := effectShadowFindings(res, effectRulesOn); len(findings) != 0 {
		t.Fatalf("unknown-tier effect created live findings: %+v", findings)
	}
}
