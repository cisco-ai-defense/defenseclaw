// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"testing"
)

type gateRecorder struct {
	fakeAdmin
	managed *bool
}

func (g gateRecorder) Gate(_ AdminVerdict, _ GateTarget, managed bool) *DenyReason {
	*g.managed = managed
	return nil
}

// TestDecideEnforcedAdminVerdictOnOSS: an enforced verdict (an Agent
// Substrate actor call on a cluster gateway) refuses and gates on an OSS
// engine as on a managed one (D4-1); a laptop verdict on OSS does not.
func TestDecideEnforcedAdminVerdictOnOSS(t *testing.T) {
	deny := &DenyReason{Code: "rule_deny:ctr"}
	oss := mustEngine(t, testConfig(), Options{Admin: fakeAdmin{verdict: AdminVerdict{Deny: deny, Enforce: true}}})
	if d := oss.Decide(context.Background(), chat("refactor")); d.Outcome != OutcomeDenied || d.Deny != deny {
		t.Fatalf("enforced deny on OSS = %+v", d)
	}
	var got bool
	rec := mustEngine(t, testConfig(), Options{Admin: gateRecorder{fakeAdmin: fakeAdmin{verdict: AdminVerdict{Enforce: true}}, managed: &got}})
	rec.Gate(rec.Decide(context.Background(), chat("refactor")), GateTarget{Provider: "anthropic", Model: "claude"})
	if !got {
		t.Fatal("an enforced verdict must gate as managed on OSS")
	}
	plain := mustEngine(t, testConfig(), Options{Admin: gateRecorder{managed: &got}})
	plain.Gate(plain.Decide(context.Background(), chat("refactor")), GateTarget{Provider: "anthropic", Model: "claude"})
	if got {
		t.Fatal("a laptop verdict on OSS must gate unmanaged")
	}
}
