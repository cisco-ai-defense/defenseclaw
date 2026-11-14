// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// GAP-0250: substrate.chain_egress_action is block by default, alert when
// set, and anything else is refused at load.
func TestSubstrateChainEgressActionGAP0250(t *testing.T) {
	if got := (SubstrateConfig{}).EffectiveChainEgressAction(); got != SubstrateChainEgressBlock {
		t.Fatalf("default %q", got)
	}
	if got := (SubstrateConfig{ChainEgressAction: " ALERT "}).EffectiveChainEgressAction(); got != SubstrateChainEgressAlert {
		t.Fatalf("alert %q", got)
	}
	for _, v := range []string{"", "block", "alert"} {
		if err := (&SubstrateConfig{ChainEgressAction: v}).Validate(); err != nil {
			t.Errorf("%q refused: %v", v, err)
		}
	}
	if err := (&SubstrateConfig{ChainEgressAction: "warn"}).Validate(); err == nil {
		t.Error("warn accepted")
	}
}
