// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// TestSubstrateChainEgressActionFromConfigGAP0250: the leader takes the
// chain egress action from config substrate.chain_egress_action (default
// block); the deprecated flag wins when set, and says so.
func TestSubstrateChainEgressActionFromConfigGAP0250(t *testing.T) {
	alert := &config.Config{Substrate: config.SubstrateConfig{ChainEgressAction: "Alert"}}
	for _, tc := range []struct {
		name         string
		cfg          *config.Config
		flag         string
		want, source string
	}{
		{"no config", nil, "", chainstate.EgressBlock, "default"},
		{"unset", &config.Config{}, "", chainstate.EgressBlock, "default"},
		{"config alert", alert, "", chainstate.EgressAlert, "config substrate.chain_egress_action"},
		{"flag wins", alert, "block", chainstate.EgressBlock, "--chain-egress-action, a deprecated alias of config substrate.chain_egress_action"},
	} {
		if a, s := substrateChainEgressAction(tc.cfg, tc.flag); a != tc.want || s != tc.source {
			t.Errorf("%s: %q from %q, want %q from %q", tc.name, a, s, tc.want, tc.source)
		}
	}
}
