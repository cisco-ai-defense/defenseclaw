// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
)

// TestSubstrateChainEgressActionFromConfigGAP0250: the leader takes the
// chain egress action from config substrate.chain_egress_action, its one
// source (default block).
func TestSubstrateChainEgressActionFromConfigGAP0250(t *testing.T) {
	alert := &config.Config{Substrate: config.SubstrateConfig{ChainEgressAction: "Alert"}}
	for _, tc := range []struct {
		name         string
		cfg          *config.Config
		want, source string
	}{
		{"no config", nil, chainstate.EgressBlock, "default"},
		{"unset", &config.Config{}, chainstate.EgressBlock, "default"},
		{"config alert", alert, chainstate.EgressAlert, "config substrate.chain_egress_action"},
	} {
		if a, s := substrateChainEgressAction(tc.cfg); a != tc.want || s != tc.source {
			t.Errorf("%s: %q from %q, want %q from %q", tc.name, a, s, tc.want, tc.source)
		}
	}
}

// The serve command has no --chain-egress-action flag: the config key is the
// one source (GAP-0250; the flag never shipped).
func TestServeHasNoChainEgressActionFlagGAP0250(t *testing.T) {
	if f := serveCmd.Flags().Lookup("chain-egress-action"); f != nil {
		t.Fatalf("serve still registers --chain-egress-action (%s)", f.Usage)
	}
}
