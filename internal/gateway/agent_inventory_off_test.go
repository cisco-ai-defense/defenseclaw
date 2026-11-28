// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Outside Secure Client every endpoint inventory collection follows
// ai_discovery.enabled. Before GAP-1836 an agent discovery request still sent
// the agent inventory with ai_discovery off.
func TestAgentInventoryOutsideSecureClientFollowsAIDiscovery(t *testing.T) {
	withManagedEnterprise(t, false)
	capture := &endpointInventoryCapture{}
	api := &APIServer{observabilityV8: capture, scannerCfg: &config.Config{}}
	if err := api.emitManagedAgentInventory(t.Context(), &agentDiscoveryReport{
		Source: "cli", ScannedAt: "2026-07-11T00:00:00Z",
		Agents: map[string]agentDiscoverySignal{"codex": {Installed: true}},
	}, 1, false); err != nil {
		t.Fatal(err)
	}
	if records := capture.snapshot(); len(records) != 0 {
		t.Fatalf("agent inventory sent with ai_discovery off: %d records", len(records))
	}
}
