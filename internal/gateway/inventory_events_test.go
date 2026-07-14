// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// withManagedEnterprise flips the process-wide managed gate on for the
// duration of a test and restores it afterwards.
func withManagedEnterprise(t *testing.T, on bool) {
	t.Helper()
	prev := ManagedEnterpriseActive()
	SetManagedEnterpriseActive(on)
	t.Cleanup(func() { SetManagedEnterpriseActive(prev) })
}

func eventsOfType(events []gatewaylog.Event, et gatewaylog.EventType) []gatewaylog.Event {
	var out []gatewaylog.Event
	for _, e := range events {
		if e.EventType == et {
			out = append(out, e)
		}
	}
	return out
}

// TestEmitEndpointInventory_ManagedEmitsConnectorAndMCP verifies that in
// managed_enterprise the connector + MCP endpoint inventory is shipped as
// discovery events, carries the device anchor, and validates against the
// gateway-event schema.
func TestEmitEndpointInventory_ManagedEmitsConnectorAndMCP(t *testing.T) {
	withManagedEnterprise(t, true)
	events := withCapturedEvents(t)
	SetEndpointInventoryAnchor("device-fingerprint-abc")

	reg := connector.NewDefaultRegistry()
	EmitEndpointInventory(context.Background(), &config.Config{}, reg)

	connEvents := eventsOfType(*events, gatewaylog.EventConnectorInventory)
	if len(connEvents) != 1 {
		t.Fatalf("expected 1 connector_inventory event, got %d", len(connEvents))
	}
	ci := connEvents[0].ConnectorInventory
	if ci == nil || ci.Count == 0 || len(ci.Connectors) != ci.Count {
		t.Fatalf("connector_inventory payload malformed: %+v", ci)
	}
	if ci.DeviceID != "device-fingerprint-abc" {
		t.Fatalf("connector_inventory missing device anchor: %+v", ci)
	}

	mcpEvents := eventsOfType(*events, gatewaylog.EventMCPInventory)
	if len(mcpEvents) != 1 {
		t.Fatalf("expected 1 mcp_inventory event, got %d", len(mcpEvents))
	}
	if mcpEvents[0].MCPInventory == nil {
		t.Fatalf("mcp_inventory payload nil")
	}

	// Every emitted inventory event must satisfy the envelope schema
	// (new event types + payload $defs).
	validator, err := gatewaylog.NewDefaultValidator()
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	for _, e := range append(connEvents, mcpEvents...) {
		if err := validator.Validate(e); err != nil {
			t.Fatalf("inventory event failed schema validation: %v\nevent=%+v", err, e)
		}
	}
}

// TestEmitEndpointInventory_NoOpWhenNotManaged pins that no inventory
// events are emitted outside managed_enterprise.
func TestEmitEndpointInventory_NoOpWhenNotManaged(t *testing.T) {
	withManagedEnterprise(t, false)
	events := withCapturedEvents(t)

	EmitEndpointInventory(context.Background(), &config.Config{}, connector.NewDefaultRegistry())

	if got := len(*events); got != 0 {
		t.Fatalf("non-managed must not emit inventory events, got %d: %+v", got, *events)
	}
}

// TestEmitAgentInventory_ManagedShipsSanitizedRoster verifies the
// agent_inventory event is built from the validated report, carries the
// device anchor + installed count, and validates against the schema.
func TestEmitAgentInventory_ManagedShipsSanitizedRoster(t *testing.T) {
	withManagedEnterprise(t, true)
	events := withCapturedEvents(t)
	SetEndpointInventoryAnchor("device-xyz")

	report := &agentDiscoveryReport{
		Source:    "cli",
		ScannedAt: "2026-07-11T00:00:00Z",
		Agents: map[string]agentDiscoverySignal{
			"cursor": {
				Installed:      true,
				HasConfig:      true,
				ConfigBasename: "config.json",
				HasBinary:      true,
				BinaryBasename: "cursor",
				Version:        "1.2.3",
			},
			"codex": {Installed: false},
		},
	}
	a := &APIServer{}
	a.emitAgentInventory(context.Background(), report, 1)

	agentEvents := eventsOfType(*events, gatewaylog.EventAgentInventory)
	if len(agentEvents) != 1 {
		t.Fatalf("expected 1 agent_inventory event, got %d", len(agentEvents))
	}
	ai := agentEvents[0].AgentInventory
	if ai == nil || ai.Count != 2 || ai.Installed != 1 {
		t.Fatalf("agent_inventory payload malformed: %+v", ai)
	}
	if ai.DeviceID != "device-xyz" || ai.Source != "cli" {
		t.Fatalf("agent_inventory missing anchor/source: %+v", ai)
	}

	validator, err := gatewaylog.NewDefaultValidator()
	if err != nil {
		t.Fatalf("validator: %v", err)
	}
	if err := validator.Validate(agentEvents[0]); err != nil {
		t.Fatalf("agent_inventory failed schema validation: %v", err)
	}
}

// TestEmitAgentInventory_NoOpWhenNotManaged pins the managed gate on the
// agent inventory path.
func TestEmitAgentInventory_NoOpWhenNotManaged(t *testing.T) {
	withManagedEnterprise(t, false)
	events := withCapturedEvents(t)

	report := &agentDiscoveryReport{
		Source:    "cli",
		ScannedAt: "2026-07-11T00:00:00Z",
		Agents:    map[string]agentDiscoverySignal{"cursor": {Installed: true}},
	}
	a := &APIServer{}
	a.emitAgentInventory(context.Background(), report, 1)

	if got := len(eventsOfType(*events, gatewaylog.EventAgentInventory)); got != 0 {
		t.Fatalf("non-managed must not emit agent_inventory, got %d", got)
	}
}

// TestMCPRedactionHelpers pins the redaction-safe reduction of MCP
// command / URL to a basename / host so the inventory never leaks local
// paths or URL query material (which can embed tokens).
func TestMCPRedactionHelpers(t *testing.T) {
	t.Parallel()
	cases := []struct {
		cmd, wantCmd string
		url, wantURL string
	}{
		{"/usr/local/bin/mcp-server", "mcp-server", "https://mcp.example.com/v1?token=secret", "mcp.example.com"},
		{"node", "node", "", ""},
		{"", "", "http://host:8080/path", "host:8080"},
	}
	for _, c := range cases {
		if got := mcpCommandBasename(c.cmd); got != c.wantCmd {
			t.Errorf("mcpCommandBasename(%q) = %q, want %q", c.cmd, got, c.wantCmd)
		}
		if got := mcpURLHost(c.url); got != c.wantURL {
			t.Errorf("mcpURLHost(%q) = %q, want %q", c.url, got, c.wantURL)
		}
	}
}
