// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestSubstrateInteractiveDefaults: port forward is on in open source and
// managed (D3-1); the MCP bridge is on in open source and off in managed
// (D3-2); off is the admin switch for both.
func TestSubstrateInteractiveDefaults(t *testing.T) {
	var c SubstrateInteractiveConfig
	if !c.PortForwardOn() {
		t.Fatal("port forward auto must be on in open source and managed")
	}
	if !c.MCPBridgeOn(false) || c.MCPBridgeOn(true) {
		t.Fatal("MCP bridge auto must be on in open source and off in managed")
	}
	if c.EffectiveMaxStreams() != 32 || c.EffectiveMaxServers() != 4 ||
		c.EffectiveMessageMaxBytes() != 1<<20 || c.EffectiveIdleClose() != 30*time.Minute {
		t.Fatalf("defaults: %d %d %d %v", c.EffectiveMaxStreams(), c.EffectiveMaxServers(), c.EffectiveMessageMaxBytes(), c.EffectiveIdleClose())
	}
	if c.PortAllowed(1023) || !c.PortAllowed(1024) || !c.PortAllowed(65535) {
		t.Fatal("default ports are 1024-65535")
	}
	// S2B-4: the relay's own port is never forwarded, whatever the list.
	if c.PortAllowed(SubstrateRelayPort) || (SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "8000-8999"}}).PortAllowed(SubstrateRelayPort) {
		t.Fatal("the relay port 8080 must never be allowed")
	}
	c.PortForward.Enabled, c.MCPBridge.Enabled = "off", "OFF"
	if c.PortForwardOn() || c.MCPBridgeOn(false) {
		t.Fatal("off must switch both streams off")
	}
	c.MCPBridge.Enabled = "on"
	if !c.MCPBridgeOn(true) {
		t.Fatal("an admin may switch the MCP bridge on in managed")
	}
	c.PortForward.Ports = "3000, 8000-8001"
	if !c.PortAllowed(3000) || !c.PortAllowed(8001) || c.PortAllowed(8002) || c.PortAllowed(1024) {
		t.Fatal("port list 3000,8000-8001")
	}
}

func TestSubstrateInteractiveValidate(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    SubstrateInteractiveConfig
		key  string
	}{
		{"switch", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Enabled: "yes"}}, "interactive.port_forward.enabled"},
		{"mcp switch", SubstrateInteractiveConfig{MCPBridge: SubstrateMCPBridgeConfig{Enabled: "true"}}, "interactive.mcp_bridge.enabled"},
		{"ports", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "9000-80"}}, "interactive.port_forward.ports"},
		{"port zero", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "0"}}, "interactive.port_forward.ports"},
		{"privileged port", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "22"}}, "interactive.port_forward.ports"},
		{"privileged range", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "3000,80-9000"}}, "interactive.port_forward.ports"},
		{"relay port", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{Ports: "3000,8080"}}, "interactive.port_forward.ports"},
		{"streams", SubstrateInteractiveConfig{PortForward: SubstratePortForwardConfig{MaxStreams: 5000}}, "interactive.port_forward.max_streams"},
		{"servers", SubstrateInteractiveConfig{MCPBridge: SubstrateMCPBridgeConfig{MaxServers: -1}}, "interactive.mcp_bridge.max_servers"},
		{"message", SubstrateInteractiveConfig{MCPBridge: SubstrateMCPBridgeConfig{MessageMaxBytes: 1 << 30}}, "interactive.mcp_bridge.message_max_bytes"},
		{"idle", SubstrateInteractiveConfig{IdleClose: "10s"}, "interactive.idle_close"},
	} {
		s := SubstrateConfig{Interactive: tc.c}
		err := s.Validate()
		if err == nil || !strings.Contains(err.Error(), tc.key) {
			t.Errorf("%s: want an error naming %s, got %v", tc.name, tc.key, err)
		}
	}
	ok := SubstrateConfig{Interactive: SubstrateInteractiveConfig{
		PortForward: SubstratePortForwardConfig{Enabled: "on", Ports: "3000,8000-8999", MaxStreams: 8},
		MCPBridge:   SubstrateMCPBridgeConfig{Enabled: "off", MaxServers: 2, MessageMaxBytes: 65536},
		IdleClose:   "1h",
	}}
	if err := ok.Validate(); err != nil {
		t.Fatalf("a good interactive block: %v", err)
	}
}
