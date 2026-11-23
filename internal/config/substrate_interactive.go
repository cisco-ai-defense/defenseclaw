// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"strconv"
	"strings"
	"time"
)

// SubstrateInteractiveConfig is substrate.interactive (B3): the streams an
// actor's owner opens through attach next to the terminal. Each switch is
// auto, on or off; off is the admin's switch for a managed install. The
// gateway reads these keys on every stream it opens (hot), and checks the
// open streams once a minute (or each quarter of idle_close, if sooner): a
// switch set to off, or a port taken out of ports, closes the streams
// already open at that check, so up to a minute later (GAP-0863).
type SubstrateInteractiveConfig struct {
	PortForward SubstratePortForwardConfig `mapstructure:"port_forward" yaml:"port_forward,omitempty"`
	MCPBridge   SubstrateMCPBridgeConfig   `mapstructure:"mcp_bridge"   yaml:"mcp_bridge,omitempty"`
	// IdleClose closes a forward or bridge that moved no bytes for this
	// long ("" = DefaultSubstrateIdleClose).
	IdleClose string `mapstructure:"idle_close" yaml:"idle_close,omitempty"`
}

// SubstratePortForwardConfig is substrate.interactive.port_forward
// (`defenseclaw substrate port`).
type SubstratePortForwardConfig struct {
	// Enabled is auto (default: on in open source and managed), on or off.
	Enabled string `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// Ports is the actor ports a forward may reach: "1024-65535"
	// (default) or a list such as "3000,8000-8999". Ports below 1024 and
	// the actor relay's own port (SubstrateRelayPort) are never forwarded.
	Ports string `mapstructure:"ports" yaml:"ports,omitempty"`
	// MaxStreams caps open forwarded connections per actor on each
	// gateway replica (0 = 32).
	MaxStreams int `mapstructure:"max_streams" yaml:"max_streams,omitempty"`
}

// SubstrateMCPBridgeConfig is substrate.interactive.mcp_bridge
// (`defenseclaw substrate run --mcp`).
type SubstrateMCPBridgeConfig struct {
	// Enabled is auto (default: on in open source, off in managed), on or off.
	Enabled string `mapstructure:"enabled" yaml:"enabled,omitempty"`
	// MaxServers caps bridged servers per actor on each gateway replica
	// (0 = 4).
	MaxServers int `mapstructure:"max_servers" yaml:"max_servers,omitempty"`
	// MessageMaxBytes refuses (never cuts) a bigger JSON-RPC message
	// (0 = 1 MiB).
	MessageMaxBytes int64 `mapstructure:"message_max_bytes" yaml:"message_max_bytes,omitempty"`
}

// Values of the substrate.interactive switches.
const (
	SubstrateSwitchAuto = "auto"
	SubstrateSwitchOn   = "on"
	SubstrateSwitchOff  = "off"
)

// Defaults and bounds of substrate.interactive.
const (
	DefaultSubstratePorts = "1024-65535"
	// SubstrateRelayPort is the actor relay's own port (the kit's
	// relay.listen ":8080"): a forward never reaches it.
	SubstrateRelayPort               = 8080
	DefaultSubstrateMaxStreams       = 32
	MaxSubstrateMaxStreams           = 1024
	DefaultSubstrateMaxServers       = 4
	MaxSubstrateMaxServers           = 32
	DefaultSubstrateMessageMaxBytes  = int64(1 << 20)
	MaxSubstrateMessageMaxBytes      = int64(16 << 20)
	DefaultSubstrateIdleClose        = 30 * time.Minute
	minSubstrateIdleClose            = time.Minute
	maxSubstrateIdleClose            = 24 * time.Hour
	substrateInteractiveSwitchValues = "auto, on or off"
)

func substrateSwitch(v string) string {
	if v = strings.ToLower(strings.TrimSpace(v)); v != "" {
		return v
	}
	return SubstrateSwitchAuto
}

// PortForwardOn reports whether port forwards are allowed: auto is on in
// open source and in managed installs (D3-1); off is the admin switch.
func (c SubstrateInteractiveConfig) PortForwardOn() bool {
	return substrateSwitch(c.PortForward.Enabled) != SubstrateSwitchOff
}

// MCPBridgeOn reports whether MCP bridges are allowed: auto is on in open
// source and off in managed installs (D3-2); on and off are explicit.
func (c SubstrateInteractiveConfig) MCPBridgeOn(managed bool) bool {
	switch substrateSwitch(c.MCPBridge.Enabled) {
	case SubstrateSwitchOn:
		return true
	case SubstrateSwitchOff:
		return false
	}
	return !managed
}

// PortRange is one inclusive range of substrate.interactive.port_forward.ports.
type PortRange struct{ Lo, Hi int }

// ParsePortRanges reads a port list such as "3000,8000-8999".
func ParsePortRanges(v string) ([]PortRange, error) {
	var out []PortRange
	for _, part := range strings.Split(v, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		lo, hi, isRange := strings.Cut(part, "-")
		if !isRange {
			hi = lo
		}
		l, err1 := strconv.Atoi(strings.TrimSpace(lo))
		h, err2 := strconv.Atoi(strings.TrimSpace(hi))
		if err1 != nil || err2 != nil || l < 1024 || h > 65535 || l > h {
			return nil, fmt.Errorf("%q is not a port or a lo-hi range within 1024-65535", part)
		}
		out = append(out, PortRange{Lo: l, Hi: h})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%q names no port", v)
	}
	return out, nil
}

// PortAllowed reports whether a forward may reach port. A list that does
// not parse allows nothing (Validate refuses it at load).
func (c SubstrateInteractiveConfig) PortAllowed(port int) bool {
	if port == SubstrateRelayPort {
		return false
	}
	v := strings.TrimSpace(c.PortForward.Ports)
	if v == "" {
		v = DefaultSubstratePorts
	}
	ranges, err := ParsePortRanges(v)
	if err != nil {
		return false
	}
	for _, r := range ranges {
		if port >= r.Lo && port <= r.Hi {
			return true
		}
	}
	return false
}

// EffectiveMaxStreams is port_forward.max_streams, 32 when unset.
func (c SubstrateInteractiveConfig) EffectiveMaxStreams() int {
	if c.PortForward.MaxStreams > 0 {
		return c.PortForward.MaxStreams
	}
	return DefaultSubstrateMaxStreams
}

// EffectiveMaxServers is mcp_bridge.max_servers, 4 when unset.
func (c SubstrateInteractiveConfig) EffectiveMaxServers() int {
	if c.MCPBridge.MaxServers > 0 {
		return c.MCPBridge.MaxServers
	}
	return DefaultSubstrateMaxServers
}

// EffectiveMessageMaxBytes is mcp_bridge.message_max_bytes, 1 MiB when unset.
func (c SubstrateInteractiveConfig) EffectiveMessageMaxBytes() int64 {
	if c.MCPBridge.MessageMaxBytes > 0 {
		return c.MCPBridge.MessageMaxBytes
	}
	return DefaultSubstrateMessageMaxBytes
}

// EffectiveIdleClose is interactive.idle_close, 30m when unset.
func (c SubstrateInteractiveConfig) EffectiveIdleClose() time.Duration {
	return durationOr(c.IdleClose, DefaultSubstrateIdleClose)
}

// validate reports each bad substrate.interactive key through bad.
func (c SubstrateInteractiveConfig) validate(bad func(key, format string, a ...any)) {
	for key, v := range map[string]string{"port_forward.enabled": c.PortForward.Enabled, "mcp_bridge.enabled": c.MCPBridge.Enabled} {
		switch substrateSwitch(v) {
		case SubstrateSwitchAuto, SubstrateSwitchOn, SubstrateSwitchOff:
		default:
			bad("interactive."+key, "%q is not %s", v, substrateInteractiveSwitchValues)
		}
	}
	if v := strings.TrimSpace(c.PortForward.Ports); v != "" {
		ranges, err := ParsePortRanges(v)
		if err != nil {
			bad("interactive.port_forward.ports", "%v", err)
		}
		for _, r := range ranges {
			if r.Lo == SubstrateRelayPort && r.Hi == SubstrateRelayPort {
				bad("interactive.port_forward.ports", "%d is the actor relay's own port", SubstrateRelayPort)
			}
		}
	}
	if n := c.PortForward.MaxStreams; n < 0 || n > MaxSubstrateMaxStreams {
		bad("interactive.port_forward.max_streams", "%d is outside 0-%d", n, MaxSubstrateMaxStreams)
	}
	if n := c.MCPBridge.MaxServers; n < 0 || n > MaxSubstrateMaxServers {
		bad("interactive.mcp_bridge.max_servers", "%d is outside 0-%d", n, MaxSubstrateMaxServers)
	}
	if n := c.MCPBridge.MessageMaxBytes; n < 0 || n > MaxSubstrateMessageMaxBytes {
		bad("interactive.mcp_bridge.message_max_bytes", "%d is outside 0-%d", n, MaxSubstrateMessageMaxBytes)
	}
	if v := c.IdleClose; v != "" {
		if d, err := time.ParseDuration(strings.TrimSpace(v)); err != nil || d < minSubstrateIdleClose || d > maxSubstrateIdleClose {
			bad("interactive.idle_close", "%q must be a Go duration from 1m to 24h", v)
		}
	}
}
