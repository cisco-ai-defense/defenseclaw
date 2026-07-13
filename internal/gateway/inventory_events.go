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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// endpointInventoryAnchor is the process-wide device.id / host.name pair
// stamped onto discovery-inventory event bodies. It duplicates the
// resource-level defenseclaw.device.id / host.name so AI Defense can bind
// an inventory event to its endpoint whether it keys on the resource or
// the body. Set once by the sidecar boot path (SetEndpointInventoryAnchor)
// after the device identity is loaded.
var endpointInventoryAnchor struct {
	deviceID string
	hostname string
}

// SetEndpointInventoryAnchor records the endpoint device anchor used by
// the discovery-inventory emitters. Hostname is resolved here so callers
// only need to pass the device fingerprint.
func SetEndpointInventoryAnchor(deviceID string) {
	gatewayEventsMu.Lock()
	defer gatewayEventsMu.Unlock()
	endpointInventoryAnchor.deviceID = deviceID
	if h, err := os.Hostname(); err == nil {
		endpointInventoryAnchor.hostname = h
	}
}

func inventoryAnchor() (deviceID, hostname string) {
	gatewayEventsMu.RLock()
	defer gatewayEventsMu.RUnlock()
	return endpointInventoryAnchor.deviceID, endpointInventoryAnchor.hostname
}

// EmitEndpointInventory ships the endpoint's connector + MCP-server
// inventory to the event fanout (and thus the managed AID sink) as
// discovery events. It is a no-op outside managed_enterprise and when no
// event writer is installed. Called at boot, on config reload, and on
// each AI-discovery scan cycle so AI Defense always has a current
// snapshot. Installed coding agents are emitted separately, inline at
// agent-discovery ingest time (emitAgentInventory).
func EmitEndpointInventory(ctx context.Context, cfg *config.Config, reg *connector.Registry) {
	if !ManagedEnterpriseActive() || EventWriter() == nil {
		return
	}
	deviceID, hostname := inventoryAnchor()
	emitConnectorInventory(ctx, reg, deviceID, hostname)
	emitMCPInventory(ctx, cfg, deviceID, hostname)
}

// makeEndpointInventoryEmitter returns a closure that (re)builds the
// connector registry from cfg and emits the connector + MCP endpoint
// inventory. The sidecar installs it as the AI-discovery scan-cadence
// hook and also invokes it directly at boot and on config reload, so the
// captured cfg is always the currently-active config for that call site
// (config reload rebuilds the closure with the new config).
func makeEndpointInventoryEmitter(cfg *config.Config) func(context.Context) {
	return func(ctx context.Context) {
		reg := connector.NewDefaultRegistry()
		if cfg != nil && cfg.PluginDir != "" {
			// Best-effort: a broken plugin dir must not stop the
			// built-in connector inventory from shipping.
			_ = reg.DiscoverPlugins(cfg.PluginDir)
		}
		EmitEndpointInventory(ctx, cfg, reg)
	}
}

func emitConnectorInventory(ctx context.Context, reg *connector.Registry, deviceID, hostname string) {
	if reg == nil {
		reg = getFallbackConnectorRegistry()
	}
	if reg == nil {
		return
	}
	avail := reg.Available()
	items := make([]gatewaylog.ConnectorInventoryItem, 0, len(avail))
	for _, info := range avail {
		items = append(items, gatewaylog.ConnectorInventoryItem{
			Name:               info.Name,
			Description:        info.Description,
			Source:             info.Source,
			ToolInspectionMode: string(info.ToolInspectionMode),
			SubprocessPolicy:   string(info.SubprocessPolicy),
		})
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventConnectorInventory,
		Severity:  gatewaylog.SeverityInfo,
		ConnectorInventory: &gatewaylog.ConnectorInventoryPayload{
			DeviceID:   deviceID,
			Hostname:   hostname,
			Count:      len(items),
			Connectors: items,
		},
	})
}

func emitMCPInventory(ctx context.Context, cfg *config.Config, deviceID, hostname string) {
	if cfg == nil {
		return
	}
	servers, err := cfg.ReadMCPServers()
	if err != nil {
		// Missing / unreadable MCP config is a normal steady state
		// (no servers configured). Still emit an empty inventory so
		// AI Defense can distinguish "scanned, none present" from
		// "never reported".
		servers = nil
	}
	items := make([]gatewaylog.MCPInventoryItem, 0, len(servers))
	for _, s := range servers {
		items = append(items, gatewaylog.MCPInventoryItem{
			Name:         s.Name,
			Transport:    s.Transport,
			Command:      mcpCommandBasename(s.Command),
			URLHost:      mcpURLHost(s.URL),
			AuthProvider: s.AuthProviderType,
			Disabled:     s.Disabled,
		})
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventMCPInventory,
		Severity:  gatewaylog.SeverityInfo,
		MCPInventory: &gatewaylog.MCPInventoryPayload{
			DeviceID: deviceID,
			Hostname: hostname,
			Count:    len(items),
			Servers:  items,
		},
	})
}

// mcpCommandBasename strips a local MCP command down to its basename so
// the inventory never leaks a local filesystem path. Args are never
// included.
func mcpCommandBasename(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	return filepath.Base(cmd)
}

// mcpURLHost extracts just the host from a remote MCP server URL so the
// inventory never carries path or query material (which can embed tokens).
func mcpURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	if u, err := url.Parse(raw); err == nil && u.Host != "" {
		return u.Host
	}
	return ""
}

// emitAgentInventory ships the endpoint's installed coding-agent roster
// as an agent_inventory discovery event, built from the already-validated
// (sanitized) agentDiscoveryReport. No-op outside managed_enterprise or
// when no event writer is installed.
func (a *APIServer) emitAgentInventory(ctx context.Context, report *agentDiscoveryReport, installed int) {
	if report == nil || !ManagedEnterpriseActive() || EventWriter() == nil {
		return
	}
	deviceID, hostname := inventoryAnchor()
	items := make([]gatewaylog.AgentInventoryItem, 0, len(report.Agents))
	for name, sig := range report.Agents {
		items = append(items, gatewaylog.AgentInventoryItem{
			Name:               name,
			Installed:          sig.Installed,
			HasConfig:          sig.HasConfig,
			ConfigBasename:     sig.ConfigBasename,
			ConfigPathHash:     sig.ConfigPathHash,
			HasBinary:          sig.HasBinary,
			BinaryBasename:     sig.BinaryBasename,
			BinaryPathHash:     sig.BinaryPathHash,
			Version:            sig.Version,
			VersionProbeStatus: normalizeDiscoveryProbeStatus(sig.VersionProbeStatus),
		})
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType: gatewaylog.EventAgentInventory,
		Severity:  gatewaylog.SeverityInfo,
		AgentInventory: &gatewaylog.AgentInventoryPayload{
			DeviceID:  deviceID,
			Hostname:  hostname,
			Source:    discoverySourceOrUnknown(report.Source),
			ScannedAt: report.ScannedAt,
			Count:     len(items),
			Installed: installed,
			Agents:    items,
		},
	})
}
