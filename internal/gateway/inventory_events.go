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
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"math"
	"net/url"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
)

const (
	endpointConnectorInventorySource = "endpoint_connector_inventory"
	endpointMCPInventorySource       = "endpoint_mcp_inventory"
	endpointInventoryDetector        = "endpoint_inventory"
	managedAgentInventoryDetector    = "managed_agent_inventory"
	maxManagedConnectorInventory     = 128
	maxManagedMCPInventory           = 256
)

var (
	endpointInventoryMCPHostPattern = regexp.MustCompile(
		`^([A-Za-z0-9][A-Za-z0-9._:-]*|\[[0-9A-Fa-f:.]+\](:[0-9]+)?)$`,
	)
	endpointInventoryExecutableBasenamePattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9._+@-]*$`,
	)
	endpointInventoryVersionPattern = regexp.MustCompile(
		`^[A-Za-z0-9][A-Za-z0-9 .,_+@():-]*$`,
	)
)

// endpointInventoryComponent is the canonical, redaction-safe projection of
// one endpoint inventory row. The canonical runtime supplies the endpoint
// resource anchor; body-level device IDs and hostnames are deliberately not
// duplicated.
type endpointInventoryComponent struct {
	id                          string
	componentType               string
	signal                      string
	product                     string
	active                      bool
	itemName                    string
	itemDescription             string
	connectorSource             string
	connectorToolInspectionMode string
	connectorSubprocessPolicy   string
	mcpTransport                string
	mcpCommandBasename          string
	mcpURLHost                  string
	mcpAuthProviderType         string
	mcpDisabled                 *bool
	agentConnector              string
	agentInstalled              *bool
	agentHasConfig              *bool
	agentConfigBasename         string
	agentConfigPathHash         string
	agentHasBinary              *bool
	agentBinaryBasename         string
	agentBinaryPathHash         string
	agentVersion                string
	agentProbeStatus            string
	agentScannedAt              string
}

// endpointInventoryCarrier is an atomic, typed snapshot split into parallel
// privacy-homogeneous sections. The central redaction engine can therefore
// apply identifier, metadata, and content policy without flattening mixed
// classes or requiring mutable aggregation at the destination adapter.
type endpointInventoryCarrier struct {
	connectorIdentifiers observability.Optional[observability.TelemetryStructuredDefenseClawInventoryConnectorIdentifiers]
	connectorMetadata    observability.Optional[observability.TelemetryStructuredDefenseClawInventoryConnectorMetadata]
	connectorContent     observability.Optional[observability.TelemetryStructuredDefenseClawInventoryConnectorContent]
	mcpIdentifiers       observability.Optional[observability.TelemetryStructuredDefenseClawInventoryMcpIdentifiers]
	mcpMetadata          observability.Optional[observability.TelemetryStructuredDefenseClawInventoryMcpMetadata]
	agentIdentifiers     observability.Optional[observability.TelemetryStructuredDefenseClawInventoryAgentIdentifiers]
	agentMetadata        observability.Optional[observability.TelemetryStructuredDefenseClawInventoryAgentMetadata]
}

// EmitEndpointInventory publishes complete connector and MCP snapshots through
// the canonical v8 runtime. Each collection gets a summary (including the empty
// collection case) followed by one ai_component.observed record per item.
// The managed gate is checked at the emission boundary so a reload that leaves
// managed_enterprise cannot keep using an earlier callback.
func EmitEndpointInventory(
	ctx context.Context,
	cfg *config.Config,
	reg *connector.Registry,
	emitter sidecarRuntimeEmitter,
) error {
	return emitEndpointInventory(ctx, cfg, reg, emitter, false, nil)
}

func emitEndpointInventory(
	ctx context.Context,
	cfg *config.Config,
	reg *connector.Registry,
	emitter sidecarRuntimeEmitter,
	connectorDiscoveryPartial bool,
	discoveryReport *inventory.AIDiscoveryReport,
) error {
	if !ManagedEnterpriseActive() || ctx == nil || emitter == nil {
		return nil
	}
	connectorComponents, connectorPartial := endpointConnectorComponents(reg)
	firstErr := emitEndpointInventorySnapshot(
		ctx,
		emitter,
		endpointConnectorInventorySource,
		connectorComponents,
		connectorPartial || connectorDiscoveryPartial,
		config.ObservabilityV8ManagedConnectorInventoryAction,
	)

	mcpComponents, partial := endpointMCPComponents(cfg)
	if err := emitEndpointInventorySnapshot(
		ctx, emitter, endpointMCPInventorySource, mcpComponents, partial,
		config.ObservabilityV8ManagedMCPInventoryAction,
	); err != nil && firstErr == nil {
		firstErr = err
	}

	// Per-entry inventories derived from the latest AI-Discovery scan. Each
	// enumerated skill / plugin / MCP server ships as its own
	// ai_component.observed record with defenseclaw.agent.discovery.connector
	// pointing at the parent connector (e.g. codex, claudecode) so downstream
	// can correlate skills / plugins / MCP servers with their owning agent.
	// managed_enterprise gates the whole function above, so this whole block
	// is inert in unmanaged mode.
	if discoveryReport != nil {
		mcpEntries := discoveredMCPEntriesFromReport(*discoveryReport)
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_discovered_mcp_inventory", mcpEntries, false,
			config.ObservabilityV8ManagedMCPInventoryAction,
		); err != nil && firstErr == nil {
			firstErr = err
		}
		skillEntries := discoveredEntriesFromReport(*discoveryReport, inventory.SignalSkill, "skill")
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_skill_inventory", skillEntries, false,
			config.ObservabilityV8ManagedSkillInventoryAction,
		); err != nil && firstErr == nil {
			firstErr = err
		}
		pluginEntries := discoveredEntriesFromReport(*discoveryReport, inventory.SignalPlugin, "plugin")
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_plugin_inventory", pluginEntries, false,
			config.ObservabilityV8ManagedPluginInventoryAction,
		); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	// Per-connector MCP fanout: enumerate every configured connector's MCP
	// server list directly from its native config, tagging each server with
	// defenseclaw.agent.discovery.connector so downstream can correlate MCP
	// entries with the parent agent (codex, claudecode, cursor, ...). This is
	// deterministic and does not depend on the AI-Discovery scan surfacing
	// mcp_server evidence rows. When cfg.ActiveConnectors() is empty (managed
	// installs that don't run `defenseclaw setup` populate no explicit
	// roster), fall back to the built-in connector registry so every known
	// connector still gets a scan.
	if perConnectorMCP := perConnectorMCPEntries(cfg, reg); len(perConnectorMCP) > 0 {
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_per_connector_mcp_inventory", perConnectorMCP, false,
			config.ObservabilityV8ManagedMCPInventoryAction,
		); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// perConnectorMCPEntries enumerates one endpointInventoryComponent per
// (home, connector, MCP server) triple by reading each configured connector's
// native MCP config directly from known filesystem paths under each user home.
// The parent connector slug is carried in agentConnector so the downstream
// ai_component.observed record ships with defenseclaw.agent.discovery.connector
// set. When cfg.ActiveConnectors() is empty the fallback set is derived from
// reg.Available() so managed installs (which don't populate
// Guardrail.Connectors) still get a per-connector scan.
//
// The connector-native readers exposed on *Config (ReadMCPServersForConnector)
// use os.UserHomeDir() which under launchd/root resolves to /var/root and
// misses every real user. To avoid mutating $HOME in a live daemon we call the
// exported per-file readers directly with paths constructed under each home in
// cfg.AIDiscovery.HomeDirs (populated by the installer's eligible-users
// enumeration).
func perConnectorMCPEntries(cfg *config.Config, reg *connector.Registry) []endpointInventoryComponent {
	if cfg == nil {
		return nil
	}
	// Union of ActiveConnectors() and reg.Available() so every registered
	// connector is scanned. ActiveConnectors() alone is often narrower than
	// what's actually installed on disk (managed installs typically pin a
	// single connector via guardrail.connector even though the registry knows
	// about codex, cursor, claudecode, etc.). Deduplicate by lowercase slug.
	seenConnector := make(map[string]struct{})
	var connectors []string
	for _, name := range cfg.ActiveConnectors() {
		key := strings.ToLower(strings.TrimSpace(name))
		if key == "" {
			continue
		}
		if _, ok := seenConnector[key]; ok {
			continue
		}
		seenConnector[key] = struct{}{}
		connectors = append(connectors, name)
	}
	if reg != nil {
		for _, info := range reg.Available() {
			key := strings.ToLower(strings.TrimSpace(info.Name))
			if key == "" {
				continue
			}
			if _, ok := seenConnector[key]; ok {
				continue
			}
			seenConnector[key] = struct{}{}
			connectors = append(connectors, info.Name)
		}
	}
	if len(connectors) == 0 {
		return nil
	}
	// homes = daemon's own HOME (via ReadMCPServersForConnector) plus every
	// configured user home (via direct-path readers). Empty homes list falls
	// back to the single ReadMCPServersForConnector path.
	homes := cfg.AIDiscovery.HomeDirs
	seenComponent := make(map[string]struct{})
	components := make([]endpointInventoryComponent, 0, len(connectors)*(len(homes)+1))
	appendServers := func(connectorName, homeScope string, servers []config.MCPServerEntry) {
		slug := inventoryStableToken(connectorName, 128)
		for _, server := range servers {
			command := inventorySafeBasename(server.Command)
			host := mcpURLHost(server.URL)
			name := inventorySafeItemName(server.Name, 256)
			if name == "" {
				continue
			}
			product := inventoryStableIdentifier(name)
			if product == "" {
				product = command
			}
			if product == "" {
				product = host
			}
			// Identity + dedup key both carry the home scope so two
			// users' same-named MCP servers (e.g. `codex/webex` in
			// each user's ~/.codex/config.toml) get distinct
			// component ids AND both survive the seenComponent
			// dedup. Empty homeScope (Pass 1 — daemon's own HOME)
			// keeps the historical shape.
			identity := connectorName + "/" + homeScope + "/" + server.Name
			if _, seen := seenComponent[identity]; seen {
				continue
			}
			seenComponent[identity] = struct{}{}
			disabled := server.Disabled
			installed := true
			// Hyphen (not underscore) in the id kind to satisfy the
			// defenseclaw.ai.component.id pattern.
			components = append(components, endpointInventoryComponent{
				id:                  endpointInventoryComponentID("mcp-entry", identity),
				componentType:       "mcp_server",
				signal:              "configured_mcp_server",
				product:             product,
				active:              !disabled,
				itemName:            name,
				mcpTransport:        inventoryStableToken(server.Transport, 64),
				mcpCommandBasename:  command,
				mcpURLHost:          host,
				mcpAuthProviderType: inventoryStableToken(server.AuthProviderType, 64),
				mcpDisabled:         &disabled,
				agentConnector:      slug,
				agentInstalled:      &installed,
			})
		}
	}
	// Pass 1 — daemon's own HOME (covers zero-HomeDirs installs and dev runs).
	// ReadMCPServersForConnector's default case reads the OpenClaw registry, so
	// any unrecognized connector slug would spuriously duplicate OpenClaw
	// servers under a foreign agent label. Restrict this pass to the slugs
	// with a native MCP reader (mirrors the switch in ReadMCPServersForConnector).
	// homeScope="" for this pass so its identity shape matches the
	// historical pre-scope id when HomeDirs is empty — that keeps
	// stable ids across a scope-aware rollout for single-home hosts.
	for _, connectorName := range connectors {
		if !hasNativeMCPReader(connectorName) {
			continue
		}
		if servers, err := cfg.ReadMCPServersForConnector(connectorName); err == nil {
			appendServers(connectorName, "", servers)
		}
	}
	// Pass 2 — every configured user home via direct-path readers.
	// Each home gets its own scope key so same-named servers across
	// homes stay distinct.
	for _, home := range homes {
		home = strings.TrimSpace(home)
		if home == "" {
			continue
		}
		homeScope := endpointInventoryScopeKey(home)
		for _, connectorName := range connectors {
			for _, servers := range readMCPServersUnderHome(connectorName, home) {
				appendServers(connectorName, homeScope, servers)
			}
		}
	}
	return components
}

// hasNativeMCPReader reports whether the given connector slug has a native
// MCP-config reader on *Config. Unknown slugs fall through to the OpenClaw
// registry default in ReadMCPServersForConnector, which would spuriously
// duplicate OpenClaw servers under a foreign agent label — inventory Pass 1
// gates on this helper so only genuinely-supported slugs are consulted.
func hasNativeMCPReader(connectorName string) bool {
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "openclaw",
		"claudecode",
		"codex",
		"zeptoclaw",
		"hermes",
		"cursor",
		"windsurf",
		"geminicli",
		"copilot",
		"openhands",
		"opencode",
		"amp",
		"antigravity":
		return true
	}
	return false
}

// readMCPServersUnderHome reads all MCP-server entries for a given connector
// from the standard filesystem paths under `home`. Returns a slice of
// per-source results so callers can label each individually if desired.
// Missing/unparseable files yield nil entries (best-effort).
func readMCPServersUnderHome(connectorName, home string) [][]config.MCPServerEntry {
	if home == "" {
		return nil
	}
	var results [][]config.MCPServerEntry
	tryFile := func(reader func(string) ([]config.MCPServerEntry, error), relPath string) {
		full := filepath.Join(home, relPath)
		if entries, err := reader(full); err == nil && len(entries) > 0 {
			results = append(results, entries)
		}
	}
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "codex":
		tryFile(config.ReadMCPFromCodexConfigTOML, ".codex/config.toml")
	case "claudecode":
		// Honor CLAUDE_CONFIG_DIR the same way readMCPServersClaudeCode does:
		// when the operator has redirected Claude Code to a custom directory,
		// the default `~/.claude/settings.json` and `~/.claude.json` files may
		// be stale or ignored by the CLI, so managed inventory must not emit
		// their servers. `.mcp.json` at the project root is unaffected because
		// it's the workspace-scope file the CLI reads regardless.
		if _, hasEnv := os.LookupEnv("CLAUDE_CONFIG_DIR"); !hasEnv {
			tryFile(config.ReadMCPFromClaudeSettings, ".claude/settings.json")
			// ~/.claude.json holds both user-scope (top-level `mcpServers`)
			// and per-project local-scope (`projects.<path>.mcpServers`)
			// entries. Read the file once and take the union instead of
			// decoding the (often multi-megabyte) conversation-state file
			// twice.
			tryFile(config.ReadMCPFromClaudeJSONBothScopes, ".claude.json")
		}
		tryFile(config.ReadMCPFromDotMCPJSON, ".mcp.json")
	case "cursor":
		tryFile(config.ReadMCPFromDotMCPJSON, ".cursor/mcp.json")
	case "windsurf":
		tryFile(config.ReadMCPFromDotMCPJSON, ".codeium/windsurf/mcp_config.json")
	case "copilot":
		tryFile(config.ReadMCPFromDotMCPJSON, ".config/github-copilot/mcp.json")
	case "geminicli":
		tryFile(config.ReadMCPFromDotMCPJSON, ".gemini/settings.json")
	case "openhands":
		tryFile(config.ReadMCPFromDotMCPJSON, ".openhands/mcp.json")
	case "zeptoclaw":
		tryFile(config.ReadMCPFromDotMCPJSON, ".zeptoclaw/mcp.json")
	case "hermes":
		tryFile(config.ReadMCPFromDotMCPJSON, ".hermes/mcp.json")
	}
	return results
}

// makeEndpointInventoryEmitter rebuilds the connector registry for each
// snapshot so config reload and plugin changes are reflected. The emitter is a
// generation-owned v8 capability supplied by the active sidecar runtime.
//
// snapshotFn optionally returns the most recent AI-Discovery scan report.
// When present the emitter enumerates the discovered skills / plugins / MCP
// servers per parent connector and ships each as its own
// ai_component.observed record with defenseclaw.agent.discovery.connector set
// so downstream can correlate MCP / skills / plugins with the owning agent.
func makeEndpointInventoryEmitter(
	cfg *config.Config,
	emitter sidecarRuntimeEmitter,
	snapshotFn func() inventory.AIDiscoveryReport,
) func(context.Context) {
	return func(ctx context.Context) {
		reg := connector.NewDefaultRegistry()
		partial := false
		if cfg != nil && cfg.PluginDir != "" {
			// A broken plugin directory must not hide built-in connectors or
			// masquerade as an authoritative complete inventory. The bounded
			// partial summary carries no path or loader error.
			partial = reg.DiscoverPlugins(cfg.PluginDir) != nil
		}
		var report *inventory.AIDiscoveryReport
		if snapshotFn != nil {
			snap := snapshotFn()
			report = &snap
		}
		_ = emitEndpointInventory(ctx, cfg, reg, emitter, partial, report)
	}
}

func endpointConnectorComponents(reg *connector.Registry) ([]endpointInventoryComponent, bool) {
	if reg == nil {
		reg = getFallbackConnectorRegistry()
	}
	if reg == nil {
		return nil, true
	}
	available := reg.Available()
	components := make([]endpointInventoryComponent, 0, len(available))
	for _, info := range available {
		name := inventoryStableIdentifier(info.Name)
		components = append(components, endpointInventoryComponent{
			id:                          endpointInventoryComponentID("connector", info.Name),
			componentType:               "supported_connector",
			signal:                      "registered_connector",
			product:                     name,
			active:                      true,
			itemName:                    inventorySafeItemName(info.Name, 128),
			itemDescription:             inventorySafeBounded(info.Description, 512),
			connectorSource:             inventoryConnectorSource(info.Source),
			connectorToolInspectionMode: inventoryToolInspectionMode(info.ToolInspectionMode),
			connectorSubprocessPolicy:   inventorySubprocessPolicy(info.SubprocessPolicy),
		})
	}
	return components, false
}

func endpointMCPComponents(cfg *config.Config) ([]endpointInventoryComponent, bool) {
	if cfg == nil {
		return nil, true
	}
	servers, err := cfg.ReadMCPServers()
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, false
		}
		// A read/parse failure is not an authoritative empty snapshot. The
		// partial summary reports the failed collection without leaking the
		// path or parser error.
		return nil, true
	}
	return endpointMCPComponentsFromServers(servers), false
}

func endpointMCPComponentsFromServers(servers []config.MCPServerEntry) []endpointInventoryComponent {
	components := make([]endpointInventoryComponent, 0, len(servers))
	for _, server := range servers {
		command := inventorySafeBasename(server.Command)
		host := mcpURLHost(server.URL)
		name := inventorySafeItemName(server.Name, 256)
		product := inventoryStableIdentifier(name)
		if product == "" {
			product = command
		}
		if product == "" {
			product = host
		}
		identity := server.Name
		if strings.TrimSpace(identity) == "" {
			identity = strings.Join([]string{command, host}, "\x00")
		}
		disabled := server.Disabled
		components = append(components, endpointInventoryComponent{
			id:                  endpointInventoryComponentID("mcp", identity),
			componentType:       "mcp_server",
			signal:              "configured_mcp_server",
			product:             product,
			active:              !disabled,
			itemName:            name,
			mcpTransport:        inventoryStableToken(server.Transport, 64),
			mcpCommandBasename:  command,
			mcpURLHost:          host,
			mcpAuthProviderType: inventoryStableToken(server.AuthProviderType, 64),
			mcpDisabled:         &disabled,
		})
	}
	return components
}

func emitEndpointInventorySnapshot(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source string,
	components []endpointInventoryComponent,
	partial bool,
	action observability.ProducerKey,
) error {
	return emitInventorySnapshot(
		ctx, emitter, source, "", components, partial,
		observability.SourceSystem, action, "endpoint_inventory", endpointInventoryDetector,
	)
}

func emitInventorySnapshot(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source, scannedAt string,
	components []endpointInventoryComponent,
	partial bool,
	recordSource observability.Source,
	managedAction observability.ProducerKey,
	phase, detector string,
) error {
	scanID := "inventory-" + uuid.NewString()
	components = append([]endpointInventoryComponent(nil), components...)
	sort.SliceStable(components, func(left, right int) bool {
		if components[left].itemName != components[right].itemName {
			return components[left].itemName < components[right].itemName
		}
		return components[left].id < components[right].id
	})
	active := 0
	for _, component := range components {
		if component.active {
			active++
		}
	}
	limit := managedInventoryLimit(managedAction)
	carrier, carrierOK := endpointInventoryCarrierFor(managedAction, components)
	action := managedAction
	if partial || limit == 0 || len(components) > limit || !carrierOK {
		partial = true
		carrier = endpointInventoryCarrier{}
		action = config.ObservabilityV8LocalInventoryDiagnosticAction
	}
	firstErr := emitEndpointInventorySummary(
		ctx, emitter, source, scanID, scannedAt, len(components), active, partial,
		recordSource, action, phase, carrier,
	)
	for _, component := range components {
		if err := emitEndpointInventoryComponent(
			ctx, emitter, source, scanID, component,
			recordSource, action, phase, detector,
		); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

func managedInventoryLimit(action observability.ProducerKey) int {
	switch action {
	case config.ObservabilityV8ManagedConnectorInventoryAction:
		return maxManagedConnectorInventory
	case config.ObservabilityV8ManagedMCPInventoryAction:
		return maxManagedMCPInventory
	case config.ObservabilityV8ManagedAgentInventoryAction:
		return 64
	case config.ObservabilityV8ManagedSkillInventoryAction,
		config.ObservabilityV8ManagedPluginInventoryAction:
		return 512
	default:
		return 0
	}
}

func endpointInventoryCarrierFor(
	action observability.ProducerKey,
	components []endpointInventoryComponent,
) (endpointInventoryCarrier, bool) {
	switch action {
	case config.ObservabilityV8ManagedConnectorInventoryAction:
		identifiers := make([]observability.TelemetryStructuredDefenseClawInventoryConnectorIdentifier, 0, len(components))
		metadata := make([]observability.TelemetryStructuredDefenseClawInventoryConnectorMetadataItem, 0, len(components))
		content := make([]observability.TelemetryStructuredDefenseClawInventoryConnectorContentItem, 0, len(components))
		for _, component := range components {
			if component.componentType != "supported_connector" ||
				component.connectorSource == "" || component.connectorToolInspectionMode == "" ||
				component.connectorSubprocessPolicy == "" {
				return endpointInventoryCarrier{}, false
			}
			identifiers = append(identifiers, observability.TelemetryStructuredDefenseClawInventoryConnectorIdentifier{
				Name: component.itemName,
			})
			metadata = append(metadata, observability.TelemetryStructuredDefenseClawInventoryConnectorMetadataItem{
				Source: component.connectorSource, ToolInspectionMode: component.connectorToolInspectionMode,
				SubprocessPolicy: component.connectorSubprocessPolicy,
			})
			content = append(content, observability.TelemetryStructuredDefenseClawInventoryConnectorContentItem{
				Description: aiDiscoveryV8OptionalText(component.itemDescription),
			})
		}
		return endpointInventoryCarrier{
			connectorIdentifiers: observability.Present(observability.TelemetryStructuredDefenseClawInventoryConnectorIdentifiers{Items: identifiers}),
			connectorMetadata:    observability.Present(observability.TelemetryStructuredDefenseClawInventoryConnectorMetadata{Items: metadata}),
			connectorContent:     observability.Present(observability.TelemetryStructuredDefenseClawInventoryConnectorContent{Items: content}),
		}, true
	case config.ObservabilityV8ManagedMCPInventoryAction:
		identifiers := make([]observability.TelemetryStructuredDefenseClawInventoryMcpIdentifier, 0, len(components))
		metadata := make([]observability.TelemetryStructuredDefenseClawInventoryMcpMetadataItem, 0, len(components))
		for _, component := range components {
			if component.componentType != "mcp_server" || component.mcpDisabled == nil {
				return endpointInventoryCarrier{}, false
			}
			identifiers = append(identifiers, observability.TelemetryStructuredDefenseClawInventoryMcpIdentifier{
				Name: component.itemName, URLHost: aiDiscoveryV8OptionalText(component.mcpURLHost),
			})
			metadata = append(metadata, observability.TelemetryStructuredDefenseClawInventoryMcpMetadataItem{
				Transport:        aiDiscoveryV8OptionalText(component.mcpTransport),
				CommandBasename:  aiDiscoveryV8OptionalText(component.mcpCommandBasename),
				AuthProviderType: aiDiscoveryV8OptionalText(component.mcpAuthProviderType),
				Disabled:         *component.mcpDisabled,
			})
		}
		return endpointInventoryCarrier{
			mcpIdentifiers: observability.Present(observability.TelemetryStructuredDefenseClawInventoryMcpIdentifiers{Items: identifiers}),
			mcpMetadata:    observability.Present(observability.TelemetryStructuredDefenseClawInventoryMcpMetadata{Items: metadata}),
		}, true
	case config.ObservabilityV8ManagedAgentInventoryAction:
		identifiers := make([]observability.TelemetryStructuredDefenseClawInventoryAgentIdentifier, 0, len(components))
		metadata := make([]observability.TelemetryStructuredDefenseClawInventoryAgentMetadataItem, 0, len(components))
		for _, component := range components {
			if component.componentType != "coding_agent" || component.agentConnector == "" ||
				component.agentInstalled == nil || component.agentHasConfig == nil ||
				component.agentHasBinary == nil || component.agentProbeStatus == "" {
				return endpointInventoryCarrier{}, false
			}
			identifiers = append(identifiers, observability.TelemetryStructuredDefenseClawInventoryAgentIdentifier{
				Name:           component.agentConnector,
				ConfigPathHash: aiDiscoveryV8OptionalText(component.agentConfigPathHash),
				BinaryPathHash: aiDiscoveryV8OptionalText(component.agentBinaryPathHash),
			})
			metadata = append(metadata, observability.TelemetryStructuredDefenseClawInventoryAgentMetadataItem{
				Installed: *component.agentInstalled, HasConfig: *component.agentHasConfig,
				ConfigBasename: aiDiscoveryV8OptionalText(component.agentConfigBasename),
				HasBinary:      *component.agentHasBinary,
				BinaryBasename: aiDiscoveryV8OptionalText(component.agentBinaryBasename),
				Version:        aiDiscoveryV8OptionalText(component.agentVersion), ProbeStatus: component.agentProbeStatus,
			})
		}
		return endpointInventoryCarrier{
			agentIdentifiers: observability.Present(observability.TelemetryStructuredDefenseClawInventoryAgentIdentifiers{Items: identifiers}),
			agentMetadata:    observability.Present(observability.TelemetryStructuredDefenseClawInventoryAgentMetadata{Items: metadata}),
		}, true
	case config.ObservabilityV8ManagedSkillInventoryAction,
		config.ObservabilityV8ManagedPluginInventoryAction:
		// Per-entry skill / plugin inventories don't populate a structured
		// aggregate carrier today — each component still flows through
		// emitEndpointInventoryComponent below as its own ai_component.observed
		// record with defenseclaw.agent.discovery.connector set so downstream
		// can correlate the entry with its parent agent.
		return endpointInventoryCarrier{}, true
	default:
		return endpointInventoryCarrier{}, false
	}
}

func emitEndpointInventorySummary(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source, scanID, scannedAt string,
	total, active int,
	partial bool,
	recordSource observability.Source,
	action observability.ProducerKey,
	phase string,
	carrier endpointInventoryCarrier,
) error {
	severity := "INFO"
	canonicalSeverity := observability.SeverityInfo
	logLevel := observability.LogLevelInfo
	outcome := observability.OutcomeCompleted
	result := "ok"
	errorsTotal := int64(0)
	if partial {
		severity = "WARN"
		canonicalSeverity = observability.SeverityMedium
		logLevel = observability.LogLevelWarn
		outcome = observability.OutcomePartial
		result = "partial"
		errorsTotal = 1
	}
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: "ai.discovery.completed", RawSeverity: severity,
		},
		recordSource,
		"",
		action,
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIDiscoveryCompleted(observability.LogAIDiscoveryCompletedInput{
			Envelope: endpointInventoryEmitEnvelope(ctx, snapshot, recordSource, action, phase),
			Severity: observability.Present(canonicalSeverity), LogLevel: observability.Present(logLevel),
			Outcome:                                  outcome,
			DefenseClawAIDiscoveryScanID:             scanID,
			DefenseClawAIDiscoverySource:             source,
			DefenseClawAIDiscoveryPrivacyMode:        "enhanced",
			DefenseClawAIDiscoveryResult:             result,
			DefenseClawAIDiscoveryDurationMs:         0,
			DefenseClawAIDiscoverySignalsTotal:       int64(total),
			DefenseClawAIDiscoveryActiveSignals:      int64(active),
			DefenseClawAIDiscoveryNewSignals:         0,
			DefenseClawAIDiscoveryChangedSignals:     0,
			DefenseClawAIDiscoveryGoneSignals:        0,
			DefenseClawAIDiscoveryFilesScanned:       0,
			DefenseClawAIDiscoveryDedupeSuppressed:   0,
			DefenseClawAIDiscoveryErrors:             errorsTotal,
			DefenseClawAgentDiscoveryScannedAt:       aiDiscoveryV8OptionalText(scannedAt),
			DefenseClawInventoryConnectorIdentifiers: carrier.connectorIdentifiers,
			DefenseClawInventoryConnectorMetadata:    carrier.connectorMetadata,
			DefenseClawInventoryConnectorContent:     carrier.connectorContent,
			DefenseClawInventoryMcpIdentifiers:       carrier.mcpIdentifiers,
			DefenseClawInventoryMcpMetadata:          carrier.mcpMetadata,
			DefenseClawInventoryAgentIdentifiers:     carrier.agentIdentifiers,
			DefenseClawInventoryAgentMetadata:        carrier.agentMetadata,
		})
	})
	return err
}

func emitEndpointInventoryComponent(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source, scanID string,
	component endpointInventoryComponent,
	recordSource observability.Source,
	action observability.ProducerKey,
	phase, detector string,
) error {
	metadata, err := router.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		observability.ProducerKey("ai_discovery"),
		observability.ClassificationContext{
			Bucket: observability.BucketAIDiscovery, EventName: "ai_component.observed", RawSeverity: "INFO",
		},
		recordSource,
		"",
		action,
	)
	if err != nil {
		return &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	_, err = emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		if admission != router.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := aiDiscoveryV8Builder()
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		return builder.BuildLogAIComponentObserved(observability.LogAIComponentObservedInput{
			Envelope:                                        endpointInventoryEmitEnvelope(ctx, snapshot, recordSource, action, phase),
			Severity:                                        observability.Present(observability.SeverityInfo),
			LogLevel:                                        observability.Present(observability.LogLevelInfo),
			DefenseClawAIComponentID:                        component.id,
			DefenseClawAIComponentType:                      component.componentType,
			DefenseClawAIDiscoveryDetector:                  observability.Present(detector),
			DefenseClawAIDiscoverySignal:                    observability.Present(component.signal),
			DefenseClawAIDiscoveryScanID:                    observability.Present(scanID),
			DefenseClawAIDiscoverySignalID:                  observability.Present(component.id),
			DefenseClawAIDiscoverySource:                    observability.Present(source),
			DefenseClawAIComponentProduct:                   aiDiscoveryV8OptionalText(component.product),
			DefenseClawInventoryItemName:                    aiDiscoveryV8OptionalText(component.itemName),
			DefenseClawInventoryItemDescription:             aiDiscoveryV8OptionalText(component.itemDescription),
			DefenseClawInventoryConnectorSource:             aiDiscoveryV8OptionalText(component.connectorSource),
			DefenseClawInventoryConnectorToolInspectionMode: aiDiscoveryV8OptionalText(component.connectorToolInspectionMode),
			DefenseClawInventoryConnectorSubprocessPolicy:   aiDiscoveryV8OptionalText(component.connectorSubprocessPolicy),
			DefenseClawInventoryMcpTransport:                aiDiscoveryV8OptionalText(component.mcpTransport),
			DefenseClawInventoryMcpCommandBasename:          aiDiscoveryV8OptionalText(component.mcpCommandBasename),
			DefenseClawInventoryMcpURLHost:                  aiDiscoveryV8OptionalText(component.mcpURLHost),
			DefenseClawInventoryMcpAuthProviderType:         aiDiscoveryV8OptionalText(component.mcpAuthProviderType),
			DefenseClawInventoryMcpDisabled:                 inventoryOptionalBool(component.mcpDisabled),
			DefenseClawAgentDiscoveryConnector:              aiDiscoveryV8OptionalText(component.agentConnector),
			DefenseClawAgentDiscoveryInstalled:              inventoryOptionalBool(component.agentInstalled),
			DefenseClawAgentDiscoveryHasConfig:              inventoryOptionalBool(component.agentHasConfig),
			DefenseClawAgentDiscoveryConfigBasename:         aiDiscoveryV8OptionalText(component.agentConfigBasename),
			DefenseClawAgentDiscoveryConfigPathHash:         aiDiscoveryV8OptionalText(component.agentConfigPathHash),
			DefenseClawAgentDiscoveryHasBinary:              inventoryOptionalBool(component.agentHasBinary),
			DefenseClawAgentDiscoveryBinaryBasename:         aiDiscoveryV8OptionalText(component.agentBinaryBasename),
			DefenseClawAgentDiscoveryBinaryPathHash:         aiDiscoveryV8OptionalText(component.agentBinaryPathHash),
			DefenseClawAgentDiscoveryVersion:                aiDiscoveryV8OptionalText(component.agentVersion),
			DefenseClawAgentDiscoveryProbeStatus:            aiDiscoveryV8OptionalText(component.agentProbeStatus),
			DefenseClawAgentDiscoveryScannedAt:              aiDiscoveryV8OptionalText(component.agentScannedAt),
		})
	})
	return err
}

// emitManagedAgentInventory publishes a validated coding-agent snapshot into
// the force-enabled ai.discovery family. The release-owned action is reserved
// by the managed plan: SQLite remains authoritative locally and only the
// CMID-authenticated AI Defense destination receives optional export work.
func (a *APIServer) emitManagedAgentInventory(
	ctx context.Context,
	report *agentDiscoveryReport,
	installed int,
	partial bool,
) error {
	if a == nil || report == nil || ctx == nil || !ManagedEnterpriseActive() {
		return nil
	}
	emitter := a.observabilityV8RuntimeEmitter()
	if emitter == nil {
		return nil
	}
	source := discoverySourceOrUnknown(report.Source)
	recordSource := agentDiscoverySource(source)
	action := config.ObservabilityV8ManagedAgentInventoryAction
	names := make([]string, 0, len(report.Agents))
	for name := range report.Agents {
		names = append(names, name)
	}
	sort.Strings(names)
	components := make([]endpointInventoryComponent, 0, len(names))
	for _, name := range names {
		signal := report.Agents[name]
		installedValue := signal.Installed
		hasConfig := signal.HasConfig
		hasBinary := signal.HasBinary
		components = append(components, endpointInventoryComponent{
			id: endpointInventoryComponentID("agent", name), componentType: "coding_agent",
			signal: "coding_agent_inventory", product: name, active: signal.Installed,
			itemName: name, agentConnector: name, agentInstalled: &installedValue,
			agentHasConfig: &hasConfig, agentConfigBasename: signal.ConfigBasename,
			agentConfigPathHash: signal.ConfigPathHash, agentHasBinary: &hasBinary,
			agentBinaryBasename: signal.BinaryBasename, agentBinaryPathHash: signal.BinaryPathHash,
			agentVersion:     signal.Version,
			agentProbeStatus: normalizeDiscoveryProbeStatus(signal.VersionProbeStatus),
			agentScannedAt:   report.ScannedAt,
		})
	}
	// installed was computed from this already-validated report by the caller;
	// the carrier builder independently retains each exact Boolean and the
	// compatibility projector verifies the aggregate before export.
	_ = installed
	return emitInventorySnapshot(
		ctx, emitter, source, report.ScannedAt, components, partial,
		recordSource, action, "agent_inventory", managedAgentInventoryDetector,
	)
}

func endpointInventoryEmitEnvelope(
	ctx context.Context,
	snapshot observabilityruntime.EmitContext,
	source observability.Source,
	action observability.ProducerKey,
	phase string,
) observability.FamilyEnvelopeInput {
	envelope := aiDiscoveryV8EmitEnvelope(ctx, snapshot, phase)
	envelope.Source = source
	envelope.Action = string(action)
	return envelope
}

func endpointInventoryComponentID(kind, identity string) string {
	digest := sha256.Sum256([]byte(kind + "\x00" + identity))
	return fmt.Sprintf("endpoint-%s-%x", kind, digest[:])
}

// endpointInventoryScopeKey returns a short deterministic key for a
// home directory / workspace path, used to disambiguate same-named
// items (skills, plugins, MCP servers) across user homes on the same
// endpoint. Without this, two users' `~/.codex/skills/hello` collapse
// to a single component ID at the SAM (Vineet's [P1] identity
// finding). The path is absolutised before hashing so a relative path
// and its absolute form produce the same scope key.
//
// Truncated to 16 hex chars — the resulting component id stays well
// under the wire-schema length limit for defenseclaw.ai.component.id,
// and the collision probability at fleet scale is negligible for a
// disambiguation-only key. This is NOT a security boundary; do not
// use the value for authentication.
func endpointInventoryScopeKey(path string) string {
	if strings.TrimSpace(path) == "" {
		return ""
	}
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	sum := sha256.Sum256([]byte(path))
	return fmt.Sprintf("%x", sum[:8])
}

// endpointInventoryScopeFromEvidence extracts the scope key from a
// signal produced by the AI-Discovery walker. The walker's evidence[0]
// is always the parent-surface row and carries the PathHash of the
// full home-prefixed path (see signalFromDirectoryChildren and
// signalFromMCPConfigPath) — reusing that hash means report-derived
// component IDs are stable across walker restarts even when the raw
// path-hash key rotates, and it costs zero extra hashing. Returns ""
// when the signal has no evidence (walker bug guard).
func endpointInventoryScopeFromEvidence(evidence []inventory.AIEvidence) string {
	if len(evidence) == 0 {
		return ""
	}
	// Trim the "hmac-sha256:" / "sha256:" prefix — the identity
	// hasher folds this token into the wider digest so the prefix
	// adds no information beyond length.
	h := evidence[0].PathHash
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[i+1:]
	}
	if len(h) > 16 {
		h = h[:16]
	}
	return h
}

func inventoryStableIdentifier(value string) string {
	return inventoryStableToken(value, observability.MaxStableTokenBytes)
}

func inventoryStableToken(value string, maxBytes int) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if len(value) <= maxBytes && observability.IsStableToken(value) {
		return value
	}
	return ""
}

func inventorySafeBounded(value string, maxBytes int) string {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > maxBytes {
		return ""
	}
	for _, r := range value {
		if r < 0x20 || r == 0x7f {
			return ""
		}
	}
	return value
}

func inventorySafeItemName(value string, maxBytes int) string {
	value = inventorySafeBounded(value, maxBytes)
	if strings.ContainsAny(value, `/\\`) {
		return ""
	}
	return value
}

func inventoryConnectorSource(value string) string {
	value = strings.TrimSpace(value)
	if value == "built-in" || value == "plugin" {
		return value
	}
	return ""
}

func inventoryToolInspectionMode(value connector.ToolInspectionMode) string {
	switch value {
	case connector.ToolModePreExecution, connector.ToolModeResponseScan, connector.ToolModeBoth:
		return string(value)
	default:
		return ""
	}
}

func inventorySubprocessPolicy(value connector.SubprocessPolicy) string {
	switch value {
	case connector.SubprocessSandbox, connector.SubprocessShims, connector.SubprocessNone:
		return string(value)
	default:
		return ""
	}
}

func inventoryOptionalBool(value *bool) observability.Optional[bool] {
	if value == nil {
		return observability.Optional[bool]{}
	}
	return observability.Present(*value)
}

// inventorySafeBasename strips a local MCP command to its basename. Arguments,
// working directories, and other path material never enter the canonical body.
func inventorySafeBasename(command string) string {
	command = strings.TrimSpace(command)
	if command == "" {
		return ""
	}
	command = strings.ReplaceAll(command, "\\", "/")
	base := path.Base(command)
	if base == "." || base == "/" || strings.ContainsAny(base, `/\\`) ||
		!endpointInventoryExecutableBasenamePattern.MatchString(base) {
		return ""
	}
	return inventorySafeBounded(base, 256)
}

// mcpURLHost returns only the host (and optional port); path, query, fragment,
// and userinfo are never retained.
func mcpURLHost(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Host == "" {
		return ""
	}
	host := inventorySafeBounded(parsed.Host, 256)
	if !endpointInventoryMCPHostPattern.MatchString(host) {
		return ""
	}
	return host
}

// discoveredEntriesFromReport enumerates per-entry inventory components for a
// given AI-Discovery category (skill or plugin). One record is produced per
// enumerated basename with defenseclaw.agent.discovery.connector set to the
// signal's supported connector slug so downstream can correlate the entry
// (e.g. "skill-a") with the parent agent (e.g. "codex"). Applies only in
// managed_enterprise, guaranteed by the caller.
func discoveredEntriesFromReport(
	report inventory.AIDiscoveryReport,
	category string,
	kind string,
) []endpointInventoryComponent {
	components := make([]endpointInventoryComponent, 0)
	for _, signal := range report.Signals {
		if signal.Category != category {
			continue
		}
		connectorSlug := inventoryStableToken(signal.SupportedConnector, 128)
		installed := true
		for _, evidence := range signal.Evidence {
			// The parent-directory row also carries a Basename ("skills",
			// "plugins", etc.). The enumerated child rows use evidence
			// types like "skill_entry" or "plugin_entry".
			if evidence.Type != kind+"_entry" {
				continue
			}
			name := inventorySafeItemName(evidence.Basename, 256)
			if name == "" {
				continue
			}
			// Use hyphen (not underscore) in the id kind — the family
			// constraint for defenseclaw.ai.component.id is
			// ^[A-Za-z0-9][A-Za-z0-9._:/-]*$ which rejects underscores.
			//
			// Identity input: signalID/scope/name where `scope` is
			// derived from the parent surface's PathHash so two
			// users' same-named skills (e.g. `~/user1/.codex/skills/hello`
			// and `~/user2/.codex/skills/hello`) don't collapse to a
			// single component id. Signals from the same home + same
			// signature + same basename still produce a stable id
			// across scans (PathHash of the parent surface is
			// deterministic within a single walker configuration).
			scope := endpointInventoryScopeFromEvidence(signal.Evidence)
			components = append(components, endpointInventoryComponent{
				id:              endpointInventoryComponentID(kind+"-entry", signal.SignatureID+"/"+scope+"/"+name),
				componentType:   kind,
				signal:          inventoryStableToken(signal.SignatureID, 128),
				product:         inventoryStableToken(signal.Product, 128),
				active:          true,
				itemName:        name,
				itemDescription: "",
				agentConnector:  connectorSlug,
				agentInstalled:  &installed,
				// agent.discovery.config_path_hash requires sha256:<64hex>.
				// Our evidence.PathHash uses hmac-sha256:... which fails
				// that pattern, so leave it empty rather than fail record
				// build.
			})
		}
	}
	return components
}

// discoveredMCPEntriesFromReport enumerates per-server MCP inventory
// components from the AI-Discovery scan. Each declared MCP server (surfaced
// through evidence rows of type "mcp_server" — see the basenames-fix
// commit) ships as its own ai_component.observed record with
// defenseclaw.agent.discovery.connector set to the parent agent's slug.
func discoveredMCPEntriesFromReport(
	report inventory.AIDiscoveryReport,
) []endpointInventoryComponent {
	components := make([]endpointInventoryComponent, 0)
	for _, signal := range report.Signals {
		if signal.Category != inventory.SignalMCPServer {
			continue
		}
		connectorSlug := inventoryStableToken(signal.SupportedConnector, 128)
		active := true
		disabled := false
		for _, evidence := range signal.Evidence {
			if evidence.Type != "mcp_server" {
				continue
			}
			name := inventorySafeItemName(evidence.Basename, 256)
			if name == "" {
				continue
			}
			// Hyphen (not underscore) in the id kind to satisfy the
			// defenseclaw.ai.component.id pattern. Scope key derives
			// from the parent MCP-config surface hash so same-named
			// servers configured in different user homes get
			// distinct component ids.
			scope := endpointInventoryScopeFromEvidence(signal.Evidence)
			components = append(components, endpointInventoryComponent{
				id:             endpointInventoryComponentID("mcp-entry", signal.SignatureID+"/"+scope+"/"+name),
				componentType:  inventory.SignalMCPServer,
				signal:         inventoryStableToken(signal.SignatureID, 128),
				product:        inventoryStableToken(signal.Product, 128),
				active:         active,
				itemName:       name,
				mcpDisabled:    &disabled,
				agentConnector: connectorSlug,
			})
		}
	}
	return components
}
