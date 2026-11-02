// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"
)

const maxMCPToolObservations = maxManagedMCPInventory

type mcpToolObservation struct {
	name string
	at   time.Time
}

// mcpToolInventory retains only tool names from completed scanner listings and
// authenticated hook calls. It is bounded and process-local; it never retains
// arguments, descriptions, schemas, or the scanner's target URL.
type mcpToolInventory struct {
	mu         sync.Mutex
	metric     func(context.Context, string, string, string)
	advertised map[string][]mcpToolObservation
	observed   map[string]map[string]time.Time
	partial    map[string]bool
	parents    map[string]string
}

// refreshParents invalidates evidence when an alias starts naming a different
// configured server. It also withholds evidence for ambiguous aliases.
func (m *mcpToolInventory) refreshParents(servers []endpointInventoryComponent) {
	if m == nil {
		return
	}
	counts := make(map[string]int, len(servers))
	next := make(map[string]string, len(servers))
	for _, server := range servers {
		key := mcpToolServerKey(server.agentConnector, server.itemName)
		counts[key]++
		next[key] = server.id
	}
	for key, count := range counts {
		if count != 1 {
			delete(next, key)
		}
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for key, old := range m.parents {
		if next[key] != old {
			delete(m.advertised, key)
			delete(m.observed, key)
			delete(m.partial, key)
		}
	}
	m.parents = next
}

func (m *mcpToolInventory) recordMetric(ctx context.Context, stage, outcome, reason string) {
	if m != nil && m.metric != nil {
		m.metric(ctx, stage, outcome, reason)
	}
}

func (a *APIServer) recordObservedMCPTool(ctx context.Context, req agentHookRequest, at time.Time) {
	if a == nil || ctx == nil {
		return
	}
	projection, ok := ctx.Value(trustedToolResourceContextKey{}).(trustedToolResourceProjection)
	if !ok || projection.connector != canonicalConnectorRulePackKey(req.ConnectorName) || projection.nativeTool != req.ToolName {
		return
	}
	server, tool, valid := exactMCPToolResource(req.ToolName, payloadString(req.Payload, "mcp_server_name"))
	if valid {
		a.mcpTools.recordObserved(projection.connector, server, tool, at)
	}
}

func mcpToolServerKey(connector, server string) string {
	return strings.ToLower(strings.TrimSpace(connector)) + "\x00" + strings.TrimSpace(server)
}

func (m *mcpToolInventory) recordAdvertised(connector, server string, names []string, at time.Time, upstreamPartial ...bool) {
	if m == nil || connector == "" || server == "" {
		return
	}
	key := mcpToolServerKey(connector, server)
	seen := make(map[string]struct{}, len(names))
	items := make([]mcpToolObservation, 0, min(len(names), 256))
	for _, raw := range names {
		name := inventorySafeItemName(raw, 256)
		if name == "" || name != raw {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		items = append(items, mcpToolObservation{name: name, at: at.UTC()})
		if len(items) == 256 {
			break
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].name < items[j].name })
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.parents[key] == "" {
		return
	}
	if m.advertised == nil {
		m.advertised = make(map[string][]mcpToolObservation)
	}
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	// An authoritative empty tools/list clears the previous advertised set.
	m.advertised[key] = items
	m.partial[key] = len(names) > len(items) || len(upstreamPartial) > 0 && upstreamPartial[0]
}

func (m *mcpToolInventory) recordListingFailure(connector, server string) {
	if m == nil || connector == "" || server == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	m.partial[mcpToolServerKey(connector, server)] = true
}

func (m *mcpToolInventory) recordObserved(connector, server, rawName string, at time.Time) {
	if m == nil || connector == "" || server == "" {
		return
	}
	name := inventorySafeItemName(rawName, 256)
	if name == "" || name != rawName {
		return
	}
	key := mcpToolServerKey(connector, server)
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.parents[key] == "" {
		return
	}
	if m.observed == nil {
		m.observed = make(map[string]map[string]time.Time)
	}
	if m.observed[key] == nil {
		m.observed[key] = make(map[string]time.Time)
	}
	if _, exists := m.observed[key][name]; !exists && len(m.observed[key]) >= 256 {
		return
	}
	m.observed[key][name] = at.UTC()
}

func (m *mcpToolInventory) components(servers []endpointInventoryComponent, remote bool) ([]endpointInventoryComponent, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	// A hook supplies an authenticated connector and server alias, but no user
	// home. An alias present in multiple profiles is ambiguous and is skipped.
	counts := make(map[string]int, len(servers))
	for _, server := range servers {
		counts[mcpToolServerKey(server.agentConnector, server.itemName)]++
	}
	rows := make([]endpointInventoryComponent, 0)
	partial := false
	for _, server := range servers {
		if server.mcpIsRemote != remote {
			continue
		}
		if remote && server.mcpServerURL == "" {
			partial = true
			continue
		}
		key := mcpToolServerKey(server.agentConnector, server.itemName)
		if counts[key] != 1 {
			partial = true
			continue
		}
		// A fresh gateway has no authoritative tools/list result yet. Keep the
		// managed collection partial until each configured server has completed
		// a listing, including an explicitly empty one. Observed calls alone
		// cannot prove that previously advertised tools disappeared.
		if _, listed := m.advertised[key]; !listed {
			partial = true
		}
		partial = partial || m.partial[key]
		add := func(name, source string, at time.Time) {
			if len(rows) >= maxMCPToolObservations {
				partial = true
				return
			}
			rows = append(rows, endpointInventoryComponent{
				id:            endpointInventoryComponentID("mcp-tool", server.id+"\x00"+source+"\x00"+name),
				componentType: "mcp_tool", signal: source + "_mcp_tool", product: name,
				active: server.active, itemName: name, agentConnector: server.agentConnector,
				mcpToolParentID: server.id, mcpToolSource: source,
				mcpToolObservedAt: at.UTC().Format(time.RFC3339Nano),
				userID:            server.userID, userIDKind: server.userIDKind,
				userName: server.userName, userEmail: server.userEmail,
			})
		}
		for _, item := range m.advertised[key] {
			add(item.name, "advertised", item.at)
		}
		// Map iteration is nondeterministic; sorting keeps snapshot digests stable.
		observedNames := make([]string, 0, len(m.observed[key]))
		for name := range m.observed[key] {
			observedNames = append(observedNames, name)
		}
		sort.Strings(observedNames)
		for _, name := range observedNames {
			add(name, "observed", m.observed[key][name])
		}
	}
	return rows, partial
}
