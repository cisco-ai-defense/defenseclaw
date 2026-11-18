// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

const (
	maxMCPToolObservations = maxManagedMCPInventory
	// The 256-name bound is per configured server. A collection can contain
	// one bounded set for each of the 256 managed MCP parents.
	maxMCPToolCollection = maxManagedMCPInventory * maxMCPToolObservations
)

type mcpToolObservation struct {
	name string
	at   time.Time
}

type mcpObservedToolStore interface {
	UpsertMCPObservedToolIf(context.Context, audit.MCPObservedTool, func() bool) error
	ListMCPObservedTools(context.Context) ([]audit.MCPObservedTool, error)
	ReplaceMCPAdvertisedToolsIf(context.Context, audit.MCPAdvertisedToolSnapshot, func() bool) error
	ListMCPAdvertisedToolSnapshots(context.Context) ([]audit.MCPAdvertisedToolSnapshot, error)
	DeleteMCPObservedToolsForParents(context.Context, []string) error
}

// mcpToolInventory retains only tool names from completed scanner listings and
// authenticated hook calls. Observed calls are projected into the audit store
// so they survive a restart. It never retains arguments, descriptions, schemas,
// results, or the scanner's target URL.
type mcpToolInventory struct {
	mu                 sync.Mutex
	metric             func(context.Context, string, string, string)
	store              mcpObservedToolStore
	advertised         map[string][]mcpToolObservation
	observed           map[string]map[string]time.Time
	partial            map[string]bool
	observedPartial    map[string]bool
	parents            map[string]string
	restored           map[string]map[string][]audit.MCPObservedTool
	restoredAdvertised map[string]map[string]audit.MCPAdvertisedToolSnapshot
	pendingRemoval     map[string]struct{}
	restoreIncomplete  bool
}

// refreshParents invalidates evidence when an alias starts naming a different
// configured server. It also withholds evidence for ambiguous aliases.
func (m *mcpToolInventory) refreshParents(servers []endpointInventoryComponent) []string {
	return m.refreshCompleteParents(servers, nil)
}

// refreshCompleteParents applies authoritative results connector by connector.
// An unrelated malformed connector configuration must not prevent a complete
// connector from accepting authenticated tool calls. Incomplete connectors
// retain their last complete parents and evidence, but cannot add new parents;
// this avoids attributing a call while an unreadable profile may hide a
// colliding alias.
func (m *mcpToolInventory) refreshCompleteParents(servers []endpointInventoryComponent, incompleteConnectors map[string]struct{}) []string {
	if m == nil {
		return nil
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
	if m.pendingRemoval == nil {
		m.pendingRemoval = make(map[string]struct{})
	}
	for key, old := range m.parents {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			continue
		}
		if next[key] != old {
			if old != "" && m.store != nil {
				m.pendingRemoval[old] = struct{}{}
			}
			delete(m.advertised, key)
			delete(m.observed, key)
			delete(m.partial, key)
			delete(m.observedPartial, key)
		}
	}
	for key := range next {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			delete(next, key)
		}
	}
	for key, old := range m.parents {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			next[key] = old
		}
	}
	m.parents = next
	// Reconcile every durable candidate only after an authoritative connector
	// read identifies the current parent. This removes stale pre-restart parent
	// generations without allowing map iteration order to choose a winner.
	for key, parents := range m.restored {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			continue
		}
		current := m.parents[key]
		for parentID, tools := range parents {
			if current == "" || parentID != current {
				m.pendingRemoval[parentID] = struct{}{}
				continue
			}
			for _, tool := range tools {
				m.restoreToolLocked(key, tool)
			}
		}
		delete(m.restored, key)
	}
	for key, parents := range m.restoredAdvertised {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			continue
		}
		current := m.parents[key]
		for parentID, snapshot := range parents {
			if current == "" || parentID != current {
				m.pendingRemoval[parentID] = struct{}{}
				continue
			}
			items := make([]mcpToolObservation, 0, len(snapshot.ToolNames))
			for _, name := range snapshot.ToolNames {
				items = append(items, mcpToolObservation{name: name, at: snapshot.ListedAt.UTC()})
			}
			if m.advertised == nil {
				m.advertised = make(map[string][]mcpToolObservation)
			}
			if m.partial == nil {
				m.partial = make(map[string]bool)
			}
			m.advertised[key] = items
			m.partial[key] = snapshot.Partial
		}
		delete(m.restoredAdvertised, key)
	}
	removed := make([]string, 0, len(m.pendingRemoval))
	for parentID := range m.pendingRemoval {
		removed = append(removed, parentID)
	}
	sort.Strings(removed)
	return removed
}

func (m *mcpToolInventory) acknowledgeRemovedParents(parentIDs []string) {
	if m == nil || len(parentIDs) == 0 {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	for _, parentID := range parentIDs {
		delete(m.pendingRemoval, parentID)
	}
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
		parentID, recorded := a.mcpTools.recordObserved(projection.connector, server, tool, at)
		if !recorded {
			a.mcpTools.recordMetric(ctx, "observe", "partial", "parent_unavailable")
			return
		}
		if a.mcpTools.store != nil {
			_ = a.mcpTools.store.UpsertMCPObservedToolIf(ctx, audit.MCPObservedTool{
				ParentComponentID: parentID,
				Connector:         projection.connector,
				ServerName:        server,
				ToolName:          tool,
				LastObservedAt:    at,
			}, func() bool {
				return a.mcpTools.parentIsCurrent(projection.connector, server, parentID)
			})
		}
	}
}

func (m *mcpToolInventory) parentIsCurrent(connector, server, parentID string) bool {
	if m == nil || parentID == "" {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.parents[mcpToolServerKey(connector, server)] == parentID
}

func mcpToolServerKey(connector, server string) string {
	return strings.ToLower(strings.TrimSpace(connector)) + "\x00" + strings.TrimSpace(server)
}

func (m *mcpToolInventory) recordAdvertised(connector, server string, names []string, at time.Time, upstreamPartial ...bool) {
	m.recordAdvertisedContext(context.Background(), connector, server, names, at, upstreamPartial...)
}

func (m *mcpToolInventory) recordAdvertisedContext(ctx context.Context, connector, server string, names []string, at time.Time, upstreamPartial ...bool) {
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
	if m.parents[key] == "" {
		m.mu.Unlock()
		return
	}
	parentID := m.parents[key]
	if m.advertised == nil {
		m.advertised = make(map[string][]mcpToolObservation)
	}
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	// An authoritative empty tools/list clears the previous advertised set.
	m.advertised[key] = items
	m.partial[key] = len(names) > len(items) || len(upstreamPartial) > 0 && upstreamPartial[0]
	partial := m.partial[key]
	m.mu.Unlock()
	if m.store != nil {
		toolNames := make([]string, 0, len(items))
		for _, item := range items {
			toolNames = append(toolNames, item.name)
		}
		_ = m.store.ReplaceMCPAdvertisedToolsIf(ctx, audit.MCPAdvertisedToolSnapshot{
			ParentComponentID: parentID, Connector: connector, ServerName: server,
			ToolNames: toolNames, ListedAt: at.UTC(), Partial: partial,
		}, func() bool { return m.parentIsCurrent(connector, server, parentID) })
	}
}

func (m *mcpToolInventory) recordListingFailure(connector, server string) {
	m.recordListingFailureContext(context.Background(), connector, server)
}

func (m *mcpToolInventory) recordListingFailureContext(ctx context.Context, connector, server string) {
	if m == nil || connector == "" || server == "" {
		return
	}
	key := mcpToolServerKey(connector, server)
	m.mu.Lock()
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	m.partial[key] = true
	parentID := m.parents[key]
	items := append([]mcpToolObservation(nil), m.advertised[key]...)
	m.mu.Unlock()
	if m.store == nil || parentID == "" {
		return
	}
	names := make([]string, 0, len(items))
	listedAt := time.Now().UTC()
	for _, item := range items {
		names = append(names, item.name)
		if item.at.Before(listedAt) {
			listedAt = item.at
		}
	}
	_ = m.store.ReplaceMCPAdvertisedToolsIf(ctx, audit.MCPAdvertisedToolSnapshot{
		ParentComponentID: parentID, Connector: connector, ServerName: server,
		ToolNames: names, ListedAt: listedAt, Partial: true,
	}, func() bool { return m.parentIsCurrent(connector, server, parentID) })
}

func (m *mcpToolInventory) recordObserved(connector, server, rawName string, at time.Time) (string, bool) {
	if m == nil || connector == "" || server == "" {
		return "", false
	}
	name := inventorySafeItemName(rawName, 256)
	if name == "" || name != rawName {
		return "", false
	}
	key := mcpToolServerKey(connector, server)
	m.mu.Lock()
	defer m.mu.Unlock()
	parentID := m.parents[key]
	if parentID == "" {
		return "", false
	}
	if m.observed == nil {
		m.observed = make(map[string]map[string]time.Time)
	}
	if m.observed[key] == nil {
		m.observed[key] = make(map[string]time.Time)
	}
	if _, exists := m.observed[key][name]; !exists && len(m.observed[key]) >= 256 {
		if m.observedPartial == nil {
			m.observedPartial = make(map[string]bool)
		}
		m.observedPartial[key] = true
		return parentID, true
	}
	m.observed[key][name] = at.UTC()
	return parentID, true
}

func (m *mcpToolInventory) restoreObserved(tools []audit.MCPObservedTool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoreIncomplete = false
	m.restored = make(map[string]map[string][]audit.MCPObservedTool)
	for _, tool := range tools {
		name := inventorySafeItemName(tool.ToolName, 256)
		if name == "" || name != tool.ToolName || tool.ParentComponentID == "" {
			continue
		}
		key := mcpToolServerKey(tool.Connector, tool.ServerName)
		if m.restored[key] == nil {
			m.restored[key] = make(map[string][]audit.MCPObservedTool)
		}
		m.restored[key][tool.ParentComponentID] = append(m.restored[key][tool.ParentComponentID], tool)
	}
}

func (m *mcpToolInventory) restoreAdvertised(snapshots []audit.MCPAdvertisedToolSnapshot) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.restoredAdvertised = make(map[string]map[string]audit.MCPAdvertisedToolSnapshot)
	for _, snapshot := range snapshots {
		key := mcpToolServerKey(snapshot.Connector, snapshot.ServerName)
		if m.restoredAdvertised[key] == nil {
			m.restoredAdvertised[key] = make(map[string]audit.MCPAdvertisedToolSnapshot)
		}
		m.restoredAdvertised[key][snapshot.ParentComponentID] = snapshot
	}
}

func (m *mcpToolInventory) restoreToolLocked(key string, tool audit.MCPObservedTool) {
	if m.observed == nil {
		m.observed = make(map[string]map[string]time.Time)
	}
	if m.observed[key] == nil {
		m.observed[key] = make(map[string]time.Time)
	}
	if _, exists := m.observed[key][tool.ToolName]; !exists && len(m.observed[key]) >= maxMCPToolObservations {
		return
	}
	m.observed[key][tool.ToolName] = tool.LastObservedAt.UTC()
	if tool.Overflowed {
		if m.observedPartial == nil {
			m.observedPartial = make(map[string]bool)
		}
		m.observedPartial[key] = true
	}
}

func (m *mcpToolInventory) restoreFromStore(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	tools, err := m.store.ListMCPObservedTools(ctx)
	if err != nil {
		m.mu.Lock()
		m.restoreIncomplete = true
		m.mu.Unlock()
		return err
	}
	m.restoreObserved(tools)
	advertised, err := m.store.ListMCPAdvertisedToolSnapshots(ctx)
	if err != nil {
		m.mu.Lock()
		m.restoreIncomplete = true
		m.mu.Unlock()
		return err
	}
	m.restoreAdvertised(advertised)
	return nil
}

func (m *mcpToolInventory) retryRestoreFromStore(ctx context.Context) {
	if m == nil || m.store == nil {
		return
	}
	m.mu.Lock()
	retry := m.restoreIncomplete
	m.mu.Unlock()
	if retry {
		_ = m.restoreFromStore(ctx)
	}
}

// observedIncomplete reports whether an incomplete connector owns durable
// observed evidence. Such a connector must keep both observed collections
// partial: its unreadable configuration may be hiding the server that tells us
// whether the retained parent is local or remote. An unrelated incomplete
// connector with no observed evidence cannot make a complete connector's
// authenticated observations diagnostic-only.
func (m *mcpToolInventory) observedIncomplete(incompleteConnectors map[string]struct{}) bool {
	if m == nil {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.restoreIncomplete || len(m.restored) > 0 || len(m.restoredAdvertised) > 0 || len(m.pendingRemoval) > 0 {
		return true
	}
	for key, tools := range m.observed {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete &&
			(len(tools) > 0 || m.observedPartial[key]) {
			return true
		}
	}
	return false
}

func (m *mcpToolInventory) components(servers []endpointInventoryComponent, remote bool, onlySource ...string) ([]endpointInventoryComponent, bool) {
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
	includeAdvertised, includeObserved := true, true
	if len(onlySource) > 0 {
		includeAdvertised = onlySource[0] == "advertised"
		includeObserved = onlySource[0] == "observed"
	}
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
		// A parent that has never been scanned contributes no advertised rows.
		// A recorded listing failure is partial, while an authoritative empty
		// listing is represented by an empty advertised slice.
		if includeAdvertised {
			partial = partial || m.partial[key]
		}
		if includeObserved {
			partial = partial || m.observedPartial[key]
		}
		add := func(name, source string, at time.Time) {
			if len(rows) >= maxMCPToolCollection {
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
		if includeAdvertised {
			for _, item := range m.advertised[key] {
				add(item.name, "advertised", item.at)
			}
		}
		// Map iteration is nondeterministic; sorting keeps snapshot digests stable.
		if includeObserved {
			observedNames := make([]string, 0, len(m.observed[key]))
			for name := range m.observed[key] {
				observedNames = append(observedNames, name)
			}
			sort.Strings(observedNames)
			for _, name := range observedNames {
				add(name, "observed", m.observed[key][name])
			}
		}
	}
	return rows, partial
}
