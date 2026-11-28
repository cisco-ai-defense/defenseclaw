// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

type pendingMCPObservedTool struct {
	parentID  string
	connector string
	server    string
	tool      string
	firstAt   time.Time
	lastAt    time.Time
	version   uint64
}

type mcpToolAliasState uint8

const (
	mcpToolAliasUnavailable mcpToolAliasState = iota
	mcpToolAliasUnique
	mcpToolAliasAmbiguous
)

type mcpToolAliasResolution struct {
	configured string
	state      mcpToolAliasState
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
	reconcileMu                 sync.Mutex
	mu                          sync.Mutex
	metric                      func(context.Context, string, string, string)
	store                       mcpObservedToolStore
	advertised                  map[string][]mcpToolObservation
	advertisedListedAt          map[string]time.Time
	observed                    map[string]map[string]time.Time
	partial                     map[string]bool
	advertisedVersion           map[string]uint64
	pendingAdvertised           map[string]uint64
	pendingObserved             map[string]map[string]pendingMCPObservedTool
	observedVersion             uint64
	observedPartial             map[string]bool
	parents                     map[string]string
	blockedObserved             map[string]bool
	aliases                     map[string]mcpToolAliasResolution
	restored                    map[string]map[string][]audit.MCPObservedTool
	restoredAdvertised          map[string]map[string]audit.MCPAdvertisedToolSnapshot
	pendingRemoval              map[string]struct{}
	observedRestoreIncomplete   bool
	advertisedRestoreIncomplete bool
	// parentSince is when each alias's current parent became current, and
	// listingSourceSince when the watcher whose MCP admission scans supply
	// the listings started (zero while none runs). Together they bound how
	// long a parent with no listing yet keeps its advertised collection
	// partial (rel-1-0-10:GAP-1857).
	parentSince        map[string]time.Time
	listingSourceSince time.Time
	now                func() time.Time
}

// mcpToolFirstListingWindow is how long a current parent with no listing
// keeps the advertised collection partial while a listing source runs: the
// watcher's MCP discovery poll plus one admission scan, with room for the
// startup rescan. After it the collection is sent as complete, as before, so
// a server that is never scanned (admitted without a scan, or an unchanged
// baseline with no kept listing) cannot keep a Secure Client endpoint from
// stamping its daily bundle.
const mcpToolFirstListingWindow = 15 * time.Minute

func (m *mcpToolInventory) clock() time.Time {
	if m.now != nil {
		return m.now()
	}
	return time.Now()
}

// setListingSource records whether the watcher that lists MCP tools runs.
func (m *mcpToolInventory) setListingSource(running bool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.listingSourceSince = time.Time{}
	if running {
		m.listingSourceSince = m.clock()
	}
}

// firstListingDueLocked reports a current parent with no recorded listing
// whose first listing a running source may still deliver: its advertised
// collection is not complete yet (rel-1-0-10:GAP-1857). With no listing
// source (gateway.watcher.enabled off) nothing will list it, and it is sent
// as before: no advertised tools in a complete collection (a documented
// limit).
func (m *mcpToolInventory) firstListingDueLocked(key string) bool {
	if m.listingSourceSince.IsZero() || !m.advertisedListedAt[key].IsZero() || m.advertised[key] != nil {
		return false
	}
	since := m.listingSourceSince
	if current := m.parentSince[key]; current.After(since) {
		since = current
	}
	return m.clock().Sub(since) < mcpToolFirstListingWindow
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
	if m.blockedObserved == nil {
		m.blockedObserved = make(map[string]bool)
	}
	// An incomplete read may retain a last-known parent, but a collision that
	// was visible in that same read makes the alias unsafe for new calls. Keep
	// the evidence while refusing observations until a complete read proves the
	// alias unique again.
	for key := range m.blockedObserved {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; !incomplete {
			delete(m.blockedObserved, key)
		}
	}
	for key, count := range counts {
		if count != 1 {
			m.blockedObserved[key] = true
			// Retain the last complete identity and evidence while refusing new
			// observations/listings. A later unique read either confirms it or
			// retires it through the ordinary parent-change path.
			if old := m.parents[key]; old != "" {
				next[key] = old
			}
		}
	}
	if m.pendingRemoval == nil {
		m.pendingRemoval = make(map[string]struct{})
	}
	// A parent whose durable cleanup has not completed cannot become current
	// again yet. Otherwise a later cleanup retry could delete observations that
	// were accepted after the parent reappeared.
	for key, parentID := range next {
		if _, pending := m.pendingRemoval[parentID]; pending {
			delete(next, key)
		}
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
			delete(m.advertisedListedAt, key)
			delete(m.advertisedVersion, key)
			delete(m.pendingAdvertised, key)
			delete(m.pendingObserved, key)
			delete(m.observed, key)
			delete(m.partial, key)
			delete(m.observedPartial, key)
		}
	}
	// A listing can complete before the first parent refresh. If an
	// authoritative connector read then says that alias is absent, discard the
	// unbound listing so it cannot attach to a different server that later reuses
	// the same connector and alias.
	for key := range m.pendingAdvertised {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			continue
		}
		if m.parents[key] == "" && next[key] == "" {
			delete(m.advertised, key)
			delete(m.advertisedListedAt, key)
			delete(m.advertisedVersion, key)
			delete(m.pendingAdvertised, key)
			delete(m.partial, key)
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
	if m.parentSince == nil {
		m.parentSince = make(map[string]time.Time)
	}
	now := m.clock()
	for key, parentID := range next {
		if m.parents[key] != parentID {
			m.parentSince[key] = now
		}
	}
	for key := range m.parentSince {
		if next[key] == "" {
			delete(m.parentSince, key)
		}
	}
	m.parents = next
	m.rebuildAliasIndexLocked()
	// Reconcile every durable candidate only after an authoritative connector
	// read identifies the current parent. This removes stale pre-restart parent
	// generations without allowing map iteration order to choose a winner.
	for key, parents := range m.restored {
		connector, _, _ := strings.Cut(key, "\x00")
		if _, incomplete := incompleteConnectors[connector]; incomplete {
			continue
		}
		if counts[key] > 1 {
			// Ambiguous is not absent. Keep every durable candidate staged
			// without attribution until a complete read identifies one current
			// parent or confirms that all candidates are gone.
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
		if counts[key] > 1 {
			continue
		}
		current := m.parents[key]
		for parentID, snapshot := range parents {
			if current == "" || parentID != current {
				m.pendingRemoval[parentID] = struct{}{}
				continue
			}
			// A scanner listing received after restore began is newer live
			// evidence. Do not replace it with the durable startup snapshot.
			if m.advertisedVersion[key] != 0 {
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
			if m.advertisedListedAt == nil {
				m.advertisedListedAt = make(map[string]time.Time)
			}
			m.advertisedListedAt[key] = snapshot.ListedAt.UTC()
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

// recordObservedMCPToolIfInventoryOn records an authenticated MCP tool call
// while the gateway sends the endpoint inventory (endpointInventoryOn).
func (a *APIServer) recordObservedMCPToolIfInventoryOn(ctx context.Context, req agentHookRequest) {
	if req.SuppressCorrelationEmit && !req.CorrelationUnavailable || !endpointInventoryOn(a.liveConfig()) {
		return
	}
	a.recordObservedMCPTool(ctx, req, time.Now())
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
		configuredServer, resolved := a.mcpTools.resolveConfiguredServer(projection.connector, server)
		if !resolved {
			a.mcpTools.recordMetric(ctx, "observe", "partial", "parent_unavailable")
			return
		}
		server = configuredServer
		if a.mcpTools.store != nil {
			pending, recorded, queued := a.mcpTools.recordObservedAndBeginWrite(projection.connector, server, tool, at)
			if !recorded {
				a.mcpTools.recordMetric(ctx, "observe", "partial", "parent_unavailable")
				return
			}
			if !queued {
				a.mcpTools.recordMetric(ctx, "observe", "partial", "incomplete")
				return
			}
			var attempted atomic.Bool
			writeCtx, report := audit.WithCallWriteReport(ctx, a.store, func(err error) {
				a.mcpTools.settleObservedWrite(pending, err, attempted.Load())
			})
			err := a.mcpTools.store.UpsertMCPObservedToolIf(writeCtx, audit.MCPObservedTool{
				ParentComponentID: pending.parentID,
				Connector:         pending.connector,
				ServerName:        pending.server,
				ToolName:          pending.tool,
				FirstObservedAt:   pending.firstAt,
				LastObservedAt:    pending.lastAt,
			}, func() bool {
				current := a.mcpTools.observedWriteIsCurrent(pending)
				attempted.Store(current)
				return current
			})
			if report == nil || !report.Deferred() {
				a.mcpTools.settleObservedWrite(pending, err, attempted.Load())
			}
		} else if _, recorded := a.mcpTools.recordObserved(projection.connector, server, tool, at); !recorded {
			a.mcpTools.recordMetric(ctx, "observe", "partial", "parent_unavailable")
		}
	}
}

// resolveConfiguredServer maps an agent's tool-name spelling back to the one
// configured server alias that owns it. Codex normalizes punctuation to
// underscores in tool names, so the literal hook spelling is not necessarily
// the durable inventory identity.
func (m *mcpToolInventory) resolveConfiguredServer(connector, toolServer string) (string, bool) {
	if m == nil {
		return "", false
	}
	connector = canonicalConnectorRulePackKey(connector)
	m.mu.Lock()
	defer m.mu.Unlock()
	resolution := m.aliases[mcpToolServerKey(connector, strings.TrimSpace(toolServer))]
	return resolution.configured, resolution.state == mcpToolAliasUnique
}

func (m *mcpToolInventory) rebuildAliasIndexLocked() {
	m.aliases = make(map[string]mcpToolAliasResolution, len(m.parents)*2)
	for key, blocked := range m.blockedObserved {
		connector, configured, ok := strings.Cut(key, "\x00")
		if !blocked || !ok {
			continue
		}
		for _, spelling := range []string{configured, config.MCPToolServerName(connector, configured)} {
			m.aliases[mcpToolServerKey(connector, spelling)] = mcpToolAliasResolution{state: mcpToolAliasAmbiguous}
		}
	}
	for key, parentID := range m.parents {
		connector, configured, ok := strings.Cut(key, "\x00")
		if !ok || parentID == "" {
			continue
		}
		spellings := []string{configured, config.MCPToolServerName(connector, configured)}
		for _, spelling := range spellings {
			aliasKey := mcpToolServerKey(connector, spelling)
			current := m.aliases[aliasKey]
			if m.blockedObserved[key] || current.state == mcpToolAliasAmbiguous ||
				current.state == mcpToolAliasUnique && current.configured != configured {
				m.aliases[aliasKey] = mcpToolAliasResolution{state: mcpToolAliasAmbiguous}
				continue
			}
			m.aliases[aliasKey] = mcpToolAliasResolution{configured: configured, state: mcpToolAliasUnique}
		}
	}
}

func (m *mcpToolInventory) beginObservedWrite(connector, server, tool, parentID string, at time.Time) (pendingMCPObservedTool, bool) {
	if m == nil || parentID == "" {
		return pendingMCPObservedTool{}, false
	}
	key := mcpToolServerKey(connector, server)
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.beginObservedWriteLocked(key, connector, server, tool, parentID, at)
}

func (m *mcpToolInventory) beginObservedWriteLocked(key, connector, server, tool, parentID string, at time.Time) (pendingMCPObservedTool, bool) {
	if m.parents[key] != parentID || m.blockedObserved[key] {
		return pendingMCPObservedTool{}, false
	}
	if m.pendingObserved == nil {
		m.pendingObserved = make(map[string]map[string]pendingMCPObservedTool)
	}
	if m.pendingObserved[key] == nil {
		m.pendingObserved[key] = make(map[string]pendingMCPObservedTool)
	}
	if _, exists := m.pendingObserved[key][tool]; !exists && len(m.pendingObserved[key]) >= maxMCPToolObservations {
		return pendingMCPObservedTool{}, false
	}
	firstAt, lastAt := at.UTC(), at.UTC()
	if current, exists := m.pendingObserved[key][tool]; exists && current.parentID == parentID {
		if current.firstAt.Before(firstAt) {
			firstAt = current.firstAt
		}
		if current.lastAt.After(lastAt) {
			lastAt = current.lastAt
		}
	}
	m.observedVersion++
	pending := pendingMCPObservedTool{
		parentID: parentID, connector: connector, server: server, tool: tool,
		firstAt: firstAt, lastAt: lastAt, version: m.observedVersion,
	}
	m.pendingObserved[key][tool] = pending
	return pending, true
}

func (m *mcpToolInventory) observedWriteIsCurrent(pending pendingMCPObservedTool) bool {
	if m == nil || pending.version == 0 {
		return false
	}
	key := mcpToolServerKey(pending.connector, pending.server)
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.pendingObserved[key][pending.tool]
	return ok && current.version == pending.version && m.parents[key] == pending.parentID && !m.blockedObserved[key]
}

func (m *mcpToolInventory) settleObservedWrite(pending pendingMCPObservedTool, err error, attempted bool) {
	if m == nil || pending.version == 0 || err != nil {
		return
	}
	key := mcpToolServerKey(pending.connector, pending.server)
	m.mu.Lock()
	defer m.mu.Unlock()
	current, ok := m.pendingObserved[key][pending.tool]
	if !ok || current.version != pending.version {
		return
	}
	parentStillExists := m.parents[key] == pending.parentID
	if !attempted && parentStillExists {
		return
	}
	delete(m.pendingObserved[key], pending.tool)
	if len(m.pendingObserved[key]) == 0 {
		delete(m.pendingObserved, key)
	}
}

func (m *mcpToolInventory) flushPendingObserved(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	m.mu.Lock()
	writes := make([]pendingMCPObservedTool, 0)
	for _, tools := range m.pendingObserved {
		for _, pending := range tools {
			writes = append(writes, pending)
		}
	}
	m.mu.Unlock()
	sort.Slice(writes, func(i, j int) bool {
		if writes[i].parentID != writes[j].parentID {
			return writes[i].parentID < writes[j].parentID
		}
		return writes[i].tool < writes[j].tool
	})
	var firstErr error
	for _, pending := range writes {
		var attempted atomic.Bool
		err := m.store.UpsertMCPObservedToolIf(ctx, audit.MCPObservedTool{
			ParentComponentID: pending.parentID,
			Connector:         pending.connector,
			ServerName:        pending.server,
			ToolName:          pending.tool,
			FirstObservedAt:   pending.firstAt,
			LastObservedAt:    pending.lastAt,
		}, func() bool {
			current := m.observedWriteIsCurrent(pending)
			attempted.Store(current)
			return current
		})
		m.settleObservedWrite(pending, err, attempted.Load())
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
	if m.blockedObserved[key] {
		m.mu.Unlock()
		m.recordMetric(ctx, "list", "partial", "incomplete")
		return
	}
	parentID := m.parents[key]
	if m.advertised == nil {
		m.advertised = make(map[string][]mcpToolObservation)
	}
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	if m.advertisedListedAt == nil {
		m.advertisedListedAt = make(map[string]time.Time)
	}
	if m.advertisedVersion == nil {
		m.advertisedVersion = make(map[string]uint64)
	}
	m.advertisedVersion[key]++
	// An authoritative empty tools/list clears the previous advertised set.
	m.advertised[key] = items
	m.advertisedListedAt[key] = at.UTC()
	m.partial[key] = len(names) > len(items) || len(upstreamPartial) > 0 && upstreamPartial[0]
	partial := m.partial[key]
	version := m.advertisedVersion[key]
	if m.pendingAdvertised == nil {
		m.pendingAdvertised = make(map[string]uint64)
	}
	// Track every listing until this exact version is durable. This covers both
	// the pre-parent path and a failed write for an already-known parent.
	m.pendingAdvertised[key] = version
	toolNames := make([]string, 0, len(items))
	for _, item := range items {
		toolNames = append(toolNames, item.name)
	}
	snapshot := audit.MCPAdvertisedToolSnapshot{
		ParentComponentID: parentID, Connector: connector, ServerName: server,
		ToolNames: toolNames, ListedAt: at.UTC(), Partial: partial,
	}
	m.mu.Unlock()
	if m.store != nil && parentID != "" {
		_ = m.persistAdvertisedSnapshot(ctx, key, version, snapshot)
	}
}

func (m *mcpToolInventory) advertisedWriteIsCurrent(key, parentID string, version uint64) bool {
	if m == nil || parentID == "" || version == 0 {
		return false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.parents[key] == parentID && m.advertisedVersion[key] == version &&
		m.pendingAdvertised[key] == version
}

func (m *mcpToolInventory) persistAdvertisedSnapshot(ctx context.Context, key string, version uint64, snapshot audit.MCPAdvertisedToolSnapshot) error {
	var attempted atomic.Bool
	err := m.store.ReplaceMCPAdvertisedToolsIf(ctx, snapshot, func() bool {
		current := m.advertisedWriteIsCurrent(key, snapshot.ParentComponentID, version)
		attempted.Store(current)
		return current
	})
	if err != nil || !attempted.Load() {
		return err
	}
	m.mu.Lock()
	if m.pendingAdvertised[key] == version && m.advertisedVersion[key] == version &&
		m.parents[key] == snapshot.ParentComponentID {
		delete(m.pendingAdvertised, key)
	}
	m.mu.Unlock()
	return nil
}

// flushPendingAdvertised durably writes listings that completed before their
// configured parent was established. A version check prevents an older flush
// from clearing a newer listing that arrived while the store write ran.
func (m *mcpToolInventory) flushPendingAdvertised(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	type pendingWrite struct {
		key      string
		version  uint64
		snapshot audit.MCPAdvertisedToolSnapshot
	}
	m.mu.Lock()
	writes := make([]pendingWrite, 0, len(m.pendingAdvertised))
	for key, version := range m.pendingAdvertised {
		parentID := m.parents[key]
		if parentID == "" {
			continue
		}
		connector, server, _ := strings.Cut(key, "\x00")
		items := m.advertised[key]
		names := make([]string, 0, len(items))
		for _, item := range items {
			names = append(names, item.name)
		}
		writes = append(writes, pendingWrite{key: key, version: version, snapshot: audit.MCPAdvertisedToolSnapshot{
			ParentComponentID: parentID, Connector: connector, ServerName: server,
			ToolNames: names, ListedAt: m.advertisedListedAt[key], Partial: m.partial[key],
		}})
	}
	m.mu.Unlock()
	for _, write := range writes {
		if err := m.persistAdvertisedSnapshot(ctx, write.key, write.version, write.snapshot); err != nil {
			return err
		}
	}
	return nil
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
	if m.blockedObserved[key] {
		m.mu.Unlock()
		m.recordMetric(ctx, "list", "partial", "incomplete")
		return
	}
	if m.partial == nil {
		m.partial = make(map[string]bool)
	}
	if m.advertisedVersion == nil {
		m.advertisedVersion = make(map[string]uint64)
	}
	if m.pendingAdvertised == nil {
		m.pendingAdvertised = make(map[string]uint64)
	}
	m.advertisedVersion[key]++
	version := m.advertisedVersion[key]
	m.pendingAdvertised[key] = version
	m.partial[key] = true
	parentID := m.parents[key]
	items := append([]mcpToolObservation(nil), m.advertised[key]...)
	names := make([]string, 0, len(items))
	listedAt := m.advertisedListedAt[key]
	if listedAt.IsZero() {
		listedAt = time.Now().UTC()
		if m.advertisedListedAt == nil {
			m.advertisedListedAt = make(map[string]time.Time)
		}
		m.advertisedListedAt[key] = listedAt
	}
	for _, item := range items {
		names = append(names, item.name)
	}
	snapshot := audit.MCPAdvertisedToolSnapshot{
		ParentComponentID: parentID, Connector: connector, ServerName: server,
		ToolNames: names, ListedAt: listedAt, Partial: true,
	}
	m.mu.Unlock()
	if m.store != nil && parentID != "" {
		_ = m.persistAdvertisedSnapshot(ctx, key, version, snapshot)
	}
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
	return m.recordObservedLocked(key, name, at)
}

func (m *mcpToolInventory) recordObservedAndBeginWrite(connector, server, rawName string, at time.Time) (pendingMCPObservedTool, bool, bool) {
	if m == nil || connector == "" || server == "" {
		return pendingMCPObservedTool{}, false, false
	}
	name := inventorySafeItemName(rawName, 256)
	if name == "" || name != rawName {
		return pendingMCPObservedTool{}, false, false
	}
	key := mcpToolServerKey(connector, server)
	m.mu.Lock()
	defer m.mu.Unlock()
	parentID := m.parents[key]
	if parentID == "" || m.blockedObserved[key] {
		return pendingMCPObservedTool{}, false, false
	}
	pending, queued := m.beginObservedWriteLocked(key, connector, server, name, parentID, at)
	if !queued {
		if m.observedPartial == nil {
			m.observedPartial = make(map[string]bool)
		}
		m.observedPartial[key] = true
		return pendingMCPObservedTool{}, true, false
	}
	_, recorded := m.recordObservedLocked(key, name, at)
	return pending, recorded, true
}

func (m *mcpToolInventory) recordObservedLocked(key, name string, at time.Time) (string, bool) {
	parentID := m.parents[key]
	if parentID == "" || m.blockedObserved[key] {
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
	observedAt := at.UTC()
	if current := m.observed[key][name]; current.IsZero() || observedAt.After(current) {
		m.observed[key][name] = observedAt
	}
	return parentID, true
}

func (m *mcpToolInventory) restoreObserved(tools []audit.MCPObservedTool) {
	if m == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.observedRestoreIncomplete = false
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
	m.advertisedRestoreIncomplete = false
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
	if tool.Overflowed {
		if m.observedPartial == nil {
			m.observedPartial = make(map[string]bool)
		}
		m.observedPartial[key] = true
	}
	if _, exists := m.observed[key][tool.ToolName]; !exists && len(m.observed[key]) >= maxMCPToolObservations {
		if m.observedPartial == nil {
			m.observedPartial = make(map[string]bool)
		}
		m.observedPartial[key] = true
		return
	}
	restoredAt := tool.LastObservedAt.UTC()
	if current := m.observed[key][tool.ToolName]; current.IsZero() || restoredAt.After(current) {
		m.observed[key][tool.ToolName] = restoredAt
	}
}

// attachStore makes store the durable state of the tool inventory, in every
// product. The gateway reads it now when it sends the endpoint inventory (a
// Secure Client endpoint, or ai_discovery on; ManagedEnterpriseActive is not
// set yet here); otherwise the first inventory cycle reads it
// (retryRestoreFromStore), so an install with the inventory off reads nothing.
func (m *mcpToolInventory) attachStore(ctx context.Context, cfg *config.Config, store mcpObservedToolStore) error {
	if m == nil || store == nil || cfg == nil {
		return nil
	}
	m.store = store
	if managed.IsManagedEnterprise(cfg.DeploymentMode) && cfg.ManagedAIDOnly() || cfg.AIDiscovery.Enabled {
		return m.restoreFromStore(ctx)
	}
	m.mu.Lock()
	m.observedRestoreIncomplete, m.advertisedRestoreIncomplete = true, true
	m.mu.Unlock()
	return nil
}

func (m *mcpToolInventory) restoreFromStore(ctx context.Context) error {
	if m == nil || m.store == nil {
		return nil
	}
	tools, err := m.store.ListMCPObservedTools(ctx)
	if err != nil {
		m.mu.Lock()
		m.observedRestoreIncomplete = true
		// The advertised read is ordered after the observed read. If the first
		// read fails, neither durable projection is authoritative yet.
		m.advertisedRestoreIncomplete = true
		m.mu.Unlock()
		return err
	}
	m.restoreObserved(tools)
	advertised, err := m.store.ListMCPAdvertisedToolSnapshots(ctx)
	if err != nil {
		m.mu.Lock()
		m.advertisedRestoreIncomplete = true
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
	retry := m.observedRestoreIncomplete || m.advertisedRestoreIncomplete
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
	if m.observedRestoreIncomplete || len(m.restored) > 0 || len(m.pendingRemoval) > 0 {
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
	if includeAdvertised && m.advertisedRestoreIncomplete {
		partial = true
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
		if m.parents[key] != server.id {
			if len(m.advertised[key]) > 0 || len(m.observed[key]) > 0 || m.partial[key] || m.observedPartial[key] {
				partial = true
			}
			continue
		}
		if includeAdvertised && m.store != nil && m.pendingAdvertised[key] != 0 {
			partial = true
		}
		// A parent that has never been scanned contributes no advertised rows,
		// and is partial while its first listing is due. A recorded listing
		// failure is partial, while an authoritative empty listing is
		// represented by an empty advertised slice.
		if includeAdvertised {
			partial = partial || m.partial[key] || m.firstListingDueLocked(key)
		}
		if includeObserved {
			partial = partial || m.observedPartial[key]
			partial = partial || len(m.pendingObserved[key]) > 0
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
