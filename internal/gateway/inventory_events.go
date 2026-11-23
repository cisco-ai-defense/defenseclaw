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
	"runtime"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
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
	endpointInventoryMCPHostPattern = lazyregexp.New(
		`^([A-Za-z0-9][A-Za-z0-9._:-]*|\[[0-9A-Fa-f:.]+\](:[0-9]+)?)$`,
	)
	endpointInventoryExecutableBasenamePattern = lazyregexp.New(
		`^[A-Za-z0-9][A-Za-z0-9._+@-]*$`,
	)
	endpointInventoryVersionPattern = lazyregexp.New(
		`^[A-Za-z0-9][A-Za-z0-9 .,_+@():-]*$`,
	)
)

// endpointInventoryComponent is the canonical, redaction-safe projection of
// one endpoint inventory row. The canonical runtime supplies the endpoint
// resource anchor; body-level device IDs and hostnames are deliberately not
// duplicated.
type endpointInventoryComponent struct {
	id            string
	componentType string
	signal        string
	product       string
	// vendor is the catalog vendor of the agent whose folder holds a skill or
	// plugin entry; who published the skill is skillPublisher.
	vendor                      string
	active                      bool
	itemName                    string
	itemDescription             string
	connectorSource             string
	connectorToolInspectionMode string
	connectorSubprocessPolicy   string
	mcpTransport                string
	mcpCommandBasename          string
	mcpCommandFingerprint       string
	mcpArgumentsFingerprint     string
	mcpSourceScope              string
	mcpServerURL                string
	mcpIsRemote                 bool
	mcpToolParentID             string
	mcpToolSource               string
	mcpToolObservedAt           string
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
	// The owning end user, when the row came from a specific profile
	// directory. Left empty for rows the scan cannot attribute — a
	// process-wide surface, or a profile whose owner does not resolve —
	// because a row attributed to the wrong person is worse than one
	// attributed to nobody.
	userID     string
	userIDKind string
	userName   string
	userEmail  string
	// Skill rows only (inventory.AISkillFacts).
	skillContentHash   string
	skillContentStatus string
	skillState         string
	skillFirstSeen     string
	skillLastSeen      string
	skillScope         string
	skillLocation      string
	skillAgents        []string
	// skillPublisherSource: vendor_bundled, plugin_manifest, declared, unknown.
	skillPublisher       string
	skillPublisherSource string
	skillPlugin          string
	skillPluginVersion   string
	skillPluginEnabled   *bool
	// skillManifestHash names the skill's SKILL.md; skillManifest carries
	// part skillManifestPart of skillManifestParts of its text
	// (managed_skill_manifest.go).
	skillManifestHash  string
	skillManifestSize  int64
	skillVersion       string
	skillManifest      string
	skillManifestPart  int
	skillManifestParts int
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
	return emitEndpointInventory(ctx, cfg, reg, emitter, false, nil, nil)
}

// endpointInventoryCycle carries one publish cycle's shared identity and change
// gate through the six collection emissions.
//
// A zero value is the ungated path: a fresh scan id is minted per collection and
// nothing is suppressed, which is what every non-managed caller gets.
type endpointInventoryCycle struct {
	scanID string
	cycle  *managedInventoryPublishCycle
}

// endpointInventoryCycleScanID derives one scan id for the whole cycle so the
// cloud can recognize the collections of a single bundle as a set — and tie them
// to the per-signal snapshot from the same discovery scan — instead of six
// unrelated arrivals under six unrelated ids.
func endpointInventoryCycleScanID(discoveryScanID string) string {
	if discoveryScanID == "" {
		return "inventory-" + uuid.NewString()
	}
	return "inventory-" + discoveryScanID
}

// aiDiscoveryResultPartial is the inventory.AIDiscoverySummary.Result value a
// scan reports when it did not complete cleanly. internal/inventory sets it
// whenever the scan recorded any error at all, including a single detector that
// failed and therefore contributed none of its signals.
const aiDiscoveryResultPartial = "partial"

// aiDiscoveryReportComplete reports whether a discovery report enumerated the
// endpoint exhaustively enough to anchor the daily complete bundle.
//
// A partial report under-enumerates the collections derived from it. Publishing
// that truncated view is still correct and self-correcting — the next complete
// scan produces a different digest and republishes in full — but treating it as
// the day's bundle is not: the cloud would hold an incomplete copy and the real
// bundle would stay suppressed for another interval.
func aiDiscoveryReportComplete(report *inventory.AIDiscoveryReport) bool {
	if report == nil || strings.TrimSpace(report.Summary.ScanID) == "" {
		return false
	}
	result := strings.TrimSpace(report.Summary.Result)
	return result != "" && !strings.EqualFold(result, aiDiscoveryResultPartial)
}

func emitEndpointInventory(
	ctx context.Context,
	cfg *config.Config,
	reg *connector.Registry,
	emitter sidecarRuntimeEmitter,
	connectorDiscoveryPartial bool,
	discoveryReport *inventory.AIDiscoveryReport,
	gate *managedInventoryPublishState,
	toolStates ...*mcpToolInventory,
) error {
	if !ManagedEnterpriseActive() || ctx == nil || emitter == nil {
		return nil
	}
	// bundleScope: only a cycle carrying a COMPLETE discovery report may satisfy
	// the daily complete-bundle guarantee, and there are two ways to fail that.
	//
	// A reload or startup emit carries no report at all, so it cannot enumerate
	// the discovered MCP / skill / plugin collections below. A partial report
	// enumerates a truncated set for those same three. Either way the bundle is
	// incomplete, so stamping the clock would hand the cloud a partial copy and
	// then suppress the real bundle for another interval.
	discoveryScanID := ""
	if discoveryReport != nil {
		discoveryScanID = strings.TrimSpace(discoveryReport.Summary.ScanID)
	}
	publish := endpointInventoryCycle{
		scanID: endpointInventoryCycleScanID(discoveryScanID),
		cycle: gate.beginCycle(
			discoveryScanID, time.Now().UTC(), aiDiscoveryReportComplete(discoveryReport),
		),
	}
	// One write per cycle at most, and none at all in steady state.
	defer publish.cycle.commit()

	connectorComponents, connectorPartial := endpointConnectorComponents(reg)
	firstErr := emitEndpointInventorySnapshot(
		ctx,
		emitter,
		endpointConnectorInventorySource,
		connectorComponents,
		connectorPartial || connectorDiscoveryPartial,
		config.ObservabilityV8ManagedConnectorInventoryAction,
		publish,
	)

	mcpComponents, partial := endpointMCPComponents(cfg)
	if err := emitEndpointInventorySnapshot(
		ctx, emitter, endpointMCPInventorySource, mcpComponents, partial,
		config.ObservabilityV8ManagedMCPInventoryAction, publish,
	); err != nil && firstErr == nil {
		firstErr = err
	}

	// Collect the connector-native MCP inventory before processing the
	// discovery report. A discovery signal can describe the same component as
	// the native reader, but it cannot carry transport, URL, or local command
	// fingerprints. When the native collection is complete it is authoritative
	// for an exact component-id match, so the thinner discovery row must not be
	// published later and overwrite those fields downstream. On a partial read
	// keep the discovery row as a fail-open fallback; partial native snapshots
	// are local diagnostics and do not reach the managed AI Defense route.
	var toolState *mcpToolInventory
	if len(toolStates) > 0 {
		toolState = toolStates[0]
	}
	readMCP := func() ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
		return perConnectorMCPEntriesWithReadStatus(cfg, reg)
	}
	var perConnectorMCP []endpointInventoryComponent
	var perConnectorStatus perConnectorMCPReadStatus
	if toolState != nil {
		perConnectorMCP, perConnectorStatus = toolState.readAndReconcileParents(ctx, readMCP)
	} else {
		perConnectorMCP, perConnectorStatus = readMCP()
	}
	perConnectorPartial := perConnectorStatus.partial

	// Per-entry inventories derived from the latest AI-Discovery scan. Each
	// enumerated skill / plugin / MCP server ships as its own
	// ai_component.observed record with defenseclaw.agent.discovery.connector
	// pointing at the parent connector (e.g. codex, claudecode) so downstream
	// can correlate skills / plugins / MCP servers with their owning agent.
	// managed_enterprise gates the whole function above, so this whole block
	// is inert in unmanaged mode.
	if discoveryReport != nil {
		discoveryPartial := !aiDiscoveryReportComplete(discoveryReport)
		mcpEntries := discoveredMCPEntriesFromReport(*discoveryReport)
		mcpEntries = preferNativeMCPInventory(mcpEntries, perConnectorMCP, perConnectorPartial)
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_discovered_mcp_inventory", mcpEntries, discoveryPartial,
			config.ObservabilityV8ManagedMCPInventoryAction, publish,
		); err != nil && firstErr == nil {
			firstErr = err
		}
		// A failure in another detector does not make the skill collection
		// partial. An incomplete skill scan stays diagnostic and cannot advance
		// the endpoint's last successfully published skill state.
		skillsComplete := skillScanComplete(discoveryReport)
		skillEntries := publish.cycle.trackSkills(
			discoveredEntriesFromReport(*discoveryReport, inventory.SignalSkill, "skill"),
			skillsComplete,
		)
		var removalErr error
		skillEntries, removalErr = prepareManagedSkillSnapshot(ctx, emitter, skillEntries, skillsComplete, publish)
		if removalErr != nil && firstErr == nil {
			firstErr = removalErr
		}
		// A partial skill list cannot prune saved receipts or advance a manifest.
		if skillsComplete && managedInventorySnapshotEligible(endpointSkillInventorySource, config.ObservabilityV8ManagedSkillInventoryAction, skillEntries) && cfg != nil && cfg.AIDiscovery.IncludeSkillManifests {
			publish.cycle.refreshManifestReceipts(ctx, emitter, skillEntries)
			publish.cycle.attachSkillManifests(skillEntries)
		}
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, endpointSkillInventorySource, skillEntries, !skillsComplete,
			config.ObservabilityV8ManagedSkillInventoryAction, publish,
		); err != nil && firstErr == nil {
			firstErr = err
		}
		pluginEntries := discoveredEntriesFromReport(*discoveryReport, inventory.SignalPlugin, "plugin")
		if err := emitEndpointInventorySnapshot(
			ctx, emitter, "endpoint_plugin_inventory", pluginEntries, discoveryPartial,
			config.ObservabilityV8ManagedPluginInventoryAction, publish,
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
	//
	// The empty case publishes too, matching the collections above. A zero-count
	// snapshot is how this collection reports that its last entry is gone, and
	// its stable empty digest is what supersedes previously published rows.
	// Skipping it would leave the cloud holding removed MCP servers forever — the
	// stored digest would never advance past the last non-empty publish — and
	// would silently drop the collection from the daily complete bundle.
	const perConnectorMCPSource = "endpoint_per_connector_mcp_inventory"
	var completeRows []endpointInventoryComponent
	acceptedParentIDs := make(map[string]struct{})
	if perConnectorPartial {
		// A partial aggregate is not an authoritative snapshot, but connectors
		// whose native reads completed still carry independently validated server
		// records. Publish those records as additive observations so their tools
		// do not reference a parent that only exists locally. The partial snapshot
		// below remains diagnostic-only and keeps the collection digest and daily
		// bundle clock unchanged; an incomplete connector can therefore neither
		// suppress a complete sibling nor cause its retained cloud rows to be
		// removed.
		completeRows = completeConnectorMCPEntriesFromPartial(perConnectorMCP, perConnectorStatus.incompleteConnectors)
		var err error
		acceptedParentIDs, err = emitEndpointInventoryComponents(
			ctx, emitter, perConnectorMCPSource, completeRows,
			config.ObservabilityV8ManagedMCPInventoryAction, publish,
		)
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	parentSnapshotErr := emitEndpointInventorySnapshot(
		ctx, emitter, perConnectorMCPSource, perConnectorMCP, perConnectorPartial,
		config.ObservabilityV8ManagedMCPInventoryAction, publish,
	)
	if parentSnapshotErr != nil && firstErr == nil {
		firstErr = parentSnapshotErr
	}
	fullParentSnapshotCovered := false
	if !perConnectorPartial && len(perConnectorMCP) <= maxManagedMCPInventory {
		if publish.cycle == nil {
			fullParentSnapshotCovered = parentSnapshotErr == nil
		} else {
			digest := managedInventoryComponentsDigest(perConnectorMCPSource, perConnectorMCP)
			fullParentSnapshotCovered = publish.cycle.covers(perConnectorMCPSource, digest)
		}
	}
	managedParentIDs := managedMCPParentIDs(perConnectorMCP, acceptedParentIDs, fullParentSnapshotCovered)
	if toolState != nil {
		incompleteConnectors := perConnectorStatus.incompleteConnectors
		if err := toolState.flushPendingAdvertised(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		if err := toolState.flushPendingObserved(ctx); err != nil && firstErr == nil {
			firstErr = err
		}
		observedReadPartial := toolState.observedIncomplete(incompleteConnectors)
		if perConnectorPartial && len(perConnectorStatus.incompleteConnectors) == 0 {
			// A partial result without connector attribution is not safe to scope.
			observedReadPartial = true
		}
		for _, collection := range []struct {
			source     string
			remote     bool
			toolSource string
		}{
			{"endpoint_local_mcp_tool_inventory", false, "advertised"},
			{"endpoint_remote_mcp_tool_inventory", true, "advertised"},
			{"endpoint_local_mcp_observed_tool_inventory", false, "observed"},
			{"endpoint_remote_mcp_observed_tool_inventory", true, "observed"},
		} {
			rows, toolPartial := toolState.components(perConnectorMCP, collection.remote, collection.toolSource)
			parentsEligible := mcpToolParentsManaged(rows, managedParentIDs)
			readPartial := perConnectorPartial
			if collection.toolSource == "observed" {
				readPartial = observedReadPartial
			}
			// A child can use the managed route only when its parent did too. In
			// particular, an over-limit parent collection is diagnostic-only even
			// when a small child collection would pass its independent limit.
			snapshotPartial := readPartial || toolPartial || !parentsEligible
			err := emitEndpointInventorySnapshot(ctx, emitter, collection.source, rows, snapshotPartial,
				config.ObservabilityV8ManagedMCPInventoryAction, publish)
			if err != nil && firstErr == nil {
				firstErr = err
			}
			outcome, reason := "submitted", "none"
			switch {
			case err != nil:
				outcome, reason = "error", "publish_error"
			case snapshotPartial:
				outcome, reason = "partial", "incomplete"
			case len(rows) == 0:
				outcome = "empty"
			}
			toolState.recordMetric(ctx, "export", outcome, reason)
		}
	}
	return firstErr
}

func managedMCPParentIDs(
	all []endpointInventoryComponent,
	accepted map[string]struct{},
	fullSnapshotCovered bool,
) map[string]struct{} {
	eligible := make(map[string]struct{}, len(all))
	if len(all) > maxManagedMCPInventory {
		return eligible
	}
	for _, parent := range all {
		if fullSnapshotCovered {
			eligible[parent.id] = struct{}{}
			continue
		}
		if _, ok := accepted[parent.id]; ok {
			eligible[parent.id] = struct{}{}
		}
	}
	return eligible
}

func mcpToolParentsManaged(rows []endpointInventoryComponent, eligible map[string]struct{}) bool {
	for _, row := range rows {
		if _, ok := eligible[row.mcpToolParentID]; !ok {
			return false
		}
	}
	return true
}

func completeConnectorMCPEntriesFromPartial(
	components []endpointInventoryComponent,
	incompleteConnectors map[string]struct{},
) []endpointInventoryComponent {
	// A partial result without connector attribution cannot be scoped safely.
	if len(components) == 0 || len(incompleteConnectors) == 0 {
		return nil
	}
	complete := make([]endpointInventoryComponent, 0, len(components))
	for _, component := range components {
		connectorName := canonicalConnectorRulePackKey(component.agentConnector)
		if connectorName == "" {
			continue
		}
		if _, incomplete := incompleteConnectors[connectorName]; incomplete {
			continue
		}
		complete = append(complete, component)
	}
	return complete
}

// preferNativeMCPInventory removes discovery-derived MCP entries that would
// shadow a richer connector-native component with the same stable id. Native
// inventory only takes precedence when its scan is complete and eligible for
// the managed route; a partial, over-limit, or invalid native snapshot is
// diagnostic-only, so discovery entries remain available as a managed fallback.
func preferNativeMCPInventory(
	discovered, native []endpointInventoryComponent,
	nativePartial bool,
) []endpointInventoryComponent {
	if nativePartial || len(discovered) == 0 || len(native) == 0 {
		return discovered
	}
	if len(native) > managedInventoryLimit(config.ObservabilityV8ManagedMCPInventoryAction) {
		return discovered
	}
	if _, ok := endpointInventoryCarrierFor(config.ObservabilityV8ManagedMCPInventoryAction, native); !ok {
		return discovered
	}
	nativeIDs := make(map[string]struct{}, len(native))
	for _, component := range native {
		if component.id != "" {
			nativeIDs[component.id] = struct{}{}
		}
	}
	filtered := make([]endpointInventoryComponent, 0, len(discovered))
	for _, component := range discovered {
		if _, shadowed := nativeIDs[component.id]; shadowed {
			continue
		}
		filtered = append(filtered, component)
	}
	return filtered
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
func perConnectorMCPEntriesWithStatus(cfg *config.Config, reg *connector.Registry) ([]endpointInventoryComponent, bool) {
	components, status := perConnectorMCPEntriesWithReadStatus(cfg, reg)
	return components, status.partial
}

func perConnectorMCPEntriesForOSWithStatus(cfg *config.Config, reg *connector.Registry, goos string) ([]endpointInventoryComponent, bool) {
	components, status := perConnectorMCPEntriesForOSWithReadStatus(cfg, reg, goos)
	return components, status.partial
}

func perConnectorMCPEntriesForOSWithHomeGuard(cfg *config.Config, reg *connector.Registry, goos string, homeGuard func(string) error) ([]endpointInventoryComponent, bool) {
	components, status := perConnectorMCPEntriesForOSWithHomeGuardStatus(cfg, reg, goos, homeGuard)
	return components, status.partial
}

type perConnectorMCPReadStatus struct {
	partial              bool
	incompleteConnectors map[string]struct{}
}

// readAndReconcileParents serializes the native read, parent replacement, and
// durable retirement as one state transition. A slower older emit therefore
// cannot resume after a newer read and delete the newer parents' tool rows.
func (m *mcpToolInventory) readAndReconcileParents(
	ctx context.Context,
	read func() ([]endpointInventoryComponent, perConnectorMCPReadStatus),
) ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
	if m == nil || read == nil {
		return nil, perConnectorMCPReadStatus{partial: true}
	}
	m.reconcileMu.Lock()
	defer m.reconcileMu.Unlock()
	components, status := read()
	m.retryRestoreFromStore(ctx)
	unscopedPartial := status.partial && len(status.incompleteConnectors) == 0
	var removed []string
	if !unscopedPartial {
		removed = m.refreshCompleteParents(components, status.incompleteConnectors)
	}
	if m.store != nil && len(removed) > 0 {
		if err := m.store.DeleteMCPObservedToolsForParents(ctx, removed); err == nil {
			m.acknowledgeRemovedParents(removed)
		}
	}
	return components, status
}

func (s *perConnectorMCPReadStatus) markIncomplete(connectorName string) {
	s.partial = true
	key := canonicalConnectorRulePackKey(connectorName)
	if key == "" {
		return
	}
	if s.incompleteConnectors == nil {
		s.incompleteConnectors = make(map[string]struct{})
	}
	s.incompleteConnectors[key] = struct{}{}
}

func perConnectorMCPEntriesWithReadStatus(cfg *config.Config, reg *connector.Registry) ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
	return perConnectorMCPEntriesForOSWithReadStatus(cfg, reg, runtime.GOOS)
}

func perConnectorMCPEntriesForOSWithReadStatus(cfg *config.Config, reg *connector.Registry, goos string) ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
	return perConnectorMCPEntriesForOSWithHomeGuardStatus(cfg, reg, goos, managed.RequireWindowsGatewayPathOutsideUserProfiles)
}

func perConnectorMCPEntriesForOSWithHomeGuardStatus(cfg *config.Config, reg *connector.Registry, goos string, homeGuard func(string) error) ([]endpointInventoryComponent, perConnectorMCPReadStatus) {
	status := perConnectorMCPReadStatus{}
	if cfg == nil {
		status.partial = true
		return nil, status
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
		if key == "" || !inventoryConnectorAvailableOnOS(key, goos) {
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
			if key == "" || !inventoryConnectorAvailableOnOS(key, goos) {
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
		return nil, status
	}
	fingerprintKey := mcpInventoryFingerprintKey(cfg)
	// homes = daemon's own HOME (via ReadMCPServersForConnector) plus every
	// configured user home (via direct-path readers). Empty homes list falls
	// back to the single ReadMCPServersForConnector path.
	homes := cfg.AIDiscovery.HomeDirs
	seenComponent := make(map[string]struct{})
	components := make([]endpointInventoryComponent, 0, len(connectors)*(len(homes)+1))
	// Owner lookups hit the passwd database or the ProfileList registry and
	// read a credential file, so they are memoized for the scan: the loops
	// below revisit the same home once per connector.
	owners := map[string]llmEventUser{}
	ownerFor := func(connectorName, home string) llmEventUser {
		if home == "" {
			return llmEventUser{}
		}
		key := connectorName + "\x00" + home
		if cached, ok := owners[key]; ok {
			return cached
		}
		owner := inventoryHomeOwner(connectorName, home)
		owners[key] = owner
		return owner
	}
	appendServers := func(connectorName, homeScope, home string, servers []config.MCPServerEntry) {
		slug := inventoryStableToken(connectorName, 128)
		owner := ownerFor(connectorName, home)
		for _, server := range servers {
			command := inventorySafeBasename(server.Command)
			commandFingerprint, argumentsFingerprint := mcpInventoryLocalFingerprints(fingerprintKey, server)
			serverURL := mcpInventoryServerURL(server.URL)
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
			// Keep the pre-fingerprint component identity stable across upgrades
			// and configuration changes. Fingerprints are change-detection
			// attributes, not identity: rotating the gateway token or updating a
			// command, arguments, or URL must not replace the server and its tool
			// history. Connector and home scope separate same-named entries owned
			// by different agents or users.
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
				id:                      endpointInventoryComponentID("mcp-entry", identity),
				componentType:           "mcp_server",
				signal:                  "configured_mcp_server",
				product:                 product,
				active:                  !disabled,
				itemName:                name,
				mcpTransport:            inventoryStableToken(server.Transport, 64),
				mcpCommandBasename:      command,
				mcpCommandFingerprint:   commandFingerprint,
				mcpArgumentsFingerprint: argumentsFingerprint,
				mcpSourceScope:          inventoryStableToken(server.SourceScope, 64),
				mcpServerURL:            serverURL,
				mcpIsRemote:             server.URL != "",
				mcpURLHost:              host,
				mcpAuthProviderType:     inventoryStableToken(server.AuthProviderType, 64),
				mcpDisabled:             &disabled,
				agentConnector:          slug,
				agentInstalled:          &installed,
				userID:                  owner.ID,
				userIDKind:              owner.IDKind,
				userName:                owner.Name,
				userEmail:               owner.Email,
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
		// Native readers check each file at its open, including links.
		servers, err := cfg.ReadMCPServersForConnector(connectorName)
		appendServers(connectorName, "", daemonHomeForInventoryAttribution(), servers)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			status.markIncomplete(connectorName)
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
		// The managed Windows LocalSystem gateway must not read a user's
		// profile. Treat that configured home as missing evidence for the
		// entire collection instead of probing each connector or publishing
		// an apparently complete snapshot that would remove its old rows.
		if homeGuard(home) != nil {
			for _, connectorName := range connectors {
				status.markIncomplete(connectorName)
			}
			continue
		}
		homeScope := endpointInventoryScopeKey(home)
		for _, connectorName := range connectors {
			groups, readPartial := readMCPServersUnderHomeForOSWithStatus(connectorName, home, goos)
			if readPartial {
				status.markIncomplete(connectorName)
			}
			var servers []config.MCPServerEntry
			// Native readers return sources in precedence order. A later file
			// cannot replace a name found in an earlier file. Entries within one
			// source may represent separate native project scopes.
			seenPriorNames := make(map[string]struct{})
			for _, group := range groups {
				for _, server := range group {
					if _, seen := seenPriorNames[server.Name]; seen {
						continue
					}
					servers = append(servers, server)
				}
				for _, server := range group {
					seenPriorNames[server.Name] = struct{}{}
				}
			}
			appendServers(connectorName, homeScope, home, servers)
		}
	}
	return components, status
}

// inventoryHomeOwner resolves who owns one profile directory, and which
// account they are signed into the connector as.
//
// The sidecar cannot use its own process identity here. It walks every profile
// root on the endpoint, and under a managed install it runs as a service
// account, so "the current user" is either the wrong user or no user at all.
func inventoryHomeOwner(connectorName, home string) llmEventUser {
	identity := useridentity.ForHome(home)
	ownerID := sanitizeLLMEventUser(identity.ID)
	owner := llmEventUser{
		ID:     ownerID,
		IDKind: useridentity.KindForID(ownerID),
		Name:   sanitizeLLMEventUser(identity.Name),
	}
	if owner.ID == "" {
		// Without a resolvable owner there is nobody to attribute the
		// address to, and emitting it alone would assert that someone on
		// this endpoint uses it without saying who.
		return llmEventUser{}
	}
	// This read is safe where the hook path's is not: home comes from the
	// operator-configured profile roots and its owner was just resolved by
	// stat'ing that directory, so no request influences whose file is opened.
	// It is still gated, because collecting the address at all is a privacy
	// decision independent of whether it can be attributed correctly.
	if UserEmailCollectionEnabled() {
		if email, err := useridentity.EmailForConnector(connectorName, home, nil); err == nil {
			owner.Email = email
		}
	}
	return owner
}

// discoveryUserEmail is the connector account address of a discovery
// signal's owner, read from that owner's own profile, while
// ai_discovery.include_user_email is on. A signal without an owner never
// carries one: the address would then name nobody on this endpoint.
func discoveryUserEmail(signal inventory.AISignal) string {
	if signal.UserID == "" || !UserEmailCollectionEnabled() {
		return ""
	}
	return signal.UserEmail
}

// discoveryUserIDKind is the id namespace of the account a signal belongs
// to: a uid from a Unix per-user scan, or the profile's SID from a managed
// Windows scan.
func discoveryUserIDKind(userID string) string {
	if userID == "" {
		return ""
	}
	if strings.HasPrefix(strings.ToUpper(userID), "S-1-") {
		return useridentity.KindWindowsSID
	}
	return useridentity.KindPOSIXUID
}

// inventoryIdentity is the directory attribution of the account an inventory
// record names. The gateway resolved that account itself (the scan's process
// owner or a profile directory's owner), never from anything a client sent,
// so its directory facts are reported as verified.
func inventoryIdentity(userID string) *llmEventIdentity {
	if userID == "" {
		return nil
	}
	if !identityFactsEnabled.Load() {
		return secureClientInventoryIdentity(userID)
	}
	return inventoryIdentityFacts(userID)
}

// inventoryIdentityFor is inventoryIdentity for a record that names the
// account it was found under. A POSIX uid can be handed to another account
// once the first is removed, so a removal record for the earlier account
// must not carry the new holder's verified directory facts (GAP-1233). The
// facts are attached only while the account database still gives the uid
// the full name the record was found under: the same uid and the same
// qualified name (alice@old.example is not alice@new.example). A record
// that names no account cannot prove it, so it gets no facts. A Windows SID
// is never reused, so it is not checked.
func inventoryIdentityFor(userID, userName string) *llmEventIdentity {
	if userID == "" {
		return nil
	}
	if !identityFactsEnabled.Load() {
		return secureClientInventoryIdentity(userID)
	}
	if useridentity.KindForID(userID) == useridentity.KindPOSIXUID {
		recorded, current := strings.TrimSpace(userName), strings.TrimSpace(userScopedIdentityName(userID))
		if recorded == "" || current == "" || !useridentity.EqualFold(current, recorded) {
			return nil
		}
	}
	return inventoryIdentityFacts(userID)
}

// inventoryTelemetryUserName keeps the short POSIX display name while the
// inventory record retains its full account spelling for holder validation.
// Windows account names keep their existing domain-qualified display form.
func inventoryTelemetryUserName(userID, userName string) string {
	if useridentity.KindForID(userID) == useridentity.KindPOSIXUID {
		return useridentity.BareAccountName(userName)
	}
	return userName
}

func inventoryIdentityFacts(userID string) *llmEventIdentity {
	facts, _ := verifiedIdentityDirectory(userID, true)
	if facts.Empty() {
		return nil
	}
	facts.Assurance = useridentity.AssuranceVerified
	return &llmEventIdentity{Directory: facts}
}

// daemonHomeForInventoryAttribution returns the profile the sidecar itself
// runs under, but only when that profile belongs to a person.
//
// The first inventory pass reads the daemon's own HOME, which covers dev runs
// and single-user installs where no profile roots are configured. Under a
// managed install that home belongs to the service account, and attributing
// its MCP configuration to that principal would put a row in the inventory
// claiming a service account uses an agent.
func daemonHomeForInventoryAttribution() string {
	if gatewayRunsAsServiceAccount() {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(home)
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
		"kiro",
		"devin",
		"copilot",
		"opencode",
		"amp",
		"antigravity":
		return true
	}
	return false
}

// readMCPServersUnderHomeForOS preserves the best-effort reader used by
// callers that do not publish authoritative inventory snapshots.
func readMCPServersUnderHomeForOS(connectorName, home, goos string) [][]config.MCPServerEntry {
	groups, _ := readMCPServersUnderHomeForOSWithStatus(connectorName, home, goos)
	return groups
}

// readMCPServersUnderHomeForOSWithStatus reads each native config source under
// home and reports whether an expected source was unreadable or invalid.
func readMCPServersUnderHomeForOSWithStatus(connectorName, home, goos string) ([][]config.MCPServerEntry, bool) {
	if home == "" {
		return nil, false
	}
	var results [][]config.MCPServerEntry
	partial := false
	tryFile := func(reader func(string) ([]config.MCPServerEntry, error), relPath string) {
		full := filepath.Join(home, relPath)
		if managed.RequireWindowsGatewayPathOutsideUserProfiles(full) != nil {
			partial = true
			return
		}
		// Some native readers wrap a missing file in a generic error, so
		// distinguish ordinary absence before asking them to parse it. A file
		// that disappears between these operations remains partial.
		if _, err := os.Lstat(full); err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				partial = true
			}
			return
		}
		entries, err := reader(full)
		if len(entries) > 0 {
			results = append(results, entries)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			partial = true
		}
	}
	tryHome := func(reader func(string) ([]config.MCPServerEntry, error)) {
		if managed.RequireWindowsGatewayPathOutsideUserProfiles(home) != nil {
			partial = true
			return
		}
		entries, err := reader(home)
		if len(entries) > 0 {
			results = append(results, entries)
		}
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			partial = true
		}
	}
	switch strings.ToLower(strings.TrimSpace(connectorName)) {
	case "codex":
		tryFile(config.ReadMCPFromCodexUserConfigTOML, ".codex/config.toml")
	case "claudecode":
		// Honor CLAUDE_CONFIG_DIR the same way readMCPServersClaudeCode does:
		// when the operator has redirected Claude Code to a custom directory,
		// the default `~/.claude/settings.json` and `~/.claude.json` files may
		// be stale or ignored by the CLI, so managed inventory must not emit
		// their servers. `.mcp.json` at the project root is unaffected because
		// it's the workspace-scope file the CLI reads regardless.
		if _, hasEnv := os.LookupEnv("CLAUDE_CONFIG_DIR"); !hasEnv {
			// ~/.claude.json holds both user-scope (top-level `mcpServers`)
			// and per-project local-scope (`projects.<path>.mcpServers`)
			// entries. Read the file once and take the union instead of
			// decoding the (often multi-megabyte) conversation-state file
			// twice. It comes before the settings.json block DefenseClaw
			// 0.8.x wrote: the first source wins a name, and Claude Code
			// reads ~/.claude.json (GAP-1340).
			tryFile(config.ReadMCPFromClaudeJSONBothScopes, ".claude.json")
			tryFile(config.ReadMCPFromClaudeSettings, ".claude/settings.json")
		}
		tryFile(config.ReadMCPFromDotMCPJSON, ".mcp.json")
	case "cursor":
		tryFile(config.ReadMCPFromDotMCPJSON, ".cursor/mcp.json")
	case "kiro":
		tryFile(config.ReadMCPFromDotMCPJSON, ".kiro/settings/mcp.json")
	case "devin":
		if strings.EqualFold(strings.TrimSpace(goos), "windows") {
			tryFile(config.ReadMCPFromDevinConfig, "AppData/Roaming/devin/mcp_config.json")
		} else {
			tryFile(config.ReadMCPFromDevinConfig, ".config/devin/mcp_config.json")
		}
	case "copilot":
		tryFile(config.ReadMCPFromDotMCPJSON, ".copilot/mcp-config.json")
	case "zeptoclaw":
		// zeptoclaw's own config is JSON with mcpServers at top level;
		// mcp.json is a legacy fallback location some installs use.
		tryFile(config.ReadMCPFromDotMCPJSON, ".zeptoclaw/config.json")
		tryFile(config.ReadMCPFromDotMCPJSON, ".zeptoclaw/mcp.json")
	case "hermes":
		// Hermes native config is YAML with `mcp.servers` at top level
		// (see cli/defenseclaw/config/hermes.yaml.template). Only the
		// YAML reader can decode this — the generic mcpServers reader
		// silently returns nothing. Fall back to the legacy .hermes/mcp.json
		// for pre-YAML installs.
		tryFile(func(p string) ([]config.MCPServerEntry, error) {
			return config.ReadMCPFromYAMLPath(p, []string{"mcp", "servers"}, []string{"mcpServers"})
		}, ".hermes/config.yaml")
		tryFile(config.ReadMCPFromDotMCPJSON, ".hermes/mcp.json")
	case "openclaw":
		tryFile(config.ReadMCPFromOpenClawConfig, ".openclaw/openclaw.json")
	case "antigravity":
		tryFile(config.ReadMCPFromDotMCPJSON, ".gemini/config/mcp_config.json")
		tryFile(config.ReadMCPFromDotMCPJSON, ".agents/mcp_config.json")
	case "opencode":
		tryHome(config.ReadMCPServersOpenCodeUnderHome)
	case "amp":
		tryHome(config.ReadMCPServersAMPUnderHome)
	}
	return results, partial
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
//
// gate is the managed_enterprise change gate; it is nil in every other
// deployment mode, and a nil gate publishes unconditionally as before.
func makeEndpointInventoryEmitter(
	cfg *config.Config,
	emitter sidecarRuntimeEmitter,
	snapshotFn func() inventory.AIDiscoveryReport,
	gate *managedInventoryPublishState,
	tools *mcpToolInventory,
) func(context.Context) {
	return func(ctx context.Context) {
		reg := connector.NewDefaultRegistry()
		partial := false
		if cfg != nil && cfg.PluginDir != "" {
			// A broken plugin directory must not hide built-in connectors or
			// masquerade as an authoritative complete inventory. The bounded
			// partial summary carries no path or loader error.
			if managed.RequireWindowsGatewayPathOutsideUserProfiles(cfg.PluginDir) != nil {
				partial = true
			} else {
				partial = reg.DiscoverPlugins(cfg.PluginDir) != nil
			}
		}
		var report *inventory.AIDiscoveryReport
		if snapshotFn != nil {
			snap := snapshotFn()
			if strings.TrimSpace(snap.Summary.ScanID) != "" {
				report = &snap
			}
		}
		_ = emitEndpointInventory(ctx, cfg, reg, emitter, partial, report, gate, tools)
	}
}

func endpointConnectorComponents(reg *connector.Registry) ([]endpointInventoryComponent, bool) {
	return endpointConnectorComponentsForOS(reg, runtime.GOOS)
}

func endpointConnectorComponentsForOS(reg *connector.Registry, goos string) ([]endpointInventoryComponent, bool) {
	if reg == nil {
		reg = getFallbackConnectorRegistry()
	}
	if reg == nil {
		return nil, true
	}
	available := reg.Available()
	components := make([]endpointInventoryComponent, 0, len(available))
	for _, info := range available {
		if !inventoryConnectorAvailableOnOS(info.Name, goos) {
			continue
		}
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

func inventoryConnectorAvailableOnOS(name, goos string) bool {
	status := connector.ConnectorSupportOnOS(strings.ToLower(strings.TrimSpace(name)), goos).Status
	return status == connector.PlatformSupported || status == connector.PlatformPreview
}

func endpointMCPComponents(cfg *config.Config) ([]endpointInventoryComponent, bool) {
	if cfg == nil {
		return nil, true
	}
	// ReadMCPServers guards each native config file, so an unreadable
	// profile file does not hide a separate outside-profile source.
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
	return endpointMCPComponentsFromServers(servers, mcpInventoryFingerprintKey(cfg)), false
}

func endpointMCPComponentsFromServers(servers []config.MCPServerEntry, fingerprintKey []byte) []endpointInventoryComponent {
	components := make([]endpointInventoryComponent, 0, len(servers))
	for _, server := range servers {
		command := inventorySafeBasename(server.Command)
		commandFingerprint, argumentsFingerprint := mcpInventoryLocalFingerprints(fingerprintKey, server)
		serverURL := mcpInventoryServerURL(server.URL)
		host := mcpURLHost(server.URL)
		name := inventorySafeItemName(server.Name, 256)
		product := inventoryStableIdentifier(name)
		if product == "" {
			product = command
		}
		if product == "" {
			product = host
		}
		// Preserve the historical alias-based component ID. Fingerprints and
		// sanitized endpoint fields describe configuration changes without
		// replacing the component or its child-tool history.
		identity := server.Name
		if strings.TrimSpace(identity) == "" {
			identity = strings.Join([]string{command, host}, "\x00")
		}
		disabled := server.Disabled
		components = append(components, endpointInventoryComponent{
			id:                      endpointInventoryComponentID("mcp", identity),
			componentType:           "mcp_server",
			signal:                  "configured_mcp_server",
			product:                 product,
			active:                  !disabled,
			itemName:                name,
			mcpTransport:            inventoryStableToken(server.Transport, 64),
			mcpCommandBasename:      command,
			mcpCommandFingerprint:   commandFingerprint,
			mcpArgumentsFingerprint: argumentsFingerprint,
			mcpSourceScope:          inventoryStableToken(server.SourceScope, 64),
			mcpServerURL:            serverURL,
			mcpIsRemote:             server.URL != "",
			mcpURLHost:              host,
			mcpAuthProviderType:     inventoryStableToken(server.AuthProviderType, 64),
			mcpDisabled:             &disabled,
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
	publish endpointInventoryCycle,
) error {
	return emitInventorySnapshot(
		ctx, emitter, source, "", components, partial,
		observability.SourceSystem, action, "endpoint_inventory", endpointInventoryDetector,
		publish,
	)
}

// emitEndpointInventoryComponents publishes independently complete rows from a
// partial collection without claiming that they form an authoritative
// snapshot. It deliberately emits no summary and stores no collection digest:
// callers must also emit the partial diagnostic snapshot so the cycle remains
// degraded until every connector can be read.
func emitEndpointInventoryComponents(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source string,
	components []endpointInventoryComponent,
	action observability.ProducerKey,
	publish endpointInventoryCycle,
) (map[string]struct{}, error) {
	accepted := make(map[string]struct{}, len(components))
	if len(components) == 0 || len(components) > managedInventoryLimit(action) {
		return accepted, nil
	}
	scanID := publish.scanID
	if scanID == "" {
		scanID = "inventory-" + uuid.NewString()
	}
	components = append([]endpointInventoryComponent(nil), components...)
	sort.SliceStable(components, func(left, right int) bool {
		if components[left].itemName != components[right].itemName {
			return components[left].itemName < components[right].itemName
		}
		return components[left].id < components[right].id
	})
	var firstErr error
	for _, component := range components {
		outcome, err := emitEndpointInventoryComponent(
			ctx, emitter, source, scanID, component,
			observability.SourceSystem, action, "endpoint_inventory", endpointInventoryDetector,
		)
		if managedInventoryPublishRejected(outcome) && publish.cycle != nil {
			publish.cycle.markDegraded()
		}
		if err == nil && !managedInventoryPublishRejected(outcome) {
			accepted[component.id] = struct{}{}
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return accepted, firstErr
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
	publish endpointInventoryCycle,
) error {
	scanID := publish.scanID
	if scanID == "" {
		scanID = "inventory-" + uuid.NewString()
	}
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
	carrier, eligible := managedInventorySnapshotCarrier(source, managedAction, components)
	action := managedAction
	if partial || !eligible {
		partial = true
		carrier = endpointInventoryCarrier{}
		action = config.ObservabilityV8LocalInventoryDiagnosticAction
	}
	// Change gate. Deliberately after the action decision above: a snapshot that
	// fell back to the local diagnostic action (partial, over-limit, or
	// carrier-rejected) never reaches the managed AI Defense route, so it must
	// publish as before but must NOT leave a digest behind — a stored digest is a
	// promise that the cloud holds that exact content — and it disqualifies the
	// cycle from satisfying the daily bundle.
	digest := ""
	gated := publish.cycle != nil && action != config.ObservabilityV8LocalInventoryDiagnosticAction
	switch {
	case gated:
		digest = managedInventoryComponentsDigest(source, components)
		if !publish.cycle.shouldPublish(source, digest) && !hasRemovedSkill(components) && !hasSkillManifest(components) {
			// Unchanged since the last successful publish and no bundle due:
			// emit neither the summary nor any component record.
			return nil
		}
	case publish.cycle != nil:
		publish.cycle.markDegraded()
	}
	summaryOutcome, firstErr := emitEndpointInventorySummary(
		ctx, emitter, source, scanID, scannedAt, len(components), active, partial,
		recordSource, action, phase, carrier,
	)
	// A nil error does not mean the managed AI Defense route received the record:
	// the managed projection is optional, and a profile or projection failure is
	// reported through the outcome while Emit still returns nil. Any such record
	// makes this collection's publish incomplete, so it must neither store a
	// digest nor count toward the daily bundle.
	managedRejected := managedInventoryPublishRejected(summaryOutcome)
	for _, component := range components {
		componentContext, current := publish.cycle.manifestEmissionContext(ctx, component)
		if !current {
			component.skillManifest = ""
			managedRejected = true
		}
		outcome, err := emitEndpointInventoryComponent(
			componentContext, emitter, source, scanID, component,
			recordSource, action, phase, detector,
		)
		if publish.cycle != nil && !managedInventoryPublishRejected(outcome) {
			publish.cycle.observeManifestProjection(component, outcome)
		}
		if managedInventoryPublishRejected(outcome) {
			managedRejected = true
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	if gated {
		if firstErr != nil || managedRejected {
			publish.cycle.markDegraded()
		} else {
			publish.cycle.recordPublished(source, digest, len(components))
		}
	}
	return firstErr
}

func managedInventorySnapshotCarrier(source string, action observability.ProducerKey, components []endpointInventoryComponent) (endpointInventoryCarrier, bool) {
	limit := managedInventoryComponentLimit(action, components)
	carrier, ok := endpointInventoryCarrierFor(action, components)
	if len(components) == 0 && strings.HasSuffix(source, "_mcp_tool_inventory") {
		carrier, ok = endpointInventoryCarrier{}, true
	}
	return carrier, ok && limit > 0 && len(components) <= limit
}

func managedInventorySnapshotEligible(source string, action observability.ProducerKey, components []endpointInventoryComponent) bool {
	_, eligible := managedInventorySnapshotCarrier(source, action, components)
	return eligible
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

func managedInventoryComponentLimit(action observability.ProducerKey, components []endpointInventoryComponent) int {
	if action == config.ObservabilityV8ManagedMCPInventoryAction &&
		(len(components) == 0 || components[0].componentType == "mcp_tool") {
		return maxMCPToolCollection
	}
	return managedInventoryLimit(action)
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
		if len(components) > 0 && components[0].componentType == "mcp_tool" {
			for _, component := range components {
				if component.componentType != "mcp_tool" || component.mcpToolParentID == "" || component.mcpToolSource == "" {
					return endpointInventoryCarrier{}, false
				}
			}
			return endpointInventoryCarrier{}, true
		}
		identifiers := make([]observability.TelemetryStructuredDefenseClawInventoryMcpIdentifier, 0, len(components))
		metadata := make([]observability.TelemetryStructuredDefenseClawInventoryMcpMetadataItem, 0, len(components))
		for _, component := range components {
			if component.componentType != "mcp_server" || component.mcpDisabled == nil {
				return endpointInventoryCarrier{}, false
			}
			identifiers = append(identifiers, observability.TelemetryStructuredDefenseClawInventoryMcpIdentifier{
				Name: component.itemName, URLHost: aiDiscoveryV8OptionalText(component.mcpURLHost),
				ServerURL:            aiDiscoveryV8OptionalText(component.mcpServerURL),
				CommandFingerprint:   aiDiscoveryV8OptionalText(component.mcpCommandFingerprint),
				ArgumentsFingerprint: aiDiscoveryV8OptionalText(component.mcpArgumentsFingerprint),
			})
			metadata = append(metadata, observability.TelemetryStructuredDefenseClawInventoryMcpMetadataItem{
				Transport:        aiDiscoveryV8OptionalText(component.mcpTransport),
				CommandBasename:  aiDiscoveryV8OptionalText(component.mcpCommandBasename),
				SourceScope:      aiDiscoveryV8OptionalText(component.mcpSourceScope),
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
) (pipeline.LocalLogOutcome, error) {
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
		return pipeline.LocalLogOutcome{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	return emitter.Emit(ctx, metadata, func(
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
}

func emitEndpointInventoryComponent(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	source, scanID string,
	component endpointInventoryComponent,
	recordSource observability.Source,
	action observability.ProducerKey,
	phase, detector string,
) (pipeline.LocalLogOutcome, error) {
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
		return pipeline.LocalLogOutcome{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
	return emitter.Emit(ctx, metadata, func(
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
		input := observability.LogAIComponentObservedInput{
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
			DefenseClawAIComponentVendor:                    aiDiscoveryV8OptionalText(component.vendor),
			DefenseClawAIComponentProduct:                   aiDiscoveryV8OptionalText(component.product),
			DefenseClawInventoryItemName:                    aiDiscoveryV8OptionalText(component.itemName),
			DefenseClawInventoryItemDescription:             aiDiscoveryV8OptionalText(component.itemDescription),
			UserID:                                          aiDiscoveryV8OptionalText(component.userID),
			DefenseClawUserIDKind:                           v8UserIDKind(component.userIDKind),
			DefenseClawUserName:                             v8UserName(inventoryTelemetryUserName(component.userID, component.userName), aiDiscoveryV8OptionalText),
			DefenseClawUserEmail:                            v8UserEmail(component.userEmail),
			DefenseClawInventoryConnectorSource:             aiDiscoveryV8OptionalText(component.connectorSource),
			DefenseClawInventoryConnectorToolInspectionMode: aiDiscoveryV8OptionalText(component.connectorToolInspectionMode),
			DefenseClawInventoryConnectorSubprocessPolicy:   aiDiscoveryV8OptionalText(component.connectorSubprocessPolicy),
			DefenseClawInventoryMcpTransport:                aiDiscoveryV8OptionalText(component.mcpTransport),
			DefenseClawInventoryMcpCommandBasename:          aiDiscoveryV8OptionalText(component.mcpCommandBasename),
			DefenseClawInventoryMcpCommandFingerprint:       aiDiscoveryV8OptionalText(component.mcpCommandFingerprint),
			DefenseClawInventoryMcpArgumentsFingerprint:     aiDiscoveryV8OptionalText(component.mcpArgumentsFingerprint),
			DefenseClawInventoryMcpSourceScope:              aiDiscoveryV8OptionalText(component.mcpSourceScope),
			DefenseClawInventoryMcpServerURL:                aiDiscoveryV8OptionalText(component.mcpServerURL),
			DefenseClawInventoryMcpToolParentID:             aiDiscoveryV8OptionalText(component.mcpToolParentID),
			DefenseClawInventoryMcpToolSource:               aiDiscoveryV8OptionalText(component.mcpToolSource),
			DefenseClawInventoryMcpToolObservedAt:           aiDiscoveryV8OptionalText(component.mcpToolObservedAt),
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
			DefenseClawAgentIdentityID:                      agentIdentityV8(inventoryAgentIdentityID(component.agentConnector, component.userID, component.userName)),
			DefenseClawInventorySkillContentHash:            aiDiscoveryV8OptionalText(component.skillContentHash),
			DefenseClawInventorySkillContentStatus:          aiDiscoveryV8OptionalText(component.skillContentStatus),
			DefenseClawInventorySkillState:                  aiDiscoveryV8OptionalText(component.skillState),
			DefenseClawInventorySkillFirstSeen:              aiDiscoveryV8OptionalText(component.skillFirstSeen),
			DefenseClawInventorySkillLastSeen:               aiDiscoveryV8OptionalText(component.skillLastSeen),
			DefenseClawInventorySkillScope:                  aiDiscoveryV8OptionalText(component.skillScope),
			DefenseClawInventorySkillLocation:               aiDiscoveryV8OptionalText(component.skillLocation),
			DefenseClawInventorySkillPublisher:              aiDiscoveryV8OptionalText(component.skillPublisher),
			DefenseClawInventorySkillPublisherSource:        aiDiscoveryV8OptionalText(component.skillPublisherSource),
			DefenseClawInventorySkillPlugin:                 aiDiscoveryV8OptionalText(component.skillPlugin),
			DefenseClawInventorySkillPluginVersion:          aiDiscoveryV8OptionalText(component.skillPluginVersion),
			DefenseClawInventorySkillPluginEnabled:          inventoryOptionalBool(component.skillPluginEnabled),
		}
		if len(component.skillAgents) > 0 {
			input.DefenseClawInventorySkillAgents = observability.Present(component.skillAgents)
		}
		if component.skillManifestHash != "" {
			input.DefenseClawInventorySkillManifestHash = observability.Present(component.skillManifestHash)
			input.DefenseClawInventorySkillManifestSize = observability.Present(component.skillManifestSize)
		}
		if component.skillVersion != "" {
			input.DefenseClawInventorySkillVersion = observability.Present(component.skillVersion)
		}
		if component.skillManifest != "" {
			input.DefenseClawInventorySkillManifest = observability.Present(component.skillManifest)
			input.DefenseClawInventorySkillManifestPart = observability.Present(int64(component.skillManifestPart))
			input.DefenseClawInventorySkillManifestParts = observability.Present(int64(component.skillManifestParts))
		}
		inventoryIdentityFor(component.userID, component.userName).applyTo(&input)
		return builder.BuildLogAIComponentObserved(input)
	})
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
	// Ungated: this path is request-driven (POST /api/v1/agents/discover), not
	// cadence-driven, so the caller expects a snapshot for every request. The
	// zero cycle mints its own scan id and suppresses nothing.
	return emitInventorySnapshot(
		ctx, emitter, source, report.ScannedAt, components, partial,
		recordSource, action, "agent_inventory", managedAgentInventoryDetector,
		endpointInventoryCycle{},
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
// signal produced by the AI-Discovery walker: the PathHash of the
// parent-surface row, the full home-prefixed path (see
// signalFromDirectoryChildren and signalFromMCPConfigPath) — reusing
// that hash means report-derived component IDs are stable across walker
// restarts even when the raw path-hash key rotates, and it costs zero
// extra hashing. Evidence is sorted by type and hash, so an entry row
// ("skill_entry" sorts before "skill") can come first; it is skipped,
// or every id in a folder would move when a sibling entry is added or
// removed. Returns "" when the signal has no evidence (walker bug guard).
func endpointInventoryScopeFromEvidence(evidence []inventory.AIEvidence) string {
	if len(evidence) == 0 {
		return ""
	}
	h := evidence[0].PathHash
	for _, ev := range evidence {
		if !strings.HasSuffix(ev.Type, "_entry") {
			h = ev.PathHash
			break
		}
	}
	// Trim the "hmac-sha256:" / "sha256:" prefix — the identity
	// hasher folds this token into the wider digest so the prefix
	// adds no information beyond length.
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

// mcpInventoryServerURL returns only the configured remote endpoint's origin.
// Paths, userinfo, query, and fragment are omitted because every one of those
// positions is used for bearer material in real MCP configurations. It does
// not contact the endpoint.
func mcpInventoryServerURL(raw string) string {
	canonical := mcpInventoryCanonicalRemoteEndpoint(raw)
	if canonical == "" {
		return ""
	}
	parsed, _ := url.Parse(canonical)
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Host)
}

// mcpInventoryCanonicalRemoteEndpoint is identity-only material. Callers must
// never export or persist it; use it only as input to a keyed fingerprint.
func mcpInventoryCanonicalRemoteEndpoint(raw string) string {
	parsed, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || parsed.Opaque != "" {
		return ""
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return ""
	}
	host := strings.ToLower(mcpURLHost(raw))
	if host == "" {
		return ""
	}
	endpoint := scheme + "://" + host + parsed.EscapedPath()
	if len(endpoint) > 1024 {
		return ""
	}
	return endpoint
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
	shared := map[string][]int{}
	for _, signal := range report.Signals {
		// A gone signal is the folder as the previous scan saw it: its
		// entries are not on the endpoint any more, or not in that form.
		if signal.Category != category || signal.State == inventory.AIStateGone {
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
			shared[scope+"/"+name] = append(shared[scope+"/"+name], len(components))
			components = append(components, endpointInventoryComponent{
				id:             endpointInventoryComponentID(kind+"-entry", signal.SignatureID+"/"+scope+"/"+name),
				componentType:  kind,
				signal:         inventoryStableToken(signal.SignatureID, 128),
				product:        inventoryStableToken(signal.Product, 128),
				vendor:         inventorySafeBounded(signal.Vendor, 256),
				active:         true,
				itemName:       name,
				agentConnector: connectorSlug,
				agentInstalled: &installed,
				userID:         signal.UserID,
				userIDKind:     discoveryUserIDKind(signal.UserID),
				userName:       signal.UserName,
				userEmail:      discoveryUserEmail(signal),
				// agent.discovery.config_path_hash requires sha256:<64hex>.
				// Our evidence.PathHash uses hmac-sha256:... which fails
				// that pattern, so leave it empty rather than fail record
				// build.
			})
			if facts := evidence.Skill; facts != nil {
				row := &components[len(components)-1]
				row.skillContentHash, row.skillContentStatus = facts.ContentHash, facts.ContentStatus
				row.skillScope, row.skillLocation = facts.Scope, facts.Location
				row.skillManifestHash = facts.ManifestHash
				if facts.ManifestHash != "" {
					row.skillManifestSize = facts.ManifestSize
				}
				row.itemDescription = inventorySafeBounded(facts.Description, 512)
				row.skillVersion = inventorySafeBounded(facts.Version, 64)
				applySkillPublisher(row, signal.Vendor, *facts)
			}
		}
	}
	if kind == "skill" {
		// One folder several agents read (~/.agents/skills) lists them all.
		for _, rows := range shared {
			var agents []string
			for _, row := range rows {
				if agent := components[row].agentConnector; agent != "" && !slices.Contains(agents, agent) {
					agents = append(agents, agent)
				}
			}
			sort.Strings(agents)
			for _, row := range rows {
				components[row].skillAgents = agents[:min(len(agents), 16)]
			}
		}
	}
	return components
}

// applySkillPublisher names the best publisher evidence the endpoint has: the
// agent vendor for a skill it ships, the plugin manifest author for a plugin
// skill, else the skill's own SKILL.md claim.
func applySkillPublisher(row *endpointInventoryComponent, vendor string, facts inventory.AISkillFacts) {
	row.skillPublisherSource = "unknown"
	if plugin := facts.Plugin; plugin != nil {
		row.skillPlugin, row.skillPluginVersion, row.skillPluginEnabled = plugin.ID, plugin.Version, plugin.Enabled
	}
	switch {
	case facts.Scope == inventory.SkillScopeBundled && vendor != "":
		row.skillPublisher, row.skillPublisherSource = inventorySafeBounded(vendor, 128), "vendor_bundled"
	case facts.Plugin != nil && facts.Plugin.Author != "":
		row.skillPublisher, row.skillPublisherSource = facts.Plugin.Author, "plugin_manifest"
	case facts.Author != "":
		row.skillPublisher, row.skillPublisherSource = facts.Author, "declared"
	}
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
				userID:         signal.UserID,
				userIDKind:     discoveryUserIDKind(signal.UserID),
				userName:       signal.UserName,
				userEmail:      discoveryUserEmail(signal),
			})
		}
	}
	return components
}
