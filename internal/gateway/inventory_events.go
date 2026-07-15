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
	"path"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	return emitEndpointInventory(ctx, cfg, reg, emitter, false)
}

func emitEndpointInventory(
	ctx context.Context,
	cfg *config.Config,
	reg *connector.Registry,
	emitter sidecarRuntimeEmitter,
	connectorDiscoveryPartial bool,
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
	return firstErr
}

// makeEndpointInventoryEmitter rebuilds the connector registry for each
// snapshot so config reload and plugin changes are reflected. The emitter is a
// generation-owned v8 capability supplied by the active sidecar runtime.
func makeEndpointInventoryEmitter(
	cfg *config.Config,
	emitter sidecarRuntimeEmitter,
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
		_ = emitEndpointInventory(ctx, cfg, reg, emitter, partial)
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
