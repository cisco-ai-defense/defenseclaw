// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	// ObservabilityV8ManagedAIDDestinationName is reserved for the
	// release-owned managed-enterprise log sink. It cannot appear in source.
	ObservabilityV8ManagedAIDDestinationName = "managed-enterprise-ai-defense"
	// ObservabilityV8ManagedAIDIngestPath is appended to the top-level managed
	// Cisco AI Defense endpoint. It is deliberately not configurable under the
	// observability destination schema.
	ObservabilityV8ManagedAIDIngestPath = "/api/v1/defenseclaw/events/ingest"

	observabilityV8ManagedAIDRedactionProfile = "sensitive"
	// ObservabilityV8ManagedAgentInventoryAction is the release-owned routing
	// identity for the sanitized coding-agent inventory. The generated managed
	// plan reserves it so the inventory remains locally durable and is exported
	// only through the CMID-authenticated AI Defense destination.
	ObservabilityV8ManagedAgentInventoryAction observability.ProducerKey = "managed_agent_inventory"
	// ObservabilityV8ManagedConnectorInventoryAction and
	// ObservabilityV8ManagedMCPInventoryAction reserve the other sanitized
	// endpoint-inventory collections to the same managed-only optional route.
	ObservabilityV8ManagedConnectorInventoryAction observability.ProducerKey = "managed_connector_inventory"
	ObservabilityV8ManagedMCPInventoryAction       observability.ProducerKey = "managed_mcp_inventory"
	// ObservabilityV8ManagedSkillInventoryAction and
	// ObservabilityV8ManagedPluginInventoryAction reserve routing identities
	// for the per-entry skill / plugin inventories the sidecar derives from
	// each AI-Discovery scan. Each entry ships as its own
	// ai_component.observed record with agent_connector set so downstream can
	// correlate skills / plugins with their parent agent (e.g. codex, claudecode).
	ObservabilityV8ManagedSkillInventoryAction  observability.ProducerKey = "managed_skill_inventory"
	ObservabilityV8ManagedPluginInventoryAction observability.ProducerKey = "managed_plugin_inventory"
	// ObservabilityV8LocalInventoryDiagnosticAction carries incomplete,
	// overflowed, or otherwise non-authoritative scans to local SQLite only.
	// It can never be projected as a managed inventory snapshot.
	ObservabilityV8LocalInventoryDiagnosticAction observability.ProducerKey = "local_inventory_diagnostic"
	// ObservabilityV8ManagedEndpointHealthAction is the release-owned routing
	// identity for the periodic platform.health endpoint health report. The
	// report carries the user.id of failing hook targets, so like the
	// inventory it stays in local SQLite and is exported only through the
	// CMID-authenticated AI Defense destination.
	ObservabilityV8ManagedEndpointHealthAction observability.ProducerKey = "endpoint_health"
)

// ObservabilityV8ManagedAIDOptions are release-owned inputs, not source
// destination fields. Callers obtain them from the validated top-level config.
type ObservabilityV8ManagedAIDOptions struct {
	DeploymentMode string
	// Profile is the resolved enterprise profile. Only the Secure Client
	// profile has the CMID-authenticated destination; a standalone
	// deployment exports to the administrator's own destinations.
	Profile  string
	Endpoint string
	// SourceContentHash is sha256 over the exact accepted config source bytes.
	// It is a runtime-generation binding, not a user-configurable destination
	// field and not the masked observability plan digest.
	SourceContentHash string
}

// WithObservabilityV8ManagedAIDDestination returns an immutable successor plan
// with the service-owned CMID destination when and only when the top-level
// deployment is managed_enterprise and its Cisco AI Defense endpoint is
// nonempty. The source destination vocabulary cannot construct, disable,
// retarget, or attach credentials to this route.
//
// The route deliberately applies the built-in sensitive profile to every
// collected log bucket. A per-inspection cloud directive that is represented
// by a canonical producer must be resolved before routing; absent such a
// directive, this destination fails closed to the sensitive projection.
func WithObservabilityV8ManagedAIDDestination(
	plan *ObservabilityV8Plan,
	options ObservabilityV8ManagedAIDOptions,
) (*ObservabilityV8Plan, error) {
	if plan == nil || !managed.IsManagedEnterprise(options.DeploymentMode) ||
		managed.IsStandaloneProfile(options.Profile) {
		return plan, nil
	}
	if options.Endpoint == "" {
		// No managed destination yet, but the endpoint health report must
		// still never reach an operator destination: a report built while a
		// reload clears the endpoint can be emitted on this plan.
		return withObservabilityV8ManagedEndpointHealthReserved(plan)
	}
	origin, ok := observabilityV8ManagedAIDOrigin(options.Endpoint)
	if !ok {
		return nil, &observabilityV8ManagedAIDPlanError{}
	}
	if options.SourceContentHash != "" && !validObservabilityV8SourceContentHash(options.SourceContentHash) {
		return nil, &observabilityV8ManagedAIDPlanError{}
	}
	effective := cloneObservabilityV8EffectivePlan(plan.effective)
	endpoint := origin + ObservabilityV8ManagedAIDIngestPath
	for index, destination := range effective.Destinations {
		if destination.Name == ObservabilityV8ManagedAIDDestinationName {
			// A generated destination is idempotent. Any other occurrence is a
			// compiler invariant violation and must not be silently replaced.
			if destination.Generated && validObservabilityV8ManagedAIDIdentity(destination) &&
				destination.Transport.Endpoint == endpoint &&
				observabilityV8ManagedAIDRequiredLogsCollected(effective) {
				if options.SourceContentHash == "" ||
					destination.managedAIDSourceContentHash == options.SourceContentHash {
					return plan, nil
				}
				effective.Destinations[index].managedAIDSourceContentHash = options.SourceContentHash
				return newObservabilityV8Plan(effective)
			}
			return nil, &observabilityV8ManagedAIDPlanError{}
		}
	}
	if len(effective.Destinations) >= ObservabilityV8MaxDestinations+1 {
		return nil, &observabilityV8ManagedAIDPlanError{}
	}
	if !forceObservabilityV8ManagedAIDRequiredLogCollection(&effective) {
		return nil, &observabilityV8ManagedAIDPlanError{}
	}
	reserveObservabilityV8ManagedInventory(&effective)

	profiles := make(map[observability.Bucket]string, len(effective.Buckets))
	buckets := make([]observability.Bucket, 0, len(effective.Buckets))
	for _, bucket := range effective.Buckets {
		buckets = append(buckets, bucket.Bucket)
		profiles[bucket.Bucket] = observabilityV8ManagedAIDRedactionProfile
	}
	destination := ObservabilityV8EffectiveDestination{
		Name:      ObservabilityV8ManagedAIDDestinationName,
		Kind:      ObservabilityV8DestinationOTLP,
		Enabled:   true,
		Generated: true,
		Capabilities: ObservabilityV8DestinationCapabilities{
			Signals: []observability.Signal{observability.SignalLogs},
		},
		SelectedSignals:     []observability.Signal{observability.SignalLogs},
		PolicyForm:          ObservabilityV8PolicyImplicitLocal,
		FirstMatchPerSignal: true,
		ReloadApplicability: ObservabilityV8EffectiveDestinationReload{
			Policy: ObservabilityV8RestartRequired, Transport: ObservabilityV8LiveReloadable,
		},
		Routes: []ObservabilityV8EffectiveRoute{
			{
				Index: 0, Name: "drop-local-inventory-diagnostics", Generated: true,
				Signals: []observability.Signal{observability.SignalLogs},
				Selector: ObservabilityV8EffectiveSelector{
					Buckets: []observability.Bucket{observability.BucketAIDiscovery},
					Actions: []observability.ProducerKey{ObservabilityV8LocalInventoryDiagnosticAction},
				},
				Action: ObservabilityV8RouteDrop,
			},
			// The old "drop-managed-inventory-components" route (agent /
			// connector inventory dropped by name at Index=1) existed
			// only to suppress raw v8 records while the managedaid
			// compatibility projector emitted them as v7
			// gatewaylog.Event wrappers on this same destination — a
			// deliberate mixed contract that Vineet flagged for
			// removal. Under the v8-only contract every ai.discovery
			// record now flows through as the original v8 OTLP log
			// (see managedaid/compatibility.go), so dropping them here
			// would silently strip the managed AID destination of its
			// inventory content.
			{
				Index: 1, Name: "all-collected-logs", Generated: true,
				Signals: []observability.Signal{observability.SignalLogs},
				Selector: ObservabilityV8EffectiveSelector{
					Buckets: buckets, BucketWildcard: true,
				},
				Action:                   ObservabilityV8RouteSend,
				RedactionProfileByBucket: profiles,
			}},
		Transport: ObservabilityV8TransportPlan{
			Endpoint: endpoint, Protocol: "http/json", Method: "POST",
			LoggerName: "defenseclaw", TimeoutMS: observabilityV8DefaultTimeoutMS,
			Batch: &ObservabilityV8BatchSource{
				MaxQueueSize:       observabilityV8DefaultQueueSize,
				MaxQueueBytes:      observabilityV8DefaultQueueBytes,
				MaxExportBatchSize: observabilityV8DefaultExportBatchSize,
				// OTLP/JSON string escaping can be larger than protobuf. Keep the
				// established process maximum so a valid maximum projection fits.
				MaxExportBatchBytes: observabilityV8MaxExportBatchBytes,
				ScheduledDelayMS:    observabilityV8DefaultBatchDelayMS,
			},
		},
		managedAIDSourceContentHash: options.SourceContentHash,
		managedAIDDeploymentAliasesOff: effective.TracePolicy.CompatibilityAliases != nil &&
			!*effective.TracePolicy.CompatibilityAliases,
	}
	effective.Destinations = append(effective.Destinations, destination)
	base := "observability.destinations." + ObservabilityV8ManagedAIDDestinationName
	effective.Provenance = append(effective.Provenance,
		ObservabilityV8Provenance{Path: base + ".name", Origin: "generated", Detail: "release-owned managed destination identity"},
		ObservabilityV8Provenance{Path: base + ".kind", Origin: "generated", Detail: "release-owned managed destination identity"},
		ObservabilityV8Provenance{Path: base + ".generated", Origin: "generated", Detail: "release-owned managed destination identity"},
		ObservabilityV8Provenance{Path: base + ".enabled", Origin: "generated", Detail: "managed-enterprise endpoint gate"},
		ObservabilityV8Provenance{Path: base + ".policy", Origin: "generated", Detail: "release-owned sensitive log route"},
		ObservabilityV8Provenance{Path: base + ".transport", Origin: "generated", Detail: "top-level cisco_ai_defense.endpoint"},
		ObservabilityV8Provenance{Path: base + ".reload_applicability", Origin: "reload-contract", Detail: "policy=restart_required,transport=live_reloadable"},
	)
	return newObservabilityV8Plan(effective)
}

// ObservabilityV8SourceContentHash returns the exact legacy-compatible source
// fingerprint used by a generated managed destination. It deliberately hashes
// raw bytes rather than canonicalized YAML so any accepted source change is
// reflected in the managed event provenance.
func ObservabilityV8SourceContentHash(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func validObservabilityV8SourceContentHash(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	for _, character := range value {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

// ObservabilityV8ManagedAIDSourceContentHash exposes only the hidden binding
// on the release-owned generated destination. Display JSON and plan digests do
// not reveal or substitute it.
func ObservabilityV8ManagedAIDSourceContentHash(
	destination ObservabilityV8EffectiveDestination,
) (string, bool) {
	value := destination.managedAIDSourceContentHash
	return value, destination.Generated && validObservabilityV8ManagedAIDIdentity(destination) &&
		validObservabilityV8SourceContentHash(value)
}

// ObservabilityV8ManagedAIDDeploymentAliases reports whether the managed AI
// Defense sink adds deployment.environment and deployment.mode to its
// resource. On main the provider added them while
// observability.trace_policy.compatibility_aliases was on (the default), so
// they follow that switch; only a Secure Client config_version 8 source can
// still turn it off. defenseclaw.device.id does not depend on it.
func ObservabilityV8ManagedAIDDeploymentAliases(destination ObservabilityV8EffectiveDestination) bool {
	return !destination.managedAIDDeploymentAliasesOff
}

// reserveObservabilityV8ManagedInventory prepends release-owned drop routes
// for the endpoint inventory and the endpoint health report to every
// operator-configured log destination. The required local SQLite
// destination is deliberately excluded so both remain durable; the
// managed destination is appended only after this pass and is therefore the
// sole optional exporter allowed to receive these actions.
func reserveObservabilityV8ManagedInventory(effective *ObservabilityV8EffectivePlan) {
	if effective == nil {
		return
	}
	for destinationIndex := range effective.Destinations {
		destination := &effective.Destinations[destinationIndex]
		if destination.Kind == ObservabilityV8DestinationLocalSQLite ||
			destination.Name == ObservabilityV8ManagedAIDDestinationName ||
			!destination.Capabilities.Supports(observability.SignalLogs) ||
			!observabilityV8SignalsContain(destination.SelectedSignals, observability.SignalLogs) {
			continue
		}
		for routeIndex := range destination.Routes {
			destination.Routes[routeIndex].Index = routeIndex + 2
		}
		destination.Routes = append([]ObservabilityV8EffectiveRoute{{
			Index: 0, Name: "drop-managed-endpoint-inventory", Generated: true,
			Signals: []observability.Signal{observability.SignalLogs},
			Selector: ObservabilityV8EffectiveSelector{
				Buckets: []observability.Bucket{observability.BucketAIDiscovery},
				Actions: []observability.ProducerKey{
					ObservabilityV8ManagedAgentInventoryAction,
					ObservabilityV8ManagedConnectorInventoryAction,
					ObservabilityV8ManagedMCPInventoryAction,
					// Per-item skill / plugin records are release-owned managed
					// inventory too — they carry endpoint identity that must
					// only reach the release-owned Cisco AI Defense destination,
					// never an operator-configured exporter.
					ObservabilityV8ManagedSkillInventoryAction,
					ObservabilityV8ManagedPluginInventoryAction,
					ObservabilityV8LocalInventoryDiagnosticAction,
				},
			},
			Action: ObservabilityV8RouteDrop,
		}, observabilityV8ManagedEndpointHealthDropRoute(1)}, destination.Routes...)
	}
}

const observabilityV8ManagedEndpointHealthDropRouteName = "drop-managed-endpoint-health"

// observabilityV8ManagedEndpointHealthDropRoute drops the endpoint health
// report. It lists the users whose hook targets are failing, so it is
// reserved to the managed destination.
func observabilityV8ManagedEndpointHealthDropRoute(index int) ObservabilityV8EffectiveRoute {
	return ObservabilityV8EffectiveRoute{
		Index: index, Name: observabilityV8ManagedEndpointHealthDropRouteName, Generated: true,
		Signals: []observability.Signal{observability.SignalLogs},
		Selector: ObservabilityV8EffectiveSelector{
			Buckets: []observability.Bucket{observability.BucketPlatformHealth},
			Actions: []observability.ProducerKey{ObservabilityV8ManagedEndpointHealthAction},
		},
		Action: ObservabilityV8RouteDrop,
	}
}

// ObservabilityV8PlanReservesEndpointHealth reports whether every operator
// log destination of plan drops the endpoint health report, so emitting it
// on plan can reach only local SQLite and the managed destination. The
// reporter checks the plan that routes each report, which closes the window
// where a reload swaps the plan after the reporter's config check.
func ObservabilityV8PlanReservesEndpointHealth(plan *ObservabilityV8Plan) bool {
	if plan == nil {
		return false
	}
	for _, destination := range plan.effective.Destinations {
		if destination.Kind == ObservabilityV8DestinationLocalSQLite ||
			destination.Name == ObservabilityV8ManagedAIDDestinationName ||
			!destination.Capabilities.Supports(observability.SignalLogs) ||
			!observabilityV8SignalsContain(destination.SelectedSignals, observability.SignalLogs) {
			continue
		}
		reserved := false
		for _, route := range destination.Routes {
			if route.Generated && route.Name == observabilityV8ManagedEndpointHealthDropRouteName {
				reserved = true
				break
			}
		}
		if !reserved {
			return false
		}
	}
	return true
}

// withObservabilityV8ManagedEndpointHealthReserved returns plan with the
// endpoint health drop route first on every operator log destination that
// lacks it, for a managed Secure Client plan compiled without the managed
// destination. It is idempotent.
func withObservabilityV8ManagedEndpointHealthReserved(plan *ObservabilityV8Plan) (*ObservabilityV8Plan, error) {
	effective := cloneObservabilityV8EffectivePlan(plan.effective)
	changed := false
	for destinationIndex := range effective.Destinations {
		destination := &effective.Destinations[destinationIndex]
		if destination.Kind == ObservabilityV8DestinationLocalSQLite ||
			destination.Name == ObservabilityV8ManagedAIDDestinationName ||
			!destination.Capabilities.Supports(observability.SignalLogs) ||
			!observabilityV8SignalsContain(destination.SelectedSignals, observability.SignalLogs) {
			continue
		}
		reserved := false
		for _, route := range destination.Routes {
			if route.Generated && route.Name == observabilityV8ManagedEndpointHealthDropRouteName {
				reserved = true
				break
			}
		}
		if reserved {
			continue
		}
		for routeIndex := range destination.Routes {
			destination.Routes[routeIndex].Index = routeIndex + 1
		}
		destination.Routes = append([]ObservabilityV8EffectiveRoute{
			observabilityV8ManagedEndpointHealthDropRoute(0),
		}, destination.Routes...)
		changed = true
	}
	if !changed {
		return plan, nil
	}
	return newObservabilityV8Plan(effective)
}

// observabilityV8ManagedAIDOrigin accepts only the release-owned base origin.
// The ingest path is appended below and can therefore never be supplied or
// influenced by source configuration.
func observabilityV8ManagedAIDOrigin(raw string) (string, bool) {
	if raw == "" || len(raw) > 2_048 || !utf8.ValidString(raw) ||
		strings.IndexFunc(raw, unicode.IsSpace) >= 0 {
		return "", false
	}
	parsed, err := url.Parse(raw)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.Host == "" ||
		parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.ForceQuery ||
		parsed.Fragment != "" || parsed.RawFragment != "" || strings.Contains(raw, "#") ||
		(parsed.Path != "" && parsed.Path != "/") ||
		(parsed.EscapedPath() != "" && parsed.EscapedPath() != "/") ||
		parsed.RawPath != "" || strings.HasSuffix(parsed.Host, ":") {
		return "", false
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.Atoi(port)
		if portErr != nil || value < 1 || value > 65_535 {
			return "", false
		}
	}
	return "https://" + parsed.Host, true
}

// forceObservabilityV8ManagedAIDRequiredLogCollection keeps the bounded
// platform-health and authoritative endpoint-inventory rails available to the
// release-owned managed destination. This is deliberately narrower than
// changing the global/default log policy: every other bucket, including the
// opt-in diagnostic bucket, retains the operator's compiled collection choice.
func forceObservabilityV8ManagedAIDRequiredLogCollection(
	effective *ObservabilityV8EffectivePlan,
) bool {
	if effective == nil {
		return false
	}
	required := map[observability.Bucket]string{
		observability.BucketPlatformHealth: "managed-enterprise AID fail-open availability collection",
		observability.BucketAIDiscovery:    "managed-enterprise endpoint inventory collection",
	}
	for index := range effective.Buckets {
		if _, ok := required[effective.Buckets[index].Bucket]; !ok {
			continue
		}
		effective.Buckets[index].Collect.Logs = true
	}
	for bucket, detail := range required {
		path := "observability.buckets." + string(bucket) + ".collect.logs"
		found := false
		for index := range effective.Provenance {
			if effective.Provenance[index].Path != path {
				continue
			}
			effective.Provenance[index] = ObservabilityV8Provenance{
				Path: path, Origin: "generated", Detail: detail,
			}
			found = true
			break
		}
		if !found {
			return false
		}
	}
	return true
}

func observabilityV8ManagedAIDRequiredLogsCollected(
	effective ObservabilityV8EffectivePlan,
) bool {
	required := map[observability.Bucket]bool{
		observability.BucketPlatformHealth: false,
		observability.BucketAIDiscovery:    false,
	}
	for _, bucket := range effective.Buckets {
		if _, ok := required[bucket.Bucket]; ok {
			required[bucket.Bucket] = bucket.Collect.Logs
		}
	}
	return required[observability.BucketPlatformHealth] && required[observability.BucketAIDiscovery]
}

func validObservabilityV8ManagedAIDIdentity(destination ObservabilityV8EffectiveDestination) bool {
	return destination.Name == ObservabilityV8ManagedAIDDestinationName &&
		destination.Kind == ObservabilityV8DestinationOTLP && destination.Generated &&
		len(destination.SelectedSignals) == 1 && destination.SelectedSignals[0] == observability.SignalLogs
}

type observabilityV8ManagedAIDPlanError struct{}

func (*observabilityV8ManagedAIDPlanError) Error() string {
	return "observability: generated managed-enterprise destination rejected"
}
