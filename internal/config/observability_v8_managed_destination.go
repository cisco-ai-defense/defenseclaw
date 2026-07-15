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
	// ObservabilityV8LocalInventoryDiagnosticAction carries incomplete,
	// overflowed, or otherwise non-authoritative scans to local SQLite only.
	// It can never be projected as a managed inventory snapshot.
	ObservabilityV8LocalInventoryDiagnosticAction observability.ProducerKey = "local_inventory_diagnostic"
)

// ObservabilityV8ManagedAIDOptions are release-owned inputs, not source
// destination fields. Callers obtain them from the validated top-level config.
type ObservabilityV8ManagedAIDOptions struct {
	DeploymentMode string
	Endpoint       string
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
	if plan == nil || !managed.IsManagedEnterprise(options.DeploymentMode) || options.Endpoint == "" {
		return plan, nil
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
			{
				Index: 1, Name: "drop-managed-inventory-components", Generated: true,
				Signals: []observability.Signal{observability.SignalLogs},
				Selector: ObservabilityV8EffectiveSelector{
					Buckets: []observability.Bucket{observability.BucketAIDiscovery},
					Actions: []observability.ProducerKey{
						ObservabilityV8ManagedAgentInventoryAction,
						ObservabilityV8ManagedConnectorInventoryAction,
						ObservabilityV8ManagedMCPInventoryAction,
					},
					EventNames: []observability.EventName{"ai_component.observed"},
				},
				Action: ObservabilityV8RouteDrop,
			},
			{
				Index: 2, Name: "all-collected-logs", Generated: true,
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
		if !(character >= '0' && character <= '9') && !(character >= 'a' && character <= 'f') {
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

// reserveObservabilityV8ManagedInventory prepends a release-owned drop route
// to every operator-configured log destination. The required local SQLite
// destination is deliberately excluded so inventory remains durable; the
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
			destination.Routes[routeIndex].Index = routeIndex + 1
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
					ObservabilityV8LocalInventoryDiagnosticAction,
				},
			},
			Action: ObservabilityV8RouteDrop,
		}}, destination.Routes...)
	}
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
