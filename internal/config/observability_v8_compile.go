// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"
	"math"
	"net"
	"net/netip"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"golang.org/x/text/unicode/norm"
)

const (
	observabilityV8DefaultRedactionProfile  = "none"
	observabilityV8DefaultSampler           = "parentbased_always_on"
	observabilityV8DefaultSemanticProfile   = observability.RuntimeSemanticProfileID
	observabilityV8DefaultMetricTemporality = "delta"
	observabilityV8DefaultTimeoutMS         = 10_000
	observabilityV8DefaultQueueSize         = 2_048
	observabilityV8DefaultQueueBytes        = 64 * 1_024 * 1_024
	observabilityV8DefaultExportBatchSize   = 512
	observabilityV8DefaultExportBatchBytes  = 8 * 1_024 * 1_024
	observabilityV8DefaultBatchDelayMS      = 5_000
	observabilityV8MaxQueueSize             = 65_536
	observabilityV8MinQueueBytes            = 4_198_400
	observabilityV8MaxQueueBytes            = 256 * 1_024 * 1_024
	observabilityV8MaxExportBatchSize       = 8_192
	observabilityV8MinExportBatchBytes      = 4_263_936
	observabilityV8MaxExportBatchBytes      = 64 * 1_024 * 1_024
	observabilityV8MaxBatchDelayMS          = 600_000
)

var (
	observabilityV8StableNamePattern  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	observabilityV8EnvNamePattern     = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]{0,255}$`)
	observabilityV8SelectorPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$`)
	observabilityV8ResourceKeyPattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_.-]{0,127}$`)
	observabilityV8HostnamePattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
	observabilityV8ReservedPrefixes   = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2001:2::/48"),
		netip.MustParsePrefix("2001:10::/28"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
)

// CompileObservabilityV8 validates and expands a typed source block into one
// deterministic, immutable effective plan. It performs no I/O, secret
// resolution, DNS lookup, exporter construction, or runtime mutation.
func CompileObservabilityV8(source *ObservabilityV8Source) (*ObservabilityV8Plan, error) {
	semanticProfileLock, err := resolveObservabilityV8SemanticLock()
	if err != nil {
		return nil, fmt.Errorf("observability.trace_policy.semantic_profile: %w", err)
	}
	if source == nil {
		source = &ObservabilityV8Source{}
	}
	if len(source.Destinations) > ObservabilityV8MaxSourceDestinations {
		return nil, fmt.Errorf("observability.destinations: got %d, maximum is %d", len(source.Destinations), ObservabilityV8MaxSourceDestinations)
	}
	if len(source.RedactionProfiles) > ObservabilityV8MaxRedactionProfiles {
		return nil, fmt.Errorf("observability.redaction_profiles: got %d, maximum is %d", len(source.RedactionProfiles), ObservabilityV8MaxRedactionProfiles)
	}
	if len(source.Connectors) > ObservabilityV8MaxMappingEntries {
		return nil, fmt.Errorf("observability.connectors: got %d entries, maximum is %d", len(source.Connectors), ObservabilityV8MaxMappingEntries)
	}
	catalogVersion, err := compileObservabilityV8CatalogVersion(source.BucketCatalogVersion)
	if err != nil {
		return nil, err
	}
	profiles, knownProfiles, err := compileObservabilityV8Profiles(source.RedactionProfiles)
	if err != nil {
		return nil, err
	}
	buckets, err := compileObservabilityV8Buckets(source.Defaults, source.Buckets, knownProfiles)
	if err != nil {
		return nil, err
	}
	tracePolicy, err := compileObservabilityV8TracePolicy(source.TracePolicy, semanticProfileLock)
	if err != nil {
		return nil, err
	}
	metricPolicy, err := compileObservabilityV8MetricPolicy(source.MetricPolicy)
	if err != nil {
		return nil, err
	}
	local, err := compileObservabilityV8Local(source.Local)
	if err != nil {
		return nil, err
	}
	resourceAttributeMap, resourceAttributes, err := compileObservabilityV8ResourceAttributes(
		source.Resource.Attributes,
		tracePolicy.CompatibilityAliases,
	)
	if err != nil {
		return nil, err
	}

	destinations := make([]ObservabilityV8EffectiveDestination, 0, len(source.Destinations)+1)
	destinations = append(destinations, compileObservabilityV8LocalDestination(buckets, local))
	seenDestinations := map[string]struct{}{ObservabilityV8LocalDestinationName: {}}
	totalRoutes := 0
	for index, destination := range source.Destinations {
		path := fmt.Sprintf("observability.destinations[%d]", index)
		compiled, explicitRoutes, err := compileObservabilityV8Destination(
			destination,
			path,
			buckets,
			knownProfiles,
			semanticProfileLock.GalileoCompatibilityProfile,
		)
		if err != nil {
			return nil, err
		}
		if _, duplicate := seenDestinations[compiled.Name]; duplicate {
			return nil, fmt.Errorf("%s.name: duplicate or reserved destination name %q", path, compiled.Name)
		}
		seenDestinations[compiled.Name] = struct{}{}
		totalRoutes += explicitRoutes
		if totalRoutes > ObservabilityV8MaxRoutesTotal {
			return nil, fmt.Errorf("observability.destinations.routes: got more than %d explicit advanced routes", ObservabilityV8MaxRoutesTotal)
		}
		destinations = append(destinations, compiled)
	}

	return newObservabilityV8Plan(ObservabilityV8EffectivePlan{
		BucketCatalogVersion:     catalogVersion,
		ResourceAttributes:       resourceAttributeMap,
		ResourceAttributeEntries: resourceAttributes,
		TracePolicy:              tracePolicy,
		MetricPolicy:             metricPolicy,
		Local:                    local,
		Buckets:                  buckets,
		Profiles:                 profiles,
		Destinations:             destinations,
		Warnings:                 compileObservabilityV8Warnings(local, destinations),
		Provenance:               compileObservabilityV8Provenance(source, buckets, profiles, destinations),
	})
}

func compileObservabilityV8CatalogVersion(source *int) (int, error) {
	if source == nil {
		return ObservabilityV8BucketCatalogVersion, nil
	}
	if *source != ObservabilityV8BucketCatalogVersion {
		return 0, fmt.Errorf("observability.bucket_catalog_version: unsupported value %d; supported value is %d", *source, ObservabilityV8BucketCatalogVersion)
	}
	return *source, nil
}

func compileObservabilityV8Buckets(defaults ObservabilityV8BucketPolicySource, overrides map[observability.Bucket]ObservabilityV8BucketPolicySource, knownProfiles map[string]struct{}) ([]ObservabilityV8EffectiveBucket, error) {
	if len(overrides) > ObservabilityV8MaxMappingEntries {
		return nil, fmt.Errorf("observability.buckets: too many entries")
	}
	if defaults.RedactionProfile != "" {
		if _, ok := knownProfiles[defaults.RedactionProfile]; !ok {
			return nil, fmt.Errorf("observability.defaults.redaction_profile: unknown profile %q", defaults.RedactionProfile)
		}
	}
	for bucket, policy := range overrides {
		if !observability.IsBucket(bucket) {
			return nil, fmt.Errorf("observability.buckets: unknown catalog-v1 bucket %q", bucket)
		}
		if policy.RedactionProfile != "" {
			if _, ok := knownProfiles[policy.RedactionProfile]; !ok {
				return nil, fmt.Errorf("observability.buckets.%s.redaction_profile: unknown profile %q", bucket, policy.RedactionProfile)
			}
		}
	}
	catalogBuckets := observability.Buckets()
	result := make([]ObservabilityV8EffectiveBucket, 0, len(catalogBuckets))
	for _, bucket := range catalogBuckets {
		collect := ObservabilityV8EffectiveCollect{Logs: true, Traces: true, Metrics: true}
		applyObservabilityV8Collect(&collect, defaults.Collect)
		profile := observabilityV8DefaultRedactionProfile
		if defaults.RedactionProfile != "" {
			profile = defaults.RedactionProfile
		}
		if override, ok := overrides[bucket]; ok {
			applyObservabilityV8Collect(&collect, override.Collect)
			if override.RedactionProfile != "" {
				profile = override.RedactionProfile
			}
		}
		result = append(result, ObservabilityV8EffectiveBucket{
			Bucket:              bucket,
			Collect:             collect,
			RedactionProfile:    profile,
			ReloadApplicability: ObservabilityV8LiveReloadable,
		})
	}
	return result, nil
}

func applyObservabilityV8Collect(target *ObservabilityV8EffectiveCollect, source ObservabilityV8CollectSource) {
	if source.Logs != nil {
		target.Logs = *source.Logs
	}
	if source.Traces != nil {
		target.Traces = *source.Traces
	}
	if source.Metrics != nil {
		target.Metrics = *source.Metrics
	}
}

func compileObservabilityV8Local(source ObservabilityV8LocalSource) (ObservabilityV8EffectiveLocal, error) {
	retentionDays := 90
	if source.RetentionDays != nil {
		retentionDays = *source.RetentionDays
	}
	if retentionDays < 0 {
		return ObservabilityV8EffectiveLocal{}, fmt.Errorf("observability.local.retention_days: must be zero or greater")
	}
	if retentionDays > ObservabilityV8MaxRetentionDays {
		return ObservabilityV8EffectiveLocal{}, fmt.Errorf(
			"observability.local.retention_days: got %d, maximum is %d",
			retentionDays,
			ObservabilityV8MaxRetentionDays,
		)
	}
	return ObservabilityV8EffectiveLocal{Path: source.Path, JudgeBodiesPath: source.JudgeBodiesPath, RetentionDays: retentionDays}, nil
}

func compileObservabilityV8TracePolicy(
	source ObservabilityV8TracePolicySource,
	semanticProfileLock ObservabilityV8SemanticProfileLock,
) (ObservabilityV8EffectiveTracePolicy, error) {
	result := ObservabilityV8EffectiveTracePolicy{
		Sampler: observabilityV8DefaultSampler, SemanticProfile: observabilityV8DefaultSemanticProfile,
		SemanticProfileLock: semanticProfileLock, CompatibilityAliases: true,
		Limits: ObservabilityV8TraceLimitsSource{MaxAttributesPerSpan: 128, MaxEventsPerSpan: 64, MaxLinksPerSpan: 32, MaxAttributesPerEvent: 32, MaxAttributeValueBytes: 16_384, MaxProjectedSpanBytes: 262_144, MaxStacktraceBytes: 32_768, MaxMessageItems: 128},
	}
	if source.Sampler != "" {
		result.Sampler = source.Sampler
	}
	if source.SemanticProfile != "" {
		result.SemanticProfile = source.SemanticProfile
	}
	if result.SemanticProfile != observabilityV8DefaultSemanticProfile {
		return ObservabilityV8EffectiveTracePolicy{}, fmt.Errorf("observability.trace_policy.semantic_profile: unsupported value %q", result.SemanticProfile)
	}
	if source.CompatibilityAliases != nil {
		result.CompatibilityAliases = *source.CompatibilityAliases
	}
	result.SamplerArg = source.SamplerArg
	if err := validateObservabilityV8Sampler(result.Sampler, result.SamplerArg); err != nil {
		return ObservabilityV8EffectiveTracePolicy{}, err
	}
	applyObservabilityV8TraceLimits(&result.Limits, source.Limits)
	if err := validateObservabilityV8TraceLimits(result.Limits); err != nil {
		return ObservabilityV8EffectiveTracePolicy{}, err
	}
	return result, nil
}

func validateObservabilityV8Sampler(sampler, argument string) error {
	switch sampler {
	case "always_on", "always_off", "parentbased_always_on", "parentbased_always_off":
		if argument != "" {
			return fmt.Errorf("observability.trace_policy.sampler_arg: not valid with sampler %q", sampler)
		}
	case "traceidratio", "parentbased_traceidratio":
		if argument == "" {
			return fmt.Errorf("observability.trace_policy.sampler_arg: required with sampler %q", sampler)
		}
		ratio, err := strconv.ParseFloat(argument, 64)
		if err != nil || math.IsNaN(ratio) || math.IsInf(ratio, 0) || ratio < 0 || ratio > 1 {
			return fmt.Errorf("observability.trace_policy.sampler_arg: must be a number from 0 through 1")
		}
	default:
		return fmt.Errorf("observability.trace_policy.sampler: unsupported value %q", sampler)
	}
	return nil
}

func applyObservabilityV8TraceLimits(target *ObservabilityV8TraceLimitsSource, source ObservabilityV8TraceLimitsSource) {
	if source.MaxAttributesPerSpan != 0 {
		target.MaxAttributesPerSpan = source.MaxAttributesPerSpan
	}
	if source.MaxEventsPerSpan != 0 {
		target.MaxEventsPerSpan = source.MaxEventsPerSpan
	}
	if source.MaxLinksPerSpan != 0 {
		target.MaxLinksPerSpan = source.MaxLinksPerSpan
	}
	if source.MaxAttributesPerEvent != 0 {
		target.MaxAttributesPerEvent = source.MaxAttributesPerEvent
	}
	if source.MaxAttributeValueBytes != 0 {
		target.MaxAttributeValueBytes = source.MaxAttributeValueBytes
	}
	if source.MaxProjectedSpanBytes != 0 {
		target.MaxProjectedSpanBytes = source.MaxProjectedSpanBytes
	}
	if source.MaxStacktraceBytes != 0 {
		target.MaxStacktraceBytes = source.MaxStacktraceBytes
	}
	if source.MaxMessageItems != 0 {
		target.MaxMessageItems = source.MaxMessageItems
	}
}

func validateObservabilityV8TraceLimits(limits ObservabilityV8TraceLimitsSource) error {
	bounds := []struct {
		name            string
		value, min, max int
	}{
		{"max_attributes_per_span", limits.MaxAttributesPerSpan, 32, 256},
		{"max_events_per_span", limits.MaxEventsPerSpan, 1, 128},
		{"max_links_per_span", limits.MaxLinksPerSpan, 1, 64},
		{"max_attributes_per_event", limits.MaxAttributesPerEvent, 4, 64},
		{"max_attribute_value_bytes", limits.MaxAttributeValueBytes, 256, 65_536},
		{"max_projected_span_bytes", limits.MaxProjectedSpanBytes, 4_096, 1_048_576},
		{"max_stacktrace_bytes", limits.MaxStacktraceBytes, 256, 131_072},
		{"max_message_items", limits.MaxMessageItems, 1, 512},
	}
	for _, bound := range bounds {
		if bound.value < bound.min || bound.value > bound.max {
			return fmt.Errorf(
				"observability.trace_policy.limits.%s: must be from %d through %d",
				bound.name,
				bound.min,
				bound.max,
			)
		}
	}
	return nil
}

func compileObservabilityV8MetricPolicy(source ObservabilityV8MetricPolicySource) (ObservabilityV8EffectiveMetricPolicy, error) {
	result := ObservabilityV8EffectiveMetricPolicy{ExportIntervalSeconds: 60, Temporality: observabilityV8DefaultMetricTemporality}
	if source.ExportIntervalSeconds != 0 {
		result.ExportIntervalSeconds = source.ExportIntervalSeconds
	}
	if result.ExportIntervalSeconds <= 0 {
		return ObservabilityV8EffectiveMetricPolicy{}, fmt.Errorf("observability.metric_policy.export_interval_seconds: must be positive")
	}
	if source.Temporality != "" {
		result.Temporality = source.Temporality
	}
	if result.Temporality != "delta" && result.Temporality != "cumulative" {
		return ObservabilityV8EffectiveMetricPolicy{}, fmt.Errorf("observability.metric_policy.temporality: unsupported value %q", result.Temporality)
	}
	return result, nil
}

func compileObservabilityV8LocalDestination(buckets []ObservabilityV8EffectiveBucket, local ObservabilityV8EffectiveLocal) ObservabilityV8EffectiveDestination {
	allBuckets := effectiveObservabilityV8BucketIDs(buckets)
	profiles := make(map[observability.Bucket]string, len(buckets))
	for _, bucket := range buckets {
		profiles[bucket.Bucket] = bucket.RedactionProfile
	}
	return ObservabilityV8EffectiveDestination{
		Name: ObservabilityV8LocalDestinationName, Kind: ObservabilityV8DestinationLocalSQLite, Enabled: true, Generated: true,
		Capabilities:    ObservabilityV8DestinationCapabilities{Signals: []observability.Signal{observability.SignalLogs}},
		SelectedSignals: []observability.Signal{observability.SignalLogs}, PolicyForm: ObservabilityV8PolicyImplicitLocal, FirstMatchPerSignal: true,
		ReloadApplicability: ObservabilityV8EffectiveDestinationReload{
			Policy: ObservabilityV8LiveReloadable, Transport: ObservabilityV8RestartRequired,
		},
		Routes:    []ObservabilityV8EffectiveRoute{{Index: 0, Name: "all-collected-logs-and-mandatory-floor", Generated: true, Signals: []observability.Signal{observability.SignalLogs}, Selector: ObservabilityV8EffectiveSelector{Buckets: allBuckets, BucketWildcard: true}, Action: ObservabilityV8RouteSend, RedactionProfileByBucket: profiles, IncludesMandatoryFloor: true}},
		Transport: ObservabilityV8TransportPlan{Path: local.Path},
	}
}

func compileObservabilityV8Destination(
	source ObservabilityV8DestinationSource,
	path string,
	buckets []ObservabilityV8EffectiveBucket,
	knownProfiles map[string]struct{},
	galileoCompatibilityProfile string,
) (ObservabilityV8EffectiveDestination, int, error) {
	if !observabilityV8StableNamePattern.MatchString(source.Name) {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.name: must be a stable lower-case identifier of at most 64 characters", path)
	}
	if source.Name == ObservabilityV8LocalDestinationName {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.name: %q is reserved for the generated local store", path, source.Name)
	}
	if source.Name == ObservabilityV8ManagedAIDDestinationName {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.name: %q is reserved for the generated managed-enterprise sink", path, source.Name)
	}
	capabilities, err := observabilityV8Capabilities(source.Kind, source.Preset)
	if err != nil {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s: %w", path, err)
	}
	if source.Send != nil && source.Routes != nil {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s: send and routes are mutually exclusive", path)
	}
	if len(source.Headers) > ObservabilityV8MaxMappingEntries {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.headers: too many entries", path)
	}
	if len(source.SignalOverrides) > len(observability.Signals()) {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.signal_overrides: too many entries", path)
	}
	if err := validateObservabilityV8Headers(
		source.Headers, source.Kind, observabilityV8ResolvedSourceProtocol(source), path+".headers",
	); err != nil {
		return ObservabilityV8EffectiveDestination{}, 0, err
	}
	enabled := true
	if source.Enabled != nil {
		enabled = *source.Enabled
	}
	result := ObservabilityV8EffectiveDestination{
		Name: source.Name, Kind: source.Kind, Enabled: enabled, Preset: source.Preset,
		Capabilities: capabilities, FirstMatchPerSignal: true,
		ReloadApplicability: ObservabilityV8EffectiveDestinationReload{
			Policy: ObservabilityV8LiveReloadable, Transport: ObservabilityV8LiveReloadable,
		},
	}
	// A Prometheus destination owns an in-process listener. The current runtime
	// cannot prepare a replacement generation on the same binding while the
	// active generation is still serving, so neither its listener policy nor
	// transport may be represented as generally live-reloadable.
	if source.Kind == ObservabilityV8DestinationPrometheus {
		result.ReloadApplicability.Policy = ObservabilityV8RestartRequired
		result.ReloadApplicability.Transport = ObservabilityV8RestartRequired
	}
	if source.Preset == "galileo" {
		result.PresetProfile = galileoCompatibilityProfile
	}
	explicitRoutes := 0
	switch {
	case source.Send != nil:
		result.PolicyForm = ObservabilityV8PolicyConciseSend
		route, err := compileObservabilityV8ConciseSend(*source.Send, path+".send", capabilities, buckets, knownProfiles)
		if err != nil {
			return ObservabilityV8EffectiveDestination{}, 0, err
		}
		result.Routes = []ObservabilityV8EffectiveRoute{route}
	case source.Routes != nil:
		if len(source.Routes) == 0 {
			return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.routes: must not be empty", path)
		}
		if len(source.Routes) > ObservabilityV8MaxRoutesPerDestination {
			return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s.routes: got %d, maximum is %d", path, len(source.Routes), ObservabilityV8MaxRoutesPerDestination)
		}
		result.PolicyForm = ObservabilityV8PolicyAdvancedRoutes
		result.Routes, err = compileObservabilityV8AdvancedRoutes(source.Routes, path+".routes", capabilities, buckets, knownProfiles)
		if err != nil {
			return ObservabilityV8EffectiveDestination{}, 0, err
		}
		explicitRoutes = len(source.Routes)
	default:
		result.PolicyForm = ObservabilityV8PolicyCapabilityDefault
		result.Routes = []ObservabilityV8EffectiveRoute{compileObservabilityV8CapabilityRoute(capabilities, buckets)}
	}
	result.SelectedSignals = unionObservabilityV8RouteSignals(result.Routes)
	transport, err := compileObservabilityV8Transport(source, result.SelectedSignals, path)
	if err != nil {
		return ObservabilityV8EffectiveDestination{}, 0, err
	}
	result.Transport = transport
	if err := validateObservabilityV8SignalOverrides(result.Transport.SignalOverrides, result.SelectedSignals, path+".signal_overrides"); err != nil {
		return ObservabilityV8EffectiveDestination{}, 0, err
	}
	result.CompatibilityProfiles, err = compileObservabilityV8DestinationCompatibility(result)
	if err != nil {
		return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s: %w", path, err)
	}
	if result.Preset == "galileo" && result.PolicyForm == ObservabilityV8PolicyCapabilityDefault {
		if err := constrainObservabilityV8CapabilityRouteToCompatibility(&result); err != nil {
			return ObservabilityV8EffectiveDestination{}, 0, fmt.Errorf("%s: %w", path, err)
		}
	}
	return result, explicitRoutes, nil
}

func observabilityV8Capabilities(kind ObservabilityV8DestinationKind, preset string) (ObservabilityV8DestinationCapabilities, error) {
	if preset != "" && preset != "galileo" {
		return ObservabilityV8DestinationCapabilities{}, fmt.Errorf("unknown preset %q", preset)
	}
	if preset == "galileo" && kind != ObservabilityV8DestinationOTLP {
		return ObservabilityV8DestinationCapabilities{}, fmt.Errorf("preset galileo requires kind otlp")
	}
	var signals []observability.Signal
	switch kind {
	case ObservabilityV8DestinationJSONL, ObservabilityV8DestinationConsole, ObservabilityV8DestinationSplunkHEC, ObservabilityV8DestinationHTTPJSONL:
		signals = []observability.Signal{observability.SignalLogs}
	case ObservabilityV8DestinationPrometheus:
		signals = []observability.Signal{observability.SignalMetrics}
	case ObservabilityV8DestinationOTLP:
		if preset == "galileo" {
			signals = []observability.Signal{observability.SignalTraces}
		} else {
			signals = observability.Signals()
		}
	case ObservabilityV8DestinationLocalSQLite:
		return ObservabilityV8DestinationCapabilities{}, fmt.Errorf("kind sqlite is generated and cannot appear in source")
	case "":
		return ObservabilityV8DestinationCapabilities{}, fmt.Errorf("kind is required")
	default:
		return ObservabilityV8DestinationCapabilities{}, fmt.Errorf("unknown destination kind %q", kind)
	}
	return ObservabilityV8DestinationCapabilities{Signals: signals}, nil
}

func compileObservabilityV8CapabilityRoute(capabilities ObservabilityV8DestinationCapabilities, buckets []ObservabilityV8EffectiveBucket) ObservabilityV8EffectiveRoute {
	allBuckets := effectiveObservabilityV8BucketIDs(buckets)
	route := ObservabilityV8EffectiveRoute{
		Index: 0, Name: "capability-default", Generated: true,
		Signals:  append([]observability.Signal(nil), capabilities.Signals...),
		Selector: ObservabilityV8EffectiveSelector{Buckets: allBuckets, BucketWildcard: true},
		Action:   ObservabilityV8RouteSend,
	}
	if observabilityV8HasContentSignal(route.Signals) {
		route.RedactionProfileByBucket = observabilityV8RouteProfiles(allBuckets, "none", buckets)
	}
	return route
}

func compileObservabilityV8ConciseSend(source ObservabilityV8SendSource, path string, capabilities ObservabilityV8DestinationCapabilities, buckets []ObservabilityV8EffectiveBucket, knownProfiles map[string]struct{}) (ObservabilityV8EffectiveRoute, error) {
	signals, err := validateObservabilityV8Signals(source.Signals, capabilities, path+".signals")
	if err != nil {
		return ObservabilityV8EffectiveRoute{}, err
	}
	selectedBuckets, wildcard, err := compileObservabilityV8BucketSelector(source.Buckets, true, path+".buckets")
	if err != nil {
		return ObservabilityV8EffectiveRoute{}, err
	}
	if err := validateObservabilityV8RouteProfile(source.RedactionProfile, signals, ObservabilityV8RouteSend, knownProfiles, path+".redaction_profile"); err != nil {
		return ObservabilityV8EffectiveRoute{}, err
	}
	if wildcard {
		selectedBuckets = effectiveObservabilityV8BucketIDs(buckets)
	}
	route := ObservabilityV8EffectiveRoute{
		Index: 0, Name: "send", Generated: true, Signals: signals,
		Selector: ObservabilityV8EffectiveSelector{Buckets: selectedBuckets, BucketWildcard: wildcard},
		Action:   ObservabilityV8RouteSend,
	}
	if observabilityV8HasContentSignal(route.Signals) {
		route.RedactionProfileByBucket = observabilityV8RouteProfiles(selectedBuckets, source.RedactionProfile, buckets)
	}
	return route, nil
}

func compileObservabilityV8AdvancedRoutes(source []ObservabilityV8RouteSource, path string, capabilities ObservabilityV8DestinationCapabilities, buckets []ObservabilityV8EffectiveBucket, knownProfiles map[string]struct{}) ([]ObservabilityV8EffectiveRoute, error) {
	result := make([]ObservabilityV8EffectiveRoute, 0, len(source))
	seenNames := make(map[string]struct{}, len(source))
	for index, route := range source {
		routePath := fmt.Sprintf("%s[%d]", path, index)
		if !observabilityV8StableNamePattern.MatchString(route.Name) {
			return nil, fmt.Errorf("%s.name: must be a stable lower-case identifier of at most 64 characters", routePath)
		}
		if _, duplicate := seenNames[route.Name]; duplicate {
			return nil, fmt.Errorf("%s.name: duplicate route name %q", routePath, route.Name)
		}
		seenNames[route.Name] = struct{}{}
		signals, err := validateObservabilityV8Signals(route.Signals, capabilities, routePath+".signals")
		if err != nil {
			return nil, err
		}
		action := route.Action
		if action == "" {
			action = ObservabilityV8RouteSend
		}
		if action != ObservabilityV8RouteSend && action != ObservabilityV8RouteDrop {
			return nil, fmt.Errorf("%s.action: expected send or drop, got %q", routePath, action)
		}
		if err := validateObservabilityV8RouteProfile(route.RedactionProfile, signals, action, knownProfiles, routePath+".redaction_profile"); err != nil {
			return nil, err
		}
		if route.Selector == nil {
			return nil, fmt.Errorf("%s.selector: required", routePath)
		}
		selector, err := compileObservabilityV8Selector(*route.Selector, routePath+".selector", buckets)
		if err != nil {
			return nil, err
		}
		compiled := ObservabilityV8EffectiveRoute{Index: index, Name: route.Name, Signals: signals, Selector: selector, Action: action}
		if action == ObservabilityV8RouteSend && observabilityV8HasContentSignal(signals) {
			compiled.RedactionProfileByBucket = observabilityV8RouteProfiles(selector.Buckets, route.RedactionProfile, buckets)
		}
		result = append(result, compiled)
	}
	return result, nil
}

func compileObservabilityV8Selector(source ObservabilityV8SelectorSource, path string, buckets []ObservabilityV8EffectiveBucket) (ObservabilityV8EffectiveSelector, error) {
	selectedBuckets, wildcard, err := compileObservabilityV8BucketSelector(source.Buckets, false, path+".buckets")
	if err != nil {
		return ObservabilityV8EffectiveSelector{}, err
	}
	if source.Buckets == nil || wildcard {
		selectedBuckets = effectiveObservabilityV8BucketIDs(buckets)
	}
	if err := validateObservabilityV8SelectorPresence(source, path); err != nil {
		return ObservabilityV8EffectiveSelector{}, err
	}
	selector := observability.Selector{Buckets: source.Buckets, Sources: source.Sources, Connectors: source.Connectors, Actions: source.Actions, EventNames: source.EventNames, MinSeverity: source.MinSeverity}
	if err := selector.Validate(); err != nil {
		return ObservabilityV8EffectiveSelector{}, fmt.Errorf("%s: %w", path, err)
	}
	for _, field := range []struct {
		name   string
		values []string
	}{
		{name: "sources", values: stringObservabilityV8Sources(source.Sources)},
		{name: "connectors", values: source.Connectors},
		{name: "actions", values: stringObservabilityV8ProducerKeys(source.Actions)},
	} {
		for _, value := range field.values {
			if value != "*" && !observabilityV8SelectorPattern.MatchString(value) {
				return ObservabilityV8EffectiveSelector{}, fmt.Errorf("%s.%s: invalid selector token", path, field.name)
			}
		}
	}
	for _, action := range source.Actions {
		if action == "*" {
			continue
		}
		if _, gateway := observability.GatewayEventClassification(action); gateway {
			continue
		}
		if _, audit := observability.AuditActionClassification(action); !audit {
			return ObservabilityV8EffectiveSelector{}, fmt.Errorf("%s.actions: unregistered action %q", path, action)
		}
	}
	for _, eventName := range source.EventNames {
		if eventName != "*" && !observability.IsRegisteredEventName(eventName) {
			return ObservabilityV8EffectiveSelector{}, fmt.Errorf("%s.event_names: unregistered event name %q", path, eventName)
		}
	}
	return ObservabilityV8EffectiveSelector{
		Buckets: selectedBuckets, BucketWildcard: wildcard,
		Sources:     append([]observability.Source(nil), source.Sources...),
		Connectors:  append([]string(nil), source.Connectors...),
		Actions:     append([]observability.ProducerKey(nil), source.Actions...),
		EventNames:  append([]observability.EventName(nil), source.EventNames...),
		MinSeverity: source.MinSeverity,
	}, nil
}

func stringObservabilityV8Sources(values []observability.Source) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func stringObservabilityV8ProducerKeys(values []observability.ProducerKey) []string {
	result := make([]string, len(values))
	for index, value := range values {
		result[index] = string(value)
	}
	return result
}

func validateObservabilityV8SelectorPresence(source ObservabilityV8SelectorSource, path string) error {
	fields := []struct {
		name    string
		present bool
		length  int
	}{
		{name: "buckets", present: source.Buckets != nil, length: len(source.Buckets)},
		{name: "sources", present: source.Sources != nil, length: len(source.Sources)},
		{name: "connectors", present: source.Connectors != nil, length: len(source.Connectors)},
		{name: "actions", present: source.Actions != nil, length: len(source.Actions)},
		{name: "event_names", present: source.EventNames != nil, length: len(source.EventNames)},
	}
	for _, field := range fields {
		if field.present && field.length == 0 {
			return fmt.Errorf("%s.%s: must not be empty when present", path, field.name)
		}
		if field.length > ObservabilityV8MaxMappingEntries {
			return fmt.Errorf("%s.%s: too many values", path, field.name)
		}
	}
	return nil
}

func compileObservabilityV8BucketSelector(source []observability.Bucket, required bool, path string) ([]observability.Bucket, bool, error) {
	if len(source) == 0 {
		if required || source != nil {
			return nil, false, fmt.Errorf("%s: must be nonempty", path)
		}
		return nil, false, nil
	}
	seen := make(map[observability.Bucket]struct{}, len(source))
	for _, bucket := range source {
		if bucket == "*" {
			if len(source) != 1 {
				return nil, false, fmt.Errorf("%s: wildcard must be the only value", path)
			}
			return nil, true, nil
		}
		if !observability.IsBucket(bucket) {
			return nil, false, fmt.Errorf("%s: unknown catalog-v1 bucket %q", path, bucket)
		}
		if _, duplicate := seen[bucket]; duplicate {
			return nil, false, fmt.Errorf("%s: duplicate bucket %q", path, bucket)
		}
		seen[bucket] = struct{}{}
	}
	return append([]observability.Bucket(nil), source...), false, nil
}

func validateObservabilityV8Signals(source []observability.Signal, capabilities ObservabilityV8DestinationCapabilities, path string) ([]observability.Signal, error) {
	if len(source) == 0 {
		return nil, fmt.Errorf("%s: must be nonempty", path)
	}
	seen := make(map[observability.Signal]struct{}, len(source))
	for _, signal := range source {
		if !observability.IsSignal(signal) {
			return nil, fmt.Errorf("%s: unknown signal %q", path, signal)
		}
		if !capabilities.Supports(signal) {
			return nil, fmt.Errorf("%s: signal %q is not supported by destination kind", path, signal)
		}
		if _, duplicate := seen[signal]; duplicate {
			return nil, fmt.Errorf("%s: duplicate signal %q", path, signal)
		}
		seen[signal] = struct{}{}
	}
	return append([]observability.Signal(nil), source...), nil
}

func validateObservabilityV8RouteProfile(profile string, signals []observability.Signal, action ObservabilityV8RouteAction, knownProfiles map[string]struct{}, path string) error {
	if profile == "" {
		return nil
	}
	if action == ObservabilityV8RouteDrop {
		return fmt.Errorf("%s: not valid on a drop route", path)
	}
	if _, ok := knownProfiles[profile]; !ok {
		return fmt.Errorf("%s: unknown profile %q", path, profile)
	}
	if !observabilityV8HasContentSignal(signals) {
		return fmt.Errorf("%s: not valid on a metric-only route", path)
	}
	return nil
}

func observabilityV8HasContentSignal(signals []observability.Signal) bool {
	for _, signal := range signals {
		if signal == observability.SignalLogs || signal == observability.SignalTraces {
			return true
		}
	}
	return false
}

func observabilityV8RouteProfiles(buckets []observability.Bucket, explicit string, policies []ObservabilityV8EffectiveBucket) map[observability.Bucket]string {
	policyByBucket := make(map[observability.Bucket]string, len(policies))
	for _, policy := range policies {
		policyByBucket[policy.Bucket] = policy.RedactionProfile
	}
	result := make(map[observability.Bucket]string, len(buckets))
	for _, bucket := range buckets {
		profile := explicit
		if profile == "" {
			profile = policyByBucket[bucket]
		}
		result[bucket] = profile
	}
	return result
}

func effectiveObservabilityV8BucketIDs(source []ObservabilityV8EffectiveBucket) []observability.Bucket {
	result := make([]observability.Bucket, len(source))
	for index, bucket := range source {
		result[index] = bucket.Bucket
	}
	return result
}

func unionObservabilityV8RouteSignals(routes []ObservabilityV8EffectiveRoute) []observability.Signal {
	selected := make(map[observability.Signal]struct{}, len(observability.Signals()))
	for _, route := range routes {
		for _, signal := range route.Signals {
			selected[signal] = struct{}{}
		}
	}
	result := make([]observability.Signal, 0, len(selected))
	for _, signal := range observability.Signals() {
		if _, ok := selected[signal]; ok {
			result = append(result, signal)
		}
	}
	return result
}

func compileObservabilityV8Transport(
	source ObservabilityV8DestinationSource,
	selected []observability.Signal,
	path string,
) (ObservabilityV8TransportPlan, error) {
	if err := validateObservabilityV8KindSpecificFields(source, path); err != nil {
		return ObservabilityV8TransportPlan{}, err
	}
	result := ObservabilityV8TransportPlan{
		Path: source.Path, Listen: source.Listen, Endpoint: source.Endpoint,
		Protocol: source.Protocol, Method: source.Method,
		Headers: cloneObservabilityV8Headers(source.Headers), TokenEnv: source.TokenEnv, BearerEnv: source.BearerEnv,
		Index: source.Index, Source: source.Source, SourceType: source.SourceType,
		SourceTypeOverrides: cloneObservabilityV8SourceTypeOverrides(source.SourceTypeOverrides), LoggerName: source.LoggerName,
		TimeoutMS:       source.TimeoutMS,
		SignalOverrides: cloneObservabilityV8SignalOverrides(source.SignalOverrides),
	}
	for _, secretReference := range []struct{ field, reference string }{
		{field: "token_env", reference: source.TokenEnv},
		{field: "bearer_env", reference: source.BearerEnv},
	} {
		if secretReference.reference != "" && !observabilityV8EnvNamePattern.MatchString(secretReference.reference) {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.%s: invalid secret-provider reference name", path, secretReference.field)
		}
	}
	if len(source.Path) > 4_096 || len(source.TLS.CACert) > 4_096 {
		return ObservabilityV8TransportPlan{}, fmt.Errorf("%s: configured path exceeds 4096 bytes", path)
	}

	switch source.Kind {
	case ObservabilityV8DestinationJSONL:
		if strings.TrimSpace(source.Path) == "" {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.path: required for jsonl", path)
		}
		rotation, err := compileObservabilityV8Rotation(source.Rotation, path+".rotation")
		if err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
		result.Rotation = &rotation
		if err := compileObservabilityV8QueueDefaults(&result, source, path, true); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	case ObservabilityV8DestinationConsole:
		if err := compileObservabilityV8QueueDefaults(&result, source, path, true); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	case ObservabilityV8DestinationPrometheus:
		if err := validateObservabilityV8PrometheusTransport(source.Listen, source.Path, path); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	case ObservabilityV8DestinationSplunkHEC:
		if strings.TrimSpace(source.TokenEnv) == "" {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.token_env: required for splunk_hec", path)
		}
		if err := validateObservabilityV8SourceTypeOverrides(source.SourceTypeOverrides, path+".sourcetype_overrides"); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
		if err := compileObservabilityV8PushDefaults(&result, source, path, true); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	case ObservabilityV8DestinationHTTPJSONL:
		if result.Method == "" {
			result.Method = "POST"
		}
		if result.Method != "POST" && result.Method != "PUT" && result.Method != "PATCH" {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.method: expected POST, PUT, or PATCH", path)
		}
		if err := compileObservabilityV8PushDefaults(&result, source, path, true); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	case ObservabilityV8DestinationOTLP:
		if source.LoggerName != "" {
			if len(source.LoggerName) > 256 {
				return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.logger_name: must contain 1 through 256 bytes", path)
			}
			if !observabilityV8SignalsContain(selected, observability.SignalLogs) {
				return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.logger_name: requires logs to be selected", path)
			}
		}
		if result.Protocol == "" {
			if source.Preset == "galileo" {
				result.Protocol = "http/protobuf"
			} else {
				result.Protocol = "grpc"
			}
		}
		if !isObservabilityV8OTLPProtocol(result.Protocol) {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.protocol: unsupported value %q", path, result.Protocol)
		}
		if source.Preset == "galileo" && result.Protocol != "http/protobuf" {
			return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.protocol: preset galileo requires http/protobuf", path)
		}
		if err := compileObservabilityV8PushDefaults(&result, source, path, false); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
		if source.Preset == "galileo" && source.Batch.ScheduledDelayMS == 0 {
			result.Batch.ScheduledDelayMS = 1_000
		}
		if err := validateObservabilityV8ResolvedOTLPEndpoints(result, selected, path); err != nil {
			return ObservabilityV8TransportPlan{}, err
		}
	default:
		return ObservabilityV8TransportPlan{}, fmt.Errorf("%s.kind: unsupported value %q", path, source.Kind)
	}
	return result, nil
}

func validateObservabilityV8KindSpecificFields(source ObservabilityV8DestinationSource, path string) error {
	configured := map[string]bool{
		"preset": source.Preset != "", "path": source.Path != "", "rotation": observabilityV8RotationConfigured(source.Rotation),
		"listen": source.Listen != "", "endpoint": source.Endpoint != "", "protocol": source.Protocol != "",
		"method": source.Method != "", "headers": source.Headers != nil, "token_env": source.TokenEnv != "",
		"bearer_env": source.BearerEnv != "", "index": source.Index != "", "source": source.Source != "",
		"sourcetype": source.SourceType != "", "sourcetype_overrides": source.SourceTypeOverrides != nil,
		"logger_name": source.LoggerName != "", "timeout_ms": source.TimeoutMS != 0,
		"tls": observabilityV8TLSConfigured(source.TLS), "batch": observabilityV8BatchConfigured(source.Batch),
		"network_safety":   observabilityV8NetworkSafetyConfigured(source.NetworkSafety),
		"signal_overrides": source.SignalOverrides != nil,
	}
	allowed := map[ObservabilityV8DestinationKind]map[string]struct{}{
		ObservabilityV8DestinationJSONL:      setObservabilityV8Fields("path", "rotation", "batch"),
		ObservabilityV8DestinationConsole:    setObservabilityV8Fields("batch"),
		ObservabilityV8DestinationPrometheus: setObservabilityV8Fields("listen", "path"),
		ObservabilityV8DestinationSplunkHEC:  setObservabilityV8Fields("endpoint", "token_env", "index", "source", "sourcetype", "sourcetype_overrides", "timeout_ms", "tls", "batch", "network_safety"),
		ObservabilityV8DestinationHTTPJSONL:  setObservabilityV8Fields("endpoint", "method", "headers", "bearer_env", "timeout_ms", "tls", "batch", "network_safety"),
		ObservabilityV8DestinationOTLP:       setObservabilityV8Fields("preset", "endpoint", "protocol", "headers", "logger_name", "timeout_ms", "tls", "batch", "network_safety", "signal_overrides"),
	}
	allowedFields, ok := allowed[source.Kind]
	if !ok {
		return nil // Capability validation reports an unknown kind first.
	}
	order := []string{
		"preset", "path", "rotation", "listen", "endpoint", "protocol", "method", "headers",
		"token_env", "bearer_env", "index", "source", "sourcetype", "sourcetype_overrides", "logger_name", "timeout_ms", "tls", "batch",
		"network_safety", "signal_overrides",
	}
	for _, field := range order {
		if !configured[field] {
			continue
		}
		if _, ok := allowedFields[field]; !ok {
			return fmt.Errorf("%s.%s: field is not supported by destination kind %s", path, field, source.Kind)
		}
	}
	return nil
}

func setObservabilityV8Fields(fields ...string) map[string]struct{} {
	result := make(map[string]struct{}, len(fields))
	for _, field := range fields {
		result[field] = struct{}{}
	}
	return result
}

func validateObservabilityV8SourceTypeOverrides(overrides map[observability.ProducerKey]string, path string) error {
	if len(overrides) > ObservabilityV8MaxMappingEntries {
		return fmt.Errorf("%s: got %d entries, maximum is %d", path, len(overrides), ObservabilityV8MaxMappingEntries)
	}
	keys := make([]string, 0, len(overrides))
	for key := range overrides {
		keys = append(keys, string(key))
	}
	sort.Strings(keys)
	for _, rawKey := range keys {
		key := observability.ProducerKey(rawKey)
		if _, registered := observability.AuditActionClassification(key); !registered {
			return fmt.Errorf("%s: unregistered audit producer key %q", path, key)
		}
		value := overrides[key]
		if len(value) < 1 || len(value) > 256 {
			return fmt.Errorf("%s.%s: sourcetype must contain 1 through 256 bytes", path, key)
		}
	}
	return nil
}

func observabilityV8SignalsContain(signals []observability.Signal, expected observability.Signal) bool {
	for _, signal := range signals {
		if signal == expected {
			return true
		}
	}
	return false
}

func observabilityV8RotationConfigured(source ObservabilityV8RotationSource) bool {
	return source.MaxSizeMB != 0 || source.MaxBackups != nil || source.MaxAgeDays != nil || source.Compress != nil
}

func observabilityV8TLSConfigured(source ObservabilityV8TLSSource) bool {
	return source.Insecure || source.InsecureSkipVerify || source.CACert != ""
}

func observabilityV8BatchConfigured(source ObservabilityV8BatchSource) bool {
	return source.MaxQueueSize != 0 || source.MaxQueueBytes != 0 || source.MaxExportBatchSize != 0 ||
		source.MaxExportBatchBytes != 0 || source.ScheduledDelayMS != 0
}

func observabilityV8NetworkSafetyConfigured(source ObservabilityV8NetworkSafetySource) bool {
	return source.AllowPrivateNetworks || source.AllowCGNAT
}

func compileObservabilityV8Rotation(source ObservabilityV8RotationSource, path string) (ObservabilityV8EffectiveRotation, error) {
	result := ObservabilityV8EffectiveRotation{MaxSizeMB: 50, MaxBackups: 5, MaxAgeDays: 30, Compress: true}
	if source.MaxSizeMB != 0 {
		result.MaxSizeMB = source.MaxSizeMB
	}
	if source.MaxBackups != nil {
		result.MaxBackups = *source.MaxBackups
	}
	if source.MaxAgeDays != nil {
		result.MaxAgeDays = *source.MaxAgeDays
	}
	if source.Compress != nil {
		result.Compress = *source.Compress
	}
	if result.MaxSizeMB < 1 || result.MaxBackups < 0 || result.MaxAgeDays < 0 {
		return ObservabilityV8EffectiveRotation{}, fmt.Errorf("%s: max_size_mb must be positive; max_backups and max_age_days must be nonnegative", path)
	}
	return result, nil
}

func compileObservabilityV8PushDefaults(
	result *ObservabilityV8TransportPlan,
	source ObservabilityV8DestinationSource,
	path string,
	httpOnly bool,
) error {
	if strings.TrimSpace(result.Endpoint) == "" && httpOnly {
		return fmt.Errorf("%s.endpoint: required for %s", path, source.Kind)
	}
	if result.TimeoutMS == 0 {
		result.TimeoutMS = observabilityV8DefaultTimeoutMS
	}
	if result.TimeoutMS < 1 {
		return fmt.Errorf("%s.timeout_ms: must be positive", path)
	}
	if result.TLS == nil {
		tls := source.TLS
		result.TLS = &tls
	}
	if result.NetworkSafety == nil {
		networkSafety := source.NetworkSafety
		result.NetworkSafety = &networkSafety
	}
	if err := compileObservabilityV8QueueDefaults(result, source, path, false); err != nil {
		return err
	}
	if result.Batch.MaxExportBatchSize == 0 {
		result.Batch.MaxExportBatchSize = observabilityV8DefaultExportBatchSize
	}
	if result.Batch.MaxExportBatchBytes == 0 {
		result.Batch.MaxExportBatchBytes = observabilityV8DefaultExportBatchBytes
	}
	if result.Batch.ScheduledDelayMS == 0 {
		result.Batch.ScheduledDelayMS = observabilityV8DefaultBatchDelayMS
	}
	if result.Batch.MaxExportBatchSize < 1 || result.Batch.MaxExportBatchSize > observabilityV8MaxExportBatchSize {
		return fmt.Errorf("%s.batch.max_export_batch_size: must be from 1 through %d", path, observabilityV8MaxExportBatchSize)
	}
	if result.Batch.MaxExportBatchBytes < observabilityV8MinExportBatchBytes || result.Batch.MaxExportBatchBytes > observabilityV8MaxExportBatchBytes {
		return fmt.Errorf("%s.batch.max_export_batch_bytes: must be from %d through %d", path, observabilityV8MinExportBatchBytes, observabilityV8MaxExportBatchBytes)
	}
	if result.Batch.ScheduledDelayMS < 1 || result.Batch.ScheduledDelayMS > observabilityV8MaxBatchDelayMS {
		return fmt.Errorf("%s.batch.scheduled_delay_ms: must be from 1 through %d", path, observabilityV8MaxBatchDelayMS)
	}
	if result.Batch.MaxExportBatchSize > result.Batch.MaxQueueSize {
		return fmt.Errorf("%s.batch.max_export_batch_size: must not exceed max_queue_size", path)
	}
	if httpOnly && result.TLS.Insecure {
		return fmt.Errorf("%s.tls.insecure: valid only for otlp", path)
	}
	if !httpOnly && result.TLS.InsecureSkipVerify {
		return fmt.Errorf("%s.tls.insecure_skip_verify: valid only for HTTP push destinations", path)
	}
	if strings.TrimSpace(result.Endpoint) == "" {
		return nil
	}
	return validateObservabilityV8Endpoint(result.Endpoint, result.Protocol, *result.NetworkSafety, path+".endpoint")
}

func compileObservabilityV8QueueDefaults(
	result *ObservabilityV8TransportPlan,
	source ObservabilityV8DestinationSource,
	path string,
	queueOnly bool,
) error {
	if queueOnly {
		switch {
		case source.Batch.MaxExportBatchSize != 0:
			return fmt.Errorf("%s.batch.max_export_batch_size: field is valid only for push destinations", path)
		case source.Batch.MaxExportBatchBytes != 0:
			return fmt.Errorf("%s.batch.max_export_batch_bytes: field is valid only for push destinations", path)
		case source.Batch.ScheduledDelayMS != 0:
			return fmt.Errorf("%s.batch.scheduled_delay_ms: field is valid only for push destinations", path)
		}
	}
	if result.Batch == nil {
		batch := source.Batch
		result.Batch = &batch
	}
	if result.Batch.MaxQueueSize == 0 {
		result.Batch.MaxQueueSize = observabilityV8DefaultQueueSize
	}
	if result.Batch.MaxQueueBytes == 0 {
		result.Batch.MaxQueueBytes = observabilityV8DefaultQueueBytes
	}
	if result.Batch.MaxQueueSize < 1 || result.Batch.MaxQueueSize > observabilityV8MaxQueueSize {
		return fmt.Errorf("%s.batch.max_queue_size: must be from 1 through %d", path, observabilityV8MaxQueueSize)
	}
	if result.Batch.MaxQueueBytes < observabilityV8MinQueueBytes || result.Batch.MaxQueueBytes > observabilityV8MaxQueueBytes {
		return fmt.Errorf("%s.batch.max_queue_bytes: must be from %d through %d", path, observabilityV8MinQueueBytes, observabilityV8MaxQueueBytes)
	}
	return nil
}

func validateObservabilityV8PrometheusTransport(listen, pathValue, path string) error {
	if strings.TrimSpace(listen) == "" {
		return fmt.Errorf("%s.listen: required for prometheus", path)
	}
	_, port, err := net.SplitHostPort(listen)
	if err != nil {
		return fmt.Errorf("%s.listen: expected host:port", path)
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber < 1 || portNumber > 65_535 {
		return fmt.Errorf("%s.listen: port must be from 1 through 65535", path)
	}
	if !strings.HasPrefix(pathValue, "/") {
		return fmt.Errorf("%s.path: required and must begin with /", path)
	}
	return nil
}

func isObservabilityV8OTLPProtocol(protocol string) bool {
	switch protocol {
	case "grpc", "grpc/protobuf", "http", "http/protobuf":
		return true
	default:
		return false
	}
}

func observabilityV8ResolvedSourceProtocol(source ObservabilityV8DestinationSource) string {
	if source.Protocol != "" || source.Kind != ObservabilityV8DestinationOTLP {
		return source.Protocol
	}
	if source.Preset == "galileo" {
		return "http/protobuf"
	}
	return "grpc"
}

func validateObservabilityV8ResolvedOTLPEndpoints(
	transport ObservabilityV8TransportPlan,
	selected []observability.Signal,
	path string,
) error {
	for _, signal := range selected {
		endpoint := transport.Endpoint
		endpointPath := path + ".signal_overrides." + string(signal) + ".endpoint"
		if strings.TrimSpace(endpoint) != "" {
			endpointPath = path + ".endpoint"
		}
		if override, ok := transport.SignalOverrides[signal]; ok && strings.TrimSpace(override.Endpoint) != "" {
			endpoint = override.Endpoint
			endpointPath = path + ".signal_overrides." + string(signal) + ".endpoint"
		}
		if strings.TrimSpace(endpoint) == "" {
			return fmt.Errorf("%s: selected signal %s has no resolved endpoint", endpointPath, signal)
		}
		networkSafety := ObservabilityV8NetworkSafetySource{}
		if transport.NetworkSafety != nil {
			networkSafety = *transport.NetworkSafety
		}
		if err := validateObservabilityV8Endpoint(endpoint, transport.Protocol, networkSafety, endpointPath); err != nil {
			return err
		}
		if strings.Contains(endpoint, "://") {
			parsed, err := url.Parse(endpoint)
			if err != nil {
				return fmt.Errorf("%s: invalid endpoint", endpointPath)
			}
			if parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" {
				return fmt.Errorf("%s: OTLP endpoints must not contain query or fragment data", endpointPath)
			}
			if (parsed.Scheme == "http") != observabilityV8TransportTLSInsecure(transport) {
				return fmt.Errorf("%s: OTLP endpoint scheme and tls.insecure disagree", endpointPath)
			}
			if (transport.Protocol == "grpc" || transport.Protocol == "grpc/protobuf") && parsed.EscapedPath() != "" && parsed.EscapedPath() != "/" {
				return fmt.Errorf("%s: gRPC OTLP endpoints must not contain a path", endpointPath)
			}
		}
		if override, ok := transport.SignalOverrides[signal]; ok && override.Path != "" {
			if transport.Protocol == "grpc" || transport.Protocol == "grpc/protobuf" {
				return fmt.Errorf("%s.signal_overrides.%s.path: gRPC OTLP service paths are fixed; remove path or use http/protobuf", path, signal)
			}
			if !strings.HasPrefix(override.Path, "/") {
				return fmt.Errorf("%s.signal_overrides.%s.path: must begin with /", path, signal)
			}
		}
	}
	return nil
}

func observabilityV8TransportTLSInsecure(transport ObservabilityV8TransportPlan) bool {
	return transport.TLS != nil && transport.TLS.Insecure
}

func validateObservabilityV8Endpoint(
	raw, protocol string,
	safety ObservabilityV8NetworkSafetySource,
	path string,
) error {
	value := strings.TrimSpace(raw)
	if value == "" || len(value) > 2_048 || strings.ContainsAny(value, "\r\n\t ") {
		return fmt.Errorf("%s: invalid or empty endpoint", path)
	}
	host := ""
	if strings.Contains(value, "://") {
		parsed, err := url.Parse(value)
		if err != nil || parsed.Host == "" || parsed.Hostname() == "" || parsed.User != nil {
			return fmt.Errorf("%s: invalid endpoint or inline URL credentials", path)
		}
		if parsed.Scheme != "http" && parsed.Scheme != "https" {
			return fmt.Errorf("%s: unsupported endpoint scheme %q", path, parsed.Scheme)
		}
		host = parsed.Hostname()
		if err := validateObservabilityV8EndpointPort(parsed.Port(), path); err != nil {
			return err
		}
	} else {
		if strings.HasPrefix(protocol, "http") || protocol == "" {
			return fmt.Errorf("%s: HTTP endpoint must use http:// or https://", path)
		}
		if strings.ContainsAny(value, "@/?#") {
			return fmt.Errorf("%s: gRPC authority contains inline credentials or path data", path)
		}
		parsedHost, port, err := net.SplitHostPort(value)
		if err != nil {
			return fmt.Errorf("%s: gRPC endpoint must be an authority or HTTP(S) URL", path)
		}
		host = strings.Trim(parsedHost, "[]")
		if host == "" {
			return fmt.Errorf("%s: gRPC authority requires a hostname", path)
		}
		if err := validateObservabilityV8EndpointPort(port, path); err != nil {
			return err
		}
	}
	return validateObservabilityV8EndpointHost(host, safety, path)
}

func validateObservabilityV8EndpointPort(port, path string) error {
	if port == "" {
		return nil
	}
	value, err := strconv.Atoi(port)
	if err != nil || value < 1 || value > 65_535 {
		return fmt.Errorf("%s: endpoint port must be from 1 through 65535", path)
	}
	return nil
}

func validateObservabilityV8EndpointHost(host string, safety ObservabilityV8NetworkSafetySource, path string) error {
	normalized := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	if normalized == "localhost" || strings.HasSuffix(normalized, ".localhost") {
		if safety.AllowPrivateNetworks {
			return nil
		}
		return fmt.Errorf("%s: localhost endpoint requires network_safety.allow_private_networks", path)
	}
	for _, blocked := range []string{
		"metadata.google.internal", "metadata.goog", "metadata.azure.internal",
		"instance-data.ec2.internal", "task-metadata-endpoint",
	} {
		if normalized == blocked {
			return fmt.Errorf("%s: cloud/container metadata endpoint is always prohibited", path)
		}
	}
	address, err := netip.ParseAddr(normalized)
	if err != nil {
		if len(normalized) > 253 || strings.Contains(normalized, "..") ||
			strings.ContainsAny(normalized, ":%") || !observabilityV8HostnamePattern.MatchString(normalized) {
			return fmt.Errorf("%s: endpoint hostname is malformed", path)
		}
		for _, label := range strings.Split(normalized, ".") {
			if len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
				return fmt.Errorf("%s: endpoint hostname is malformed", path)
			}
		}
		return nil // DNS answers are revalidated by the guarded runtime dialer.
	}
	address = address.Unmap()
	for _, metadata := range []string{"169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16"} {
		if address.String() == metadata {
			return fmt.Errorf("%s: cloud/container metadata endpoint is always prohibited", path)
		}
	}
	if address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsUnspecified() || address.IsMulticast() {
		return fmt.Errorf("%s: link-local, unspecified, or multicast endpoint is prohibited", path)
	}
	for _, prefix := range observabilityV8ReservedPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("%s: reserved or documentation-only endpoint is prohibited", path)
		}
	}
	cgnat := netip.MustParsePrefix("100.64.0.0/10").Contains(address)
	if cgnat {
		if safety.AllowCGNAT {
			return nil
		}
		return fmt.Errorf("%s: CGNAT endpoint requires network_safety.allow_cgnat", path)
	}
	if address.IsLoopback() || address.IsPrivate() {
		if safety.AllowPrivateNetworks {
			return nil
		}
		return fmt.Errorf("%s: loopback/private endpoint requires network_safety.allow_private_networks", path)
	}
	if !address.IsGlobalUnicast() {
		return fmt.Errorf("%s: reserved endpoint is prohibited", path)
	}
	return nil
}

func validateObservabilityV8Headers(
	source map[string]ObservabilityV8HeaderValue,
	kind ObservabilityV8DestinationKind,
	protocol string,
	path string,
) error {
	if len(source) > 128 {
		return fmt.Errorf("%s: got %d entries, maximum is 128", path, len(source))
	}
	canonicalNames := make(map[string]struct{}, len(source))
	for name, value := range source {
		if !observabilityV8ValidHeaderName(name) {
			return fmt.Errorf("%s: header name must use the HTTP token grammar and contain 1 through 256 bytes", path)
		}
		normalizedName := strings.ToLower(name)
		if _, duplicate := canonicalNames[normalizedName]; duplicate {
			return fmt.Errorf("%s: header names must be unique ignoring case", path)
		}
		canonicalNames[normalizedName] = struct{}{}
		if observabilityV8ForbiddenTransportHeader(normalizedName) {
			return fmt.Errorf("%s.%s: header is owned by the destination transport", path, name)
		}
		if kind == ObservabilityV8DestinationOTLP && strings.HasPrefix(protocol, "grpc") &&
			(!observabilityV8ValidGRPCMetadataName(normalizedName) ||
				strings.HasPrefix(normalizedName, "grpc-") || strings.HasSuffix(normalizedName, "-bin")) {
			return fmt.Errorf("%s.%s: header is not valid gRPC metadata", path, name)
		}
		if (value.Static == nil) == (value.Secret == nil) {
			return fmt.Errorf("%s.%s: exactly one of static value or secret reference is required", path, name)
		}
		if value.Secret != nil && strings.TrimSpace(value.Secret.Env) == "" {
			return fmt.Errorf("%s.%s.env: must not be empty", path, name)
		}
		if value.Secret != nil && !observabilityV8EnvNamePattern.MatchString(value.Secret.Env) {
			return fmt.Errorf("%s.%s.env: invalid secret-provider reference name", path, name)
		}
		if value.Static != nil && len(*value.Static) > 16_384 {
			return fmt.Errorf("%s.%s: static header value exceeds 16384 bytes", path, name)
		}
		if value.Static != nil && !observabilityV8ValidStaticHeaderValue(*value.Static) {
			return fmt.Errorf("%s.%s: static header value contains a prohibited control character", path, name)
		}
	}
	return nil
}

func observabilityV8ValidStaticHeaderValue(value string) bool {
	for index := 0; index < len(value); index++ {
		character := value[index]
		if character == '\t' {
			continue
		}
		if character < 0x20 || character == 0x7f {
			return false
		}
	}
	return true
}

func observabilityV8ValidHeaderName(value string) bool {
	if value == "" || len(value) > 256 || !utf8.ValidString(value) {
		return false
	}
	for index := 0; index < len(value); index++ {
		character := value[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') ||
			strings.ContainsRune("!#$%&'*+-.^_`|~", rune(character))) {
			return false
		}
	}
	return true
}

func observabilityV8ForbiddenTransportHeader(normalized string) bool {
	switch normalized {
	case "host", "content-length", "content-type", "connection", "proxy-connection",
		"keep-alive", "transfer-encoding", "upgrade", "trailer", "te":
		return true
	default:
		return false
	}
}

func observabilityV8ValidGRPCMetadataName(normalized string) bool {
	for index := 0; index < len(normalized); index++ {
		character := normalized[index]
		if !((character >= 'a' && character <= 'z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.') {
			return false
		}
	}
	return true
}

func compileObservabilityV8ResourceAttributes(
	attributes map[string]string,
	compatibilityAliases bool,
) (map[string]string, observability.TelemetryCustomResourceAttributes, error) {
	if len(attributes) > ObservabilityV8MaxResourceAttributes {
		return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
			"observability.resource.attributes: got %d entries, maximum is %d",
			len(attributes),
			ObservabilityV8MaxResourceAttributes,
		)
	}
	names := make([]string, 0, len(attributes))
	normalizedNames := make(map[string]string, len(attributes))
	for name := range attributes {
		if !utf8.ValidString(name) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes: attribute names must be valid UTF-8")
		}
		normalized := norm.NFC.String(name)
		if first, exists := normalizedNames[normalized]; exists && first != name {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes: attribute names collide after NFC normalization")
		}
		normalizedNames[normalized] = name
		names = append(names, name)
	}
	sort.Strings(names)
	if err := validateObservabilityV8ResourceAliasConflicts(attributes); err != nil {
		return nil, observability.TelemetryCustomResourceAttributes{}, err
	}
	var normalizedAttributes map[string]string
	var custom map[string]string
	if len(names) > 0 {
		normalizedAttributes = make(map[string]string, len(attributes))
		custom = make(map[string]string, len(names))
	}
	totalBytes := 0
	for _, name := range names {
		value := attributes[name]
		if !utf8.ValidString(name) || len(name) > ObservabilityV8MaxResourceKeyBytes ||
			!observabilityV8ResourceKeyPattern.MatchString(name) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
				"observability.resource.attributes: attribute names must match %s and contain at most %d ASCII bytes",
				observabilityV8ResourceKeyPattern,
				ObservabilityV8MaxResourceKeyBytes,
			)
		}
		if !utf8.ValidString(value) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: value must be valid UTF-8", name)
		}
		if len(value) == 0 || len(value) > ObservabilityV8MaxResourceValueBytes {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
				"observability.resource.attributes.%s: value must contain 1 through %d UTF-8 bytes",
				name,
				ObservabilityV8MaxResourceValueBytes,
			)
		}
		if strings.TrimSpace(value) == "" {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: value must not be blank", name)
		}
		if strings.IndexFunc(value, unicode.IsControl) >= 0 {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: value must not contain control characters", name)
		}
		if observabilityV8SecretBearingResourceKey(name) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: secret-bearing resource attributes are prohibited", name)
		}
		if observabilityV8PathBearingResourceKey(name) || observabilityV8LooksFilesystemPathResourceValue(value) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: filesystem and home-directory paths are prohibited", name)
		}
		if observabilityV8LooksSecretResourceValue(value) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf("observability.resource.attributes.%s: value resembles credential material and is prohibited", name)
		}
		canonicalName := name
		if name == "deployment.environment" {
			canonicalName = "deployment.environment.name"
		}
		if observabilityV8ReservedResourceKey(name) && !observabilityV8ConfigurableCoreResourceKey(name) {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
				"observability.resource.attributes.%s: registered, process-owned, and compatibility-alias keys cannot be configured as custom attributes",
				name,
			)
		}
		totalBytes += len(name) + len(value)
		if totalBytes > ObservabilityV8MaxResourceTotalBytes {
			return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
				"observability.resource.attributes: aggregate key and value data exceeds %d UTF-8 bytes",
				ObservabilityV8MaxResourceTotalBytes,
			)
		}
		normalizedAttributes[canonicalName] = value
		if !observabilityV8ConfigurableCoreResourceKey(name) {
			custom[name] = value
		}
	}
	sealed, err := observability.NewTelemetryCustomResourceAttributes(custom, compatibilityAliases)
	if err != nil {
		// The generated registry owns the runtime contract. Config keeps its
		// actionable path-specific checks above, and treats any disagreement as a
		// closed validation failure rather than admitting an unbuildable plan.
		return nil, observability.TelemetryCustomResourceAttributes{}, fmt.Errorf(
			"observability.resource.attributes: attributes violate the generated telemetry resource contract: %w",
			err,
		)
	}
	return normalizedAttributes, sealed, nil
}

func validateObservabilityV8ResourceAliasConflicts(attributes map[string]string) error {
	for _, pair := range [][2]string{
		{"deployment.environment.name", "deployment.environment"},
		{"defenseclaw.deployment.mode", "deployment.mode"},
		{"defenseclaw.device.public_key_fingerprint", "defenseclaw.device.id"},
	} {
		canonicalValue, canonical := attributes[pair[0]]
		legacyValue, legacy := attributes[pair[1]]
		if canonical && legacy && canonicalValue != legacyValue {
			return fmt.Errorf(
				"observability.resource.attributes: conflicting canonical and legacy alias spellings are prohibited",
			)
		}
	}
	return nil
}

func observabilityV8ConfigurableCoreResourceKey(name string) bool {
	switch name {
	case "service.name", "deployment.environment.name", "deployment.environment", "tenant.id", "workspace.id":
		return true
	default:
		return false
	}
}

func observabilityV8ReservedResourceKey(name string) bool {
	_, reserved := observabilityV8ReservedResourceKeys[name]
	return reserved
}

var observabilityV8ReservedResourceKeys = map[string]struct{}{
	"service.name": {}, "service.version": {}, "service.namespace": {}, "service.instance.id": {},
	"deployment.environment.name": {}, "host.name": {}, "host.arch": {}, "os.type": {},
	"tenant.id": {}, "workspace.id": {},
	"defenseclaw.deployment.mode": {}, "defenseclaw.claw.mode": {}, "defenseclaw.instance.id": {},
	"defenseclaw.device.public_key_fingerprint": {}, "defenseclaw.claw.home_dir": {},
	"defenseclaw.gateway.host": {}, "defenseclaw.gateway.port": {}, "discovery.source": {},
	"deployment.environment": {}, "deployment.mode": {}, "defenseclaw.device.id": {},
	"defenseclaw.preset": {}, "defenseclaw.preset_name": {},
	"telemetry.sdk.name": {}, "telemetry.sdk.language": {}, "telemetry.sdk.version": {},
}

func observabilityV8LooksSecretResourceValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	upper := strings.ToUpper(trimmed)
	if strings.Contains(upper, "PRIVATE KEY") && strings.Contains(upper, "-----BEGIN") {
		return true
	}
	if strings.HasPrefix(upper, "BEARER ") || strings.HasPrefix(upper, "BASIC ") {
		return true
	}
	if parsed, err := url.Parse(trimmed); err == nil && parsed.User != nil {
		return true
	}
	return false
}

func observabilityV8SecretBearingResourceKey(name string) bool {
	normalized := strings.NewReplacer("-", ".", "_", ".", "/", ".").Replace(strings.ToLower(name))
	for _, segment := range strings.Split(normalized, ".") {
		switch segment {
		case "authorization", "credential", "credentials", "password", "passwd", "secret", "token", "apikey", "cookie":
			return true
		}
	}
	return strings.Contains(normalized, "api.key")
}

func observabilityV8PathBearingResourceKey(name string) bool {
	normalized := strings.NewReplacer("-", ".", "_", ".", "/", ".").Replace(strings.ToLower(name))
	for _, segment := range strings.Split(normalized, ".") {
		switch segment {
		case "cwd", "dir", "directory", "file", "filepath", "home", "path", "workdir":
			return true
		}
	}
	return false
}

func observabilityV8LooksFilesystemPathResourceValue(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" {
		return false
	}
	lower := strings.ToLower(trimmed)
	if strings.HasPrefix(trimmed, "/") || strings.HasPrefix(trimmed, "~/") ||
		strings.HasPrefix(trimmed, `\\`) || strings.HasPrefix(lower, "file://") {
		return true
	}
	return len(trimmed) >= 3 &&
		((trimmed[0] >= 'a' && trimmed[0] <= 'z') || (trimmed[0] >= 'A' && trimmed[0] <= 'Z')) &&
		trimmed[1] == ':' && (trimmed[2] == '\\' || trimmed[2] == '/')
}

func compileObservabilityV8Warnings(
	local ObservabilityV8EffectiveLocal,
	destinations []ObservabilityV8EffectiveDestination,
) []ObservabilityV8Warning {
	warnings := make([]ObservabilityV8Warning, 0)
	if local.RetentionDays == 0 {
		warnings = append(warnings, ObservabilityV8Warning{
			Code: "retention_unbounded", Path: "observability.local.retention_days",
			Summary: "event, evidence, and retained judge-body history are unbounded by age",
		})
	}
	for _, destination := range destinations {
		if destination.Generated {
			continue
		}
		base := "observability.destinations[" + destination.Name + "]"
		if destination.Transport.TLS != nil && (destination.Transport.TLS.Insecure || destination.Transport.TLS.InsecureSkipVerify) {
			warnings = append(warnings, ObservabilityV8Warning{
				Code: "tls_verification_disabled", Path: base + ".tls",
				Summary: "destination transport uses an explicitly unsafe TLS mode",
			})
		}
		if destination.Transport.NetworkSafety != nil && destination.Transport.NetworkSafety.AllowPrivateNetworks {
			warnings = append(warnings, ObservabilityV8Warning{
				Code: "private_export_network_allowed", Path: base + ".network_safety.allow_private_networks",
				Summary: "destination may connect to loopback or private collector addresses",
			})
		}
		if destination.Transport.NetworkSafety != nil && destination.Transport.NetworkSafety.AllowCGNAT {
			warnings = append(warnings, ObservabilityV8Warning{
				Code: "cgnat_export_network_allowed", Path: base + ".network_safety.allow_cgnat",
				Summary: "destination may connect to RFC 6598 collector addresses",
			})
		}
	}
	return warnings
}

func compileObservabilityV8Provenance(
	source *ObservabilityV8Source,
	buckets []ObservabilityV8EffectiveBucket,
	profiles []ObservabilityV8EffectiveProfile,
	destinations []ObservabilityV8EffectiveDestination,
) []ObservabilityV8Provenance {
	result := make([]ObservabilityV8Provenance, 0, len(buckets)*3+len(profiles)+len(destinations)*5+14+len(source.Resource.Attributes))
	resourceOrigin := "compiled-default"
	resourceDetail := "no resource attributes configured"
	if len(source.Resource.Attributes) > 0 {
		resourceOrigin = "source"
		resourceDetail = "normalized configured resource attributes"
	}
	result = append(result,
		ObservabilityV8Provenance{Path: "observability.bucket_catalog_version", Origin: originObservabilityV8Pointer(source.BucketCatalogVersion), Detail: "catalog-v1"},
		ObservabilityV8Provenance{Path: "observability.resource_attributes", Origin: resourceOrigin, Detail: resourceDetail},
		ObservabilityV8Provenance{Path: "observability.warnings", Origin: "compiler-derived", Detail: "validation and risk warnings"},
		ObservabilityV8Provenance{Path: "observability.trace_policy.sampler", Origin: originObservabilityV8String(source.TracePolicy.Sampler)},
		ObservabilityV8Provenance{Path: "observability.trace_policy.semantic_profile", Origin: originObservabilityV8String(source.TracePolicy.SemanticProfile)},
		ObservabilityV8Provenance{Path: "observability.trace_policy.semantic_profile_lock", Origin: "registry-lock", Source: "schemas/telemetry/v8/registry.yaml", Line: 3, Column: 5},
		ObservabilityV8Provenance{Path: "observability.trace_policy.compatibility_aliases", Origin: originObservabilityV8Pointer(source.TracePolicy.CompatibilityAliases)},
		ObservabilityV8Provenance{Path: "observability.trace_policy.limits", Origin: originObservabilityV8TraceLimits(source.TracePolicy.Limits)},
		ObservabilityV8Provenance{Path: "observability.metric_policy.export_interval_seconds", Origin: originObservabilityV8Int(source.MetricPolicy.ExportIntervalSeconds)},
		ObservabilityV8Provenance{Path: "observability.metric_policy.temporality", Origin: originObservabilityV8String(source.MetricPolicy.Temporality)},
		ObservabilityV8Provenance{Path: "observability.local.path", Origin: originObservabilityV8Path(source.Local.Path, source.localPathDefaulted)},
		ObservabilityV8Provenance{Path: "observability.local.judge_bodies_path", Origin: originObservabilityV8Path(source.Local.JudgeBodiesPath, source.judgePathDefaulted)},
		ObservabilityV8Provenance{Path: "observability.local.retention_days", Origin: originObservabilityV8Pointer(source.Local.RetentionDays)},
	)
	resourceNames := make([]string, 0, len(source.Resource.Attributes))
	for name := range source.Resource.Attributes {
		resourceNames = append(resourceNames, name)
	}
	sort.Strings(resourceNames)
	for _, name := range resourceNames {
		result = append(result, ObservabilityV8Provenance{Path: "observability.resource.attributes." + name, Origin: "source"})
	}
	for _, bucket := range buckets {
		policy, overridden := source.Buckets[bucket.Bucket]
		collectOrigin := "catalog-default"
		profileOrigin := "catalog-default"
		if observabilityV8CollectConfigured(source.Defaults.Collect) {
			collectOrigin = "global-default"
		}
		if source.Defaults.RedactionProfile != "" {
			profileOrigin = "global-default"
		}
		if overridden && observabilityV8CollectConfigured(policy.Collect) {
			collectOrigin = "bucket-override"
		}
		if overridden && policy.RedactionProfile != "" {
			profileOrigin = "bucket-override"
		}
		base := "observability.buckets." + string(bucket.Bucket)
		result = append(result,
			ObservabilityV8Provenance{Path: base + ".bucket", Origin: "catalog-default", Detail: "catalog-v1", Source: "schemas/telemetry/generated/catalog.json"},
			ObservabilityV8Provenance{Path: base + ".collect", Origin: collectOrigin},
			ObservabilityV8Provenance{Path: base + ".collect.logs", Origin: observabilityV8BucketSignalOrigin(source.Defaults.Collect.Logs, policy.Collect.Logs, overridden)},
			ObservabilityV8Provenance{Path: base + ".collect.traces", Origin: observabilityV8BucketSignalOrigin(source.Defaults.Collect.Traces, policy.Collect.Traces, overridden)},
			ObservabilityV8Provenance{Path: base + ".collect.metrics", Origin: observabilityV8BucketSignalOrigin(source.Defaults.Collect.Metrics, policy.Collect.Metrics, overridden)},
			ObservabilityV8Provenance{Path: base + ".redaction_profile", Origin: profileOrigin},
			ObservabilityV8Provenance{Path: base + ".reload_applicability", Origin: "reload-contract", Detail: string(bucket.ReloadApplicability)},
		)
	}
	for _, profile := range profiles {
		origin := "built-in-profile"
		if !profile.BuiltIn {
			origin = "source"
		}
		result = append(result, ObservabilityV8Provenance{
			Path:   v8YAMLChildPath("observability.redaction_profiles", profile.Name),
			Origin: origin,
		})
	}
	for _, destination := range destinations {
		origin := "source"
		identityOrigin := "source"
		if destination.Generated {
			origin = "generated"
			identityOrigin = "generated"
		} else if destination.PolicyForm == ObservabilityV8PolicyCapabilityDefault {
			origin = "capability-default"
		}
		base := "observability.destinations." + destination.Name
		result = append(result,
			ObservabilityV8Provenance{Path: base + ".name", Origin: identityOrigin, Detail: "compiled destination identity"},
			ObservabilityV8Provenance{Path: base + ".kind", Origin: identityOrigin, Detail: "compiled destination identity"},
			ObservabilityV8Provenance{Path: base + ".generated", Origin: identityOrigin, Detail: "compiled destination identity"},
			ObservabilityV8Provenance{Path: base + ".enabled", Origin: observabilityV8DestinationEnabledOrigin(source, destination)},
			ObservabilityV8Provenance{Path: base + ".policy", Origin: origin},
			ObservabilityV8Provenance{Path: base + ".transport", Origin: observabilityV8TransportOrigin(destination)},
			ObservabilityV8Provenance{
				Path: base + ".reload_applicability", Origin: "reload-contract",
				Detail: "policy=" + string(destination.ReloadApplicability.Policy) + ",transport=" + string(destination.ReloadApplicability.Transport),
			},
		)
		if destination.PresetProfile != "" {
			result = append(result, ObservabilityV8Provenance{Path: base + ".preset_profile", Origin: "preset", Detail: destination.PresetProfile})
		}
		for _, profile := range destination.CompatibilityProfiles {
			result = append(result, ObservabilityV8Provenance{
				Path: base + ".compatibility_profiles." + profile.ID, Origin: "registry-profile",
				Detail: profile.ID, Source: "schemas/telemetry/generated/catalog.json",
			})
		}
	}
	return result
}

func observabilityV8BucketSignalOrigin(global, override *bool, bucketOverridden bool) string {
	if bucketOverridden && override != nil {
		return "bucket-override"
	}
	if global != nil {
		return "global-default"
	}
	return "catalog-default"
}

func observabilityV8DestinationEnabledOrigin(source *ObservabilityV8Source, destination ObservabilityV8EffectiveDestination) string {
	if destination.Generated {
		return "generated"
	}
	for index := range source.Destinations {
		if source.Destinations[index].Name == destination.Name {
			if source.Destinations[index].Enabled == nil {
				return "compiled-default"
			}
			return "source"
		}
	}
	return "source"
}

func observabilityV8CollectConfigured(source ObservabilityV8CollectSource) bool {
	return source.Logs != nil || source.Traces != nil || source.Metrics != nil
}

func originObservabilityV8Pointer[T any](value *T) string {
	if value == nil {
		return "compiled-default"
	}
	return "source"
}

func originObservabilityV8String(value string) string {
	if value == "" {
		return "compiled-default"
	}
	return "source"
}

func originObservabilityV8Int(value int) string {
	if value == 0 {
		return "compiled-default"
	}
	return "source"
}

func originObservabilityV8TraceLimits(source ObservabilityV8TraceLimitsSource) string {
	if source == (ObservabilityV8TraceLimitsSource{}) {
		return "compiled-default"
	}
	return "source-with-compiled-defaults"
}

func originObservabilityV8Path(value string, defaulted bool) string {
	if value == "" || defaulted {
		return "compiled-default"
	}
	return "source"
}

func observabilityV8TransportOrigin(destination ObservabilityV8EffectiveDestination) string {
	if destination.Generated {
		return "generated"
	}
	if destination.PresetProfile != "" {
		return "preset-with-source-overrides"
	}
	return "source-with-adapter-defaults"
}

func validateObservabilityV8SignalOverrides(overrides map[observability.Signal]ObservabilityV8SignalOverrideSource, selected []observability.Signal, path string) error {
	selectedSet := make(map[observability.Signal]struct{}, len(selected))
	for _, signal := range selected {
		selectedSet[signal] = struct{}{}
	}
	for signal := range overrides {
		if !observability.IsSignal(signal) {
			return fmt.Errorf("%s: unknown signal %q", path, signal)
		}
		if _, ok := selectedSet[signal]; !ok {
			return fmt.Errorf("%s.%s: signal is not selected by destination policy", path, signal)
		}
	}
	return nil
}

func compileObservabilityV8Profiles(source map[string]ObservabilityV8RedactionProfileSource) ([]ObservabilityV8EffectiveProfile, map[string]struct{}, error) {
	builtIns := observabilityV8BuiltInProfiles()
	known := make(map[string]struct{}, len(builtIns)+len(source))
	for name := range builtIns {
		known[name] = struct{}{}
	}
	for name := range source {
		if !observabilityV8StableNamePattern.MatchString(name) {
			return nil, nil, fmt.Errorf("observability.redaction_profiles: profile name %q is not a stable lower-case identifier", name)
		}
		if _, reserved := builtIns[name]; reserved {
			return nil, nil, fmt.Errorf("observability.redaction_profiles.%s: built-in profile name is reserved", name)
		}
		known[name] = struct{}{}
	}
	result := make([]ObservabilityV8EffectiveProfile, 0, len(builtIns)+len(source))
	for _, name := range []string{"none", "sensitive", "content", "strict", "legacy-v7"} {
		result = append(result, cloneObservabilityV8Profile(builtIns[name]))
	}
	names := make([]string, 0, len(source))
	for name := range source {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		profileSource := source[name]
		base, ok := builtIns[profileSource.Extends]
		if !ok || profileSource.Extends == "none" || profileSource.Extends == "legacy-v7" {
			return nil, nil, fmt.Errorf("observability.redaction_profiles.%s.extends: expected sensitive, content, or strict", name)
		}
		if profileSource.Detectors != nil && len(profileSource.Detectors) == 0 {
			return nil, nil, fmt.Errorf("observability.redaction_profiles.%s.detectors: explicit list must not be empty", name)
		}
		profile := cloneObservabilityV8Profile(base)
		profile.Name, profile.BuiltIn, profile.Extends = name, false, profileSource.Extends
		if profileSource.Detectors != nil {
			profile.Detectors = append([]ObservabilityV8DetectorGroup(nil), profileSource.Detectors...)
		}
		if err := validateObservabilityV8DetectorGroups(profile.Detectors, name); err != nil {
			return nil, nil, err
		}
		for fieldClass, mode := range profileSource.FieldClasses {
			if !isObservabilityV8FieldClass(fieldClass) {
				return nil, nil, fmt.Errorf("observability.redaction_profiles.%s.field_classes: unknown class %q", name, fieldClass)
			}
			if !isObservabilityV8FieldMode(mode) {
				return nil, nil, fmt.Errorf("observability.redaction_profiles.%s.field_classes.%s: unknown mode %q", name, fieldClass, mode)
			}
			profile.FieldClasses[fieldClass] = mode
		}
		if err := validateObservabilityV8ProfileStrength(profile); err != nil {
			return nil, nil, fmt.Errorf("observability.redaction_profiles.%s: %w", name, err)
		}
		result = append(result, profile)
	}
	return result, known, nil
}

func observabilityV8BuiltInProfiles() map[string]ObservabilityV8EffectiveProfile {
	allDetectors := []ObservabilityV8DetectorGroup{ObservabilityV8DetectorPII, ObservabilityV8DetectorCredentials, ObservabilityV8DetectorSecrets}
	preserveAll := map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{
		ObservabilityV8FieldMetadata: ObservabilityV8ModePreserve, ObservabilityV8FieldIdentifier: ObservabilityV8ModePreserve,
		ObservabilityV8FieldContent: ObservabilityV8ModePreserve, ObservabilityV8FieldReason: ObservabilityV8ModePreserve,
		ObservabilityV8FieldEvidence: ObservabilityV8ModePreserve, ObservabilityV8FieldError: ObservabilityV8ModePreserve,
		ObservabilityV8FieldPath: ObservabilityV8ModePreserve, ObservabilityV8FieldCredential: ObservabilityV8ModePreserve,
	}
	sensitive := map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{
		ObservabilityV8FieldMetadata: ObservabilityV8ModePreserve, ObservabilityV8FieldIdentifier: ObservabilityV8ModePreserve,
		ObservabilityV8FieldContent: ObservabilityV8ModeDetect, ObservabilityV8FieldReason: ObservabilityV8ModeDetect,
		ObservabilityV8FieldEvidence: ObservabilityV8ModeDetect, ObservabilityV8FieldError: ObservabilityV8ModeDetect,
		ObservabilityV8FieldPath: ObservabilityV8ModeHash, ObservabilityV8FieldCredential: ObservabilityV8ModeRemove,
	}
	content := cloneObservabilityV8FieldModes(sensitive)
	for _, fieldClass := range []ObservabilityV8FieldClass{
		ObservabilityV8FieldContent,
		ObservabilityV8FieldReason,
		ObservabilityV8FieldEvidence,
		ObservabilityV8FieldError,
	} {
		content[fieldClass] = ObservabilityV8ModeWhole
	}
	strict := map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{
		ObservabilityV8FieldMetadata: ObservabilityV8ModePreserve, ObservabilityV8FieldIdentifier: ObservabilityV8ModePreserve,
		ObservabilityV8FieldContent: ObservabilityV8ModeRemove, ObservabilityV8FieldReason: ObservabilityV8ModeRemove,
		ObservabilityV8FieldEvidence: ObservabilityV8ModeRemove, ObservabilityV8FieldError: ObservabilityV8ModeRemove,
		ObservabilityV8FieldPath: ObservabilityV8ModeRemove, ObservabilityV8FieldCredential: ObservabilityV8ModeRemove,
	}
	legacyV7 := map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{
		ObservabilityV8FieldMetadata: ObservabilityV8ModePreserve, ObservabilityV8FieldIdentifier: ObservabilityV8ModeWhole,
		ObservabilityV8FieldContent: ObservabilityV8ModeWhole, ObservabilityV8FieldReason: ObservabilityV8ModeWhole,
		ObservabilityV8FieldEvidence: ObservabilityV8ModeWhole, ObservabilityV8FieldError: ObservabilityV8ModeWhole,
		ObservabilityV8FieldPath: ObservabilityV8ModeWhole, ObservabilityV8FieldCredential: ObservabilityV8ModeWhole,
	}
	return map[string]ObservabilityV8EffectiveProfile{
		"none":      {Name: "none", BuiltIn: true, Detectors: []ObservabilityV8DetectorGroup{}, FieldClasses: preserveAll},
		"sensitive": {Name: "sensitive", BuiltIn: true, Detectors: allDetectors, FieldClasses: sensitive},
		"content":   {Name: "content", BuiltIn: true, Detectors: allDetectors, FieldClasses: content},
		"strict":    {Name: "strict", BuiltIn: true, Detectors: allDetectors, FieldClasses: strict},
		"legacy-v7": {Name: "legacy-v7", BuiltIn: true, Detectors: []ObservabilityV8DetectorGroup{}, FieldClasses: legacyV7},
	}
}

func cloneObservabilityV8Profile(source ObservabilityV8EffectiveProfile) ObservabilityV8EffectiveProfile {
	result := source
	result.Detectors = append([]ObservabilityV8DetectorGroup(nil), source.Detectors...)
	result.FieldClasses = cloneObservabilityV8FieldModes(source.FieldClasses)
	return result
}

func validateObservabilityV8DetectorGroups(groups []ObservabilityV8DetectorGroup, profile string) error {
	seen := make(map[ObservabilityV8DetectorGroup]struct{}, len(groups))
	for _, group := range groups {
		switch group {
		case ObservabilityV8DetectorPII, ObservabilityV8DetectorCredentials, ObservabilityV8DetectorSecrets:
		default:
			return fmt.Errorf("observability.redaction_profiles.%s.detectors: unknown group %q", profile, group)
		}
		if _, duplicate := seen[group]; duplicate {
			return fmt.Errorf("observability.redaction_profiles.%s.detectors: duplicate group %q", profile, group)
		}
		seen[group] = struct{}{}
	}
	return nil
}

func validateObservabilityV8ProfileStrength(profile ObservabilityV8EffectiveProfile) error {
	for fieldClass, mode := range profile.FieldClasses {
		if (fieldClass == ObservabilityV8FieldMetadata || fieldClass == ObservabilityV8FieldIdentifier) &&
			mode != ObservabilityV8ModePreserve {
			return fmt.Errorf("field class %s must use preserve", fieldClass)
		}
		if mode == ObservabilityV8ModePreserve && fieldClass != ObservabilityV8FieldMetadata && fieldClass != ObservabilityV8FieldIdentifier {
			return fmt.Errorf("field class %s cannot use preserve", fieldClass)
		}
		if fieldClass == ObservabilityV8FieldCredential && mode != ObservabilityV8ModeRemove && mode != ObservabilityV8ModeWhole {
			return fmt.Errorf("credential may use only remove or whole")
		}
		if mode == ObservabilityV8ModeDetect && len(profile.Detectors) == 0 {
			return fmt.Errorf("detect requires at least one detector group")
		}
	}
	return nil
}

func isObservabilityV8FieldClass(fieldClass ObservabilityV8FieldClass) bool {
	switch fieldClass {
	case ObservabilityV8FieldMetadata, ObservabilityV8FieldIdentifier, ObservabilityV8FieldContent, ObservabilityV8FieldReason, ObservabilityV8FieldEvidence, ObservabilityV8FieldError, ObservabilityV8FieldPath, ObservabilityV8FieldCredential:
		return true
	default:
		return false
	}
}

func isObservabilityV8FieldMode(mode ObservabilityV8FieldMode) bool {
	switch mode {
	case ObservabilityV8ModePreserve, ObservabilityV8ModeDetect, ObservabilityV8ModeWhole, ObservabilityV8ModeHash, ObservabilityV8ModeRemove:
		return true
	default:
		return false
	}
}
