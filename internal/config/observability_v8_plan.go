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
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"net/url"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const ObservabilityV8LocalDestinationName = "local-sqlite"

type ObservabilityV8EffectiveCollect struct {
	Logs    bool `json:"logs"`
	Traces  bool `json:"traces"`
	Metrics bool `json:"metrics"`
}

func (collect ObservabilityV8EffectiveCollect) Enabled(signal observability.Signal) bool {
	switch signal {
	case observability.SignalLogs:
		return collect.Logs
	case observability.SignalTraces:
		return collect.Traces
	case observability.SignalMetrics:
		return collect.Metrics
	default:
		return false
	}
}

type ObservabilityV8EffectiveBucket struct {
	Bucket              observability.Bucket               `json:"bucket"`
	Collect             ObservabilityV8EffectiveCollect    `json:"collect"`
	RedactionProfile    string                             `json:"redaction_profile"`
	ReloadApplicability ObservabilityV8ReloadApplicability `json:"reload_applicability"`
}

type ObservabilityV8ReloadApplicability string

const (
	ObservabilityV8LiveReloadable  ObservabilityV8ReloadApplicability = "live_reloadable"
	ObservabilityV8RestartRequired ObservabilityV8ReloadApplicability = "restart_required"
)

type ObservabilityV8EffectiveProfile struct {
	Name         string                                                 `json:"name"`
	BuiltIn      bool                                                   `json:"built_in"`
	Extends      string                                                 `json:"extends,omitempty"`
	Detectors    []ObservabilityV8DetectorGroup                         `json:"detectors"`
	FieldClasses map[ObservabilityV8FieldClass]ObservabilityV8FieldMode `json:"field_classes"`
}

type ObservabilityV8EffectiveLocal struct {
	Path            string `json:"path,omitempty"`
	JudgeBodiesPath string `json:"judge_bodies_path,omitempty"`
	RetentionDays   int    `json:"retention_days"`
}

type ObservabilityV8EffectiveTracePolicy struct {
	Sampler              string                             `json:"sampler"`
	SamplerArg           string                             `json:"sampler_arg,omitempty"`
	SemanticProfile      string                             `json:"semantic_profile"`
	SemanticProfileLock  ObservabilityV8SemanticProfileLock `json:"semantic_profile_lock"`
	CompatibilityAliases bool                               `json:"compatibility_aliases"`
	Limits               ObservabilityV8TraceLimitsSource   `json:"limits"`
}

type ObservabilityV8SemanticProfileLock struct {
	TraceSchemaVersion          string `json:"trace_schema_version"`
	GenAISemconvProfile         string `json:"gen_ai_semconv_profile"`
	OpenInferenceProfile        string `json:"openinference_profile"`
	GalileoCompatibilityProfile string `json:"galileo_compatibility_profile"`
}

type ObservabilityV8EffectiveMetricPolicy struct {
	ExportIntervalSeconds int    `json:"export_interval_seconds"`
	Temporality           string `json:"temporality"`
}

type ObservabilityV8DestinationCapabilities struct {
	Signals []observability.Signal `json:"signals"`
}

func (capabilities ObservabilityV8DestinationCapabilities) Supports(signal observability.Signal) bool {
	for _, candidate := range capabilities.Signals {
		if candidate == signal {
			return true
		}
	}
	return false
}

type ObservabilityV8PolicyForm string

const (
	ObservabilityV8PolicyImplicitLocal     ObservabilityV8PolicyForm = "implicit_local"
	ObservabilityV8PolicyCapabilityDefault ObservabilityV8PolicyForm = "capability_default"
	ObservabilityV8PolicyConciseSend       ObservabilityV8PolicyForm = "concise_send"
	ObservabilityV8PolicyAdvancedRoutes    ObservabilityV8PolicyForm = "advanced_routes"
	ObservabilityV8PolicyDisabledNoPolicy  ObservabilityV8PolicyForm = "disabled_no_policy"
)

type ObservabilityV8EffectiveRotation struct {
	MaxSizeMB  int  `json:"max_size_mb"`
	MaxBackups int  `json:"max_backups"`
	MaxAgeDays int  `json:"max_age_days"`
	Compress   bool `json:"compress"`
}

type ObservabilityV8EffectiveSpanFamily struct {
	EventName    observability.EventName `json:"event_name"`
	Bucket       observability.Bucket    `json:"bucket"`
	Availability string                  `json:"availability"`
}

type ObservabilityV8EffectiveCompatibilityProfile struct {
	ID                   string                               `json:"id"`
	Availability         string                               `json:"availability"`
	EligibleSpanFamilies []ObservabilityV8EffectiveSpanFamily `json:"eligible_span_families"`
}

type ObservabilityV8EffectiveDestinationReload struct {
	Policy    ObservabilityV8ReloadApplicability `json:"policy"`
	Transport ObservabilityV8ReloadApplicability `json:"transport"`
}

type ObservabilityV8EffectiveSelector struct {
	Buckets        []observability.Bucket      `json:"buckets,omitempty"`
	BucketWildcard bool                        `json:"bucket_wildcard,omitempty"`
	Sources        []observability.Source      `json:"sources,omitempty"`
	Connectors     []string                    `json:"connectors,omitempty"`
	Actions        []observability.ProducerKey `json:"actions,omitempty"`
	EventNames     []observability.EventName   `json:"event_names,omitempty"`
	MinSeverity    observability.Severity      `json:"min_severity,omitempty"`
}

type ObservabilityV8EffectiveRoute struct {
	Index                    int                              `json:"index"`
	Name                     string                           `json:"name"`
	Generated                bool                             `json:"generated"`
	Signals                  []observability.Signal           `json:"signals"`
	Selector                 ObservabilityV8EffectiveSelector `json:"selector"`
	Action                   ObservabilityV8RouteAction       `json:"action"`
	RedactionProfileByBucket map[observability.Bucket]string  `json:"redaction_profile_by_bucket,omitempty"`
	IncludesMandatoryFloor   bool                             `json:"includes_mandatory_floor,omitempty"`
}

type ObservabilityV8TransportPlan struct {
	Path                string                                                       `json:"path,omitempty"`
	Rotation            *ObservabilityV8EffectiveRotation                            `json:"rotation,omitempty"`
	Listen              string                                                       `json:"listen,omitempty"`
	Endpoint            string                                                       `json:"endpoint,omitempty"`
	Protocol            string                                                       `json:"protocol,omitempty"`
	Method              string                                                       `json:"method,omitempty"`
	Headers             map[string]ObservabilityV8HeaderValue                        `json:"headers,omitempty"`
	TokenEnv            string                                                       `json:"token_env,omitempty"`
	BearerEnv           string                                                       `json:"bearer_env,omitempty"`
	Index               string                                                       `json:"index,omitempty"`
	Source              string                                                       `json:"source,omitempty"`
	SourceType          string                                                       `json:"sourcetype,omitempty"`
	SourceTypeOverrides map[observability.ProducerKey]string                         `json:"sourcetype_overrides,omitempty"`
	LoggerName          string                                                       `json:"logger_name,omitempty"`
	TimeoutMS           int                                                          `json:"timeout_ms,omitempty"`
	TLS                 *ObservabilityV8TLSSource                                    `json:"tls,omitempty"`
	Batch               *ObservabilityV8BatchSource                                  `json:"batch,omitempty"`
	NetworkSafety       *ObservabilityV8NetworkSafetySource                          `json:"network_safety,omitempty"`
	SignalOverrides     map[observability.Signal]ObservabilityV8SignalOverrideSource `json:"signal_overrides,omitempty"`
}

type ObservabilityV8EffectiveDestination struct {
	Name                  string                                         `json:"name"`
	Kind                  ObservabilityV8DestinationKind                 `json:"kind"`
	Enabled               bool                                           `json:"enabled"`
	Generated             bool                                           `json:"generated"`
	Preset                string                                         `json:"preset,omitempty"`
	PresetProfile         string                                         `json:"preset_profile,omitempty"`
	CompatibilityProfiles []ObservabilityV8EffectiveCompatibilityProfile `json:"compatibility_profiles,omitempty"`
	Capabilities          ObservabilityV8DestinationCapabilities         `json:"capabilities"`
	SelectedSignals       []observability.Signal                         `json:"selected_signals"`
	PolicyForm            ObservabilityV8PolicyForm                      `json:"policy_form"`
	FirstMatchPerSignal   bool                                           `json:"first_match_per_signal"`
	ReloadApplicability   ObservabilityV8EffectiveDestinationReload      `json:"reload_applicability"`
	Routes                []ObservabilityV8EffectiveRoute                `json:"routes"`
	Transport             ObservabilityV8TransportPlan                   `json:"transport,omitempty"`
	// managedAIDSourceContentHash is generation-local release metadata. It is
	// intentionally absent from display/effective JSON and public plan digests.
	managedAIDSourceContentHash string
}

type ObservabilityV8Warning struct {
	Code    string `json:"code"`
	Path    string `json:"path"`
	Summary string `json:"summary"`
}

type ObservabilityV8Provenance struct {
	Path      string `json:"path"`
	ValuePath string `json:"value_path,omitempty"`
	Origin    string `json:"origin"`
	Detail    string `json:"detail,omitempty"`
	Source    string `json:"source,omitempty"`
	Line      int    `json:"line,omitempty"`
	Column    int    `json:"column,omitempty"`
}

// ObservabilityV8EffectivePlan is a detached snapshot. Mutating it cannot alter
// the immutable plan returned by CompileObservabilityV8.
type ObservabilityV8EffectivePlan struct {
	BucketCatalogVersion int `json:"bucket_catalog_version"`
	// ResourceAttributes is the normalized registered-core plus custom resource
	// map. Compatibility aliases are canonicalized before the plan is frozen.
	ResourceAttributes map[string]string `json:"resource_attributes"`
	// ResourceAttributeEntries is the generated, sealed custom-only projection.
	// Runtime builders combine it with typed registered-core inputs. It is
	// JSON-neutral so plan digests retain one canonical map representation.
	ResourceAttributeEntries observability.TelemetryCustomResourceAttributes `json:"-"`
	TracePolicy              ObservabilityV8EffectiveTracePolicy             `json:"trace_policy"`
	MetricPolicy             ObservabilityV8EffectiveMetricPolicy            `json:"metric_policy"`
	Local                    ObservabilityV8EffectiveLocal                   `json:"local"`
	Buckets                  []ObservabilityV8EffectiveBucket                `json:"buckets"`
	Profiles                 []ObservabilityV8EffectiveProfile               `json:"redaction_profiles"`
	Destinations             []ObservabilityV8EffectiveDestination           `json:"destinations"`
	Warnings                 []ObservabilityV8Warning                        `json:"warnings"`
	Provenance               []ObservabilityV8Provenance                     `json:"provenance"`
}

// ObservabilityV8Plan keeps all mutable representation private. Every accessor
// returns a value or deep copy so a plan can be atomically shared by readers.
type ObservabilityV8Plan struct {
	effective     ObservabilityV8EffectivePlan
	display       ObservabilityV8EffectivePlan
	canonicalJSON []byte
	// digest is safe to emit in telemetry and diagnostics: it is derived
	// exclusively from the masked effective plan.
	digest [sha256.Size]byte
	// reloadDigest retains secret-sensitive comparison semantics without ever
	// exposing a secret-derived token to callers. ReloadEquivalent is the only
	// accessor for this value.
	reloadDigest [sha256.Size]byte
}

func newObservabilityV8Plan(effective ObservabilityV8EffectivePlan) (*ObservabilityV8Plan, error) {
	provenance, err := completeObservabilityV8EffectiveProvenance(effective)
	if err != nil {
		return nil, err
	}
	effective.Provenance = provenance
	display := maskObservabilityV8EffectivePlan(effective)
	canonical, err := json.Marshal(display)
	if err != nil {
		return nil, err
	}
	digestDisplay := cloneObservabilityV8EffectivePlan(display)
	digestDisplay.Provenance = nil
	digestJSON, err := json.Marshal(digestDisplay)
	if err != nil {
		return nil, err
	}
	digestEffective := cloneObservabilityV8EffectivePlan(effective)
	digestEffective.Provenance = nil
	reloadJSON, err := json.Marshal(digestEffective)
	if err != nil {
		return nil, err
	}
	reloadBindings := make([]struct {
		Name        string `json:"name"`
		ContentHash string `json:"content_hash"`
	}, 0, len(effective.Destinations))
	for _, destination := range effective.Destinations {
		if destination.managedAIDSourceContentHash == "" {
			continue
		}
		reloadBindings = append(reloadBindings, struct {
			Name        string `json:"name"`
			ContentHash string `json:"content_hash"`
		}{Name: destination.Name, ContentHash: destination.managedAIDSourceContentHash})
	}
	reloadBindingJSON, err := json.Marshal(reloadBindings)
	if err != nil {
		return nil, err
	}
	reloadInput := make([]byte, 0, len(reloadJSON)+1+len(reloadBindingJSON))
	reloadInput = append(reloadInput, reloadJSON...)
	reloadInput = append(reloadInput, '\n')
	reloadInput = append(reloadInput, reloadBindingJSON...)
	return &ObservabilityV8Plan{
		effective:     cloneObservabilityV8EffectivePlan(effective),
		display:       cloneObservabilityV8EffectivePlan(display),
		canonicalJSON: append([]byte(nil), canonical...),
		digest:        sha256.Sum256(digestJSON),
		reloadDigest:  sha256.Sum256(reloadInput),
	}, nil
}

func (plan *ObservabilityV8Plan) Snapshot() ObservabilityV8EffectivePlan {
	if plan == nil {
		return ObservabilityV8EffectivePlan{}
	}
	return cloneObservabilityV8EffectivePlan(plan.display)
}

func (plan *ObservabilityV8Plan) EffectiveJSON() []byte {
	if plan == nil {
		return nil
	}
	return append([]byte(nil), plan.canonicalJSON...)
}

func (plan *ObservabilityV8Plan) Digest() string {
	if plan == nil {
		return ""
	}
	return hex.EncodeToString(plan.digest[:])
}

// ReloadEquivalent reports whether two plans have identical runtime inputs,
// including static headers and endpoint query/fragment values that are masked
// from Digest and every display accessor. The secret-sensitive comparison is
// performed internally so no reusable secret-derived fingerprint escapes the
// plan.
func (plan *ObservabilityV8Plan) ReloadEquivalent(other *ObservabilityV8Plan) bool {
	if plan == nil || other == nil {
		return false
	}
	return subtle.ConstantTimeCompare(plan.reloadDigest[:], other.reloadDigest[:]) == 1
}

func (plan *ObservabilityV8Plan) Bucket(bucket observability.Bucket) (ObservabilityV8EffectiveBucket, bool) {
	if plan == nil {
		return ObservabilityV8EffectiveBucket{}, false
	}
	for _, candidate := range plan.display.Buckets {
		if candidate.Bucket == bucket {
			return candidate, true
		}
	}
	return ObservabilityV8EffectiveBucket{}, false
}

func (plan *ObservabilityV8Plan) Destinations() []ObservabilityV8EffectiveDestination {
	if plan == nil {
		return nil
	}
	return cloneObservabilityV8Destinations(plan.display.Destinations)
}

func (plan *ObservabilityV8Plan) Destination(name string) (ObservabilityV8EffectiveDestination, bool) {
	if plan == nil {
		return ObservabilityV8EffectiveDestination{}, false
	}
	for _, candidate := range plan.display.Destinations {
		if candidate.Name == name {
			return cloneObservabilityV8Destination(candidate), true
		}
	}
	return ObservabilityV8EffectiveDestination{}, false
}

// RuntimeDestination returns the unmasked source transport for adapter
// initialization. It must never be used by config display, diagnostics, or logs.
func (plan *ObservabilityV8Plan) RuntimeDestination(name string) (ObservabilityV8EffectiveDestination, bool) {
	if plan == nil {
		return ObservabilityV8EffectiveDestination{}, false
	}
	for _, candidate := range plan.effective.Destinations {
		if candidate.Name == name {
			return cloneObservabilityV8Destination(candidate), true
		}
	}
	return ObservabilityV8EffectiveDestination{}, false
}

func cloneObservabilityV8EffectivePlan(source ObservabilityV8EffectivePlan) ObservabilityV8EffectivePlan {
	result := source
	result.ResourceAttributes = cloneStringMap(source.ResourceAttributes)
	// TelemetryCustomResourceAttributes is immutable: its constructor owns its
	// private copy and Values always returns a detached map.
	result.ResourceAttributeEntries = source.ResourceAttributeEntries
	result.Buckets = append([]ObservabilityV8EffectiveBucket(nil), source.Buckets...)
	result.Profiles = make([]ObservabilityV8EffectiveProfile, len(source.Profiles))
	for index, profile := range source.Profiles {
		result.Profiles[index] = profile
		result.Profiles[index].Detectors = append([]ObservabilityV8DetectorGroup(nil), profile.Detectors...)
		result.Profiles[index].FieldClasses = cloneObservabilityV8FieldModes(profile.FieldClasses)
	}
	result.Destinations = cloneObservabilityV8Destinations(source.Destinations)
	result.Warnings = append([]ObservabilityV8Warning(nil), source.Warnings...)
	result.Provenance = append([]ObservabilityV8Provenance(nil), source.Provenance...)
	return result
}

func maskObservabilityV8EffectivePlan(source ObservabilityV8EffectivePlan) ObservabilityV8EffectivePlan {
	result := cloneObservabilityV8EffectivePlan(source)
	for destinationIndex := range result.Destinations {
		destination := &result.Destinations[destinationIndex]
		destination.Transport.Endpoint = maskObservabilityV8Endpoint(destination.Transport.Endpoint)
		for signal, override := range destination.Transport.SignalOverrides {
			override.Endpoint = maskObservabilityV8Endpoint(override.Endpoint)
			destination.Transport.SignalOverrides[signal] = override
		}
		for name, value := range destination.Transport.Headers {
			if value.Static == nil {
				continue
			}
			destination.Transport.Headers[name] = ObservabilityV8StaticHeader("[REDACTED]")
		}
	}
	return result
}

func maskObservabilityV8Endpoint(value string) string {
	if value == "" {
		return value
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return value
	}
	if parsed.RawQuery != "" || parsed.ForceQuery {
		parsed.RawQuery = "[REDACTED]"
		parsed.ForceQuery = true
	}
	if parsed.Fragment != "" {
		parsed.Fragment = "[REDACTED]"
	}
	return parsed.String()
}

func cloneObservabilityV8Destinations(source []ObservabilityV8EffectiveDestination) []ObservabilityV8EffectiveDestination {
	result := make([]ObservabilityV8EffectiveDestination, len(source))
	for index, destination := range source {
		result[index] = cloneObservabilityV8Destination(destination)
	}
	return result
}

func cloneObservabilityV8Destination(source ObservabilityV8EffectiveDestination) ObservabilityV8EffectiveDestination {
	result := source
	if source.CompatibilityProfiles != nil {
		result.CompatibilityProfiles = make([]ObservabilityV8EffectiveCompatibilityProfile, len(source.CompatibilityProfiles))
		for index, profile := range source.CompatibilityProfiles {
			result.CompatibilityProfiles[index] = profile
			result.CompatibilityProfiles[index].EligibleSpanFamilies = append(
				[]ObservabilityV8EffectiveSpanFamily(nil),
				profile.EligibleSpanFamilies...,
			)
		}
	}
	result.Capabilities.Signals = append([]observability.Signal(nil), source.Capabilities.Signals...)
	result.SelectedSignals = append([]observability.Signal(nil), source.SelectedSignals...)
	result.Routes = make([]ObservabilityV8EffectiveRoute, len(source.Routes))
	for index, route := range source.Routes {
		result.Routes[index] = route
		result.Routes[index].Signals = append([]observability.Signal(nil), route.Signals...)
		result.Routes[index].Selector = cloneObservabilityV8Selector(route.Selector)
		result.Routes[index].RedactionProfileByBucket = cloneBucketProfileMap(route.RedactionProfileByBucket)
	}
	result.Transport.Headers = cloneObservabilityV8Headers(source.Transport.Headers)
	result.Transport.SignalOverrides = cloneObservabilityV8SignalOverrides(source.Transport.SignalOverrides)
	result.Transport.SourceTypeOverrides = cloneObservabilityV8SourceTypeOverrides(source.Transport.SourceTypeOverrides)
	if source.Transport.Rotation != nil {
		rotation := *source.Transport.Rotation
		result.Transport.Rotation = &rotation
	}
	if source.Transport.TLS != nil {
		tls := *source.Transport.TLS
		result.Transport.TLS = &tls
	}
	if source.Transport.Batch != nil {
		batch := *source.Transport.Batch
		result.Transport.Batch = &batch
	}
	if source.Transport.NetworkSafety != nil {
		networkSafety := *source.Transport.NetworkSafety
		result.Transport.NetworkSafety = &networkSafety
	}
	return result
}

func cloneObservabilityV8Selector(source ObservabilityV8EffectiveSelector) ObservabilityV8EffectiveSelector {
	result := source
	result.Buckets = append([]observability.Bucket(nil), source.Buckets...)
	result.Sources = append([]observability.Source(nil), source.Sources...)
	result.Connectors = append([]string(nil), source.Connectors...)
	result.Actions = append([]observability.ProducerKey(nil), source.Actions...)
	result.EventNames = append([]observability.EventName(nil), source.EventNames...)
	return result
}

func cloneObservabilityV8Headers(source map[string]ObservabilityV8HeaderValue) map[string]ObservabilityV8HeaderValue {
	if source == nil {
		return nil
	}
	result := make(map[string]ObservabilityV8HeaderValue, len(source))
	for key, value := range source {
		cloned := value
		if value.Static != nil {
			static := *value.Static
			cloned.Static = &static
		}
		if value.Secret != nil {
			secret := *value.Secret
			cloned.Secret = &secret
		}
		result[key] = cloned
	}
	return result
}

func cloneObservabilityV8SignalOverrides(source map[observability.Signal]ObservabilityV8SignalOverrideSource) map[observability.Signal]ObservabilityV8SignalOverrideSource {
	if source == nil {
		return nil
	}
	result := make(map[observability.Signal]ObservabilityV8SignalOverrideSource, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneObservabilityV8SourceTypeOverrides(source map[observability.ProducerKey]string) map[observability.ProducerKey]string {
	if source == nil {
		return nil
	}
	result := make(map[observability.ProducerKey]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneObservabilityV8FieldModes(source map[ObservabilityV8FieldClass]ObservabilityV8FieldMode) map[ObservabilityV8FieldClass]ObservabilityV8FieldMode {
	if source == nil {
		return nil
	}
	result := make(map[ObservabilityV8FieldClass]ObservabilityV8FieldMode, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneBucketProfileMap(source map[observability.Bucket]string) map[observability.Bucket]string {
	if source == nil {
		return nil
	}
	result := make(map[observability.Bucket]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func cloneStringMap(source map[string]string) map[string]string {
	if source == nil {
		return nil
	}
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}
