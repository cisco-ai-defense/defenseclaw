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
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"regexp"
	"sort"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/asrruntime"
)

const (
	asrReplayMaxSemanticBytes        = 1 << 20
	asrReplayMaxSemanticItems        = 1_024
	asrReplayMaxSemanticControls     = 256
	asrReplayMaxSemanticCategories   = 64
	asrReplayMaxSemanticCategoryByte = 128
	asrReplayMaxCardinality          = 1 << 20
)

// asrReplaySemanticSummary is the only ASR semantic representation safe for
// benchmark output. It deliberately excludes argv, resource identifiers,
// paths, URLs, control values, conditions, parameters, and other free text.
// Every emitted categorical value comes from a closed vocabulary below.
type asrReplaySemanticSummary struct {
	Valid                     bool     `json:"valid"`
	InvalidReason             string   `json:"invalid_reason,omitempty"`
	PinsValid                 bool     `json:"pins_valid"`
	SchemaVersion             string   `json:"schema_version,omitempty"`
	CatalogVersion            string   `json:"catalog_version,omitempty"`
	CatalogDigest             string   `json:"catalog_digest,omitempty"`
	EvaluatorABI              string   `json:"evaluator_abi,omitempty"`
	SemanticContractDigest    string   `json:"semantic_contract_digest,omitempty"`
	ConformanceDigest         string   `json:"conformance_digest,omitempty"`
	MappingID                 string   `json:"mapping_id,omitempty"`
	MappingRevision           int      `json:"mapping_revision,omitempty"`
	Profile                   string   `json:"profile,omitempty"`
	Mode                      string   `json:"mode,omitempty"`
	ControlCardinality        int      `json:"control_cardinality"`
	OperationCardinality      int      `json:"operation_cardinality"`
	Operations                []string `json:"operations"`
	EffectCardinality         int      `json:"effect_cardinality"`
	EffectBuckets             []string `json:"effect_buckets"`
	ResourceCardinality       int      `json:"resource_cardinality"`
	ResourceKinds             []string `json:"resource_kinds"`
	ResourceTypeFamilies      []string `json:"resource_type_families"`
	ResourceRoles             []string `json:"resource_roles"`
	ResourceResolutions       []string `json:"resource_resolutions"`
	ResourceResolutionKinds   []string `json:"resource_resolution_kinds"`
	ResourceLocations         []string `json:"resource_locations"`
	ScopeCardinality          int      `json:"scope_cardinality"`
	ScopeKinds                []string `json:"scope_kinds"`
	ScopeExtents              []string `json:"scope_extents"`
	DirectCardinalityKinds    []string `json:"direct_cardinality_kinds"`
	SelectionCardinalityKinds []string `json:"selection_cardinality_kinds"`
	ScopeDirectExactTotal     int      `json:"scope_direct_exact_total"`
	ScopeSelectionExactTotal  int      `json:"scope_selection_exact_total"`
	FlowCardinality           int      `json:"flow_cardinality"`
	FlowKinds                 []string `json:"flow_kinds"`
	EvaluationIssueCodes      []string `json:"evaluation_issue_codes"`
}

type asrReplaySemanticDocument struct {
	MappingID *string                    `json:"mapping_id"`
	Mode      *string                    `json:"mode"`
	Modifiers *[]string                  `json:"modifiers"`
	Evidence  json.RawMessage            `json:"evidence"`
	Controls  *[]json.RawMessage         `json:"controls"`
	Effects   *[]asrReplaySemanticEffect `json:"effects"`
	Flows     *[]asrReplaySemanticFlow   `json:"flows"`
}

type asrReplaySemanticEvidence struct {
	Kind              *string `json:"kind"`
	MappingID         *string `json:"mapping_id"`
	MappingRevision   *int    `json:"mapping_revision"`
	Profile           *string `json:"profile"`
	CoverageStatus    *string `json:"coverage_status"`
	EvaluationDefault *string `json:"evaluation_default"`
	CoverageBasis     *string `json:"coverage_basis"`
	ReviewState       *string `json:"review_state"`
}

type asrReplaySemanticEffect struct {
	EffectID      *int                       `json:"effect_id"`
	Operation     *string                    `json:"operation"`
	EffectBuckets *[]string                  `json:"effect_buckets"`
	Mode          *string                    `json:"mode"`
	Resource      *asrReplaySemanticResource `json:"resource"`
	Scope         *asrReplaySemanticScope    `json:"scope"`
	Conditions    *[]string                  `json:"conditions"`
	Parameters    *[]json.RawMessage         `json:"parameters"`
	MappingID     *string                    `json:"mapping_id"`
}

type asrReplaySemanticFlow struct {
	FlowID     *int                       `json:"flow_id"`
	Kind       *string                    `json:"kind"`
	From       *asrReplaySemanticResource `json:"from"`
	To         *asrReplaySemanticResource `json:"to"`
	Conditions *[]string                  `json:"conditions"`
	MappingID  *string                    `json:"mapping_id"`
}

type asrReplaySemanticResource struct {
	Kind            *string         `json:"kind"`
	Type            *string         `json:"type"`
	Role            *string         `json:"role"`
	ID              json.RawMessage `json:"id"`
	Resolution      *string         `json:"resolution"`
	RawValue        json.RawMessage `json:"raw_value"`
	NormalizedValue json.RawMessage `json:"normalized_value"`
	ResolvedValue   json.RawMessage `json:"resolved_value"`
	ResolutionKind  *string         `json:"resolution_kind"`
	Location        *string         `json:"location"`
	Expansions      *[]string       `json:"expansions"`
}

type asrReplaySemanticScope struct {
	Kind                 *string                       `json:"kind"`
	DirectCardinality    *asrReplaySemanticCardinality `json:"direct_cardinality"`
	SelectionCardinality *asrReplaySemanticCardinality `json:"selection_cardinality"`
	Extent               *string                       `json:"extent"`
	UpperBound           json.RawMessage               `json:"upper_bound"`
	DirectUpperBound     json.RawMessage               `json:"direct_upper_bound"`
}

type asrReplaySemanticCardinality struct {
	Kind  *string         `json:"kind"`
	Value json.RawMessage `json:"value"`
}

var (
	asrReplayMappingIDPattern = regexp.MustCompile(`^[a-z0-9-]+(?:\.[a-z0-9-]+)+\.v[1-9][0-9]*$`)
	asrReplayTokenPattern     = regexp.MustCompile(`^[A-Z][A-Z0-9_]*$`)
	asrReplayTypePattern      = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
	asrReplayVersionPattern   = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+)+$`)
	asrReplayABIPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9_.-]*$`)
	asrReplayDigestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
)

var asrReplaySemanticOperations = asrReplayStringSet(
	"account_change", "append", "config_change", "connect", "copy", "create",
	"credential_read", "delete", "disable", "disk_write", "download", "environment_read",
	"execute", "export", "format", "install", "link", "list", "metadata_set", "move",
	"namespace_enter", "overwrite", "permission_change", "policy_bypass", "process_kill",
	"process_signal", "read", "reboot", "schedule", "search", "shutdown", "truncate",
	"uninstall", "unmount", "upload", "write",
)

var asrReplaySemanticEffectBuckets = asrReplayStringSet(
	"B1_READ_DISCOVERY", "B2_ADDITIVE_CREATION", "B3_MUTATION_REPLACEMENT",
	"B4_DESTRUCTION_BULK_IMPACT", "B5_IDENTITY_AUTH_CREDENTIALS",
	"B6_EXECUTION_BOUNDARY_CROSSING", "B7_NETWORK_REACHABILITY_EXPOSURE",
	"B8_DATA_MOVEMENT_EGRESS", "B9_SECURITY_CONTROL_IMPAIRMENT",
	"B10_PERSISTENCE_SCHEDULING", "B11_OPERATIONAL_LIFECYCLE",
	"B12_DOMAIN_SPECIFIC_HIGH_IMPACT",
)

var asrReplaySemanticResourceKinds = asrReplayStringSet(
	"COMPUTE_CONTAINER_WORKLOAD", "DATABASE_SCHEMA_DATA", "HOST_FILESYSTEM_DEVICE",
	"IDENTITY_AUTH_CREDENTIAL", "LOGGING_MONITORING_AUDIT_BACKUP_SECURITY",
	"NETWORK_DNS_FIREWALL_ENDPOINT", "OBJECT_DATA_PLANE", "PROCESS_RUNTIME_AGENT_CONFIG",
	"SECRET_KEY_CERTIFICATE", "SOURCE_CONTROL_BUILD_DEPLOYMENT",
)

var asrReplaySemanticResourceTypeFamilies = asrReplayStringSet(
	"audit", "build", "certificate", "compute", "configuration", "credential", "data",
	"database", "filesystem", "identity", "mac", "network", "package", "process",
	"runtime", "secret", "security", "source-control", "storage", "stream",
)

var asrReplaySemanticIssueCodes = asrReplayStringSet(
	"argv_incomplete", "complete_without_effects", "conditional_operand_count", "decoder_input_limit", "effect_limit",
	"effect_predicate_unresolved", "empty_resource_value", "evaluator_failure", "flow_limit",
	"flow_pairing_mismatch", "input_limit", "invalid_argv", "invalid_call_id",
	"invalid_context", "invalid_control_value", "invalid_decoder_config", "invalid_enum_value",
	"invalid_evaluator_semantics", "invalid_evaluator_status", "invalid_profile",
	"invalid_program", "invalid_resource_value", "invalid_surface", "invalid_value_contract",
	"invalid_word_facts", "missing_control", "missing_operand", "missing_option_value",
	"missing_unconsumed_operand", "mutually_exclusive_options", "native_semantics_encoding_failure",
	"no_mapping", "opaque_operand_prefix", "option_after_operand", "option_context_unmodeled", "option_requirement_missing", "partial_control_value",
	"partial_resource_value", "profile_coverage_partial", "program_argv_mismatch",
	"repeated_assignment_unmodeled", "repeated_option_unmodeled", "required_option_group_missing",
	"resource_fact_limit", "resource_resolution_unknown", "runtime_unavailable", "too_many_operands",
	"unexpected_option_value", "unknown_assignment", "unknown_option", "unknown_option_arity",
	"unsafe_expansion_provenance", "unresolved_control_value", "unsupported_assignment",
	"unsupported_control_source", "unsupported_decoder", "unsupported_option",
	"unsupported_resource_selector",
)

// asrReplaySummarizeSemantics accepts only the bounded native ActionSemantics
// projection. Any shape or vocabulary drift produces a value-free invalid
// summary; the raw error and raw semantics are never returned.
func asrReplaySummarizeSemantics(result asrruntime.Result) asrReplaySemanticSummary {
	summary := asrReplaySummaryBase(result)
	raw := result.Semantics
	switch {
	case len(raw) == 0:
		summary.InvalidReason = "UNAVAILABLE"
		return summary
	case len(raw) > asrReplayMaxSemanticBytes:
		summary.InvalidReason = "OVERSIZED"
		return summary
	case !utf8.Valid(raw):
		summary.InvalidReason = "MALFORMED"
		return summary
	}
	if err := asrReplayRejectDuplicateSemanticKeys(raw); err != nil {
		summary.InvalidReason = "MALFORMED"
		return summary
	}

	var document asrReplaySemanticDocument
	if err := asrReplayStrictSemanticDecode(raw, &document); err != nil ||
		document.Controls == nil || document.Effects == nil || document.Flows == nil ||
		len(document.Evidence) == 0 {
		summary.InvalidReason = "MALFORMED"
		return summary
	}
	if len(*document.Controls) > asrReplayMaxSemanticControls ||
		len(*document.Effects) > asrReplayMaxSemanticItems ||
		len(*document.Flows) > asrReplayMaxSemanticItems {
		summary.InvalidReason = "LIMIT_EXCEEDED"
		return summary
	}
	for _, control := range *document.Controls {
		if !asrReplayJSONObject(control) {
			summary.InvalidReason = "MALFORMED"
			return summary
		}
	}

	evidenceRaw := bytes.TrimSpace(document.Evidence)
	if bytes.Equal(evidenceRaw, []byte("null")) {
		if document.MappingID != nil || document.Mode != nil || document.Modifiers != nil ||
			len(*document.Controls) != 0 || len(*document.Effects) != 0 || len(*document.Flows) != 0 {
			summary.InvalidReason = "INCONSISTENT_IDENTITY"
			return summary
		}
		summary.Valid = true
		summary.Operations = []string{}
		summary.EffectBuckets = []string{}
		summary.ResourceKinds = []string{}
		summary.ResourceTypeFamilies = []string{}
		summary.ResourceRoles = []string{}
		summary.ResourceResolutions = []string{}
		summary.ResourceResolutionKinds = []string{}
		summary.ResourceLocations = []string{}
		summary.ScopeKinds = []string{}
		summary.ScopeExtents = []string{}
		summary.DirectCardinalityKinds = []string{}
		summary.SelectionCardinalityKinds = []string{}
		summary.FlowKinds = []string{}
		return summary
	}
	if document.MappingID == nil || document.Mode == nil || document.Modifiers == nil {
		summary.InvalidReason = "INCONSISTENT_IDENTITY"
		return summary
	}

	var evidence asrReplaySemanticEvidence
	if err := asrReplayStrictSemanticDecode(document.Evidence, &evidence); err != nil ||
		!asrReplayValidEvidence(evidence, *document.MappingID) ||
		!asrReplayAllowed(*document.Mode, "EXECUTE", "PREVIEW", "VALIDATE", "HELP", "UNCERTAIN") ||
		!asrReplayValidTokens(*document.Modifiers, asrReplayMaxSemanticItems) {
		summary.InvalidReason = "UNRECOGNIZED_CATEGORY"
		return summary
	}

	operations := make(map[string]struct{})
	effectBuckets := make(map[string]struct{})
	resourceKinds := make(map[string]struct{})
	resourceTypeFamilies := make(map[string]struct{})
	resourceRoles := make(map[string]struct{})
	resourceResolutions := make(map[string]struct{})
	resourceResolutionKinds := make(map[string]struct{})
	resourceLocations := make(map[string]struct{})
	scopeKinds := make(map[string]struct{})
	scopeExtents := make(map[string]struct{})
	directCardinalityKinds := make(map[string]struct{})
	selectionCardinalityKinds := make(map[string]struct{})
	flowKinds := make(map[string]struct{})

	for index, effect := range *document.Effects {
		if !asrReplayValidEffect(
			effect, index+1, *document.MappingID, operations, effectBuckets,
			resourceKinds, resourceTypeFamilies, resourceRoles, resourceResolutions,
			resourceResolutionKinds, resourceLocations, scopeKinds, scopeExtents,
			directCardinalityKinds, selectionCardinalityKinds, &summary,
		) {
			summary = asrReplayInvalidSummary(result, "UNRECOGNIZED_CATEGORY")
			return summary
		}
	}
	for index, flow := range *document.Flows {
		if !asrReplayValidFlow(
			flow, index+1, *document.MappingID, flowKinds, resourceKinds,
			resourceTypeFamilies, resourceRoles, resourceResolutions,
			resourceResolutionKinds, resourceLocations, &summary,
		) {
			summary = asrReplayInvalidSummary(result, "UNRECOGNIZED_CATEGORY")
			return summary
		}
	}

	summary.Valid = true
	summary.MappingID = *document.MappingID
	summary.MappingRevision = *evidence.MappingRevision
	summary.Profile = *evidence.Profile
	summary.Mode = *document.Mode
	summary.ControlCardinality = len(*document.Controls)
	summary.OperationCardinality = len(*document.Effects)
	summary.Operations = asrReplaySortedSemanticSet(operations)
	summary.EffectCardinality = len(*document.Effects)
	summary.EffectBuckets = asrReplaySortedSemanticSet(effectBuckets)
	summary.ResourceKinds = asrReplaySortedSemanticSet(resourceKinds)
	summary.ResourceTypeFamilies = asrReplaySortedSemanticSet(resourceTypeFamilies)
	summary.ResourceRoles = asrReplaySortedSemanticSet(resourceRoles)
	summary.ResourceResolutions = asrReplaySortedSemanticSet(resourceResolutions)
	summary.ResourceResolutionKinds = asrReplaySortedSemanticSet(resourceResolutionKinds)
	summary.ResourceLocations = asrReplaySortedSemanticSet(resourceLocations)
	summary.ScopeCardinality = len(*document.Effects)
	summary.ScopeKinds = asrReplaySortedSemanticSet(scopeKinds)
	summary.ScopeExtents = asrReplaySortedSemanticSet(scopeExtents)
	summary.DirectCardinalityKinds = asrReplaySortedSemanticSet(directCardinalityKinds)
	summary.SelectionCardinalityKinds = asrReplaySortedSemanticSet(selectionCardinalityKinds)
	summary.FlowCardinality = len(*document.Flows)
	summary.FlowKinds = asrReplaySortedSemanticSet(flowKinds)
	return summary
}

func asrReplaySummaryBase(result asrruntime.Result) asrReplaySemanticSummary {
	pins, pinsValid := asrReplaySafeSemanticPins(result.Pins)
	return asrReplaySemanticSummary{
		PinsValid:                 pinsValid,
		SchemaVersion:             pins.SchemaVersion,
		CatalogVersion:            pins.CatalogVersion,
		CatalogDigest:             pins.CatalogDigest,
		EvaluatorABI:              pins.EvaluatorABI,
		SemanticContractDigest:    pins.SemanticContractDigest,
		ConformanceDigest:         pins.ConformanceDigest,
		Operations:                []string{},
		EffectBuckets:             []string{},
		ResourceKinds:             []string{},
		ResourceTypeFamilies:      []string{},
		ResourceRoles:             []string{},
		ResourceResolutions:       []string{},
		ResourceResolutionKinds:   []string{},
		ResourceLocations:         []string{},
		ScopeKinds:                []string{},
		ScopeExtents:              []string{},
		DirectCardinalityKinds:    []string{},
		SelectionCardinalityKinds: []string{},
		FlowKinds:                 []string{},
		EvaluationIssueCodes:      asrReplaySemanticIssueSummary(result.Issues),
	}
}

func asrReplayInvalidSummary(result asrruntime.Result, reason string) asrReplaySemanticSummary {
	summary := asrReplaySummaryBase(result)
	summary.InvalidReason = reason
	return summary
}

func asrReplayValidEvidence(evidence asrReplaySemanticEvidence, mappingID string) bool {
	return evidence.Kind != nil && *evidence.Kind == "REVIEWED_REGISTRY_MAPPING" &&
		evidence.MappingID != nil && *evidence.MappingID == mappingID &&
		evidence.MappingRevision != nil && *evidence.MappingRevision > 0 &&
		*evidence.MappingRevision <= asrReplayMaxCardinality &&
		evidence.Profile != nil && *evidence.Profile == "universal-linux" &&
		evidence.CoverageStatus != nil && asrReplayAllowed(*evidence.CoverageStatus, "COMPLETE", "PARTIAL") &&
		evidence.EvaluationDefault != nil && asrReplayAllowed(*evidence.EvaluationDefault, "COMPLETE", "PARTIAL") &&
		evidence.CoverageBasis != nil && asrReplayAllowed(
		*evidence.CoverageBasis, "PORTABLE_INTERSECTION", "UNIVERSAL_LINUX", "UPSTREAM_VERSIONED",
	) && evidence.ReviewState != nil && *evidence.ReviewState == "REVIEWED" &&
		asrReplayMappingIDPattern.MatchString(mappingID) && len(mappingID) <= asrReplayMaxSemanticCategoryByte
}

func asrReplayValidEffect(
	effect asrReplaySemanticEffect,
	wantID int,
	mappingID string,
	operations, effectBuckets, resourceKinds, resourceTypeFamilies, resourceRoles,
	resourceResolutions, resourceResolutionKinds, resourceLocations, scopeKinds,
	scopeExtents, directCardinalityKinds, selectionCardinalityKinds map[string]struct{},
	summary *asrReplaySemanticSummary,
) bool {
	if effect.EffectID == nil || *effect.EffectID != wantID || effect.Operation == nil ||
		!asrReplaySetContains(asrReplaySemanticOperations, *effect.Operation) ||
		effect.EffectBuckets == nil || len(*effect.EffectBuckets) == 0 ||
		effect.Mode == nil || !asrReplayAllowed(*effect.Mode, "EXECUTE", "PREVIEW", "VALIDATE", "HELP", "UNCERTAIN") ||
		effect.Resource == nil || effect.Scope == nil || effect.Conditions == nil ||
		effect.Parameters == nil || effect.MappingID == nil || *effect.MappingID != mappingID ||
		!asrReplayValidTokens(*effect.Conditions, asrReplayMaxSemanticItems) ||
		len(*effect.Parameters) > asrReplayMaxSemanticControls {
		return false
	}
	for _, parameter := range *effect.Parameters {
		if !asrReplayJSONObject(parameter) {
			return false
		}
	}
	for _, bucket := range *effect.EffectBuckets {
		if !asrReplaySetContains(asrReplaySemanticEffectBuckets, bucket) {
			return false
		}
		effectBuckets[bucket] = struct{}{}
	}
	operations[*effect.Operation] = struct{}{}
	if !asrReplayRecordResource(
		*effect.Resource, resourceKinds, resourceTypeFamilies, resourceRoles,
		resourceResolutions, resourceResolutionKinds, resourceLocations, summary,
	) {
		return false
	}
	return asrReplayRecordScope(
		*effect.Scope, scopeKinds, scopeExtents, directCardinalityKinds,
		selectionCardinalityKinds, summary,
	)
}

func asrReplayValidFlow(
	flow asrReplaySemanticFlow,
	wantID int,
	mappingID string,
	flowKinds, resourceKinds, resourceTypeFamilies, resourceRoles, resourceResolutions,
	resourceResolutionKinds, resourceLocations map[string]struct{},
	summary *asrReplaySemanticSummary,
) bool {
	if flow.FlowID == nil || *flow.FlowID != wantID || flow.Kind == nil ||
		!asrReplayAllowed(*flow.Kind, "CONTENT", "METADATA", "MOVE", "REFERENCE") ||
		flow.From == nil || flow.To == nil || flow.Conditions == nil ||
		flow.MappingID == nil || *flow.MappingID != mappingID ||
		!asrReplayValidTokens(*flow.Conditions, asrReplayMaxSemanticItems) {
		return false
	}
	flowKinds[*flow.Kind] = struct{}{}
	return asrReplayRecordResource(
		*flow.From, resourceKinds, resourceTypeFamilies, resourceRoles,
		resourceResolutions, resourceResolutionKinds, resourceLocations, summary,
	) && asrReplayRecordResource(
		*flow.To, resourceKinds, resourceTypeFamilies, resourceRoles,
		resourceResolutions, resourceResolutionKinds, resourceLocations, summary,
	)
}

func asrReplayRecordResource(
	resource asrReplaySemanticResource,
	kinds, typeFamilies, roles, resolutions, resolutionKinds, locations map[string]struct{},
	summary *asrReplaySemanticSummary,
) bool {
	if resource.Kind == nil || !asrReplaySetContains(asrReplaySemanticResourceKinds, *resource.Kind) ||
		resource.Type == nil || !asrReplayTypePattern.MatchString(*resource.Type) ||
		len(*resource.Type) > asrReplayMaxSemanticCategoryByte || resource.Role == nil ||
		!asrReplayAllowed(*resource.Role, "SOURCE", "DESTINATION", "TARGET", "CONTEXT") ||
		resource.Resolution == nil || !asrReplayAllowed(*resource.Resolution, "STATIC", "UNRESOLVED") ||
		resource.ResolutionKind == nil || !asrReplayAllowed(
		*resource.ResolutionKind, "EXACT", "CONTEXTUAL", "ANCHORED_PATTERN", "GENERATED", "UNKNOWN",
	) || resource.Location == nil || !asrReplayAllowed(
		*resource.Location, "ROOT", "SYSTEM", "WORKSPACE", "HOME", "TEMP", "OTHER", "UNKNOWN",
	) || resource.Expansions == nil || !asrReplayValidClosedValues(
		*resource.Expansions, asrReplayStringSet("VARIABLE", "TILDE", "GLOB", "COMMAND_SUBSTITUTION"),
		asrReplayMaxSemanticCategories,
	) || !asrReplayNullableString(resource.ID) || !asrReplayNullableString(resource.RawValue) ||
		!asrReplayNullableString(resource.NormalizedValue) || !asrReplayNullableString(resource.ResolvedValue) {
		return false
	}
	typeFamily := strings.SplitN(*resource.Type, ".", 2)[0]
	if !asrReplaySetContains(asrReplaySemanticResourceTypeFamilies, typeFamily) {
		return false
	}
	if summary.ResourceCardinality == asrReplayMaxSemanticItems*3 {
		return false
	}
	summary.ResourceCardinality++
	kinds[*resource.Kind] = struct{}{}
	typeFamilies[typeFamily] = struct{}{}
	roles[*resource.Role] = struct{}{}
	resolutions[*resource.Resolution] = struct{}{}
	resolutionKinds[*resource.ResolutionKind] = struct{}{}
	locations[*resource.Location] = struct{}{}
	return true
}

func asrReplayRecordScope(
	scope asrReplaySemanticScope,
	kinds, extents, directKinds, selectionKinds map[string]struct{},
	summary *asrReplaySemanticSummary,
) bool {
	if scope.Kind == nil || !asrReplayAllowed(*scope.Kind, "ONE", "BOUNDED_MANY", "UNBOUNDED", "ALL", "UNKNOWN") ||
		scope.DirectCardinality == nil || scope.SelectionCardinality == nil || scope.Extent == nil ||
		!asrReplayAllowed(*scope.Extent, "DIRECT", "DESCENDANTS", "GENERATED", "GLOBAL", "UNKNOWN") ||
		!asrReplayOptionalBound(scope.UpperBound) || !asrReplayOptionalBound(scope.DirectUpperBound) {
		return false
	}
	directKind, directValue, directOK := asrReplayCardinality(*scope.DirectCardinality)
	selectionKind, selectionValue, selectionOK := asrReplayCardinality(*scope.SelectionCardinality)
	if !directOK || !selectionOK || summary.ScopeDirectExactTotal > asrReplayMaxCardinality-directValue ||
		summary.ScopeSelectionExactTotal > asrReplayMaxCardinality-selectionValue {
		return false
	}
	summary.ScopeDirectExactTotal += directValue
	summary.ScopeSelectionExactTotal += selectionValue
	kinds[*scope.Kind] = struct{}{}
	extents[*scope.Extent] = struct{}{}
	directKinds[directKind] = struct{}{}
	selectionKinds[selectionKind] = struct{}{}
	return true
}

func asrReplayCardinality(cardinality asrReplaySemanticCardinality) (string, int, bool) {
	if cardinality.Kind == nil {
		return "", 0, false
	}
	switch *cardinality.Kind {
	case "UNKNOWN":
		return "UNKNOWN", 0, len(cardinality.Value) == 0
	case "EXACT":
		value, ok := asrReplayNonnegativeInteger(cardinality.Value)
		return "EXACT", value, ok
	default:
		return "", 0, false
	}
}

func asrReplaySafeSemanticPins(pins asrruntime.Pins) (asrruntime.Pins, bool) {
	if !asrReplayVersionPattern.MatchString(pins.SchemaVersion) || len(pins.SchemaVersion) > 32 ||
		!asrReplayVersionPattern.MatchString(pins.CatalogVersion) || len(pins.CatalogVersion) > 32 ||
		!asrReplayDigestPattern.MatchString(pins.CatalogDigest) ||
		!asrReplayABIPattern.MatchString(pins.EvaluatorABI) || len(pins.EvaluatorABI) > 128 ||
		!asrReplayDigestPattern.MatchString(pins.SemanticContractDigest) ||
		!asrReplayDigestPattern.MatchString(pins.ConformanceDigest) {
		return asrruntime.Pins{}, false
	}
	return pins, true
}

func asrReplaySemanticIssueSummary(issues []string) []string {
	set := make(map[string]struct{})
	for _, issue := range issues {
		code := strings.SplitN(issue, ":", 2)[0]
		if !asrReplaySetContains(asrReplaySemanticIssueCodes, code) {
			code = "OTHER"
		}
		set[code] = struct{}{}
		if len(set) == asrReplayMaxSemanticCategories {
			break
		}
	}
	return asrReplaySortedSemanticSet(set)
}

func asrReplayStrictSemanticDecode(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	decoder.UseNumber()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func asrReplayRejectDuplicateSemanticKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := asrReplayWalkSemanticJSON(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return errors.New("trailing JSON")
	}
	return nil
}

func asrReplayWalkSemanticJSON(decoder *json.Decoder, depth int) error {
	if depth > 64 {
		return errors.New("JSON nesting limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, keyErr := decoder.Token()
			if keyErr != nil {
				return keyErr
			}
			key, keyOK := keyToken.(string)
			if !keyOK {
				return errors.New("non-string object key")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := asrReplayWalkSemanticJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	case '[':
		for decoder.More() {
			if err := asrReplayWalkSemanticJSON(decoder, depth+1); err != nil {
				return err
			}
		}
		_, err = decoder.Token()
		return err
	default:
		return errors.New("unexpected delimiter")
	}
}

func asrReplayJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

func asrReplayNullableString(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return false
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return true
	}
	var value string
	return asrReplayStrictSemanticDecode(raw, &value) == nil
}

func asrReplayOptionalBound(raw json.RawMessage) bool {
	if len(raw) == 0 {
		return true
	}
	_, ok := asrReplayNonnegativeInteger(raw)
	return ok
}

func asrReplayNonnegativeInteger(raw json.RawMessage) (int, bool) {
	if len(raw) == 0 {
		return 0, false
	}
	var number json.Number
	if err := asrReplayStrictSemanticDecode(raw, &number); err != nil {
		return 0, false
	}
	value, err := number.Int64()
	return int(value), err == nil && value >= 0 && value <= asrReplayMaxCardinality
}

func asrReplayValidTokens(values []string, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if len(value) > asrReplayMaxSemanticCategoryByte || !asrReplayTokenPattern.MatchString(value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func asrReplayValidClosedValues(values []string, allowed map[string]struct{}, maximum int) bool {
	if len(values) > maximum {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !asrReplaySetContains(allowed, value) {
			return false
		}
		if _, duplicate := seen[value]; duplicate {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

func asrReplayAllowed(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func asrReplayStringSet(values ...string) map[string]struct{} {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		set[value] = struct{}{}
	}
	return set
}

func asrReplaySetContains(set map[string]struct{}, value string) bool {
	_, ok := set[value]
	return ok
}

func asrReplaySortedSemanticSet(set map[string]struct{}) []string {
	values := make([]string, 0, len(set))
	for value := range set {
		values = append(values, value)
	}
	sort.Strings(values)
	return values
}

func TestASRReplaySemanticSummaryIsBoundedAndValueFree(t *testing.T) {
	const secret = "https://token@example.test/private?secret=hunter2"
	semantics := json.RawMessage(`{
		"mapping_id":"universal-linux.curl.v1",
		"mode":"EXECUTE",
		"modifiers":["FOLLOW_REDIRECTS"],
		"evidence":{
			"kind":"REVIEWED_REGISTRY_MAPPING",
			"mapping_id":"universal-linux.curl.v1",
			"mapping_revision":4,
			"profile":"universal-linux",
			"coverage_status":"COMPLETE",
			"evaluation_default":"COMPLETE",
			"coverage_basis":"UPSTREAM_VERSIONED",
			"review_state":"REVIEWED"
		},
		"controls":[{"id":"payload","value":"` + secret + `"}],
		"effects":[{
			"effect_id":1,
			"operation":"upload",
			"effect_buckets":["B7_NETWORK_REACHABILITY_EXPOSURE","B8_DATA_MOVEMENT_EGRESS"],
			"mode":"EXECUTE",
			"resource":{
				"kind":"NETWORK_DNS_FIREWALL_ENDPOINT",
				"type":"network.url-upload-destination",
				"role":"DESTINATION",
				"id":"` + secret + `",
				"resolution":"STATIC",
				"raw_value":"` + secret + `",
				"normalized_value":"` + secret + `",
				"resolved_value":"` + secret + `",
				"resolution_kind":"CONTEXTUAL",
				"location":"OTHER",
				"expansions":[]
			},
			"scope":{
				"kind":"ONE",
				"direct_cardinality":{"kind":"EXACT","value":1},
				"selection_cardinality":{"kind":"EXACT","value":2},
				"extent":"DIRECT",
				"upper_bound":2
			},
			"conditions":["IF_UPLOAD_SELECTED"],
			"parameters":[{"value":"` + secret + `"}],
			"mapping_id":"universal-linux.curl.v1"
		}],
		"flows":[{
			"flow_id":1,
			"kind":"CONTENT",
			"from":{
				"kind":"HOST_FILESYSTEM_DEVICE","type":"filesystem.file","role":"SOURCE",
				"id":"/private/key","resolution":"STATIC","raw_value":"/private/key",
				"normalized_value":"/private/key","resolved_value":"/private/key",
				"resolution_kind":"EXACT","location":"WORKSPACE","expansions":[]
			},
			"to":{
				"kind":"NETWORK_DNS_FIREWALL_ENDPOINT","type":"network.url","role":"DESTINATION",
				"id":"` + secret + `","resolution":"STATIC","raw_value":"` + secret + `",
				"normalized_value":"` + secret + `","resolved_value":"` + secret + `",
				"resolution_kind":"EXACT","location":"OTHER","expansions":[]
			},
			"conditions":[],
			"mapping_id":"universal-linux.curl.v1"
		}]
	}`)
	result := asrruntime.Result{
		Status:    asrruntime.StatusComplete,
		Issues:    []string{"unknown_option", "effect_predicate_unresolved:raw-profile-id", "future:/private/key"},
		Semantics: semantics,
		Pins:      asrReplayTestPins(),
	}

	summary := asrReplaySummarizeSemantics(result)
	if !summary.Valid || summary.InvalidReason != "" {
		t.Fatalf("summary = %+v", summary)
	}
	if summary.MappingID != "universal-linux.curl.v1" || summary.MappingRevision != 4 ||
		summary.Profile != "universal-linux" || summary.OperationCardinality != 1 ||
		summary.EffectCardinality != 1 || summary.ResourceCardinality != 3 ||
		summary.ScopeCardinality != 1 || summary.FlowCardinality != 1 ||
		summary.ScopeDirectExactTotal != 1 || summary.ScopeSelectionExactTotal != 2 {
		t.Fatalf("unexpected summary cardinalities or identity: %+v", summary)
	}
	if got, want := strings.Join(summary.Operations, ","), "upload"; got != want {
		t.Fatalf("operations = %q, want %q", got, want)
	}
	if got, want := strings.Join(summary.ResourceTypeFamilies, ","), "filesystem,network"; got != want {
		t.Fatalf("resource type families = %q, want %q", got, want)
	}
	if got, want := strings.Join(summary.EvaluationIssueCodes, ","),
		"OTHER,effect_predicate_unresolved,unknown_option"; got != want {
		t.Fatalf("issue codes = %q, want %q", got, want)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{secret, "/private/key", "raw-profile-id", "hunter2"} {
		if bytes.Contains(encoded, []byte(forbidden)) {
			t.Fatalf("summary leaked forbidden value %q: %s", forbidden, encoded)
		}
	}
}

func TestASRReplaySemanticSummaryRejectsUnsafeShapes(t *testing.T) {
	valid := `{
		"mapping_id":"universal-linux.rm.v1","mode":"EXECUTE","modifiers":[],
		"evidence":{"kind":"REVIEWED_REGISTRY_MAPPING","mapping_id":"universal-linux.rm.v1",
		"mapping_revision":1,"profile":"universal-linux","coverage_status":"COMPLETE",
		"evaluation_default":"COMPLETE","coverage_basis":"UNIVERSAL_LINUX","review_state":"REVIEWED"},
		"controls":[],"effects":[],"flows":[]}`
	tests := []struct {
		name   string
		raw    json.RawMessage
		reason string
	}{
		{name: "unavailable", raw: nil, reason: "UNAVAILABLE"},
		{name: "trailing", raw: json.RawMessage(valid + `{}`), reason: "MALFORMED"},
		{name: "duplicate", raw: json.RawMessage(strings.Replace(valid, `"mode":"EXECUTE"`, `"mode":"EXECUTE","mode":"HELP"`, 1)), reason: "MALFORMED"},
		{name: "unknown top field", raw: json.RawMessage(strings.Replace(valid, `"flows":[]`, `"flows":[],"argv":["secret"]`, 1)), reason: "MALFORMED"},
		{name: "identity mismatch", raw: json.RawMessage(strings.Replace(valid, `"mapping_id":"universal-linux.rm.v1"`, `"mapping_id":"universal-linux.cp.v1"`, 1)), reason: "UNRECOGNIZED_CATEGORY"},
		{name: "unknown mode", raw: json.RawMessage(strings.Replace(valid, `"mode":"EXECUTE"`, `"mode":"RAW_COMMAND"`, 1)), reason: "UNRECOGNIZED_CATEGORY"},
		{name: "oversized", raw: json.RawMessage(strings.Repeat("x", asrReplayMaxSemanticBytes+1)), reason: "OVERSIZED"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			summary := asrReplaySummarizeSemantics(asrruntime.Result{
				Semantics: test.raw,
				Pins:      asrReplayTestPins(),
			})
			if summary.Valid || summary.InvalidReason != test.reason {
				t.Fatalf("summary = %+v, want invalid reason %q", summary, test.reason)
			}
			encoded, err := json.Marshal(summary)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte("secret")) || bytes.Contains(encoded, []byte("RAW_COMMAND")) {
				t.Fatalf("invalid summary leaked input: %s", encoded)
			}
		})
	}
}

func TestASRReplaySemanticSummaryAcceptsValueFreeInvalidProjection(t *testing.T) {
	summary := asrReplaySummarizeSemantics(asrruntime.Result{
		Status:    asrruntime.StatusInvalid,
		Issues:    []string{"missing_operand"},
		Semantics: json.RawMessage(`{"evidence":null,"controls":[],"effects":[],"flows":[]}`),
		Pins:      asrReplayTestPins(),
	})
	if !summary.Valid || summary.MappingID != "" || summary.EffectCardinality != 0 {
		t.Fatalf("summary = %+v", summary)
	}
	if got := strings.Join(summary.EvaluationIssueCodes, ","); got != "missing_operand" {
		t.Fatalf("issue codes = %q", got)
	}
}

func TestASRReplaySemanticSummaryRejectsUnknownNestedCategories(t *testing.T) {
	valid := `{
		"mapping_id":"universal-linux.rm.v1","mode":"EXECUTE","modifiers":[],
		"evidence":{"kind":"REVIEWED_REGISTRY_MAPPING","mapping_id":"universal-linux.rm.v1",
		"mapping_revision":1,"profile":"universal-linux","coverage_status":"COMPLETE",
		"evaluation_default":"COMPLETE","coverage_basis":"UNIVERSAL_LINUX","review_state":"REVIEWED"},
		"controls":[],
		"effects":[{"effect_id":1,"operation":"delete","effect_buckets":["B4_DESTRUCTION_BULK_IMPACT"],
		"mode":"EXECUTE","resource":{"kind":"HOST_FILESYSTEM_DEVICE","type":"filesystem.entry",
		"role":"TARGET","id":"private-value","resolution":"STATIC","raw_value":"private-value",
		"normalized_value":"private-value","resolved_value":null,"resolution_kind":"EXACT",
		"location":"WORKSPACE","expansions":[]},"scope":{"kind":"ONE",
		"direct_cardinality":{"kind":"EXACT","value":1},"selection_cardinality":{"kind":"EXACT","value":1},
		"extent":"DIRECT"},"conditions":[],"parameters":[],"mapping_id":"universal-linux.rm.v1"}],
		"flows":[]}`
	tests := []struct {
		name string
		old  string
		new  string
	}{
		{name: "operation", old: `"operation":"delete"`, new: `"operation":"future_operation"`},
		{name: "effect bucket", old: `"B4_DESTRUCTION_BULK_IMPACT"`, new: `"B99_RAW_VALUE"`},
		{name: "resource kind", old: `"HOST_FILESYSTEM_DEVICE"`, new: `"RAW_COMMAND"`},
		{name: "resource family", old: `"filesystem.entry"`, new: `"payload.secret"`},
		{name: "resource role", old: `"role":"TARGET"`, new: `"role":"ARGUMENT"`},
		{name: "resolution", old: `"resolution_kind":"EXACT"`, new: `"resolution_kind":"GUESSED"`},
		{name: "location", old: `"location":"WORKSPACE"`, new: `"location":"PRIVATE_PATH"`},
		{name: "scope", old: `"scope":{"kind":"ONE"`, new: `"scope":{"kind":"EVERYTHING"`},
		{name: "extent", old: `"extent":"DIRECT"`, new: `"extent":"RAW_PATHS"`},
		{name: "cardinality", old: `"direct_cardinality":{"kind":"EXACT"`, new: `"direct_cardinality":{"kind":"ESTIMATE"`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			raw := json.RawMessage(strings.Replace(valid, test.old, test.new, 1))
			summary := asrReplaySummarizeSemantics(asrruntime.Result{
				Semantics: raw,
				Pins:      asrReplayTestPins(),
			})
			if summary.Valid || summary.InvalidReason != "UNRECOGNIZED_CATEGORY" {
				t.Fatalf("summary = %+v", summary)
			}
			encoded, err := json.Marshal(summary)
			if err != nil {
				t.Fatal(err)
			}
			if bytes.Contains(encoded, []byte(test.new)) || bytes.Contains(encoded, []byte("private-value")) {
				t.Fatalf("invalid summary leaked nested input: %s", encoded)
			}
		})
	}
}

func TestASRReplaySemanticSummarySanitizesInvalidPins(t *testing.T) {
	pins := asrReplayTestPins()
	pins.EvaluatorABI = "/private/path"
	summary := asrReplaySummarizeSemantics(asrruntime.Result{
		Semantics: json.RawMessage(`{"evidence":null,"controls":[],"effects":[],"flows":[]}`),
		Pins:      pins,
	})
	if !summary.Valid || summary.PinsValid || summary.SchemaVersion != "" || summary.EvaluatorABI != "" {
		t.Fatalf("summary = %+v", summary)
	}
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(encoded, []byte("private")) {
		t.Fatalf("summary leaked invalid pin: %s", encoded)
	}
}

func TestASRReplaySemanticSummaryAcceptsEmbeddedNativeProjection(t *testing.T) {
	runtime, err := asrruntime.LoadEmbedded()
	if err != nil {
		t.Fatal(err)
	}
	result := runtime.Evaluate(asrruntime.NormalizedInvocation{
		CallID:       "semantic-summary-test",
		Program:      "rm",
		Surface:      asrruntime.SurfaceDirectArgv,
		Profile:      "universal-linux",
		Argv:         []string{"rm", "-rf", "build"},
		ArgvComplete: true,
	})
	summary := asrReplaySummarizeSemantics(result)
	if !summary.Valid || !summary.PinsValid || summary.MappingID != "universal-linux.rm.v1" ||
		summary.EffectCardinality == 0 || summary.ResourceCardinality == 0 || summary.ScopeCardinality == 0 {
		t.Fatalf("result status = %s, summary = %+v", result.Status, summary)
	}
}

func asrReplayTestPins() asrruntime.Pins {
	return asrruntime.Pins{
		SchemaVersion:          "1.0.0",
		CatalogVersion:         "2026.08.17.5",
		CatalogDigest:          "sha256:" + strings.Repeat("a", 64),
		EvaluatorABI:           "asr.evaluator.v1",
		SemanticContractDigest: "sha256:" + strings.Repeat("b", 64),
		ConformanceDigest:      "sha256:" + strings.Repeat("c", 64),
	}
}
