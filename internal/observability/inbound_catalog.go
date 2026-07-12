// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"errors"
	"regexp"
	"strconv"
	"strings"
	"sync"
)

// ErrInboundCatalogInvalid is returned when the generated inbound catalog does
// not satisfy the closed runtime contract. The receiver must fail closed rather
// than continue with a partial catalog.
var ErrInboundCatalogInvalid = errors.New("generated inbound telemetry catalog is invalid")

// InboundLocation is one exact OTLP location inspected by a generated
// discriminator. It deliberately has no arbitrary attribute-map location.
type InboundLocation string

const (
	InboundLocationInstrumentName       InboundLocation = "instrument_name"
	InboundLocationLeafAttribute        InboundLocation = "leaf_attribute"
	InboundLocationLogBody              InboundLocation = "log_body"
	InboundLocationMetricPoint          InboundLocation = "metric_point"
	InboundLocationMetricPointAttribute InboundLocation = "metric_point_attribute"
	InboundLocationResourceAttribute    InboundLocation = "resource_attribute"
	InboundLocationResourceSchemaURL    InboundLocation = "resource_schema_url"
	InboundLocationScopeName            InboundLocation = "scope_name"
	InboundLocationScopeSchemaURL       InboundLocation = "scope_schema_url"
	InboundLocationSpan                 InboundLocation = "span"
)

type InboundPredicateOperator string

const (
	InboundPredicateAbsent              InboundPredicateOperator = "absent"
	InboundPredicateEquals              InboundPredicateOperator = "equals"
	InboundPredicateOneOf               InboundPredicateOperator = "one_of"
	InboundPredicatePresent             InboundPredicateOperator = "present"
	InboundPredicateProjectedRecordJSON InboundPredicateOperator = "projected_record_json"
	InboundPredicateUint32Max           InboundPredicateOperator = "uint32_max"
	InboundPredicateValidEndedSpan      InboundPredicateOperator = "valid_ended_span"
)

type InboundValueType string

const (
	InboundValueString     InboundValueType = "string"
	InboundValueBoolean    InboundValueType = "boolean"
	InboundValueInt64      InboundValueType = "int64"
	InboundValueDouble     InboundValueType = "double"
	InboundValueStructured InboundValueType = "structured"
	InboundValueStructural InboundValueType = "structural"
)

type InboundPredicateValueKind uint8

const (
	InboundPredicateValueInvalid InboundPredicateValueKind = iota
	InboundPredicateValueString
	InboundPredicateValueInt64
)

// InboundPredicateValue is a closed scalar union. Generated predicate JSON is
// parsed into this form once; callers never receive json.RawMessage or any.
type InboundPredicateValue struct {
	kind        InboundPredicateValueKind
	stringValue string
	int64Value  int64
}

func (value InboundPredicateValue) Kind() InboundPredicateValueKind { return value.kind }

func (value InboundPredicateValue) StringValue() (string, bool) {
	return value.stringValue, value.kind == InboundPredicateValueString
}

func (value InboundPredicateValue) Int64Value() (int64, bool) {
	return value.int64Value, value.kind == InboundPredicateValueInt64
}

type InboundPredicate struct {
	location  InboundLocation
	key       string
	operator  InboundPredicateOperator
	valueType InboundValueType
	values    []InboundPredicateValue
}

func (predicate InboundPredicate) Location() InboundLocation { return predicate.location }
func (predicate InboundPredicate) Key() string               { return predicate.key }
func (predicate InboundPredicate) Operator() InboundPredicateOperator {
	return predicate.operator
}
func (predicate InboundPredicate) ValueType() InboundValueType { return predicate.valueType }
func (predicate InboundPredicate) Values() []InboundPredicateValue {
	return append([]InboundPredicateValue(nil), predicate.values...)
}

type InboundShape string

const (
	InboundShapeExternal        InboundShape = "external"
	InboundShapeNativeExact     InboundShape = "native_exact"
	InboundShapeNativeMalformed InboundShape = "native_malformed"
)

type InboundDiscriminatorKind string

const (
	InboundDiscriminatorConnectorLog    InboundDiscriminatorKind = "connector-log-v1"
	InboundDiscriminatorConnectorMetric InboundDiscriminatorKind = "connector-metric-v1"
	InboundDiscriminatorDurationMetric  InboundDiscriminatorKind = "duration-metric-v1"
	InboundDiscriminatorGenAIOperation  InboundDiscriminatorKind = "genai-operation-span-v1"
	InboundDiscriminatorNativeLog       InboundDiscriminatorKind = "native-v8-log"
	InboundDiscriminatorNativeMetric    InboundDiscriminatorKind = "native-v8-metric"
	InboundDiscriminatorNativeSpan      InboundDiscriminatorKind = "native-v8-span"
)

type InboundMappingStrategy string

const (
	InboundMappingClaudeTokenUsage  InboundMappingStrategy = "claude-token-usage-v1"
	InboundMappingConnectorModelLog InboundMappingStrategy = "connector-model-log-v1"
	InboundMappingDurationMetric    InboundMappingStrategy = "duration-metric-v1"
	InboundMappingReverseMetric     InboundMappingStrategy = "generated-reverse-metric-v1"
	InboundMappingReverseSpan       InboundMappingStrategy = "generated-reverse-span-v1"
	InboundMappingNativeLog         InboundMappingStrategy = "native-projected-log-v1"
	InboundMappingStandardGenAISpan InboundMappingStrategy = "standard-genai-span-v1"
)

type InboundTimeRule string

const (
	InboundTimeLogObservedReceipt InboundTimeRule = "log-time-observed-receipt-v1"
	InboundTimeMetricPointReceipt InboundTimeRule = "metric-point-receipt-v1"
	InboundTimeSpanElapsed        InboundTimeRule = "span-elapsed-v1"
	InboundTimeSpanEnd            InboundTimeRule = "span-end-v1"
)

type InboundOutcomeRuleKind string

const (
	InboundOutcomeForbidden       InboundOutcomeRuleKind = "forbidden"
	InboundOutcomeNativeSpan      InboundOutcomeRuleKind = "native-span-v1"
	InboundOutcomeOTelStatus      InboundOutcomeRuleKind = "otel-status-v1"
	InboundOutcomeProjectedRecord InboundOutcomeRuleKind = "projected-record-v1"
	InboundOutcomeFixed           InboundOutcomeRuleKind = "fixed"
)

type InboundOutcomeRule struct {
	kind  InboundOutcomeRuleKind
	fixed Outcome
}

func (rule InboundOutcomeRule) Kind() InboundOutcomeRuleKind { return rule.kind }
func (rule InboundOutcomeRule) Fixed() (Outcome, bool) {
	return rule.fixed, rule.kind == InboundOutcomeFixed
}

type InboundTargetRole string

const (
	InboundTargetImport InboundTargetRole = "import"
	InboundTargetDerive InboundTargetRole = "derive"
)

type InboundTargetKind string

const (
	InboundTargetPrimary InboundTargetKind = "primary"
	InboundTargetDerived InboundTargetKind = "derived"
)

type InboundDerivationStrategy string

const (
	InboundDerivationNone             InboundDerivationStrategy = ""
	InboundDerivationClaudeTokenUsage InboundDerivationStrategy = "claude-token-usage-v1"
	InboundDerivationCodexTokenFields InboundDerivationStrategy = "codex-token-fields-v1"
	InboundDerivationDurationMetric   InboundDerivationStrategy = "duration-metric-v1"
	InboundDerivationElapsedTime      InboundDerivationStrategy = "elapsed-time-v1"
	InboundDerivationFieldValue       InboundDerivationStrategy = "field-value-v1"
)

type InboundMarkerKind string

const (
	InboundMarkerExactStructuralValue InboundMarkerKind = "exact_structural_value"
	InboundMarkerProjectedStructure   InboundMarkerKind = "projected_record_structure"
	InboundMarkerReservedKeyPresence  InboundMarkerKind = "reserved_key_presence"
)

type InboundForwardPlacement string

const (
	InboundForwardLeaf     InboundForwardPlacement = "leaf"
	InboundForwardResource InboundForwardPlacement = "resource"
)

// InboundTargetOverride is the only catalog-owned source-to-target rename.
type InboundTargetOverride struct {
	source        string
	target        string
	normalization string
}

func (override InboundTargetOverride) Source() string        { return override.source }
func (override InboundTargetOverride) Target() string        { return override.target }
func (override InboundTargetOverride) Normalization() string { return override.normalization }

type InboundSourceUnitRuleKind string

const (
	InboundSourceUnitNone           InboundSourceUnitRuleKind = "none"
	InboundSourceUnitTargetEquality InboundSourceUnitRuleKind = "target-unit-equality-v1"
	InboundSourceUnitScaleTable     InboundSourceUnitRuleKind = "scale-table-v1"
)

// InboundSourceUnitScale is one exact source-unit spelling and its multiplier
// into the sealed target family unit. Source units are compared byte-for-byte;
// callers cannot request trimming, case folding, or any other free-form
// normalization.
type InboundSourceUnitScale struct {
	sourceUnit string
	scale      float64
}

func (entry InboundSourceUnitScale) SourceUnit() string { return entry.sourceUnit }
func (entry InboundSourceUnitScale) Scale() float64     { return entry.scale }

type inboundSourceUnitRuleEntry struct {
	kind       InboundSourceUnitRuleKind
	targetUnit string
	accepted   []InboundSourceUnitScale
}

// InboundSourceUnitRule is an immutable view of compiler-generated source-unit
// authority for one exact match/target. ScaleFor performs exact lookup only.
type InboundSourceUnitRule struct{ entry inboundSourceUnitRuleEntry }

func (rule InboundSourceUnitRule) Kind() InboundSourceUnitRuleKind { return rule.entry.kind }
func (rule InboundSourceUnitRule) TargetUnit() string              { return rule.entry.targetUnit }
func (rule InboundSourceUnitRule) Accepted() []InboundSourceUnitScale {
	return append([]InboundSourceUnitScale(nil), rule.entry.accepted...)
}
func (rule InboundSourceUnitRule) ScaleFor(sourceUnit string) (float64, bool) {
	for _, entry := range rule.entry.accepted {
		if entry.sourceUnit == sourceUnit {
			return entry.scale, true
		}
	}
	return 0, false
}

type InboundSourcePlacement string

const (
	InboundSourceMetricPointAttribute InboundSourcePlacement = "metric_point_attribute"
	InboundSourceResourceAttribute    InboundSourcePlacement = "resource_attribute"
	InboundSourceAuthenticated        InboundSourcePlacement = "authenticated_source"
	InboundSourceFixed                InboundSourcePlacement = "fixed"
	InboundSourceInstrumentName       InboundSourcePlacement = "instrument_name"
)

type InboundProjectionDisposition string

const (
	InboundProjectionProject InboundProjectionDisposition = "project"
	InboundProjectionOmit    InboundProjectionDisposition = "omit"
)

type InboundSourceRequirement string

const (
	InboundSourceRequired InboundSourceRequirement = "required"
	InboundSourceOptional InboundSourceRequirement = "optional"
)

type inboundSourceNormalizerRuleEntry struct {
	output   string
	exact    []string
	contains []string
	inputs   []string
}

type inboundSourceNormalizerEntry struct {
	id           string
	kind         string
	trim         string
	casePolicy   string
	maxUTF8Bytes int
	empty        string
	overflow     string
	unmatched    string
	pattern      string
	compiled     *regexp.Regexp
	values       []string
	separators   []string
	prefixes     []string
	rules        []inboundSourceNormalizerRuleEntry
}

// InboundSourceNormalizer is an immutable compiler-generated label normalizer.
// Normalize returns false only for a value the closed contract rejects.
type InboundSourceNormalizer struct{ entry inboundSourceNormalizerEntry }

func (normalizer InboundSourceNormalizer) ID() string { return normalizer.entry.id }

func (normalizer InboundSourceNormalizer) Normalize(raw string) (string, bool) {
	entry := normalizer.entry
	value := raw
	if entry.trim == "unicode-space" {
		value = strings.TrimSpace(value)
	}
	if entry.casePolicy == "lowercase" {
		value = strings.ToLower(value)
	}
	terminal := func(policy string) (string, bool) {
		switch policy {
		case "unknown", "other":
			return policy, true
		default:
			return "", false
		}
	}
	if value == "" {
		return terminal(entry.empty)
	}
	if entry.maxUTF8Bytes > 0 && len(value) > entry.maxUTF8Bytes {
		return terminal(entry.overflow)
	}
	switch entry.kind {
	case "bounded":
		return value, true
	case "identifier":
		if entry.compiled == nil || !entry.compiled.MatchString(value) {
			return "", false
		}
		return value, true
	case "ordered-exact-contains":
		for _, rule := range entry.rules {
			if containsInboundString(rule.exact, value) {
				return rule.output, true
			}
			for _, token := range rule.contains {
				if strings.Contains(value, token) {
					return rule.output, true
				}
			}
		}
		return terminal(entry.unmatched)
	case "ordered-prefix-family":
		for _, prefix := range entry.prefixes {
			if value == prefix {
				return prefix, true
			}
			for _, separator := range entry.separators {
				if strings.HasPrefix(value, prefix+separator) {
					return prefix, true
				}
			}
		}
		return terminal(entry.unmatched)
	case "exact-map":
		for _, rule := range entry.rules {
			if containsInboundString(rule.inputs, value) {
				return rule.output, true
			}
		}
		return terminal(entry.unmatched)
	case "enum":
		if containsInboundString(entry.values, value) {
			return value, true
		}
		return terminal(entry.unmatched)
	default:
		return "", false
	}
}

type InboundSourceGroup struct {
	placement InboundSourcePlacement
	keys      []string
}

func (group InboundSourceGroup) Placement() InboundSourcePlacement { return group.placement }
func (group InboundSourceGroup) Keys() []string                    { return append([]string(nil), group.keys...) }

type inboundProjectionFieldEntry struct {
	target        string
	disposition   InboundProjectionDisposition
	requirement   InboundSourceRequirement
	normalizer    inboundSourceNormalizerEntry
	allowedValues []string
	sourceGroups  []InboundSourceGroup
}

type InboundProjectionField struct{ entry inboundProjectionFieldEntry }

func (field InboundProjectionField) Target() string { return field.entry.target }
func (field InboundProjectionField) Disposition() InboundProjectionDisposition {
	return field.entry.disposition
}
func (field InboundProjectionField) Requirement() InboundSourceRequirement {
	return field.entry.requirement
}
func (field InboundProjectionField) Normalizer() InboundSourceNormalizer {
	return InboundSourceNormalizer{entry: cloneInboundSourceNormalizer(field.entry.normalizer)}
}
func (field InboundProjectionField) AllowedValues() []string {
	return append([]string(nil), field.entry.allowedValues...)
}
func (field InboundProjectionField) SourceGroups() []InboundSourceGroup {
	return cloneInboundSourceGroups(field.entry.sourceGroups)
}

type inboundSeriesComponentEntry struct {
	id            string
	requirement   InboundSourceRequirement
	normalizer    inboundSourceNormalizerEntry
	allowedValues []string
	sourceGroups  []InboundSourceGroup
}

type InboundSeriesComponent struct{ entry inboundSeriesComponentEntry }

func (component InboundSeriesComponent) ID() string { return component.entry.id }
func (component InboundSeriesComponent) Requirement() InboundSourceRequirement {
	return component.entry.requirement
}
func (component InboundSeriesComponent) Normalizer() InboundSourceNormalizer {
	return InboundSourceNormalizer{entry: cloneInboundSourceNormalizer(component.entry.normalizer)}
}
func (component InboundSeriesComponent) AllowedValues() []string {
	return append([]string(nil), component.entry.allowedValues...)
}
func (component InboundSeriesComponent) SourceGroups() []InboundSourceGroup {
	return cloneInboundSourceGroups(component.entry.sourceGroups)
}

type InboundResetEpoch struct {
	role          string
	identity      bool
	placement     string
	key           string
	normalization string
}

func (epoch InboundResetEpoch) Role() string          { return epoch.role }
func (epoch InboundResetEpoch) IsIdentity() bool      { return epoch.identity }
func (epoch InboundResetEpoch) Placement() string     { return epoch.placement }
func (epoch InboundResetEpoch) Key() string           { return epoch.key }
func (epoch InboundResetEpoch) Normalization() string { return epoch.normalization }

type inboundCumulativeSeriesEntry struct {
	applicability      string
	framing            string
	normalizationStage string
	components         []inboundSeriesComponentEntry
	resetEpoch         InboundResetEpoch
}

type InboundCumulativeSeries struct{ entry inboundCumulativeSeriesEntry }

func (series InboundCumulativeSeries) Applicability() string { return series.entry.applicability }
func (series InboundCumulativeSeries) Framing() string       { return series.entry.framing }
func (series InboundCumulativeSeries) NormalizationStage() string {
	return series.entry.normalizationStage
}
func (series InboundCumulativeSeries) Components() []InboundSeriesComponent {
	result := make([]InboundSeriesComponent, len(series.entry.components))
	for index, component := range series.entry.components {
		result[index] = InboundSeriesComponent{entry: cloneInboundSeriesComponent(component)}
	}
	return result
}
func (series InboundCumulativeSeries) ResetEpoch() InboundResetEpoch { return series.entry.resetEpoch }

// FrameNormalized encodes one value per generated component with explicit
// presence and byte-length framing. Present values must already equal their
// generated normal form, so normalization necessarily precedes identity.
func (series InboundCumulativeSeries) FrameNormalized(values []Optional[string]) (string, error) {
	if series.entry.framing != "length-prefixed-presence-v1" ||
		series.entry.normalizationStage != "before_framing" || len(values) != len(series.entry.components) {
		return "", ErrInboundCatalogInvalid
	}
	var framed strings.Builder
	for index, component := range series.entry.components {
		identifier := component.id
		framed.WriteString(strconv.Itoa(len(identifier)))
		framed.WriteByte(':')
		framed.WriteString(identifier)
		value, present := values[index].Get()
		if !present {
			if component.requirement == InboundSourceRequired {
				return "", ErrInboundCatalogInvalid
			}
			framed.WriteString(";0;")
			continue
		}
		normalized, ok := (InboundSourceNormalizer{entry: component.normalizer}).Normalize(value)
		if !ok || normalized != value {
			return "", ErrInboundCatalogInvalid
		}
		framed.WriteString(";1:")
		framed.WriteString(strconv.Itoa(len(value)))
		framed.WriteByte(':')
		framed.WriteString(value)
		framed.WriteByte(';')
	}
	return framed.String(), nil
}

type inboundSourceProjectionPlanEntry struct {
	id               string
	targetFamily     string
	fieldRules       []inboundProjectionFieldEntry
	cumulativeSeries Optional[inboundCumulativeSeriesEntry]
}

type InboundSourceProjectionPlan struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (plan InboundSourceProjectionPlan) entry() (inboundSourceProjectionPlanEntry, bool) {
	if plan.snapshot == nil || plan.index < 0 || plan.index >= len(plan.snapshot.projections) {
		return inboundSourceProjectionPlanEntry{}, false
	}
	return plan.snapshot.projections[plan.index], true
}
func (plan InboundSourceProjectionPlan) ID() string { entry, _ := plan.entry(); return entry.id }
func (plan InboundSourceProjectionPlan) TargetFamily() string {
	entry, _ := plan.entry()
	return entry.targetFamily
}
func (plan InboundSourceProjectionPlan) FieldRules() []InboundProjectionField {
	entry, ok := plan.entry()
	if !ok {
		return nil
	}
	result := make([]InboundProjectionField, len(entry.fieldRules))
	for index, field := range entry.fieldRules {
		result[index] = InboundProjectionField{entry: cloneInboundProjectionField(field)}
	}
	return result
}
func (plan InboundSourceProjectionPlan) CumulativeSeries() (InboundCumulativeSeries, bool) {
	entry, ok := plan.entry()
	if !ok {
		return InboundCumulativeSeries{}, false
	}
	series, present := entry.cumulativeSeries.Get()
	return InboundCumulativeSeries{entry: cloneInboundCumulativeSeries(series)}, present
}

type inboundCatalogSnapshot struct {
	aliases         []inboundAliasEntry
	normalizers     []inboundSourceNormalizerEntry
	projections     []inboundSourceProjectionPlanEntry
	matches         []inboundMatchEntry
	targets         []inboundTargetEntry
	markers         []inboundMarkerEntry
	echoes          []inboundEchoEntry
	contexts        []inboundImportContextEntry
	aliasByID       map[string]int
	normalizerByID  map[string]int
	projectionByID  map[string]int
	matchByID       map[string]int
	targetByID      map[string]int
	markerByKey     map[inboundMarkerLookupKey]int
	echoByIdentity  map[inboundEchoLookupKey]int
	echoByWire      map[inboundEchoWireLookupKey]int
	contextByID     map[string]int
	contextByFamily map[string]int
	policies        InboundTerminalPolicies
	wire            InboundWireContract
}

type inboundAliasEntry struct {
	id             string
	target         string
	valueType      InboundValueType
	normalization  string
	sources        []string
	conflictPolicy string
	absencePolicy  string
	fieldClass     FieldClass
	sensitivity    string
}

type inboundMatchEntry struct {
	id                string
	classID           string
	signal            Signal
	sources           []string
	shape             InboundShape
	discriminatorKind InboundDiscriminatorKind
	predicates        []InboundPredicate
	mappingStrategy   InboundMappingStrategy
	aliasIndexes      []int
	targetOverride    Optional[InboundTargetOverride]
	sourceUnitRule    inboundSourceUnitRuleEntry
	targetIndexes     []int
	timeRule          InboundTimeRule
	outcomeRule       InboundOutcomeRule
	nativeRoundTrip   bool
	projectionIndex   int
}

type inboundTargetEntry struct {
	id                  string
	matchIndex          int
	classID             string
	signal              Signal
	role                InboundTargetRole
	targetKind          InboundTargetKind
	family              string
	bucket              Bucket
	eventName           EventName
	familySchemaVersion uint32
	instrumentName      string
	instrumentType      string
	instrumentUnit      string
	sourceUnitRule      inboundSourceUnitRuleEntry
	fields              []InboundTargetField
	descriptor          familyDescriptor
	descriptorType      string
	mappingStrategy     InboundMappingStrategy
	derivationStrategy  InboundDerivationStrategy
	timeRule            InboundTimeRule
	outcomeRule         InboundOutcomeRule
	importContextIndex  int
	projectionID        string
	projectionIndex     int
}

type inboundMarkerEntry struct {
	id         string
	signal     Signal
	location   InboundLocation
	key        string
	markerKind InboundMarkerKind
	valueType  InboundValueType
	values     []InboundPredicateValue
}

type inboundEchoEntry struct {
	id               string
	signal           Signal
	family           string
	bucket           Bucket
	eventName        EventName
	instrumentName   string
	forwardPlacement InboundForwardPlacement
	compareSelfWith  string
}

type inboundImportContextEntry struct {
	id                 string
	familyDescriptorID string
	bucket             Bucket
	eventName          EventName
	constructionMode   string
	capabilities       []string
	descriptor         familyDescriptor
	descriptorType     string
}

// InboundCatalog is a read-only handle to the validated generated catalog.
// Every collection returned from it is detached from the shared snapshot.
type InboundCatalog struct{ snapshot *inboundCatalogSnapshot }

var (
	inboundCatalogOnce     sync.Once
	inboundCatalogInstance InboundCatalog
	inboundCatalogError    error
)

// LoadInboundCatalog parses and validates the generated inbound catalog once.
// Any drift is sticky for the process lifetime and fails the receiver closed.
func LoadInboundCatalog() (InboundCatalog, error) {
	inboundCatalogOnce.Do(func() {
		inboundCatalogInstance, inboundCatalogError = buildInboundCatalog(generatedInboundCatalogSourceValue())
	})
	return inboundCatalogInstance, inboundCatalogError
}

func (catalog InboundCatalog) Policies() InboundTerminalPolicies {
	if catalog.snapshot == nil {
		return InboundTerminalPolicies{}
	}
	return catalog.snapshot.policies
}

func (catalog InboundCatalog) WireContract() InboundWireContract {
	if catalog.snapshot == nil {
		return InboundWireContract{}
	}
	return catalog.snapshot.wire
}

func (catalog InboundCatalog) Aliases() []InboundAlias {
	if catalog.snapshot == nil {
		return nil
	}
	result := make([]InboundAlias, len(catalog.snapshot.aliases))
	for index := range result {
		result[index] = InboundAlias{snapshot: catalog.snapshot, index: index}
	}
	return result
}

func (catalog InboundCatalog) Alias(id string) (InboundAlias, bool) {
	if catalog.snapshot == nil {
		return InboundAlias{}, false
	}
	index, ok := catalog.snapshot.aliasByID[id]
	if !ok {
		return InboundAlias{}, false
	}
	return InboundAlias{snapshot: catalog.snapshot, index: index}, ok
}

func (catalog InboundCatalog) SourceNormalizer(id string) (InboundSourceNormalizer, bool) {
	if catalog.snapshot == nil {
		return InboundSourceNormalizer{}, false
	}
	index, ok := catalog.snapshot.normalizerByID[id]
	if !ok {
		return InboundSourceNormalizer{}, false
	}
	return InboundSourceNormalizer{entry: cloneInboundSourceNormalizer(catalog.snapshot.normalizers[index])}, true
}

func (catalog InboundCatalog) SourceProjectionPlan(id string) (InboundSourceProjectionPlan, bool) {
	if catalog.snapshot == nil {
		return InboundSourceProjectionPlan{}, false
	}
	index, ok := catalog.snapshot.projectionByID[id]
	if !ok {
		return InboundSourceProjectionPlan{}, false
	}
	return InboundSourceProjectionPlan{snapshot: catalog.snapshot, index: index}, true
}

// Matches returns exact candidates for the signal and authenticated receiver
// source. any_authenticated is interpreted only from generated source policy; a
// caller-provided source never becomes a wildcard.
func (catalog InboundCatalog) Matches(signal Signal, authenticatedSource string) []InboundMatch {
	if catalog.snapshot == nil || !IsSignal(signal) || !IsStableToken(authenticatedSource) || authenticatedSource == "any_authenticated" {
		return nil
	}
	result := make([]InboundMatch, 0)
	for index, match := range catalog.snapshot.matches {
		if match.signal == signal && inboundSourceApplies(match.sources, authenticatedSource) {
			result = append(result, InboundMatch{snapshot: catalog.snapshot, index: index})
		}
	}
	return result
}

func (catalog InboundCatalog) Match(id string) (InboundMatch, bool) {
	if catalog.snapshot == nil {
		return InboundMatch{}, false
	}
	index, ok := catalog.snapshot.matchByID[id]
	if !ok {
		return InboundMatch{}, false
	}
	return InboundMatch{snapshot: catalog.snapshot, index: index}, ok
}

func (catalog InboundCatalog) Target(id string) (InboundTarget, bool) {
	if catalog.snapshot == nil {
		return InboundTarget{}, false
	}
	index, ok := catalog.snapshot.targetByID[id]
	if !ok {
		return InboundTarget{}, false
	}
	return InboundTarget{snapshot: catalog.snapshot, index: index}, ok
}

func (catalog InboundCatalog) NativeMarkers(signal Signal) []InboundNativeMarker {
	if catalog.snapshot == nil || !IsSignal(signal) {
		return nil
	}
	result := make([]InboundNativeMarker, 0)
	for index, marker := range catalog.snapshot.markers {
		if marker.signal == signal {
			result = append(result, InboundNativeMarker{snapshot: catalog.snapshot, index: index})
		}
	}
	return result
}

func (catalog InboundCatalog) NativeMarker(signal Signal, location InboundLocation, key string) (InboundNativeMarker, bool) {
	if catalog.snapshot == nil {
		return InboundNativeMarker{}, false
	}
	index, ok := catalog.snapshot.markerByKey[inboundMarkerLookupKey{signal: signal, location: location, key: key}]
	if !ok {
		return InboundNativeMarker{}, false
	}
	return InboundNativeMarker{snapshot: catalog.snapshot, index: index}, ok
}

// EchoRecognizer resolves one exact generated native identity. Blank fields are
// significant and are never treated as wildcards.
func (catalog InboundCatalog) EchoRecognizer(
	signal Signal,
	family string,
	bucket Bucket,
	eventName EventName,
	instrumentName string,
) (InboundEchoRecognizer, bool) {
	if catalog.snapshot == nil {
		return InboundEchoRecognizer{}, false
	}
	key := inboundEchoLookupKey{
		signal: signal, family: family, bucket: bucket,
		eventName: eventName, instrumentName: instrumentName,
	}
	index, ok := catalog.snapshot.echoByIdentity[key]
	if !ok {
		return InboundEchoRecognizer{}, false
	}
	return InboundEchoRecognizer{snapshot: catalog.snapshot, index: index}, ok
}

// EchoRecognizerForWireIdentity resolves only fields available on the OTLP
// wire before canonical import. Logs use bucket+event, traces use
// bucket+family-marker, and metrics use instrument name. Irrelevant components
// must be empty and are never interpreted as wildcards.
func (catalog InboundCatalog) EchoRecognizerForWireIdentity(
	signal Signal,
	bucket Bucket,
	eventOrFamily EventName,
	instrumentName string,
) (InboundEchoRecognizer, bool) {
	if catalog.snapshot == nil {
		return InboundEchoRecognizer{}, false
	}
	key := inboundEchoWireLookupKey{signal: signal}
	switch signal {
	case SignalLogs, SignalTraces:
		if !IsBucket(bucket) || eventOrFamily.Validate() != nil || instrumentName != "" {
			return InboundEchoRecognizer{}, false
		}
		key.bucket = bucket
		key.eventOrFamily = eventOrFamily
	case SignalMetrics:
		if bucket != "" || eventOrFamily != "" || !IsStableToken(instrumentName) {
			return InboundEchoRecognizer{}, false
		}
		key.instrumentName = instrumentName
	default:
		return InboundEchoRecognizer{}, false
	}
	index, ok := catalog.snapshot.echoByWire[key]
	if !ok {
		return InboundEchoRecognizer{}, false
	}
	return InboundEchoRecognizer{snapshot: catalog.snapshot, index: index}, true
}

func (catalog InboundCatalog) ImportContext(id string) (InboundImportContext, bool) {
	if catalog.snapshot == nil {
		return InboundImportContext{}, false
	}
	index, ok := catalog.snapshot.contextByID[id]
	if !ok {
		return InboundImportContext{}, false
	}
	return InboundImportContext{snapshot: catalog.snapshot, index: index}, ok
}

func (catalog InboundCatalog) ImportContextForFamily(familyDescriptorID string) (InboundImportContext, bool) {
	if catalog.snapshot == nil {
		return InboundImportContext{}, false
	}
	index, ok := catalog.snapshot.contextByFamily[familyDescriptorID]
	if !ok {
		return InboundImportContext{}, false
	}
	return InboundImportContext{snapshot: catalog.snapshot, index: index}, ok
}

type InboundAlias struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (alias InboundAlias) entry() (inboundAliasEntry, bool) {
	if alias.snapshot == nil || alias.index < 0 || alias.index >= len(alias.snapshot.aliases) {
		return inboundAliasEntry{}, false
	}
	return alias.snapshot.aliases[alias.index], true
}

func (alias InboundAlias) ID() string     { entry, _ := alias.entry(); return entry.id }
func (alias InboundAlias) Target() string { entry, _ := alias.entry(); return entry.target }
func (alias InboundAlias) ValueType() InboundValueType {
	entry, _ := alias.entry()
	return entry.valueType
}
func (alias InboundAlias) Normalization() string {
	entry, _ := alias.entry()
	return entry.normalization
}
func (alias InboundAlias) Sources() []string {
	entry, _ := alias.entry()
	return append([]string(nil), entry.sources...)
}
func (alias InboundAlias) ConflictPolicy() string {
	entry, _ := alias.entry()
	return entry.conflictPolicy
}
func (alias InboundAlias) AbsencePolicy() string {
	entry, _ := alias.entry()
	return entry.absencePolicy
}
func (alias InboundAlias) FieldClass() FieldClass { entry, _ := alias.entry(); return entry.fieldClass }
func (alias InboundAlias) Sensitivity() string    { entry, _ := alias.entry(); return entry.sensitivity }

type InboundMatch struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (match InboundMatch) entry() (inboundMatchEntry, bool) {
	if match.snapshot == nil || match.index < 0 || match.index >= len(match.snapshot.matches) {
		return inboundMatchEntry{}, false
	}
	return match.snapshot.matches[match.index], true
}

func (match InboundMatch) ID() string      { entry, _ := match.entry(); return entry.id }
func (match InboundMatch) ClassID() string { entry, _ := match.entry(); return entry.classID }
func (match InboundMatch) Signal() Signal  { entry, _ := match.entry(); return entry.signal }
func (match InboundMatch) Sources() []string {
	entry, _ := match.entry()
	return append([]string(nil), entry.sources...)
}
func (match InboundMatch) Shape() InboundShape { entry, _ := match.entry(); return entry.shape }
func (match InboundMatch) DiscriminatorKind() InboundDiscriminatorKind {
	entry, _ := match.entry()
	return entry.discriminatorKind
}
func (match InboundMatch) Predicates() []InboundPredicate {
	entry, _ := match.entry()
	return cloneInboundPredicates(entry.predicates)
}
func (match InboundMatch) MappingStrategy() InboundMappingStrategy {
	entry, _ := match.entry()
	return entry.mappingStrategy
}
func (match InboundMatch) Aliases() []InboundAlias {
	entry, ok := match.entry()
	if !ok {
		return nil
	}
	result := make([]InboundAlias, len(entry.aliasIndexes))
	for index, aliasIndex := range entry.aliasIndexes {
		result[index] = InboundAlias{snapshot: match.snapshot, index: aliasIndex}
	}
	return result
}
func (match InboundMatch) TargetOverride() (InboundTargetOverride, bool) {
	entry, _ := match.entry()
	return entry.targetOverride.Get()
}
func (match InboundMatch) SourceUnitRule() InboundSourceUnitRule {
	entry, _ := match.entry()
	return InboundSourceUnitRule{entry: cloneInboundSourceUnitRule(entry.sourceUnitRule)}
}
func (match InboundMatch) SourceProjectionPlan() (InboundSourceProjectionPlan, bool) {
	entry, ok := match.entry()
	if !ok || entry.projectionIndex < 0 {
		return InboundSourceProjectionPlan{}, false
	}
	return InboundSourceProjectionPlan{snapshot: match.snapshot, index: entry.projectionIndex}, true
}
func (match InboundMatch) Targets() []InboundTarget {
	entry, ok := match.entry()
	if !ok {
		return nil
	}
	result := make([]InboundTarget, len(entry.targetIndexes))
	for index, targetIndex := range entry.targetIndexes {
		result[index] = InboundTarget{snapshot: match.snapshot, index: targetIndex}
	}
	return result
}
func (match InboundMatch) TimeRule() InboundTimeRule {
	entry, _ := match.entry()
	return entry.timeRule
}
func (match InboundMatch) OutcomeRule() InboundOutcomeRule {
	entry, _ := match.entry()
	return entry.outcomeRule
}
func (match InboundMatch) NativeRoundTrip() bool {
	entry, _ := match.entry()
	return entry.nativeRoundTrip
}

type InboundTargetField struct {
	fieldRef     string
	descriptorID string
	scope        inboundTargetFieldScope
	componentID  string
}

func (field InboundTargetField) FieldRef() string     { return field.fieldRef }
func (field InboundTargetField) DescriptorID() string { return field.descriptorID }

type inboundTargetFieldScope uint8

const (
	inboundTargetFieldScopeFamily inboundTargetFieldScope = iota
	inboundTargetFieldScopeResource
	inboundTargetFieldScopeEvent
)

// InboundTarget is both a read-only view and an opaque capability. Callers may
// pass it back to observability construction code, but cannot access or create
// the private generated descriptor stored in the validated snapshot.
type InboundTarget struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (target InboundTarget) entry() (inboundTargetEntry, bool) {
	if target.snapshot == nil || target.index < 0 || target.index >= len(target.snapshot.targets) {
		return inboundTargetEntry{}, false
	}
	return target.snapshot.targets[target.index], true
}

func (target InboundTarget) ID() string { entry, _ := target.entry(); return entry.id }
func (target InboundTarget) MatchID() string {
	entry, ok := target.entry()
	if !ok || target.snapshot == nil || entry.matchIndex < 0 || entry.matchIndex >= len(target.snapshot.matches) {
		return ""
	}
	return target.snapshot.matches[entry.matchIndex].id
}
func (target InboundTarget) ClassID() string         { entry, _ := target.entry(); return entry.classID }
func (target InboundTarget) Signal() Signal          { entry, _ := target.entry(); return entry.signal }
func (target InboundTarget) Role() InboundTargetRole { entry, _ := target.entry(); return entry.role }
func (target InboundTarget) TargetKind() InboundTargetKind {
	entry, _ := target.entry()
	return entry.targetKind
}
func (target InboundTarget) Family() string       { entry, _ := target.entry(); return entry.family }
func (target InboundTarget) Bucket() Bucket       { entry, _ := target.entry(); return entry.bucket }
func (target InboundTarget) EventName() EventName { entry, _ := target.entry(); return entry.eventName }
func (target InboundTarget) FamilySchemaVersion() uint32 {
	entry, _ := target.entry()
	return entry.familySchemaVersion
}
func (target InboundTarget) InstrumentName() string {
	entry, _ := target.entry()
	return entry.instrumentName
}
func (target InboundTarget) InstrumentType() string {
	entry, _ := target.entry()
	return entry.instrumentType
}
func (target InboundTarget) InstrumentUnit() string {
	entry, _ := target.entry()
	return entry.instrumentUnit
}
func (target InboundTarget) SourceUnitRule() InboundSourceUnitRule {
	entry, _ := target.entry()
	return InboundSourceUnitRule{entry: cloneInboundSourceUnitRule(entry.sourceUnitRule)}
}
func (target InboundTarget) SourceProjectionPlan() (InboundSourceProjectionPlan, bool) {
	entry, ok := target.entry()
	if !ok || entry.projectionIndex < 0 {
		return InboundSourceProjectionPlan{}, false
	}
	return InboundSourceProjectionPlan{snapshot: target.snapshot, index: entry.projectionIndex}, true
}
func (target InboundTarget) Fields() []InboundTargetField {
	entry, _ := target.entry()
	return append([]InboundTargetField(nil), entry.fields...)
}

// RequiredBooleanInputFields returns required generated boolean inputs for the
// sealed target. External normalizers use this to represent honest absence as
// false without carrying a handwritten family-field list. Native exact input
// remains responsible for supplying its original registered values.
func (target InboundTarget) RequiredBooleanInputFields() []InboundTargetField {
	entry, ok := target.entry()
	if !ok || entry.descriptor == nil {
		return nil
	}
	contract := entry.descriptor.familyDescriptorContract()
	capabilities := make(map[string]InboundTargetField, len(entry.fields))
	for _, field := range entry.fields {
		capabilities[field.fieldRef] = field
	}
	result := make([]InboundTargetField, 0)
	for _, descriptor := range contract.fields {
		if descriptor.source != familyValueInput || descriptor.typeOf != familyFieldBoolean ||
			descriptor.requirement != familyRequirementRequired {
			continue
		}
		if field, present := capabilities[descriptor.key]; present {
			result = append(result, field)
		}
	}
	return result
}
func (target InboundTarget) DescriptorID() string { entry, _ := target.entry(); return entry.family }
func (target InboundTarget) MappingStrategy() InboundMappingStrategy {
	entry, _ := target.entry()
	return entry.mappingStrategy
}
func (target InboundTarget) DerivationStrategy() InboundDerivationStrategy {
	entry, _ := target.entry()
	return entry.derivationStrategy
}
func (target InboundTarget) TimeRule() InboundTimeRule {
	entry, _ := target.entry()
	return entry.timeRule
}
func (target InboundTarget) OutcomeRule() InboundOutcomeRule {
	entry, _ := target.entry()
	return entry.outcomeRule
}
func (target InboundTarget) ImportContext() (InboundImportContext, bool) {
	entry, ok := target.entry()
	if !ok || entry.importContextIndex < 0 {
		return InboundImportContext{}, false
	}
	return InboundImportContext{snapshot: target.snapshot, index: entry.importContextIndex}, true
}

type InboundNativeMarker struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (marker InboundNativeMarker) entry() (inboundMarkerEntry, bool) {
	if marker.snapshot == nil || marker.index < 0 || marker.index >= len(marker.snapshot.markers) {
		return inboundMarkerEntry{}, false
	}
	return marker.snapshot.markers[marker.index], true
}

func (marker InboundNativeMarker) ID() string     { entry, _ := marker.entry(); return entry.id }
func (marker InboundNativeMarker) Signal() Signal { entry, _ := marker.entry(); return entry.signal }
func (marker InboundNativeMarker) Location() InboundLocation {
	entry, _ := marker.entry()
	return entry.location
}
func (marker InboundNativeMarker) Key() string { entry, _ := marker.entry(); return entry.key }
func (marker InboundNativeMarker) MarkerKind() InboundMarkerKind {
	entry, _ := marker.entry()
	return entry.markerKind
}
func (marker InboundNativeMarker) ValueType() InboundValueType {
	entry, _ := marker.entry()
	return entry.valueType
}
func (marker InboundNativeMarker) Values() []InboundPredicateValue {
	entry, _ := marker.entry()
	return append([]InboundPredicateValue(nil), entry.values...)
}

type InboundEchoRecognizer struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (echo InboundEchoRecognizer) entry() (inboundEchoEntry, bool) {
	if echo.snapshot == nil || echo.index < 0 || echo.index >= len(echo.snapshot.echoes) {
		return inboundEchoEntry{}, false
	}
	return echo.snapshot.echoes[echo.index], true
}

func (echo InboundEchoRecognizer) ID() string     { entry, _ := echo.entry(); return entry.id }
func (echo InboundEchoRecognizer) Signal() Signal { entry, _ := echo.entry(); return entry.signal }
func (echo InboundEchoRecognizer) Family() string { entry, _ := echo.entry(); return entry.family }
func (echo InboundEchoRecognizer) Bucket() Bucket { entry, _ := echo.entry(); return entry.bucket }
func (echo InboundEchoRecognizer) EventName() EventName {
	entry, _ := echo.entry()
	return entry.eventName
}
func (echo InboundEchoRecognizer) InstrumentName() string {
	entry, _ := echo.entry()
	return entry.instrumentName
}
func (echo InboundEchoRecognizer) ForwardPlacement() InboundForwardPlacement {
	entry, _ := echo.entry()
	return entry.forwardPlacement
}
func (echo InboundEchoRecognizer) CompareSelfWith() string {
	entry, _ := echo.entry()
	return entry.compareSelfWith
}

// InboundImportContext is an opaque ordinary-only log construction capability.
// It contains no mandatory facts and exposes no private family descriptor.
type InboundImportContext struct {
	snapshot *inboundCatalogSnapshot
	index    int
}

func (context InboundImportContext) entry() (inboundImportContextEntry, bool) {
	if context.snapshot == nil || context.index < 0 || context.index >= len(context.snapshot.contexts) {
		return inboundImportContextEntry{}, false
	}
	return context.snapshot.contexts[context.index], true
}

func (context InboundImportContext) ID() string { entry, _ := context.entry(); return entry.id }
func (context InboundImportContext) FamilyDescriptorID() string {
	entry, _ := context.entry()
	return entry.familyDescriptorID
}
func (context InboundImportContext) Bucket() Bucket { entry, _ := context.entry(); return entry.bucket }
func (context InboundImportContext) EventName() EventName {
	entry, _ := context.entry()
	return entry.eventName
}
func (context InboundImportContext) ConstructionMode() string {
	entry, _ := context.entry()
	return entry.constructionMode
}
func (context InboundImportContext) Capabilities() []string {
	entry, _ := context.entry()
	return append([]string(nil), entry.capabilities...)
}

type InboundTerminalPolicies struct {
	UnknownFields                   string
	NativeMarkerRule                string
	StructuralMarkerRule            string
	NativeMalformedDisposition      string
	NativeMalformedExternalFallback string
}

type InboundWireContract struct {
	ScopeName             string
	ScopeSchemaURL        string
	ResourceSchemaURL     string
	SemanticInstanceKey   string
	ForwardInstanceKey    string
	ForwardDestinationKey string
	ForwardHopCountKey    string
	RecordIDKey           string
	MaxForwardHops        uint32
}

type inboundMarkerLookupKey struct {
	signal   Signal
	location InboundLocation
	key      string
}

type inboundEchoLookupKey struct {
	signal         Signal
	family         string
	bucket         Bucket
	eventName      EventName
	instrumentName string
}

type inboundEchoWireLookupKey struct {
	signal         Signal
	bucket         Bucket
	eventOrFamily  EventName
	instrumentName string
}

func inboundSourceApplies(sources []string, authenticatedSource string) bool {
	for _, source := range sources {
		if source == "any_authenticated" || source == authenticatedSource {
			return true
		}
	}
	return false
}

func cloneInboundPredicates(input []InboundPredicate) []InboundPredicate {
	output := make([]InboundPredicate, len(input))
	copy(output, input)
	for index := range output {
		output[index].values = append([]InboundPredicateValue(nil), input[index].values...)
	}
	return output
}

func cloneInboundSourceUnitRule(input inboundSourceUnitRuleEntry) inboundSourceUnitRuleEntry {
	input.accepted = append([]InboundSourceUnitScale(nil), input.accepted...)
	return input
}

func cloneInboundSourceNormalizer(input inboundSourceNormalizerEntry) inboundSourceNormalizerEntry {
	input.values = append([]string(nil), input.values...)
	input.separators = append([]string(nil), input.separators...)
	input.prefixes = append([]string(nil), input.prefixes...)
	input.rules = append([]inboundSourceNormalizerRuleEntry(nil), input.rules...)
	for index := range input.rules {
		input.rules[index].exact = append([]string(nil), input.rules[index].exact...)
		input.rules[index].contains = append([]string(nil), input.rules[index].contains...)
		input.rules[index].inputs = append([]string(nil), input.rules[index].inputs...)
	}
	return input
}

func cloneInboundSourceGroups(input []InboundSourceGroup) []InboundSourceGroup {
	output := append([]InboundSourceGroup(nil), input...)
	for index := range output {
		output[index].keys = append([]string(nil), input[index].keys...)
	}
	return output
}

func cloneInboundProjectionField(input inboundProjectionFieldEntry) inboundProjectionFieldEntry {
	input.normalizer = cloneInboundSourceNormalizer(input.normalizer)
	input.allowedValues = append([]string(nil), input.allowedValues...)
	input.sourceGroups = cloneInboundSourceGroups(input.sourceGroups)
	return input
}

func cloneInboundSeriesComponent(input inboundSeriesComponentEntry) inboundSeriesComponentEntry {
	input.normalizer = cloneInboundSourceNormalizer(input.normalizer)
	input.allowedValues = append([]string(nil), input.allowedValues...)
	input.sourceGroups = cloneInboundSourceGroups(input.sourceGroups)
	return input
}

func cloneInboundCumulativeSeries(input inboundCumulativeSeriesEntry) inboundCumulativeSeriesEntry {
	input.components = append([]inboundSeriesComponentEntry(nil), input.components...)
	for index := range input.components {
		input.components[index] = cloneInboundSeriesComponent(input.components[index])
	}
	return input
}
