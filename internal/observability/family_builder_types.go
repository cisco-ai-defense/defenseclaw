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

import "time"

// Optional preserves the difference between an absent field and a present zero
// value. Generated family inputs use it for optional scalars instead of sentinel
// strings, magic numbers, or pointers whose target could be mutated concurrently.
type Optional[T any] struct {
	value   T
	present bool
}

func Present[T any](value T) Optional[T] { return Optional[T]{value: value, present: true} }
func Absent[T any]() Optional[T]         { return Optional[T]{} }

func (value Optional[T]) Get() (T, bool)  { return value.value, value.present }
func (value Optional[T]) IsPresent() bool { return value.present }

// FamilyProvenanceInput intentionally omits registry_schema_version. The family
// kernel stamps the version compiled into Record. Config generation and digest
// come from Runtime.Emit's pinned generation; Runtime.Emit remains the authority
// that rejects a stale or fabricated pair before persistence.
type FamilyProvenanceInput struct {
	Producer         string
	BinaryVersion    string
	ConfigGeneration int64
	BuildCommit      string
	ConfigDigest     string
}

func (input FamilyProvenanceInput) recordProvenance() Provenance {
	return Provenance{
		Producer:              input.Producer,
		BinaryVersion:         input.BinaryVersion,
		RegistrySchemaVersion: CurrentRecordSchemaVersion,
		ConfigGeneration:      input.ConfigGeneration,
		BuildCommit:           input.BuildCommit,
		ConfigDigest:          input.ConfigDigest,
	}
}

// FamilyEnvelopeInput is the common producer-controlled envelope subset. Bucket,
// signal, event/family identity, versions, span name, field classes, mandatory,
// floor state, and metric instrument metadata are deliberately absent.
type FamilyEnvelopeInput struct {
	ObservedAt  Optional[time.Time]
	Source      Source
	Connector   string
	Action      string
	Phase       string
	Correlation Correlation
	Provenance  FamilyProvenanceInput
}

type TraceStatusCode string

const (
	TraceStatusUnset TraceStatusCode = "UNSET"
	TraceStatusOK    TraceStatusCode = "OK"
	TraceStatusError TraceStatusCode = "ERROR"
)

// TraceStatusInput is a closed status union. A description can only accompany
// ERROR; callers cannot construct contradictory status state with a struct literal.
type TraceStatusInput struct {
	code        TraceStatusCode
	description Optional[string]
}

func NewTraceStatusUnset() TraceStatusInput { return TraceStatusInput{code: TraceStatusUnset} }
func NewTraceStatusOK() TraceStatusInput    { return TraceStatusInput{code: TraceStatusOK} }
func NewTraceStatusError(description Optional[string]) TraceStatusInput {
	return TraceStatusInput{code: TraceStatusError, description: description}
}

func (status TraceStatusInput) Code() TraceStatusCode { return status.code }
func (status TraceStatusInput) Description() (string, bool) {
	return status.description.Get()
}

// TraceResourceInput carries only structural state. Registered resource
// attributes are populated by generated wrappers through package-private values.
type TraceResourceInput struct {
	SchemaURL              string
	DroppedAttributesCount Optional[uint32]
	values                 familyFieldValues
	customValues           familyFieldValues
	compatibilityAliases   bool
}

// TraceScopeInput carries only the structural dropped count. Scope name, version,
// schema URL, trace schema, and semantic profile are descriptor/provenance-derived.
type TraceScopeInput struct {
	DroppedAttributesCount Optional[uint32]
	values                 familyFieldValues
}

// TraceEventInput cannot be given an event family/name or attribute map by an
// ordinary caller. Generated wrappers bind the private event contract, values,
// and the condition facts owned by that event instance.
type TraceEventInput struct {
	TimeUnixNano           uint64
	DroppedAttributesCount Optional[uint32]
	contract               familyEventContract
	values                 familyFieldValues
	conditions             familyConditionFacts
}

// TraceLinkInput exposes genuine OTel relationship data but not a free-form
// relation or attributes. Generated wrappers bind those catalog-owned values and
// the condition facts owned by that link instance.
type TraceLinkInput struct {
	TraceID                string
	SpanID                 string
	TraceState             Optional[string]
	DroppedAttributesCount Optional[uint32]
	relation               string
	values                 familyFieldValues
	conditions             familyConditionFacts
}

type familySignal uint8

const (
	familySignalInvalid familySignal = iota
	familySignalLog
	familySignalTrace
	familySignalMetric
)

func (signal familySignal) canonical() Signal {
	switch signal {
	case familySignalLog:
		return SignalLogs
	case familySignalTrace:
		return SignalTraces
	case familySignalMetric:
		return SignalMetrics
	default:
		return ""
	}
}

type familyFieldType uint8

const (
	familyFieldInvalid familyFieldType = iota
	familyFieldString
	familyFieldBoolean
	familyFieldInt64
	familyFieldUint32
	familyFieldUint64
	familyFieldDouble
	familyFieldStringArray
	familyFieldStructured
)

type familyRequirement uint8

const (
	familyRequirementInvalid familyRequirement = iota
	familyRequirementRequired
	familyRequirementRecommended
	familyRequirementOptional
	familyRequirementConditional
	familyRequirementForbidden
)

type familyFalseRequirement uint8

const (
	familyFalseInvalid familyFalseRequirement = iota
	familyFalseOptional
	familyFalseForbidden
)

type familyValueSource uint8

const (
	familyValueInput familyValueSource = iota + 1
	familyValueBucket
	familyValueFamily
	familyValueFamilySchemaVersion
	familyValueSourceName
	familyValueConfigGeneration
	familyValueOutcome
	familyValueBinaryVersion
	familyValueTraceSchemaVersion
	familyValueSemanticProfile
	familyValueLinkRelation
)

type familyConditionState uint8

const (
	familyConditionUnknown familyConditionState = iota
	familyConditionFalse
	familyConditionTrue
)

type familyConditionFact struct {
	id    string
	state familyConditionState
}

type familyConditionFacts []familyConditionFact

type familyStructuredLimits struct {
	maxEncodedBytes  int
	maxItemUTF8Bytes int
	maxItems         int
	maxDepth         int
	maxProperties    int
}

type familyFieldConstraints struct {
	maxUTF8Bytes int
	minItems     int
	maxItems     int
	pattern      string
	enum         []string
	hasIntMin    bool
	intMin       int64
	hasIntMax    bool
	intMax       int64
	hasUintMin   bool
	uintMin      uint64
	hasUintMax   bool
	uintMax      uint64
	hasFloatMin  bool
	floatMin     float64
	hasFloatMax  bool
	floatMax     float64
	structured   familyStructuredLimits
}

type familyFieldDescriptor struct {
	key              string
	typeOf           familyFieldType
	requirement      familyRequirement
	conditionID      string
	falseRequirement familyFalseRequirement
	fieldClass       FieldClass
	constraints      familyFieldConstraints
	source           familyValueSource
}

type familyFieldValue struct {
	key     string
	value   any
	present bool
}

type familyFieldValues []familyFieldValue

type familyResourceCompatibilityAlias struct {
	canonical  string
	descriptor familyFieldDescriptor
}

type familyResourceDynamicContract struct {
	maxItems              int
	maxValueUTF8Bytes     int
	maxAggregateUTF8Bytes int
	fieldClass            FieldClass
	aliases               []familyResourceCompatibilityAlias
	validate              func(string, string) error
	prometheusKey         func(string) string
}

type familyOutcomePolicy struct {
	requirement familyRequirement
	allowed     []Outcome
}

// familyValueCodeEntry is one immutable string-to-int64 catalog pair. Generated
// descriptors use the closed relation below for sibling fields whose individual
// scalar constraints cannot prove their pairwise consistency.
type familyValueCodeEntry struct {
	value string
	code  int64
}

type familyCrossFieldRelation struct {
	valueKey     string
	codeKey      string
	entries      []familyValueCodeEntry
	mismatchCode FamilyBuildErrorCode
}

type familyDescriptorContract struct {
	id                  string
	identity            EventIdentity
	familySchemaVersion uint32
	outcome             familyOutcomePolicy
	fields              []familyFieldDescriptor
	crossFieldRelations []familyCrossFieldRelation
}

type familyDescriptor interface {
	familyDescriptorContract() familyDescriptorContract
}

// generatedLogFamilyContract is implemented only by future generated values in
// this package. It also satisfies Record's private mandatory/identity capability.
type generatedLogFamilyContract interface {
	familyDescriptor
	schemaDerivedLogFamilyContract
}

type spanNamePart struct {
	literal string
	field   string
}

type familyEventContract struct {
	id     string
	name   string
	fields []familyFieldDescriptor
}

type familyTraceContract struct {
	familyDescriptorContract
	allowedKinds       []string
	spanName           []spanNamePart
	attributeLimits    familyStructuredLimits
	resourceFields     []familyFieldDescriptor
	resourceLimits     familyStructuredLimits
	scopeFields        []familyFieldDescriptor
	scopeLimits        familyStructuredLimits
	allowedEvents      []familyEventContract
	eventLimits        familyStructuredLimits
	maxEvents          int
	allowedLinks       []string
	linkFields         []familyFieldDescriptor
	linkLimits         familyStructuredLimits
	maxLinks           int
	scopeName          string
	scopeSchemaURL     string
	traceSchemaVersion string
	semanticProfile    string
}

type generatedTraceFamilyContract interface {
	familyDescriptor
	familyTraceContract() familyTraceContract
}

type familyMetricNumberType uint8

const (
	familyMetricNumberInvalid familyMetricNumberType = iota
	familyMetricNumberInt64
	familyMetricNumberDouble
)

type familyMetricContract struct {
	familyDescriptorContract
	valueType       familyMetricNumberType
	attributeLimits familyStructuredLimits
	instrumentName  string
	instrumentType  string
	unit            string
	temporality     string
}

type generatedMetricFamilyContract interface {
	familyDescriptor
	familyMetricContract() familyMetricContract
}

type familyMetricNumber struct {
	typeOf familyMetricNumberType
	int64  int64
	double float64
}

func familyInt64MetricNumber(value int64) familyMetricNumber {
	return familyMetricNumber{typeOf: familyMetricNumberInt64, int64: value}
}

func familyDoubleMetricNumber(value float64) familyMetricNumber {
	return familyMetricNumber{typeOf: familyMetricNumberDouble, double: value}
}

type familyLogBuildInput struct {
	envelope   FamilyEnvelopeInput
	severity   Optional[Severity]
	logLevel   Optional[LogLevel]
	outcome    Optional[Outcome]
	values     familyFieldValues
	conditions familyConditionFacts
	// timestamp and importProvenance are package-private accepted-record facts.
	// Generated producer wrappers leave both unset, so ordinary production keeps
	// using the builder clock and cannot attach inbound provenance accidentally.
	timestamp        Optional[time.Time]
	importProvenance *ImportProvenance
}

type familyTraceBuildInput struct {
	envelope               FamilyEnvelopeInput
	outcome                Optional[Outcome]
	kind                   string
	startTimeUnixNano      uint64
	endTimeUnixNano        uint64
	parentSpanID           Optional[string]
	traceState             Optional[string]
	flags                  uint32
	status                 TraceStatusInput
	resource               TraceResourceInput
	scope                  TraceScopeInput
	values                 familyFieldValues
	conditions             familyConditionFacts
	events                 []TraceEventInput
	droppedEventsCount     Optional[uint32]
	links                  []TraceLinkInput
	droppedLinksCount      Optional[uint32]
	droppedAttributesCount Optional[uint32]
	// timestamp and importProvenance are package-private accepted-record facts.
	// Generated producer wrappers leave both unset, so ordinary production keeps
	// using the builder clock and cannot attach inbound provenance accidentally.
	timestamp        Optional[time.Time]
	importProvenance *ImportProvenance
}

type familyMetricBuildInput struct {
	envelope   FamilyEnvelopeInput
	value      familyMetricNumber
	labels     familyFieldValues
	conditions familyConditionFacts
	// See familyTraceBuildInput. The inbound constructor is the only caller that
	// may select a source/fallback point timestamp and attach import provenance.
	timestamp        Optional[time.Time]
	importProvenance *ImportProvenance
}
