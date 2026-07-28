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
	"math"
	"reflect"
	"strings"
	"time"
)

const inboundMaximumFutureSkew = 5 * time.Minute

const inboundImportProducer = "defenseclaw"

// InboundMappedValueKind is the closed set of already-normalized field arms
// accepted by the private OTLP import constructor. There is deliberately no
// null, raw JSON, map, field-name, family-name, or field-class arm.
type InboundMappedValueKind uint8

const (
	InboundMappedValueInvalid InboundMappedValueKind = iota
	InboundMappedValueString
	InboundMappedValueBoolean
	InboundMappedValueInt64
	InboundMappedValueUint32
	InboundMappedValueUint64
	InboundMappedValueDouble
	InboundMappedValueStringArray
	InboundMappedValueGenAIInputMessages
	InboundMappedValueGenAIOutputMessages
	InboundMappedValueGenAIToolCallArguments
	InboundMappedValueGenAIToolCallResult
)

// InboundMappedField binds one typed mapped value to a generated target-field
// capability. Its members are private so a receiver cannot select an arbitrary
// body key or supply a field class.
type InboundMappedField struct {
	field InboundTargetField
	kind  InboundMappedValueKind
	value any
}

func NewInboundMappedString(field InboundTargetField, value string) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueString, value: strings.Clone(value)}
}

func NewInboundMappedBoolean(field InboundTargetField, value bool) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueBoolean, value: value}
}

func NewInboundMappedInt64(field InboundTargetField, value int64) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueInt64, value: value}
}

func NewInboundMappedUint32(field InboundTargetField, value uint32) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueUint32, value: value}
}

func NewInboundMappedUint64(field InboundTargetField, value uint64) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueUint64, value: value}
}

func NewInboundMappedDouble(field InboundTargetField, value float64) InboundMappedField {
	return InboundMappedField{field: field, kind: InboundMappedValueDouble, value: value}
}

func NewInboundMappedStringArray(field InboundTargetField, value []string) InboundMappedField {
	copyValue := make([]string, len(value))
	for index := range value {
		copyValue[index] = strings.Clone(value[index])
	}
	return InboundMappedField{field: field, kind: InboundMappedValueStringArray, value: copyValue}
}

type inboundSealedStructuredValue struct {
	binding string
	wrapped Value
}

func NewInboundMappedGenAIInputMessages(
	field InboundTargetField,
	value TelemetryStructuredGenAIInputMessages,
) (InboundMappedField, error) {
	if err := validateInboundSealedStructuredField(field, "gen_ai.input.messages"); err != nil {
		return InboundMappedField{}, err
	}
	encoded, err := encodeTelemetryStructuredGenAIInputMessages("gen_ai.input.messages", value, true)
	return newInboundSealedStructuredField(
		field, "gen_ai.input.messages", InboundMappedValueGenAIInputMessages, encoded, err,
	)
}

func NewInboundMappedGenAIOutputMessages(
	field InboundTargetField,
	value TelemetryStructuredGenAIOutputMessages,
) (InboundMappedField, error) {
	if err := validateInboundSealedStructuredField(field, "gen_ai.output.messages"); err != nil {
		return InboundMappedField{}, err
	}
	encoded, err := encodeTelemetryStructuredGenAIOutputMessages("gen_ai.output.messages", value, true)
	return newInboundSealedStructuredField(
		field, "gen_ai.output.messages", InboundMappedValueGenAIOutputMessages, encoded, err,
	)
}

func NewInboundMappedGenAIToolCallArguments(
	field InboundTargetField,
	value TelemetryStructuredGenAIToolCallArguments,
) (InboundMappedField, error) {
	if err := validateInboundSealedStructuredField(field, "gen_ai.tool.call.arguments"); err != nil {
		return InboundMappedField{}, err
	}
	encoded, err := encodeTelemetryStructuredGenAIToolCallArguments("gen_ai.tool.call.arguments", value, true)
	return newInboundSealedStructuredField(
		field, "gen_ai.tool.call.arguments", InboundMappedValueGenAIToolCallArguments, encoded, err,
	)
}

func NewInboundMappedGenAIToolCallResult(
	field InboundTargetField,
	value TelemetryStructuredGenAIToolCallResult,
) (InboundMappedField, error) {
	if err := validateInboundSealedStructuredField(field, "gen_ai.tool.call.result"); err != nil {
		return InboundMappedField{}, err
	}
	encoded, err := encodeTelemetryStructuredGenAIToolCallResult("gen_ai.tool.call.result", value, true)
	return newInboundSealedStructuredField(
		field, "gen_ai.tool.call.result", InboundMappedValueGenAIToolCallResult, encoded, err,
	)
}

func validateInboundSealedStructuredField(field InboundTargetField, binding string) error {
	if field.fieldRef != binding || field.descriptorID == "" ||
		!strings.HasSuffix(field.descriptorID, ":"+binding) {
		return familyBuildFailure(FamilyBuildInvalidType)
	}
	return nil
}

func newInboundSealedStructuredField(
	field InboundTargetField,
	binding string,
	kind InboundMappedValueKind,
	encoded familyFieldValue,
	encodeErr error,
) (InboundMappedField, error) {
	if encodeErr != nil {
		return InboundMappedField{}, encodeErr
	}
	if validateInboundSealedStructuredField(field, binding) != nil ||
		encoded.key != binding || !encoded.present || encoded.value == nil {
		return InboundMappedField{}, familyBuildFailure(FamilyBuildInvalidType)
	}
	wrapper, err := NewValue(map[string]any{"value": encoded.value})
	if err != nil {
		return InboundMappedField{}, familyBuildFailure(FamilyBuildInvalidType)
	}
	return InboundMappedField{
		field: field, kind: kind,
		value: inboundSealedStructuredValue{binding: binding, wrapped: wrapper},
	}, nil
}

func (value inboundSealedStructuredValue) unwrap(expected string) (any, error) {
	if value.binding != expected || value.wrapped.IsZero() {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	object, err := value.wrapped.Object()
	if err != nil || len(object) != 1 {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	result, exists := object["value"]
	if !exists || result == nil {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	return result, nil
}

// InboundImportProvenanceInput contains only receiver-validated occurrence
// facts. Protocol, binding ID, mode, and derivation are selected structurally by
// the generated target and cannot be supplied by a receiver caller.
type InboundImportProvenanceInput struct {
	AuthenticatedSource      string
	UpstreamInstanceID       string
	UpstreamRecordID         string
	UpstreamServiceName      string
	UpstreamRedactionProfile string
	IngressHopCount          uint32
	LastHopInstanceID        string
	LastHopDestination       string
}

// InboundLocalProvenanceInput is the runtime-generation provenance subset.
// The constructor stamps the local importer producer and registry version.
type InboundLocalProvenanceInput struct {
	BinaryVersion    string
	ConfigGeneration int64
	BuildCommit      string
	ConfigDigest     string
}

// InboundImportedLogInput is the body-free construction input for one already
// identified and collected log target. ReceiptTime becomes observed_at;
// Timestamp is the selected source/fallback timestamp from OTLP-I05.
type InboundImportedLogInput struct {
	Timestamp   time.Time
	ReceiptTime time.Time
	Correlation Correlation
	Provenance  InboundLocalProvenanceInput
	Import      InboundImportProvenanceInput
	Severity    Optional[Severity]
	LogLevel    Optional[LogLevel]
	Outcome     Optional[Outcome]
	Fields      []InboundMappedField
}

// InboundImportBuilder is the narrow accepted-record construction surface. It
// is separate from FamilyBuilder so generated producer-method API checks remain
// closed to compiler-emitted family methods.
type InboundImportBuilder struct{ family *FamilyBuilder }

func NewInboundImportBuilder(
	clock Clock,
	idGenerator OccurrenceIDGenerator,
) (*InboundImportBuilder, error) {
	family, err := NewFamilyBuilder(clock, idGenerator)
	if err != nil {
		return nil, err
	}
	return &InboundImportBuilder{family: family}, nil
}

// BuildLog constructs one ordinary, non-floor canonical log
// through the exact descriptor sealed into target and context. Callers cannot
// select identity, schema, mandatory state, field classes, or a body map.
func (builder *InboundImportBuilder) BuildLog(
	target InboundTarget,
	context InboundImportContext,
	input InboundImportedLogInput,
) (Record, error) {
	if builder == nil || builder.family == nil || !builder.family.ready() {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	targetEntry, contextEntry, matchEntry, err := resolveInboundLogImportCapability(
		target, context, input.Import.AuthenticatedSource,
	)
	if err != nil {
		return Record{}, err
	}
	if err := validateInboundImportTimes(input.Timestamp, input.ReceiptTime); err != nil {
		return Record{}, err
	}
	values, conditions, err := inboundFamilyLogValues(targetEntry, input.Fields, input.Outcome)
	if err != nil {
		return Record{}, err
	}
	provenance := ImportProvenance{
		Protocol:                 ImportProtocolOTLP,
		BindingID:                matchEntry.id,
		Mode:                     ImportModeImport,
		AuthenticatedSource:      input.Import.AuthenticatedSource,
		UpstreamInstanceID:       input.Import.UpstreamInstanceID,
		UpstreamRecordID:         input.Import.UpstreamRecordID,
		UpstreamServiceName:      input.Import.UpstreamServiceName,
		UpstreamRedactionProfile: input.Import.UpstreamRedactionProfile,
		IngressHopCount:          input.Import.IngressHopCount,
		LastHopInstanceID:        input.Import.LastHopInstanceID,
		LastHopDestination:       input.Import.LastHopDestination,
	}
	if err := validateInboundImportProvenanceShape(matchEntry, provenance); err != nil {
		return Record{}, err
	}
	if err := provenance.Validate(); err != nil {
		return Record{}, familyBuildFailure(FamilyBuildConstraint)
	}
	envelope := FamilyEnvelopeInput{
		ObservedAt:  Present(input.ReceiptTime),
		Source:      SourceOTelReceiver,
		Connector:   input.Import.AuthenticatedSource,
		Correlation: input.Correlation,
		Provenance: FamilyProvenanceInput{
			Producer: inboundImportProducer, BinaryVersion: input.Provenance.BinaryVersion,
			ConfigGeneration: input.Provenance.ConfigGeneration,
			BuildCommit:      input.Provenance.BuildCommit, ConfigDigest: input.Provenance.ConfigDigest,
		},
	}
	record, err := builder.family.buildResolvedGeneratedLog(
		contextEntry.descriptor.familyDescriptorContract(),
		resolveGeneratedLogMandatory(false),
		familyLogBuildInput{
			envelope: envelope, severity: input.Severity, logLevel: input.LogLevel,
			outcome: input.Outcome, values: values, conditions: conditions,
			timestamp: Present(input.Timestamp), importProvenance: &provenance,
		},
	)
	if err != nil {
		return Record{}, err
	}
	// These are structural postconditions, not caller assertions. They protect
	// the floor boundary even if the shared family kernel changes later.
	if record.Identity() != targetEntry.descriptor.familyDescriptorContract().identity ||
		record.Mandatory() || record.IsFloorOnly() {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func validateInboundImportProvenanceShape(
	match inboundMatchEntry,
	provenance ImportProvenance,
) error {
	switch match.shape {
	case InboundShapeNativeExact:
		if provenance.UpstreamInstanceID == "" || provenance.UpstreamRecordID == "" ||
			provenance.LastHopInstanceID == "" || provenance.LastHopDestination == "" ||
			provenance.IngressHopCount == 0 {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	case InboundShapeExternal:
		if provenance.UpstreamInstanceID != "" || provenance.UpstreamRecordID != "" ||
			provenance.UpstreamRedactionProfile != "" || provenance.IngressHopCount != 0 ||
			provenance.LastHopInstanceID != "" || provenance.LastHopDestination != "" {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	default:
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return nil
}

func resolveInboundLogImportCapability(
	target InboundTarget,
	context InboundImportContext,
	authenticatedSource string,
) (inboundTargetEntry, inboundImportContextEntry, inboundMatchEntry, error) {
	targetEntry, targetOK := target.entry()
	contextEntry, contextOK := context.entry()
	if !targetOK || !contextOK || target.snapshot == nil || target.snapshot != context.snapshot ||
		targetEntry.signal != SignalLogs || targetEntry.role != InboundTargetImport ||
		targetEntry.importContextIndex != context.index ||
		contextEntry.constructionMode != "ordinary_import_only" ||
		!reflect.DeepEqual(contextEntry.capabilities, []string{"validate", "construct_ordinary"}) ||
		contextEntry.familyDescriptorID != targetEntry.family ||
		contextEntry.bucket != targetEntry.bucket || contextEntry.eventName != targetEntry.eventName ||
		contextEntry.descriptorType != targetEntry.descriptorType ||
		targetEntry.matchIndex < 0 || targetEntry.matchIndex >= len(target.snapshot.matches) ||
		nilInterface(targetEntry.descriptor) || nilInterface(contextEntry.descriptor) {
		return inboundTargetEntry{}, inboundImportContextEntry{}, inboundMatchEntry{},
			familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	targetContract := cloneFamilyDescriptorContract(targetEntry.descriptor.familyDescriptorContract())
	contextContract := cloneFamilyDescriptorContract(contextEntry.descriptor.familyDescriptorContract())
	if !reflect.DeepEqual(targetContract, contextContract) ||
		targetContract.id != targetEntry.family || targetContract.identity.Bucket != targetEntry.bucket ||
		targetContract.identity.Name != targetEntry.eventName ||
		targetContract.familySchemaVersion != targetEntry.familySchemaVersion ||
		validateFamilyDescriptor(targetContract, familySignalLog) != nil {
		return inboundTargetEntry{}, inboundImportContextEntry{}, inboundMatchEntry{},
			familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	match := target.snapshot.matches[targetEntry.matchIndex]
	bound := false
	for _, index := range match.targetIndexes {
		if index == target.index {
			bound = true
			break
		}
	}
	if !bound || match.signal != SignalLogs || !IsStableToken(match.id) ||
		!inboundSourceApplies(match.sources, authenticatedSource) ||
		!IsStableToken(authenticatedSource) || authenticatedSource == "any_authenticated" {
		return inboundTargetEntry{}, inboundImportContextEntry{}, inboundMatchEntry{},
			familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return targetEntry, contextEntry, match, nil
}

// AcceptsAuthenticatedSource reports whether this exact target's generated
// match authorizes a concrete receiver source. It is used by the collection
// metadata gate before any body mapping or builder allocation.
func (target InboundTarget) AcceptsAuthenticatedSource(authenticatedSource string) bool {
	entry, ok := target.entry()
	if !ok || target.snapshot == nil || entry.matchIndex < 0 ||
		entry.matchIndex >= len(target.snapshot.matches) ||
		!IsStableToken(authenticatedSource) || authenticatedSource == "any_authenticated" {
		return false
	}
	return inboundSourceApplies(target.snapshot.matches[entry.matchIndex].sources, authenticatedSource)
}

// MappedValueKind resolves the exact constructor arm for one target-field
// capability. Derived descriptor fields intentionally return false: an inbound
// projection may validate them as consistency assertions, but cannot supply
// them to the family kernel as caller-owned values.
func (target InboundTarget) MappedValueKind(field InboundTargetField) (InboundMappedValueKind, bool) {
	entry, ok := target.entry()
	if !ok || nilInterface(entry.descriptor) || field.fieldRef == "" {
		return InboundMappedValueInvalid, false
	}
	if field.scope != inboundTargetFieldScopeFamily {
		return target.inboundComponentMappedValueKind(field)
	}
	bound := false
	for _, candidate := range entry.fields {
		if candidate.descriptorID == field.descriptorID && candidate.fieldRef == field.fieldRef {
			bound = true
			break
		}
	}
	if !bound {
		return InboundMappedValueInvalid, false
	}
	for _, descriptor := range entry.descriptor.familyDescriptorContract().fields {
		if descriptor.key != field.fieldRef {
			continue
		}
		if descriptor.source != familyValueInput {
			return InboundMappedValueInvalid, false
		}
		kind := inboundMappedKindForFamilyField(descriptor)
		return kind, kind != InboundMappedValueInvalid
	}
	return InboundMappedValueInvalid, false
}

// Targets returns detached opaque handles for the validated generated target
// inventory. The private descriptors remain sealed in the catalog snapshot.
func (catalog InboundCatalog) Targets() []InboundTarget {
	if catalog.snapshot == nil {
		return nil
	}
	result := make([]InboundTarget, len(catalog.snapshot.targets))
	for index := range result {
		result[index] = InboundTarget{snapshot: catalog.snapshot, index: index}
	}
	return result
}

func validateInboundImportTimes(timestamp, receipt time.Time) error {
	if timestamp.IsZero() || receipt.IsZero() ||
		marshalTimeInvalid(timestamp) || marshalTimeInvalid(receipt) ||
		timestamp.After(receipt) && timestamp.Sub(receipt) > inboundMaximumFutureSkew {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	return nil
}

func marshalTimeInvalid(value time.Time) bool {
	_, err := value.UTC().MarshalJSON()
	return err != nil
}

func inboundFamilyLogValues(
	target inboundTargetEntry,
	mapped []InboundMappedField,
	outcome Optional[Outcome],
) (familyFieldValues, familyConditionFacts, error) {
	contract := cloneFamilyDescriptorContract(target.descriptor.familyDescriptorContract())
	allowed := make(map[string]InboundTargetField, len(target.fields))
	for _, field := range target.fields {
		allowed[field.descriptorID] = field
	}
	descriptors := make(map[string]familyFieldDescriptor, len(contract.fields))
	for _, descriptor := range contract.fields {
		descriptors[descriptor.key] = descriptor
	}
	values := make(familyFieldValues, 0, len(mapped))
	provided := make(map[string]any, len(mapped))
	for _, field := range mapped {
		capability, exists := allowed[field.field.descriptorID]
		if !exists || capability.fieldRef != field.field.fieldRef || field.field.fieldRef == "" {
			return nil, nil, familyBuildFailure(FamilyBuildUnknownField)
		}
		descriptor, exists := descriptors[capability.fieldRef]
		if !exists {
			return nil, nil, familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if descriptor.source != familyValueInput {
			return nil, nil, familyBuildFailure(FamilyBuildForbiddenField)
		}
		if _, duplicate := provided[descriptor.key]; duplicate {
			return nil, nil, familyBuildFailure(FamilyBuildDuplicateField)
		}
		value, err := inboundMappedFamilyValue(descriptor, field)
		if err != nil {
			return nil, nil, err
		}
		provided[descriptor.key] = value
		values = append(values, familyFieldValue{key: descriptor.key, value: value, present: true})
	}
	conditions, err := inboundLogConditionFacts(contract.fields, provided, outcome)
	if err != nil {
		return nil, nil, err
	}
	return values, conditions, nil
}

func inboundMappedFamilyValue(expected familyFieldDescriptor, field InboundMappedField) (any, error) {
	wantKind := inboundMappedKindForFamilyField(expected)
	if wantKind == InboundMappedValueInvalid || field.kind != wantKind {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	switch field.kind {
	case InboundMappedValueString:
		value, ok := field.value.(string)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return strings.Clone(value), nil
	case InboundMappedValueBoolean:
		value, ok := field.value.(bool)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return value, nil
	case InboundMappedValueInt64:
		value, ok := field.value.(int64)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return value, nil
	case InboundMappedValueUint32:
		value, ok := field.value.(uint32)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return value, nil
	case InboundMappedValueUint64:
		value, ok := field.value.(uint64)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return value, nil
	case InboundMappedValueDouble:
		value, ok := field.value.(float64)
		if !ok || math.IsNaN(value) || math.IsInf(value, 0) {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return value, nil
	case InboundMappedValueStringArray:
		value, ok := field.value.([]string)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		result := make([]string, len(value))
		for index := range value {
			result[index] = strings.Clone(value[index])
		}
		return result, nil
	case InboundMappedValueGenAIInputMessages,
		InboundMappedValueGenAIOutputMessages,
		InboundMappedValueGenAIToolCallArguments,
		InboundMappedValueGenAIToolCallResult:
		value, ok := field.value.(inboundSealedStructuredValue)
		if !ok {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		unwrapped, err := value.unwrap(expected.key)
		if err != nil || unwrapped == nil {
			return nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		return unwrapped, nil
	default:
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
}

func inboundMappedKindForFamilyField(expected familyFieldDescriptor) InboundMappedValueKind {
	if expected.typeOf == familyFieldStructured {
		switch expected.key {
		case "gen_ai.input.messages":
			return InboundMappedValueGenAIInputMessages
		case "gen_ai.output.messages":
			return InboundMappedValueGenAIOutputMessages
		case "gen_ai.tool.call.arguments":
			return InboundMappedValueGenAIToolCallArguments
		case "gen_ai.tool.call.result":
			return InboundMappedValueGenAIToolCallResult
		default:
			return InboundMappedValueInvalid
		}
	}
	return map[familyFieldType]InboundMappedValueKind{
		familyFieldString:      InboundMappedValueString,
		familyFieldBoolean:     InboundMappedValueBoolean,
		familyFieldInt64:       InboundMappedValueInt64,
		familyFieldUint32:      InboundMappedValueUint32,
		familyFieldUint64:      InboundMappedValueUint64,
		familyFieldDouble:      InboundMappedValueDouble,
		familyFieldStringArray: InboundMappedValueStringArray,
	}[expected.typeOf]
}

func inboundLogConditionFacts(
	descriptors []familyFieldDescriptor,
	provided map[string]any,
	outcome Optional[Outcome],
) (familyConditionFacts, error) {
	conditionFields := make(map[string][]familyFieldDescriptor)
	for _, descriptor := range descriptors {
		if descriptor.conditionID != "" {
			conditionFields[descriptor.conditionID] = append(conditionFields[descriptor.conditionID], descriptor)
		}
	}
	result := make(familyConditionFacts, 0, len(conditionFields))
	for conditionID, fields := range conditionFields {
		state, err := inboundLogConditionState(conditionID, fields, provided, outcome)
		if err != nil {
			return nil, err
		}
		result = append(result, familyConditionFact{id: conditionID, state: state})
	}
	return result, nil
}

func inboundLogConditionState(
	conditionID string,
	fields []familyFieldDescriptor,
	provided map[string]any,
	outcome Optional[Outcome],
) (familyConditionState, error) {
	switch conditionID {
	case "operation-terminal-v1":
		value, present := outcome.Get()
		if present && value != OutcomeAttempted {
			return familyConditionTrue, nil
		}
		return familyConditionFalse, nil
	case "destination-test-failed-v1":
		if value, ok := provided["defenseclaw.destination.test.result"].(string); ok && value == "failed" {
			return familyConditionTrue, nil
		}
		return familyConditionFalse, nil
	case "agent-reported-cost-available-v1":
		if value, ok := provided["defenseclaw.agent.reported_cost.present"].(bool); ok && value {
			return familyConditionTrue, nil
		}
		return familyConditionFalse, nil
	}
	for _, field := range fields {
		if field.source == familyValueInput {
			if _, present := provided[field.key]; present {
				return familyConditionTrue, nil
			}
		}
	}
	// A future condition backed only by derived values needs an explicit closed
	// inference rule above; silently choosing false would weaken validation.
	for _, field := range fields {
		if field.source == familyValueInput {
			return familyConditionFalse, nil
		}
	}
	return familyConditionUnknown, familyBuildFailure(FamilyBuildInvalidDescriptor)
}
