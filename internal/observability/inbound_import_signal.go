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
	"unicode/utf8"
)

// InboundTraceEventTarget is an opaque event capability derived from the exact
// generated trace descriptor sealed in an InboundTarget. ID and Name expose
// read-only generated identity for typed mapping; callers cannot select an
// identity, family, field class, or untyped attribute surface.
type InboundTraceEventTarget struct {
	target     InboundTarget
	eventIndex int
}

func (target InboundTraceEventTarget) ID() string {
	_, event, _ := target.entry()
	return event.id
}

func (target InboundTraceEventTarget) Name() string {
	_, event, _ := target.entry()
	return event.name
}

// Fields returns the exact generated fields accepted by this event. Derived
// fields remain consistency-only and cannot be supplied as mapped values.
func (target InboundTraceEventTarget) Fields() []InboundTargetField {
	entry, event, ok := target.entry()
	if !ok {
		return nil
	}
	result := make([]InboundTargetField, len(event.fields))
	for index, descriptor := range event.fields {
		result[index] = inboundComponentField(
			entry.family, inboundTargetFieldScopeEvent, event.id, descriptor.key,
		)
	}
	return result
}

func (target InboundTraceEventTarget) entry() (inboundTargetEntry, familyEventContract, bool) {
	entry, ok := target.target.entry()
	if !ok || entry.signal != SignalTraces || nilInterface(entry.descriptor) {
		return inboundTargetEntry{}, familyEventContract{}, false
	}
	descriptor, ok := entry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return inboundTargetEntry{}, familyEventContract{}, false
	}
	contract := descriptor.familyTraceContract()
	if target.eventIndex < 0 || target.eventIndex >= len(contract.allowedEvents) {
		return inboundTargetEntry{}, familyEventContract{}, false
	}
	return entry, cloneFamilyEventContract(contract.allowedEvents[target.eventIndex]), true
}

// TraceResourceFields returns opaque capabilities for the generated trace
// resource's fixed input fields. Scope identity and its fields are generated
// constants and intentionally have no inbound caller capability.
func (target InboundTarget) TraceResourceFields() []InboundTargetField {
	entry, ok := target.entry()
	if !ok || entry.signal != SignalTraces || nilInterface(entry.descriptor) {
		return nil
	}
	descriptor, ok := entry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return nil
	}
	fields := descriptor.familyTraceContract().resourceFields
	result := make([]InboundTargetField, 0, len(fields))
	for _, field := range fields {
		if field.source == familyValueInput {
			result = append(result, inboundComponentField(
				entry.family, inboundTargetFieldScopeResource, "resource", field.key,
			))
		}
	}
	return result
}

// TraceEvents returns the complete exact generated event capability set for a
// trace target. Unsupported event names have no capability and cannot be built.
func (target InboundTarget) TraceEvents() []InboundTraceEventTarget {
	entry, ok := target.entry()
	if !ok || entry.signal != SignalTraces || nilInterface(entry.descriptor) {
		return nil
	}
	descriptor, ok := entry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return nil
	}
	events := descriptor.familyTraceContract().allowedEvents
	result := make([]InboundTraceEventTarget, len(events))
	for index := range result {
		result[index] = InboundTraceEventTarget{target: target, eventIndex: index}
	}
	return result
}

func inboundComponentField(
	family string,
	scope inboundTargetFieldScope,
	componentID, fieldRef string,
) InboundTargetField {
	return InboundTargetField{
		fieldRef:     fieldRef,
		descriptorID: "inbound:" + family + ":" + componentID + ":" + fieldRef,
		scope:        scope, componentID: componentID,
	}
}

// NewInboundTraceEvent constructs one exact generated event from already-mapped
// typed values. Unknown events, cross-family capabilities, raw maps, and caller
// selected classes are structurally absent from this API.
func NewInboundTraceEvent(
	target InboundTraceEventTarget,
	timeUnixNano uint64,
	droppedAttributesCount Optional[uint32],
	fields []InboundMappedField,
) (TraceEventInput, error) {
	entry, event, ok := target.entry()
	if !ok || timeUnixNano == 0 || timeUnixNano > math.MaxInt64 {
		return TraceEventInput{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	capabilities := target.Fields()
	values, provided, err := inboundMappedValues(capabilities, event.fields, fields)
	if err != nil {
		return TraceEventInput{}, err
	}
	conditions, err := inboundConditionFacts(event.fields, provided, Absent[Outcome]())
	if err != nil {
		return TraceEventInput{}, err
	}
	if entry.family == "" {
		return TraceEventInput{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return TraceEventInput{
		TimeUnixNano: timeUnixNano, DroppedAttributesCount: droppedAttributesCount,
		contract: event, values: values, conditions: conditions,
	}, nil
}

// InboundTraceLinkRelation is a closed generated relation capability. The four
// values are the only relations in the v8 trace registry.
type InboundTraceLinkRelation string

const (
	InboundTraceLinkCausedBy       InboundTraceLinkRelation = "caused_by"
	InboundTraceLinkResumes        InboundTraceLinkRelation = "resumes"
	InboundTraceLinkDerivedFrom    InboundTraceLinkRelation = "derived_from"
	InboundTraceLinkCorrelatesWith InboundTraceLinkRelation = "correlates_with"
)

// NewInboundTraceLink seals a link only when the selected relation belongs to
// the exact generated target descriptor. Link attributes are descriptor-derived;
// v8 currently exposes no caller-owned arbitrary link attribute map.
func NewInboundTraceLink(
	target InboundTarget,
	relation InboundTraceLinkRelation,
	traceID, spanID string,
	traceState Optional[string],
	droppedAttributesCount Optional[uint32],
) (TraceLinkInput, error) {
	entry, ok := target.entry()
	if !ok || entry.signal != SignalTraces || nilInterface(entry.descriptor) {
		return TraceLinkInput{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	descriptor, ok := entry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return TraceLinkInput{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	contract := descriptor.familyTraceContract()
	if !containsString(contract.allowedLinks, string(relation)) ||
		!validateOTelID(traceID, 32) || !validateOTelID(spanID, 16) {
		return TraceLinkInput{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	if state, present := traceState.Get(); present && !validW3CTraceState(state) {
		return TraceLinkInput{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	return TraceLinkInput{
		TraceID: strings.Clone(traceID), SpanID: strings.Clone(spanID),
		TraceState: traceState, DroppedAttributesCount: droppedAttributesCount,
		relation: string(relation),
	}, nil
}

// InboundTraceResourceInput carries only exact generated resource fields and a
// previously sealed generated custom-resource value. The schema URL is selected
// from the generated inbound wire contract, never by the receiver caller.
type InboundTraceResourceInput struct {
	DroppedAttributesCount Optional[uint32]
	Fields                 []InboundMappedField
	Custom                 Optional[TelemetryCustomResourceAttributes]
}

// InboundLocalTraceResource is a sealed target-specific projection of the
// generation-pinned local provider resource. Only generated target resource
// capabilities can enter it; callers cannot supply resource keys, classes, or
// descriptor requirements. External imports use it to establish the new local
// canonical process resource. Native exact imports must not carry it because
// their original registered semantic resource is preserved from the wire.
type InboundLocalTraceResource struct {
	targetSnapshot *inboundCatalogSnapshot
	targetIndex    int
	fields         []InboundMappedField
	custom         TelemetryCustomResourceAttributes
	present        bool
}

// NewInboundLocalTraceResource seals values already bound to generated
// resource-field capabilities. The runtime constructs this only from the exact
// V8ResourceContext pinned by the inbound request's provider generation.
func NewInboundLocalTraceResource(
	target InboundTarget,
	fields []InboundMappedField,
) (InboundLocalTraceResource, error) {
	return NewInboundLocalTraceResourceWithCustom(target, fields, TelemetryCustomResourceAttributes{})
}

// NewInboundLocalTraceResourceWithCustom seals the generated fixed projection
// and the already validated dynamic-resource projection from one provider
// snapshot. It is private receiver authority: neither set can select a family.
func NewInboundLocalTraceResourceWithCustom(
	target InboundTarget,
	fields []InboundMappedField,
	custom TelemetryCustomResourceAttributes,
) (InboundLocalTraceResource, error) {
	entry, ok := target.entry()
	if !ok || entry.signal != SignalTraces || entry.role != InboundTargetImport {
		return InboundLocalTraceResource{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	resourceCapabilities := target.TraceResourceFields()
	allowed := make(map[string]InboundTargetField, len(resourceCapabilities))
	for _, field := range resourceCapabilities {
		allowed[field.descriptorID] = field
	}
	seen := make(map[string]struct{}, len(fields))
	copyFields := make([]InboundMappedField, len(fields))
	for index, mapped := range fields {
		capability, exists := allowed[mapped.field.descriptorID]
		if !exists || mapped.field.scope != inboundTargetFieldScopeResource ||
			capability.fieldRef != mapped.field.fieldRef || capability.componentID != mapped.field.componentID {
			return InboundLocalTraceResource{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seen[mapped.field.descriptorID]; duplicate {
			return InboundLocalTraceResource{}, familyBuildFailure(FamilyBuildDuplicateField)
		}
		seen[mapped.field.descriptorID] = struct{}{}
		copyFields[index] = mapped
	}
	return InboundLocalTraceResource{
		targetSnapshot: target.snapshot, targetIndex: target.index,
		fields: copyFields, custom: custom, present: true,
	}, nil
}

func (resource InboundLocalTraceResource) validFor(target InboundTarget) bool {
	return resource.present && resource.targetSnapshot != nil &&
		resource.targetSnapshot == target.snapshot && resource.targetIndex == target.index
}

// InboundImportedTraceInput is the closed structural input for one already
// identified trace target. NativeSpanName is a consistency assertion required
// only for native exact shapes; it never selects the canonical span name.
type InboundImportedTraceInput struct {
	ReceiptTime            time.Time
	Correlation            Correlation
	Provenance             InboundLocalProvenanceInput
	Import                 InboundImportProvenanceInput
	Outcome                Optional[Outcome]
	Kind                   string
	NativeSpanName         Optional[string]
	StartTimeUnixNano      uint64
	EndTimeUnixNano        uint64
	ParentSpanID           Optional[string]
	TraceState             Optional[string]
	Flags                  uint32
	Status                 TraceStatusInput
	Resource               InboundTraceResourceInput
	LocalResource          InboundLocalTraceResource
	ScopeDroppedCount      Optional[uint32]
	Fields                 []InboundMappedField
	Events                 []TraceEventInput
	DroppedEventsCount     Optional[uint32]
	Links                  []TraceLinkInput
	DroppedLinksCount      Optional[uint32]
	DroppedAttributesCount Optional[uint32]
}

// inboundImportedTraceDescriptor is the import-only generated descriptor view
// after the sealed dynamic resource contract has materialized safe custom keys
// and compatibility aliases. It cannot change family identity or ordinary
// fields; it only carries descriptors returned by mergeFamilyTraceResource.
type inboundImportedTraceDescriptor struct{ contract familyTraceContract }

func (descriptor inboundImportedTraceDescriptor) familyDescriptorContract() familyDescriptorContract {
	return cloneFamilyDescriptorContract(descriptor.contract.familyDescriptorContract)
}

func (descriptor inboundImportedTraceDescriptor) familyTraceContract() familyTraceContract {
	return cloneFamilyTraceContract(descriptor.contract)
}

// BuildTrace constructs an ordinary imported canonical trace through the exact
// generated descriptor sealed into target. It does not route, persist, sample,
// or activate a gateway producer.
func (builder *InboundImportBuilder) BuildTrace(
	target InboundTarget,
	input InboundImportedTraceInput,
) (Record, error) {
	if builder == nil || builder.family == nil || !builder.family.ready() {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	targetEntry, match, err := resolveInboundSignalTargetCapability(
		target, input.Import.AuthenticatedSource, SignalTraces, InboundTargetImport,
	)
	if err != nil {
		return Record{}, err
	}
	descriptor, ok := targetEntry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	contract := cloneFamilyTraceContract(descriptor.familyTraceContract())
	if input.EndTimeUnixNano > math.MaxInt64 || input.StartTimeUnixNano > math.MaxInt64 {
		return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	selected := time.Unix(0, int64(input.EndTimeUnixNano)).UTC()
	if err := validateInboundImportTimes(selected, input.ReceiptTime); err != nil {
		return Record{}, err
	}
	if parent, present := input.ParentSpanID.Get(); present && parent == input.Correlation.SpanID {
		return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	values, provided, err := inboundMappedValues(targetEntry.fields, contract.fields, input.Fields)
	if err != nil {
		return Record{}, err
	}
	if err := validateInboundTraceOutcome(match.outcomeRule, input.Outcome, input.Status, provided); err != nil {
		return Record{}, err
	}
	resourceCapabilities := target.TraceResourceFields()
	resourceValues, resourceProvided, err := inboundMappedValues(
		resourceCapabilities, contract.resourceFields, input.Resource.Fields,
	)
	if err != nil {
		return Record{}, err
	}
	if match.shape == InboundShapeNativeExact {
		if input.LocalResource.present {
			return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
		}
	} else {
		if !input.LocalResource.validFor(target) {
			return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
		}
		localValues, localProvided, localErr := inboundMappedValues(
			resourceCapabilities, contract.resourceFields, input.LocalResource.fields,
		)
		if localErr != nil {
			return Record{}, localErr
		}
		resourceIndex := make(map[string]int, len(resourceValues))
		for index, value := range resourceValues {
			resourceIndex[value.key] = index
		}
		localByKey := make(map[string]familyFieldValue, len(localValues))
		for _, value := range localValues {
			localByKey[value.key] = value
		}
		// The pinned local provider owns required canonical process-resource
		// fields for a new external occurrence. Optional source fields are
		// preserved when present; otherwise local optional/custom fields fill
		// from the same generated descriptor.
		for _, descriptor := range contract.resourceFields {
			localValue, localPresent := localProvided[descriptor.key]
			if !localPresent {
				continue
			}
			_, sourcePresent := resourceProvided[descriptor.key]
			if descriptor.requirement == familyRequirementRequired || !sourcePresent {
				mapped := localByKey[descriptor.key]
				if index, exists := resourceIndex[descriptor.key]; exists {
					resourceValues[index] = mapped
				} else {
					resourceIndex[descriptor.key] = len(resourceValues)
					resourceValues = append(resourceValues, mapped)
				}
				resourceProvided[descriptor.key] = localValue
			}
		}
		localCustom := input.LocalResource.custom.Values()
		if sourceCustom, present := input.Resource.Custom.Get(); present {
			for key, value := range sourceCustom.Values() {
				// Source-declared safe custom values retain precedence; the
				// provider fills only keys absent from the source occurrence.
				localCustom[key] = value
			}
		}
		mergedCustom, mergeErr := NewTelemetryCustomResourceAttributes(
			localCustom,
			input.LocalResource.custom.CompatibilityAliasesEnabled(),
		)
		if mergeErr != nil {
			return Record{}, mergeErr
		}
		input.Resource.Custom = Present(mergedCustom)
	}
	allDescriptors := append([]familyFieldDescriptor(nil), contract.fields...)
	allDescriptors = append(allDescriptors, contract.resourceFields...)
	allProvided := make(map[string]any, len(provided)+len(resourceProvided))
	for key, value := range provided {
		allProvided[key] = value
	}
	for key, value := range resourceProvided {
		allProvided[key] = value
	}
	conditions, err := inboundConditionFacts(allDescriptors, allProvided, input.Outcome)
	if err != nil {
		return Record{}, err
	}
	for _, scopeField := range contract.scopeFields {
		if scopeField.source == familyValueInput {
			return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	}
	resource := TraceResourceInput{
		SchemaURL:              target.snapshot.wire.ResourceSchemaURL,
		DroppedAttributesCount: input.Resource.DroppedAttributesCount,
	}
	if custom, present := input.Resource.Custom.Get(); present {
		resource = WithTelemetryCustomResourceAttributes(resource, custom)
	}
	resource, dynamicResourceFields, err := mergeFamilyTraceResource(
		resource, resourceValues, generatedTelemetryResourceContract(),
	)
	if err != nil {
		return Record{}, err
	}
	contract.resourceFields = append(contract.resourceFields, dynamicResourceFields...)
	descriptor = inboundImportedTraceDescriptor{contract: contract}
	provenance := inboundImportProvenance(match, targetEntry.role, input.Import, Absent[uint64](), "")
	if err := validateInboundSignalImportProvenanceShape(SignalTraces, match, provenance); err != nil {
		return Record{}, err
	}
	if err := provenance.Validate(); err != nil {
		return Record{}, familyBuildFailure(FamilyBuildConstraint)
	}
	envelope := inboundFamilyEnvelope(input.ReceiptTime, input.Correlation, input.Provenance, input.Import)
	if err := validateInboundNativeTraceName(
		match, contract, envelope, input.Outcome, values, conditions, input.NativeSpanName,
	); err != nil {
		return Record{}, err
	}
	record, err := builder.family.buildGeneratedTrace(descriptor, familyTraceBuildInput{
		envelope: envelope, outcome: input.Outcome, kind: input.Kind,
		startTimeUnixNano: input.StartTimeUnixNano, endTimeUnixNano: input.EndTimeUnixNano,
		parentSpanID: input.ParentSpanID, traceState: input.TraceState, flags: input.Flags,
		status: input.Status, resource: resource,
		scope:  TraceScopeInput{DroppedAttributesCount: input.ScopeDroppedCount},
		values: values, conditions: conditions, events: append([]TraceEventInput(nil), input.Events...),
		droppedEventsCount: input.DroppedEventsCount, links: append([]TraceLinkInput(nil), input.Links...),
		droppedLinksCount: input.DroppedLinksCount, droppedAttributesCount: input.DroppedAttributesCount,
		timestamp: Present(selected), importProvenance: &provenance,
	})
	if err != nil {
		return Record{}, err
	}
	if record.Identity() != contract.identity || record.Mandatory() || record.IsFloorOnly() {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func validateInboundNativeTraceName(
	match inboundMatchEntry,
	contract familyTraceContract,
	envelope FamilyEnvelopeInput,
	outcome Optional[Outcome],
	values familyFieldValues,
	conditions familyConditionFacts,
	inbound Optional[string],
) error {
	if match.shape != InboundShapeNativeExact {
		if _, present := inbound.Get(); present {
			return familyBuildFailure(FamilyBuildInvalidTrace)
		}
		return nil
	}
	name, present := inbound.Get()
	if !present {
		return familyBuildFailure(FamilyBuildInvalidTrace)
	}
	context := familyContext(contract.familyDescriptorContract, envelope, outcome)
	context.traceSchemaVersion = contract.traceSchemaVersion
	context.semanticProfile = contract.semanticProfile
	attributes, _, err := materializeFamilyFields(
		contract.fields, values,
		selectFamilyConditionFacts(contract.fields, conditions), context,
	)
	if err != nil {
		return err
	}
	rendered, err := renderFamilySpanName(contract.spanName, attributes)
	if err != nil {
		return err
	}
	if name != rendered {
		return familyBuildFailure(FamilyBuildInvalidTrace)
	}
	return nil
}

// InboundMetricValue is a closed metric-number union. It has no generic number,
// JSON, or any arm, and the generated target descriptor selects the required arm.
type InboundMetricValue struct {
	kind   familyMetricNumberType
	int64  int64
	double float64
}

func NewInboundMetricInt64Value(value int64) InboundMetricValue {
	return InboundMetricValue{kind: familyMetricNumberInt64, int64: value}
}

func NewInboundMetricDoubleValue(value float64) InboundMetricValue {
	return InboundMetricValue{kind: familyMetricNumberDouble, double: value}
}

type inboundMetricSourceKind uint8

const (
	inboundMetricSourceInvalid inboundMetricSourceKind = iota
	inboundMetricSourceGauge
	inboundMetricSourceDeltaSum
	inboundMetricSourceCumulativeSum
	inboundMetricSourceCumulativeDelta
	inboundMetricSourceHistogramMean
	inboundMetricSourceMappedField
	inboundMetricSourceElapsedTime
)

// InboundMetricSourceFacts is a closed assertion about the classified source
// point. Native reversible imports accept only gauges or delta sums.
type InboundMetricSourceFacts struct {
	kind           inboundMetricSourceKind
	unit           string
	monotonic      bool
	aggregateCount uint64
}

func NewInboundMetricGaugeSource(unit string) InboundMetricSourceFacts {
	return InboundMetricSourceFacts{kind: inboundMetricSourceGauge, unit: strings.Clone(unit)}
}

func NewInboundMetricDeltaSumSource(unit string, monotonic bool) InboundMetricSourceFacts {
	return InboundMetricSourceFacts{
		kind: inboundMetricSourceDeltaSum, unit: strings.Clone(unit), monotonic: monotonic,
	}
}

// NewInboundMetricCumulativeSumSource describes a classified cumulative source
// sum. It is valid for direct duration bindings, but not for Claude token usage,
// whose stateful conversion must use NewInboundMetricCumulativeDeltaSource.
func NewInboundMetricCumulativeSumSource(unit string, monotonic bool) InboundMetricSourceFacts {
	return InboundMetricSourceFacts{
		kind: inboundMetricSourceCumulativeSum, unit: strings.Clone(unit), monotonic: monotonic,
	}
}

// NewInboundMetricCumulativeDeltaSource is the only arm that can produce
// cumulative_delta provenance. The receiver supplies the positive delta after
// applying the generated, bounded cumulative-series state contract.
func NewInboundMetricCumulativeDeltaSource(unit string) InboundMetricSourceFacts {
	return InboundMetricSourceFacts{
		kind: inboundMetricSourceCumulativeDelta, unit: strings.Clone(unit), monotonic: true,
	}
}

// NewInboundMetricHistogramMeanSource seals the source aggregate count used by
// the one explicit PR #412 arithmetic-mean derivation. No other source arm can
// attach this count to provenance.
func NewInboundMetricHistogramMeanSource(unit string, count uint64) InboundMetricSourceFacts {
	return InboundMetricSourceFacts{
		kind: inboundMetricSourceHistogramMean, unit: strings.Clone(unit), aggregateCount: count,
	}
}

func NewInboundMetricMappedFieldSource() InboundMetricSourceFacts {
	return InboundMetricSourceFacts{kind: inboundMetricSourceMappedField}
}

func NewInboundMetricElapsedTimeSource() InboundMetricSourceFacts {
	return InboundMetricSourceFacts{kind: inboundMetricSourceElapsedTime}
}

// InboundImportedMetricInput constructs one reversible native or exact derived
// point. Value is the source value (or the already state-differenced value for
// the cumulative-delta arm); generated unit scaling and histogram division run
// only inside BuildMetric.
type InboundImportedMetricInput struct {
	Timestamp   time.Time
	ReceiptTime time.Time
	Correlation Correlation
	Provenance  InboundLocalProvenanceInput
	Import      InboundImportProvenanceInput
	SourcePoint InboundMetricSourceFacts
	Value       InboundMetricValue
	Fields      []InboundMappedField
}

// BuildMetric constructs one exact reversible or derived metric observation.
func (builder *InboundImportBuilder) BuildMetric(
	target InboundTarget,
	input InboundImportedMetricInput,
) (Record, error) {
	if builder == nil || builder.family == nil || !builder.family.ready() {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	role := target.Role()
	if role != InboundTargetImport && role != InboundTargetDerive {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	targetEntry, match, err := resolveInboundSignalTargetCapability(
		target, input.Import.AuthenticatedSource, SignalMetrics, role,
	)
	if err != nil {
		return Record{}, err
	}
	descriptor, ok := targetEntry.descriptor.(generatedMetricFamilyContract)
	if !ok {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	contract := cloneFamilyMetricContract(descriptor.familyMetricContract())
	if err := validateInboundImportTimes(input.Timestamp, input.ReceiptTime); err != nil {
		return Record{}, err
	}
	pointNanos := input.Timestamp.UnixNano()
	if pointNanos <= 0 || !time.Unix(0, pointNanos).UTC().Equal(input.Timestamp.UTC()) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidMetric)
	}
	values, provided, err := inboundMappedValues(targetEntry.fields, contract.fields, input.Fields)
	if err != nil {
		return Record{}, err
	}
	conditions, err := inboundConditionFacts(contract.fields, provided, Absent[Outcome]())
	if err != nil {
		return Record{}, err
	}
	number, derivation, aggregateCount, err := inboundMetricNumberAndDerivation(
		contract, targetEntry, match, input.SourcePoint, input.Value,
	)
	if err != nil {
		return Record{}, err
	}
	provenance := inboundImportProvenance(
		match, targetEntry.role, input.Import, aggregateCount, derivation,
	)
	if err := validateInboundSignalImportProvenanceShape(SignalMetrics, match, provenance); err != nil {
		return Record{}, err
	}
	if err := provenance.Validate(); err != nil {
		return Record{}, familyBuildFailure(FamilyBuildConstraint)
	}
	envelope := inboundFamilyEnvelope(input.ReceiptTime, input.Correlation, input.Provenance, input.Import)
	record, err := builder.family.buildGeneratedMetric(descriptor, familyMetricBuildInput{
		envelope: envelope, value: number, labels: values, conditions: conditions,
		timestamp: Present(input.Timestamp), importProvenance: &provenance,
	})
	if err != nil {
		return Record{}, err
	}
	if record.Identity() != contract.identity || record.Mandatory() || record.IsFloorOnly() {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func inboundMetricNumberAndDerivation(
	contract familyMetricContract,
	target inboundTargetEntry,
	match inboundMatchEntry,
	source InboundMetricSourceFacts,
	value InboundMetricValue,
) (familyMetricNumber, ImportDerivation, Optional[uint64], error) {
	if contract.instrumentName != target.instrumentName || contract.instrumentType != target.instrumentType ||
		contract.unit != target.instrumentUnit {
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if target.role == InboundTargetImport {
		if match.shape != InboundShapeNativeExact || match.signal != SignalMetrics ||
			target.mappingStrategy != InboundMappingReverseMetric ||
			target.derivationStrategy != InboundDerivationNone ||
			validateInboundNativeMetricSource(contract, match, source) != nil {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
		}
		number, err := inboundMetricNumberExact(value)
		return number, "", Absent[uint64](), err
	}
	if target.role != InboundTargetDerive || match.shape != InboundShapeExternal {
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if contract.valueType == familyMetricNumberInt64 {
		if target.derivationStrategy != InboundDerivationCodexTokenFields ||
			match.signal != SignalLogs || target.mappingStrategy != InboundMappingConnectorModelLog ||
			target.sourceUnitRule.kind != InboundSourceUnitNone ||
			!reflect.DeepEqual(target.sourceUnitRule, match.sourceUnitRule) ||
			source.kind != inboundMetricSourceMappedField || source.unit != "" || source.aggregateCount != 0 ||
			value.kind != familyMetricNumberInt64 || value.int64 <= 0 {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
		}
		return familyInt64MetricNumber(value.int64), ImportDerivationFieldValue,
			Absent[uint64](), nil
	}
	if contract.valueType != familyMetricNumberDouble {
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	raw, err := inboundMetricValueAsDouble(value)
	if err != nil || raw <= 0 {
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
	}
	derivation := ImportDerivation("")
	aggregateCount := Absent[uint64]()
	scale := 1.0
	switch target.derivationStrategy {
	case InboundDerivationFieldValue, InboundDerivationCodexTokenFields:
		if match.signal != SignalLogs || target.mappingStrategy != InboundMappingConnectorModelLog ||
			target.sourceUnitRule.kind != InboundSourceUnitNone ||
			!reflect.DeepEqual(target.sourceUnitRule, match.sourceUnitRule) ||
			source.kind != inboundMetricSourceMappedField ||
			source.unit != "" || source.aggregateCount != 0 {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
		}
		derivation = ImportDerivationFieldValue
	case InboundDerivationElapsedTime:
		if match.signal != SignalTraces || target.mappingStrategy != InboundMappingStandardGenAISpan ||
			target.sourceUnitRule.kind != InboundSourceUnitNone ||
			!reflect.DeepEqual(target.sourceUnitRule, match.sourceUnitRule) ||
			source.kind != inboundMetricSourceElapsedTime ||
			source.unit != "" || source.aggregateCount != 0 {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
		}
		derivation = ImportDerivationElapsedTime
	case InboundDerivationClaudeTokenUsage:
		if match.signal != SignalMetrics || target.mappingStrategy != InboundMappingClaudeTokenUsage {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		scale, err = inboundMetricSourceScale(target, match, source, "gauge", "sum", "histogram")
		if err != nil {
			return familyMetricNumber{}, "", Absent[uint64](), err
		}
		switch source.kind {
		case inboundMetricSourceGauge, inboundMetricSourceDeltaSum:
			derivation = ImportDerivationFieldValue
		case inboundMetricSourceCumulativeDelta:
			derivation = ImportDerivationCumulativeDelta
		case inboundMetricSourceHistogramMean:
			if source.aggregateCount == 0 {
				return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
			}
			raw /= float64(source.aggregateCount)
			derivation = ImportDerivationArithmeticMean
			aggregateCount = Present(source.aggregateCount)
		default:
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
		}
	case InboundDerivationDurationMetric:
		if match.signal != SignalMetrics || target.mappingStrategy != InboundMappingDurationMetric {
			return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		scale, err = inboundMetricSourceScale(target, match, source, "gauge", "sum", "histogram")
		if err != nil {
			return familyMetricNumber{}, "", Absent[uint64](), err
		}
		if source.kind == inboundMetricSourceHistogramMean {
			if source.aggregateCount == 0 {
				return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
			}
			raw /= float64(source.aggregateCount)
			derivation = ImportDerivationArithmeticMean
			aggregateCount = Present(source.aggregateCount)
		} else {
			switch source.kind {
			case inboundMetricSourceGauge, inboundMetricSourceDeltaSum, inboundMetricSourceCumulativeSum:
				derivation = ImportDerivationFieldValue
			default:
				return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
			}
		}
	default:
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	normalized := raw * scale
	if math.IsNaN(normalized) || math.IsInf(normalized, 0) || normalized <= 0 {
		return familyMetricNumber{}, "", Absent[uint64](), familyBuildFailure(FamilyBuildInvalidMetric)
	}
	return familyDoubleMetricNumber(normalized), derivation, aggregateCount, nil
}

func inboundMetricNumberExact(value InboundMetricValue) (familyMetricNumber, error) {
	switch value.kind {
	case familyMetricNumberInt64:
		return familyInt64MetricNumber(value.int64), nil
	case familyMetricNumberDouble:
		if math.IsNaN(value.double) || math.IsInf(value.double, 0) {
			return familyMetricNumber{}, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		return familyDoubleMetricNumber(value.double), nil
	default:
		return familyMetricNumber{}, familyBuildFailure(FamilyBuildInvalidMetric)
	}
}

func inboundMetricValueAsDouble(value InboundMetricValue) (float64, error) {
	switch value.kind {
	case familyMetricNumberInt64:
		if value.int64 > 1<<53 || value.int64 < -(1<<53) {
			return 0, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		return float64(value.int64), nil
	case familyMetricNumberDouble:
		if math.IsNaN(value.double) || math.IsInf(value.double, 0) {
			return 0, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		return value.double, nil
	default:
		return 0, familyBuildFailure(FamilyBuildInvalidMetric)
	}
}

func inboundMetricSourceScale(
	target inboundTargetEntry,
	match inboundMatchEntry,
	source InboundMetricSourceFacts,
	allowedShapes ...string,
) (float64, error) {
	shape := ""
	switch source.kind {
	case inboundMetricSourceGauge:
		if source.monotonic || source.aggregateCount != 0 {
			return 0, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		shape = "gauge"
	case inboundMetricSourceDeltaSum, inboundMetricSourceCumulativeSum,
		inboundMetricSourceCumulativeDelta:
		if source.aggregateCount != 0 {
			return 0, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		shape = "sum"
	case inboundMetricSourceHistogramMean:
		if source.aggregateCount == 0 || source.monotonic {
			return 0, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		shape = "histogram"
	default:
		return 0, familyBuildFailure(FamilyBuildInvalidMetric)
	}
	if !containsString(allowedShapes, shape) || !inboundMetricMatchAllowsShape(match, shape) {
		return 0, familyBuildFailure(FamilyBuildInvalidMetric)
	}
	if target.sourceUnitRule.kind != InboundSourceUnitScaleTable ||
		target.sourceUnitRule.targetUnit != target.instrumentUnit ||
		!reflect.DeepEqual(target.sourceUnitRule, match.sourceUnitRule) {
		return 0, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	for _, accepted := range target.sourceUnitRule.accepted {
		if accepted.sourceUnit == source.unit {
			return accepted.scale, nil
		}
	}
	return 0, familyBuildFailure(FamilyBuildInvalidMetric)
}

func inboundMetricMatchAllowsShape(match inboundMatchEntry, want string) bool {
	for _, predicate := range match.predicates {
		if predicate.location != InboundLocationMetricPoint || predicate.key != "$point_shape" {
			continue
		}
		for _, value := range predicate.values {
			if actual, ok := value.StringValue(); ok && actual == want {
				return true
			}
		}
		return false
	}
	return false
}

func validateInboundNativeMetricSource(
	contract familyMetricContract,
	match inboundMatchEntry,
	source InboundMetricSourceFacts,
) error {
	if source.unit != contract.unit || !utf8.ValidString(source.unit) || len(source.unit) > 128 ||
		match.sourceUnitRule.kind != InboundSourceUnitTargetEquality ||
		match.sourceUnitRule.targetUnit != contract.unit ||
		len(match.sourceUnitRule.accepted) != 1 ||
		match.sourceUnitRule.accepted[0].sourceUnit != contract.unit ||
		match.sourceUnitRule.accepted[0].scale != 1 {
		return familyBuildFailure(FamilyBuildInvalidMetric)
	}
	wantShape := ""
	switch source.kind {
	case inboundMetricSourceGauge:
		if source.monotonic || contract.instrumentType != "gauge" || contract.temporality != "unspecified" {
			return familyBuildFailure(FamilyBuildInvalidMetric)
		}
		wantShape = "gauge"
	case inboundMetricSourceDeltaSum:
		if contract.temporality != "delta" ||
			source.monotonic && contract.instrumentType != "counter" ||
			!source.monotonic && contract.instrumentType != "updowncounter" {
			return familyBuildFailure(FamilyBuildInvalidMetric)
		}
		wantShape = "sum_delta"
		if source.monotonic {
			wantShape = "sum_delta_monotonic"
		}
	default:
		return familyBuildFailure(FamilyBuildInvalidMetric)
	}
	for _, predicate := range match.predicates {
		if predicate.location != InboundLocationMetricPoint || predicate.key != "$point_shape" {
			continue
		}
		for _, value := range predicate.values {
			if actual, ok := value.StringValue(); ok && actual == wantShape {
				return nil
			}
		}
		return familyBuildFailure(FamilyBuildInvalidMetric)
	}
	return familyBuildFailure(FamilyBuildInvalidDescriptor)
}

func resolveInboundSignalTargetCapability(
	target InboundTarget,
	authenticatedSource string,
	signal Signal,
	role InboundTargetRole,
) (inboundTargetEntry, inboundMatchEntry, error) {
	entry, ok := target.entry()
	if !ok || target.snapshot == nil || entry.signal != signal || entry.role != role ||
		entry.matchIndex < 0 || entry.matchIndex >= len(target.snapshot.matches) ||
		nilInterface(entry.descriptor) || !IsStableToken(authenticatedSource) ||
		authenticatedSource == "any_authenticated" {
		return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	match := target.snapshot.matches[entry.matchIndex]
	bound := false
	for _, index := range match.targetIndexes {
		if index == target.index {
			bound = true
			break
		}
	}
	if !bound || !inboundSourceApplies(match.sources, authenticatedSource) ||
		!IsStableToken(match.id) || match.shape == InboundShapeNativeMalformed {
		return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	base := cloneFamilyDescriptorContract(entry.descriptor.familyDescriptorContract())
	if base.id != entry.family || base.identity.Signal != signal ||
		base.identity.Bucket != entry.bucket || base.identity.Name != entry.eventName ||
		base.familySchemaVersion != entry.familySchemaVersion {
		return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	switch signal {
	case SignalTraces:
		descriptor, exact := entry.descriptor.(generatedTraceFamilyContract)
		if !exact || validateFamilyTraceContract(descriptor.familyTraceContract()) != nil {
			return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case SignalMetrics:
		descriptor, exact := entry.descriptor.(generatedMetricFamilyContract)
		if !exact || validateFamilyMetricContract(descriptor.familyMetricContract()) != nil {
			return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	default:
		return inboundTargetEntry{}, inboundMatchEntry{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return entry, match, nil
}

func inboundMappedValues(
	capabilities []InboundTargetField,
	descriptors []familyFieldDescriptor,
	mapped []InboundMappedField,
) (familyFieldValues, map[string]any, error) {
	allowed := make(map[string]InboundTargetField, len(capabilities))
	for _, capability := range capabilities {
		allowed[capability.descriptorID] = capability
	}
	byKey := make(map[string]familyFieldDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		byKey[descriptor.key] = descriptor
	}
	values := make(familyFieldValues, 0, len(mapped))
	provided := make(map[string]any, len(mapped))
	for _, field := range mapped {
		capability, exists := allowed[field.field.descriptorID]
		if !exists || capability.fieldRef != field.field.fieldRef ||
			capability.scope != field.field.scope || capability.componentID != field.field.componentID ||
			field.field.fieldRef == "" {
			return nil, nil, familyBuildFailure(FamilyBuildUnknownField)
		}
		descriptor, exists := byKey[capability.fieldRef]
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
	return values, provided, nil
}

func inboundConditionFacts(
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
		if conditionID == "telemetry-canary-enabled-v1" {
			state = familyConditionFalse
			if value, ok := provided["defenseclaw.telemetry.canary"].(bool); ok && value {
				state = familyConditionTrue
			}
		}
		result = append(result, familyConditionFact{id: conditionID, state: state})
	}
	return result, nil
}

func validateInboundTraceOutcome(
	rule InboundOutcomeRule,
	outcome Optional[Outcome],
	status TraceStatusInput,
	provided map[string]any,
) error {
	value, present := outcome.Get()
	switch rule.kind {
	case InboundOutcomeForbidden:
		if present {
			return familyBuildFailure(FamilyBuildInvalidOutcome)
		}
	case InboundOutcomeFixed:
		if !present || value != rule.fixed {
			return familyBuildFailure(FamilyBuildInvalidOutcome)
		}
	case InboundOutcomeNativeSpan:
		if !present || !IsOutcome(value) {
			return familyBuildFailure(FamilyBuildInvalidOutcome)
		}
	case InboundOutcomeOTelStatus:
		errorType, _ := provided["error.type"].(string)
		var expected Outcome
		switch {
		case errorType == "policy_denied":
			expected = OutcomeDenied
		case status.Code() == TraceStatusError:
			expected = OutcomeFailed
		case errorType == "" && (status.Code() == TraceStatusOK || status.Code() == TraceStatusUnset):
			expected = OutcomeCompleted
		default:
			return familyBuildFailure(FamilyBuildInvalidOutcome)
		}
		if !present || value != expected {
			return familyBuildFailure(FamilyBuildInvalidOutcome)
		}
	default:
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return nil
}

func inboundImportProvenance(
	match inboundMatchEntry,
	role InboundTargetRole,
	input InboundImportProvenanceInput,
	aggregateCount Optional[uint64],
	derivation ImportDerivation,
) ImportProvenance {
	mode := ImportModeImport
	if role == InboundTargetDerive {
		mode = ImportModeDerive
	}
	return ImportProvenance{
		Protocol: ImportProtocolOTLP, BindingID: match.id, Mode: mode,
		Derivation: derivation, SourceAggregateCount: aggregateCount,
		AuthenticatedSource:      input.AuthenticatedSource,
		UpstreamInstanceID:       input.UpstreamInstanceID,
		UpstreamRecordID:         input.UpstreamRecordID,
		UpstreamServiceName:      input.UpstreamServiceName,
		UpstreamRedactionProfile: input.UpstreamRedactionProfile,
		IngressHopCount:          input.IngressHopCount,
		LastHopInstanceID:        input.LastHopInstanceID,
		LastHopDestination:       input.LastHopDestination,
	}
}

func inboundFamilyEnvelope(
	receipt time.Time,
	correlation Correlation,
	local InboundLocalProvenanceInput,
	importInput InboundImportProvenanceInput,
) FamilyEnvelopeInput {
	return FamilyEnvelopeInput{
		ObservedAt: Present(receipt), Source: SourceOTelReceiver,
		Connector: importInput.AuthenticatedSource, Correlation: correlation,
		Provenance: FamilyProvenanceInput{
			Producer: inboundImportProducer, BinaryVersion: local.BinaryVersion,
			ConfigGeneration: local.ConfigGeneration,
			BuildCommit:      local.BuildCommit, ConfigDigest: local.ConfigDigest,
		},
	}
}

func validateInboundSignalImportProvenanceShape(
	signal Signal,
	match inboundMatchEntry,
	provenance ImportProvenance,
) error {
	switch match.shape {
	case InboundShapeNativeExact:
		if provenance.UpstreamInstanceID == "" || provenance.LastHopInstanceID == "" ||
			provenance.LastHopDestination == "" || provenance.IngressHopCount == 0 {
			return familyBuildFailure(FamilyBuildConstraint)
		}
		if signal == SignalLogs && provenance.UpstreamRecordID == "" {
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

// MappedValueKind also recognizes exact resource/event capabilities derived
// from a generated trace descriptor. It never accepts a forged placement.
func (target InboundTarget) inboundComponentMappedValueKind(field InboundTargetField) (InboundMappedValueKind, bool) {
	entry, ok := target.entry()
	if !ok || entry.signal != SignalTraces || nilInterface(entry.descriptor) {
		return InboundMappedValueInvalid, false
	}
	descriptor, ok := entry.descriptor.(generatedTraceFamilyContract)
	if !ok {
		return InboundMappedValueInvalid, false
	}
	contract := descriptor.familyTraceContract()
	var descriptors []familyFieldDescriptor
	switch field.scope {
	case inboundTargetFieldScopeResource:
		if field.componentID != "resource" {
			return InboundMappedValueInvalid, false
		}
		descriptors = contract.resourceFields
	case inboundTargetFieldScopeEvent:
		for _, event := range contract.allowedEvents {
			if event.id == field.componentID {
				descriptors = event.fields
				break
			}
		}
	default:
		return InboundMappedValueInvalid, false
	}
	expectedID := inboundComponentField(entry.family, field.scope, field.componentID, field.fieldRef).descriptorID
	if expectedID != field.descriptorID {
		return InboundMappedValueInvalid, false
	}
	for _, candidate := range descriptors {
		if candidate.key == field.fieldRef && candidate.source == familyValueInput {
			kind := inboundMappedKindForFamilyField(candidate)
			return kind, kind != InboundMappedValueInvalid
		}
	}
	return InboundMappedValueInvalid, false
}
