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
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"go.opentelemetry.io/otel/trace"
)

const (
	maxFamilyTraceEvents = 128
	maxFamilyTraceLinks  = 64
)

// FamilyBuilder is the stateless package-local target for generated family
// methods. Generated wrappers expose typed family inputs and translate them into
// the private build forms below. The kernel owns all identity, schema, mandatory,
// field-class, span-name, and metric-instrument state.
type FamilyBuilder struct {
	clock       Clock
	idGenerator OccurrenceIDGenerator
}

func NewFamilyBuilder(clock Clock, idGenerator OccurrenceIDGenerator) (*FamilyBuilder, error) {
	if nilInterface(clock) || nilInterface(idGenerator) {
		return nil, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	return &FamilyBuilder{clock: clock, idGenerator: idGenerator}, nil
}

type resolvedSchemaDerivedLogFamilyContract struct {
	identity  EventIdentity
	mandatory bool
}

// resolvedGeneratedLogContract is the package-private bridge between generated
// mandatory programs and the schema-derived record constructor. Generated
// wrappers resolve their typed mandatory facts to one boolean and seal it here;
// no caller-visible input can provide a raw mandatory result.
type resolvedGeneratedLogContract struct {
	mandatory   bool
	initialized bool
}

func resolveGeneratedLogMandatory(mandatory bool) resolvedGeneratedLogContract {
	return resolvedGeneratedLogContract{mandatory: mandatory, initialized: true}
}

func (contract resolvedSchemaDerivedLogFamilyContract) schemaDerivedLogIdentity() EventIdentity {
	return contract.identity
}

func (contract resolvedSchemaDerivedLogFamilyContract) schemaDerivedLogMandatory() bool {
	return contract.mandatory
}

func (builder *FamilyBuilder) buildGeneratedLog(
	descriptor generatedLogFamilyContract,
	input familyLogBuildInput,
) (Record, error) {
	if !builder.ready() || nilInterface(descriptor) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	contract := cloneFamilyDescriptorContract(descriptor.familyDescriptorContract())
	if err := validateFamilyDescriptor(contract, familySignalLog); err != nil {
		return Record{}, err
	}
	resolvedIdentity := descriptor.schemaDerivedLogIdentity()
	if resolvedIdentity != contract.identity || resolvedIdentity.Signal != SignalLogs {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return builder.buildResolvedGeneratedLog(
		contract,
		resolveGeneratedLogMandatory(descriptor.schemaDerivedLogMandatory()),
		input,
	)
}

// buildGeneratedResolvedLog is the private entry point used by generated
// wrappers whose mandatory value is computed from compiler-owned typed facts.
// The legacy generatedLogFamilyContract adapter above remains until generated
// descriptors replace the handwritten compatibility witnesses.
func (builder *FamilyBuilder) buildGeneratedResolvedLog(
	descriptor familyDescriptor,
	resolved resolvedGeneratedLogContract,
	input familyLogBuildInput,
) (Record, error) {
	if !builder.ready() || nilInterface(descriptor) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	return builder.buildResolvedGeneratedLog(
		cloneFamilyDescriptorContract(descriptor.familyDescriptorContract()),
		resolved,
		input,
	)
}

func (builder *FamilyBuilder) buildResolvedGeneratedLog(
	contract familyDescriptorContract,
	resolved resolvedGeneratedLogContract,
	input familyLogBuildInput,
) (Record, error) {
	if !resolved.initialized {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if err := validateFamilyDescriptor(contract, familySignalLog); err != nil {
		return Record{}, err
	}
	if err := validateFamilyEnvelope(input.envelope); err != nil {
		return Record{}, err
	}
	if err := validateFamilyOutcome(contract.outcome, input.outcome); err != nil {
		return Record{}, err
	}
	severity, logLevel, err := validateFamilyLogState(input.severity, input.logLevel)
	if err != nil {
		return Record{}, err
	}
	context := familyContext(contract, input.envelope, input.outcome)
	body, classes, err := materializeFamilyFields(contract.fields, input.values, input.conditions, context)
	if err != nil {
		return Record{}, err
	}
	if err := validateFamilyCrossFieldValues(contract.crossFieldRelations, body); err != nil {
		return Record{}, err
	}
	if err := verifyFamilyFieldClassCoverage(body, classes); err != nil {
		return Record{}, err
	}
	recordInput := familyRecordInput(input.envelope, contract.identity)
	if input.importProvenance != nil {
		recordInput.Provenance.Import = cloneImportProvenance(input.importProvenance)
	}
	recordInput.Severity = severity
	recordInput.LogLevel = logLevel
	if outcome, present := input.outcome.Get(); present {
		recordInput.Outcome = outcome
	}
	recordInput.Body = body
	recordInput.FieldClasses = classes
	resolvedContract := resolvedSchemaDerivedLogFamilyContract{
		identity: contract.identity, mandatory: resolved.mandatory,
	}
	if err := preflightGeneratedLogRecord(recordInput, resolvedContract); err != nil {
		return Record{}, err
	}
	recordInput, err = builder.recordInputAt(recordInput, input.timestamp)
	if err != nil {
		return Record{}, err
	}
	record, err := newSchemaDerivedLogRecord(recordInput, resolvedContract)
	if err != nil {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func (builder *FamilyBuilder) buildGeneratedTrace(
	descriptor generatedTraceFamilyContract,
	input familyTraceBuildInput,
) (Record, error) {
	if !builder.ready() || nilInterface(descriptor) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	contract := cloneFamilyTraceContract(descriptor.familyTraceContract())
	base := cloneFamilyDescriptorContract(descriptor.familyDescriptorContract())
	if !reflect.DeepEqual(base, contract.familyDescriptorContract) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if err := validateFamilyTraceContract(contract); err != nil {
		return Record{}, err
	}
	if err := validateFamilyEnvelope(input.envelope); err != nil {
		return Record{}, err
	}
	if err := validateFamilyOutcome(base.outcome, input.outcome); err != nil {
		return Record{}, err
	}
	if !containsString(contract.allowedKinds, input.kind) ||
		input.startTimeUnixNano == 0 || input.endTimeUnixNano == 0 ||
		input.startTimeUnixNano > input.endTimeUnixNano ||
		!validateOTelID(input.envelope.Correlation.TraceID, 32) ||
		!validateOTelID(input.envelope.Correlation.SpanID, 16) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	if parent, present := input.parentSpanID.Get(); present && !validateOTelID(parent, 16) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	if traceState, present := input.traceState.Get(); present && !validW3CTraceState(traceState) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	if err := validateTraceStatus(input.status); err != nil {
		return Record{}, err
	}
	activeConditions, err := activeFamilyTraceConditionFacts(contract, input)
	if err != nil {
		return Record{}, err
	}
	context := familyContext(base, input.envelope, input.outcome)
	context.traceSchemaVersion = contract.traceSchemaVersion
	context.semanticProfile = contract.semanticProfile
	attributes, attributeClasses, err := materializeFamilyFields(
		contract.fields,
		input.values,
		selectFamilyConditionFacts(contract.fields, activeConditions),
		context,
	)
	if err != nil {
		return Record{}, err
	}
	if err := validateFamilyCrossFieldValues(base.crossFieldRelations, attributes); err != nil {
		return Record{}, err
	}
	if err := validateFamilyStructuredValue(attributes, contract.attributeLimits); err != nil {
		return Record{}, err
	}
	spanName, err := renderFamilySpanName(contract.spanName, attributes)
	if err != nil {
		return Record{}, err
	}
	resource, resourceClasses, err := buildFamilyTraceResource(contract, input, context, activeConditions)
	if err != nil {
		return Record{}, err
	}
	scope, scopeClasses, err := buildFamilyTraceScope(contract, input, context, activeConditions)
	if err != nil {
		return Record{}, err
	}
	events, eventClasses, err := buildFamilyTraceEvents(contract, input, context, activeConditions)
	if err != nil {
		return Record{}, err
	}
	links, linkClasses, err := buildFamilyTraceLinks(contract, input, context, activeConditions)
	if err != nil {
		return Record{}, err
	}

	body := map[string]any{
		"kind":                 input.kind,
		"start_time_unix_nano": input.startTimeUnixNano,
		"end_time_unix_nano":   input.endTimeUnixNano,
		"flags":                input.flags,
		"status":               familyTraceStatusObject(input.status),
		"resource":             resource,
		"scope":                scope,
		"attributes":           attributes,
	}
	if parent, present := input.parentSpanID.Get(); present {
		body["parent_span_id"] = parent
	}
	if traceState, present := input.traceState.Get(); present {
		body["trace_state"] = traceState
	}
	if count, present := input.droppedAttributesCount.Get(); present {
		body["dropped_attributes_count"] = count
	}
	if events != nil {
		body["events"] = events
	}
	if count, present := input.droppedEventsCount.Get(); present {
		body["dropped_events_count"] = count
	}
	if links != nil {
		body["links"] = links
	}
	if count, present := input.droppedLinksCount.Get(); present {
		body["dropped_links_count"] = count
	}
	classes := make(map[string]FieldClass)
	classes["/kind"] = FieldClassMetadata
	classes["/start_time_unix_nano"] = FieldClassMetadata
	classes["/end_time_unix_nano"] = FieldClassMetadata
	classes["/flags"] = FieldClassMetadata
	classes["/status/code"] = FieldClassMetadata
	if _, present := input.status.Description(); present {
		classes["/status/description"] = FieldClassError
	}
	if _, present := input.parentSpanID.Get(); present {
		classes["/parent_span_id"] = FieldClassIdentifier
	}
	if _, present := input.traceState.Get(); present {
		classes["/trace_state"] = FieldClassMetadata
	}
	for _, pointer := range []string{
		"/dropped_attributes_count", "/dropped_events_count", "/dropped_links_count",
	} {
		if _, present := body[strings.TrimPrefix(pointer, "/")]; present {
			classes[pointer] = FieldClassMetadata
		}
	}
	mergeFamilyClasses(classes, "/attributes", attributes, attributeClasses, FieldClassMetadata)
	mergePrefixedFamilyClasses(classes, "/resource", resourceClasses)
	mergePrefixedFamilyClasses(classes, "/scope", scopeClasses)
	if events != nil && len(events) == 0 {
		classes["/events"] = FieldClassMetadata
	}
	mergePrefixedFamilyClasses(classes, "", eventClasses)
	if links != nil && len(links) == 0 {
		classes["/links"] = FieldClassMetadata
	}
	mergePrefixedFamilyClasses(classes, "", linkClasses)
	if err := verifyFamilyFieldClassCoverage(body, classes); err != nil {
		return Record{}, err
	}
	recordInput := familyRecordInput(input.envelope, base.identity)
	if input.importProvenance != nil {
		recordInput.Provenance.Import = cloneImportProvenance(input.importProvenance)
	}
	recordInput.SpanName = spanName
	if outcome, present := input.outcome.Get(); present {
		recordInput.Outcome = outcome
	}
	recordInput.Body = body
	recordInput.FieldClasses = classes
	if err := preflightGeneratedRecord(recordInput); err != nil {
		return Record{}, err
	}
	recordInput, err = builder.recordInputAt(recordInput, input.timestamp)
	if err != nil {
		return Record{}, err
	}
	record, err := newSchemaDerivedRecord(recordInput)
	if err != nil {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func activeFamilyTraceConditionFacts(
	contract familyTraceContract,
	input familyTraceBuildInput,
) (familyConditionFacts, error) {
	if len(input.events) > contract.maxEvents || len(input.links) > contract.maxLinks {
		return nil, familyBuildFailure(FamilyBuildConstraint)
	}
	familyFields := append([]familyFieldDescriptor(nil), contract.fields...)
	familyFields = append(familyFields, contract.resourceFields...)
	familyFields = append(familyFields, contract.scopeFields...)
	if _, err := validatedConditionStates(familyFields, input.conditions); err != nil {
		return nil, err
	}
	merged := append(familyConditionFacts(nil), input.conditions...)
	for _, eventInput := range input.events {
		allowed, ok := findFamilyEvent(contract.allowedEvents, eventInput.contract.id)
		if !ok || !reflect.DeepEqual(cloneFamilyEventContract(eventInput.contract), allowed) ||
			eventInput.TimeUnixNano == 0 {
			return nil, familyBuildFailure(FamilyBuildInvalidTrace)
		}
		if _, err := validatedConditionStates(allowed.fields, eventInput.conditions); err != nil {
			return nil, err
		}
		var err error
		merged, err = mergeFamilyConditionFacts(merged, eventInput.conditions)
		if err != nil {
			return nil, err
		}
	}
	if len(input.links) != 0 {
		for _, linkInput := range input.links {
			if !validateOTelID(linkInput.TraceID, 32) || !validateOTelID(linkInput.SpanID, 16) ||
				!containsString(contract.allowedLinks, linkInput.relation) {
				return nil, familyBuildFailure(FamilyBuildInvalidTrace)
			}
			if traceState, present := linkInput.TraceState.Get(); present && !validW3CTraceState(traceState) {
				return nil, familyBuildFailure(FamilyBuildInvalidTrace)
			}
			if _, err := validatedConditionStates(contract.linkFields, linkInput.conditions); err != nil {
				return nil, err
			}
			var err error
			merged, err = mergeFamilyConditionFacts(merged, linkInput.conditions)
			if err != nil {
				return nil, err
			}
		}
	}
	return merged, nil
}

func mergeFamilyConditionFacts(
	merged familyConditionFacts,
	component familyConditionFacts,
) (familyConditionFacts, error) {
	states := make(map[string]familyConditionState, len(merged)+len(component))
	for _, fact := range merged {
		states[fact.id] = fact.state
	}
	for _, fact := range component {
		if state, exists := states[fact.id]; exists {
			if state != fact.state {
				return nil, familyBuildFailure(FamilyBuildInvalidCondition)
			}
			continue
		}
		states[fact.id] = fact.state
		merged = append(merged, fact)
	}
	return merged, nil
}

func (builder *FamilyBuilder) buildGeneratedMetric(
	descriptor generatedMetricFamilyContract,
	input familyMetricBuildInput,
) (Record, error) {
	if !builder.ready() || nilInterface(descriptor) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDependency)
	}
	contract := cloneFamilyMetricContract(descriptor.familyMetricContract())
	base := cloneFamilyDescriptorContract(descriptor.familyDescriptorContract())
	if !reflect.DeepEqual(base, contract.familyDescriptorContract) {
		return Record{}, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if err := validateFamilyMetricContract(contract); err != nil {
		return Record{}, err
	}
	if err := validateFamilyEnvelope(input.envelope); err != nil {
		return Record{}, err
	}
	value, err := resolvedFamilyMetricNumber(contract.valueType, input.value)
	if err != nil {
		return Record{}, err
	}
	context := familyContext(base, input.envelope, Absent[Outcome]())
	labels, labelClasses, err := materializeFamilyFields(base.fields, input.labels, input.conditions, context)
	if err != nil {
		return Record{}, err
	}
	if err := validateFamilyCrossFieldValues(base.crossFieldRelations, labels); err != nil {
		return Record{}, err
	}
	if err := validateFamilyStructuredValue(labels, contract.attributeLimits); err != nil {
		return Record{}, err
	}
	instrumentData := map[string]any{"value": value, "attributes": labels}
	classes := map[string]FieldClass{"/value": FieldClassMetadata}
	mergeFamilyClasses(classes, "/attributes", labels, labelClasses, FieldClassMetadata)
	if err := verifyFamilyFieldClassCoverage(instrumentData, classes); err != nil {
		return Record{}, err
	}
	recordInput := familyRecordInput(input.envelope, base.identity)
	if input.importProvenance != nil {
		recordInput.Provenance.Import = cloneImportProvenance(input.importProvenance)
	}
	recordInput.InstrumentData = instrumentData
	recordInput.FieldClasses = classes
	if err := preflightGeneratedRecord(recordInput); err != nil {
		return Record{}, err
	}
	recordInput, err = builder.recordInputAt(recordInput, input.timestamp)
	if err != nil {
		return Record{}, err
	}
	record, err := newSchemaDerivedRecord(recordInput)
	if err != nil {
		return Record{}, familyBuildFailure(FamilyBuildRecordRejected)
	}
	return record, nil
}

func (builder *FamilyBuilder) ready() bool {
	return builder != nil && !nilInterface(builder.clock) && !nilInterface(builder.idGenerator)
}

func validateFamilyEnvelope(input FamilyEnvelopeInput) error {
	if !input.ProjectionPolicy.valid() {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	if err := ValidateStableToken("family source", string(input.Source)); err != nil {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	for _, value := range []string{input.Connector, input.Action, input.Phase} {
		if value != "" {
			if err := ValidateStableToken("family envelope token", value); err != nil {
				return familyBuildFailure(FamilyBuildConstraint)
			}
		}
	}
	if observedAt, present := input.ObservedAt.Get(); present && observedAt.IsZero() {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	if err := input.Correlation.validate(); err != nil {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	if err := input.Provenance.recordProvenance().Validate(); err != nil {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	return nil
}

func validateFamilyLogState(
	severityInput Optional[Severity],
	logLevelInput Optional[LogLevel],
) (*Severity, LogLevel, error) {
	var severity *Severity
	if value, present := severityInput.Get(); present {
		if _, valid := SeverityRank(value); !valid {
			return nil, "", familyBuildFailure(FamilyBuildConstraint)
		}
		copy := value
		severity = &copy
	}
	var logLevel LogLevel
	if value, present := logLevelInput.Get(); present {
		if !isLogLevel(value) {
			return nil, "", familyBuildFailure(FamilyBuildConstraint)
		}
		logLevel = value
	}
	return severity, logLevel, nil
}

func familyContext(
	contract familyDescriptorContract,
	envelope FamilyEnvelopeInput,
	outcome Optional[Outcome],
) familyDerivationContext {
	return familyDerivationContext{
		bucket: contract.identity.Bucket, family: contract.id,
		familySchemaVersion: contract.familySchemaVersion, source: envelope.Source,
		configGeneration: envelope.Provenance.ConfigGeneration, outcome: outcome,
		binaryVersion: envelope.Provenance.BinaryVersion,
	}
}

func familyRecordInput(envelope FamilyEnvelopeInput, identity EventIdentity) RecordInput {
	result := RecordInput{
		Identity: identity,
		Source:   envelope.Source, Connector: envelope.Connector, Action: envelope.Action,
		Phase: envelope.Phase, Correlation: envelope.Correlation,
		Provenance:       envelope.Provenance.recordProvenance(),
		projectionPolicy: envelope.ProjectionPolicy,
	}
	if observedAt, present := envelope.ObservedAt.Get(); present {
		copy := observedAt
		result.ObservedAt = &copy
	}
	return result
}

func preflightGeneratedRecord(input RecordInput) error {
	input.Timestamp = time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
	input.RecordID = strings.Repeat("\\", MaxRecordIDBytes)
	if _, err := newSchemaDerivedRecord(input); err != nil {
		return familyBuildFailure(FamilyBuildRecordRejected)
	}
	return nil
}

func preflightGeneratedLogRecord(
	input RecordInput,
	contract resolvedSchemaDerivedLogFamilyContract,
) error {
	input.Timestamp = time.Date(9999, 12, 31, 23, 59, 59, 999_999_999, time.UTC)
	input.RecordID = strings.Repeat("\\", MaxRecordIDBytes)
	if _, err := newSchemaDerivedLogRecord(input, contract); err != nil {
		return familyBuildFailure(FamilyBuildRecordRejected)
	}
	return nil
}

// recordInput is deliberately the last construction step. Family descriptors,
// producer inputs, payload size, field-class coverage, and signal invariants are
// preflighted before the occurrence provider is called. A trusted clock or ID
// provider can still return an invalid candidate; that attempt is consumed and
// reported with a stable, value-free occurrence error rather than gaplessly
// retrying or exposing the rejected candidate.
func (builder *FamilyBuilder) recordInput(input RecordInput) (RecordInput, error) {
	return builder.recordInputAt(input, Absent[time.Time]())
}

// recordInputAt is used only after a private accepted-record constructor has
// validated the selected upstream timestamp against its local receipt time.
// Ordinary generated producers cannot set it and continue to use the clock.
func (builder *FamilyBuilder) recordInputAt(input RecordInput, selected Optional[time.Time]) (RecordInput, error) {
	timestamp, present := selected.Get()
	if !present {
		timestamp = builder.clock.Now()
	}
	if timestamp.IsZero() {
		return RecordInput{}, familyBuildFailure(FamilyBuildOccurrence)
	}
	if _, err := timestamp.UTC().MarshalJSON(); err != nil {
		return RecordInput{}, familyBuildFailure(FamilyBuildOccurrence)
	}
	recordID, err := builder.idGenerator.NewOccurrenceID()
	if err != nil {
		return RecordInput{}, familyBuildFailure(FamilyBuildOccurrence)
	}
	if err := validateRequiredBoundedText("record ID", recordID, MaxRecordIDBytes); err != nil {
		return RecordInput{}, familyBuildFailure(FamilyBuildOccurrence)
	}
	input.Timestamp = timestamp
	input.RecordID = recordID
	return input, nil
}

func validateFamilyTraceContract(contract familyTraceContract) error {
	if err := validateFamilyDescriptor(contract.familyDescriptorContract, familySignalTrace); err != nil {
		return err
	}
	if contract.id != string(contract.identity.Name) || len(contract.allowedKinds) == 0 || len(contract.spanName) == 0 ||
		contract.scopeName == "" || contract.scopeSchemaURL == "" ||
		contract.traceSchemaVersion == "" || contract.semanticProfile == "" ||
		contract.maxEvents <= 0 || contract.maxEvents > maxFamilyTraceEvents ||
		contract.maxLinks <= 0 || contract.maxLinks > maxFamilyTraceLinks ||
		!validRequiredFamilyStructuredLimits(contract.attributeLimits) ||
		!validRequiredFamilyStructuredLimits(contract.resourceLimits) ||
		!validRequiredFamilyStructuredLimits(contract.scopeLimits) ||
		!validRequiredFamilyStructuredLimits(contract.eventLimits) ||
		!validRequiredFamilyStructuredLimits(contract.linkLimits) ||
		!validFamilySchemaURL(contract.scopeSchemaURL) ||
		!IsStableToken(contract.scopeName) || !IsStableToken(contract.traceSchemaVersion) ||
		!IsStableToken(contract.semanticProfile) {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	fields := make(map[string]familyFieldDescriptor, len(contract.fields))
	for _, field := range contract.fields {
		fields[field.key] = field
	}
	for _, part := range contract.spanName {
		field := fields[part.field]
		if (part.literal == "") == (part.field == "") ||
			part.literal != "" && !utf8.ValidString(part.literal) ||
			part.field != "" && (field.typeOf != familyFieldString || field.requirement != familyRequirementRequired) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	}
	seenKinds := make(map[string]struct{}, len(contract.allowedKinds))
	for _, kind := range contract.allowedKinds {
		if !containsString([]string{"INTERNAL", "SERVER", "CLIENT", "PRODUCER", "CONSUMER"}, kind) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seenKinds[kind]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenKinds[kind] = struct{}{}
	}
	if err := validateFamilyFieldDescriptors(contract.resourceFields); err != nil {
		return err
	}
	if err := validateFamilyFieldDescriptors(contract.scopeFields); err != nil {
		return err
	}
	if err := validateFamilyFieldDescriptors(contract.linkFields); err != nil {
		return err
	}
	seenEvents := make(map[string]struct{}, len(contract.allowedEvents))
	seenEventNames := make(map[string]struct{}, len(contract.allowedEvents))
	for _, event := range contract.allowedEvents {
		if !IsStableToken(event.id) || !IsStableToken(event.name) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seenEvents[event.id]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenEvents[event.id] = struct{}{}
		if _, duplicate := seenEventNames[event.name]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenEventNames[event.name] = struct{}{}
		if err := validateFamilyFieldDescriptors(event.fields); err != nil {
			return err
		}
	}
	seenLinks := make(map[string]struct{}, len(contract.allowedLinks))
	for _, relation := range contract.allowedLinks {
		if !IsStableToken(relation) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seenLinks[relation]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenLinks[relation] = struct{}{}
	}
	linkRelationFields := 0
	for _, field := range contract.linkFields {
		if field.source != familyValueLinkRelation {
			continue
		}
		linkRelationFields++
		if field.typeOf != familyFieldString || field.requirement != familyRequirementRequired ||
			len(field.constraints.enum) == 0 {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		for _, relation := range contract.allowedLinks {
			if !containsString(field.constraints.enum, relation) {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
		}
	}
	if linkRelationFields != 1 {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return nil
}

func validateFamilyMetricContract(contract familyMetricContract) error {
	if err := validateFamilyDescriptor(contract.familyDescriptorContract, familySignalMetric); err != nil {
		return err
	}
	if contract.id != "metric."+contract.instrumentName || string(contract.identity.Name) != contract.instrumentName ||
		contract.valueType != familyMetricNumberInt64 && contract.valueType != familyMetricNumberDouble ||
		contract.instrumentName == "" || contract.instrumentType == "" ||
		contract.unit == "" || contract.temporality == "" ||
		!IsStableToken(contract.instrumentName) ||
		!utf8.ValidString(contract.instrumentType) || !utf8.ValidString(contract.unit) ||
		!utf8.ValidString(contract.temporality) ||
		len(contract.instrumentType) > 64 || len(contract.unit) > 128 || len(contract.temporality) > 128 ||
		!validRequiredFamilyStructuredLimits(contract.attributeLimits) {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	for _, label := range contract.fields {
		if label.fieldClass != FieldClassMetadata && label.fieldClass != FieldClassIdentifier {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	}
	return nil
}

func resolvedFamilyMetricNumber(expected familyMetricNumberType, input familyMetricNumber) (any, error) {
	if input.typeOf != expected {
		return nil, familyBuildFailure(FamilyBuildInvalidMetric)
	}
	switch expected {
	case familyMetricNumberInt64:
		return input.int64, nil
	case familyMetricNumberDouble:
		if !isFinite(input.double) {
			return nil, familyBuildFailure(FamilyBuildInvalidMetric)
		}
		return input.double, nil
	default:
		return nil, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
}

func buildFamilyTraceResource(
	contract familyTraceContract,
	input familyTraceBuildInput,
	context familyDerivationContext,
	conditions familyConditionFacts,
) (map[string]any, map[string]FieldClass, error) {
	if !validFamilySchemaURL(input.resource.SchemaURL) {
		return nil, nil, familyBuildFailure(FamilyBuildInvalidTrace)
	}
	attributes, attributeClasses, err := materializeFamilyFields(
		contract.resourceFields,
		input.resource.values,
		selectFamilyConditionFacts(contract.resourceFields, conditions),
		context,
	)
	if err != nil {
		return nil, nil, err
	}
	if err := validateFamilyStructuredValue(attributes, contract.resourceLimits); err != nil {
		return nil, nil, err
	}
	resource := map[string]any{"schema_url": input.resource.SchemaURL, "attributes": attributes}
	classes := map[string]FieldClass{"/schema_url": FieldClassMetadata}
	mergeFamilyClasses(classes, "/attributes", attributes, attributeClasses, FieldClassMetadata)
	if count, present := input.resource.DroppedAttributesCount.Get(); present {
		resource["dropped_attributes_count"] = count
		classes["/dropped_attributes_count"] = FieldClassMetadata
	}
	return resource, classes, nil
}

func buildFamilyTraceScope(
	contract familyTraceContract,
	input familyTraceBuildInput,
	context familyDerivationContext,
	conditions familyConditionFacts,
) (map[string]any, map[string]FieldClass, error) {
	attributes, attributeClasses, err := materializeFamilyFields(
		contract.scopeFields,
		input.scope.values,
		selectFamilyConditionFacts(contract.scopeFields, conditions),
		context,
	)
	if err != nil {
		return nil, nil, err
	}
	if err := validateFamilyStructuredValue(attributes, contract.scopeLimits); err != nil {
		return nil, nil, err
	}
	scope := map[string]any{
		"name": contract.scopeName, "version": input.envelope.Provenance.BinaryVersion,
		"schema_url": contract.scopeSchemaURL, "attributes": attributes,
	}
	classes := map[string]FieldClass{
		"/name": FieldClassMetadata, "/version": FieldClassMetadata, "/schema_url": FieldClassMetadata,
	}
	mergeFamilyClasses(classes, "/attributes", attributes, attributeClasses, FieldClassMetadata)
	if count, present := input.scope.DroppedAttributesCount.Get(); present {
		scope["dropped_attributes_count"] = count
		classes["/dropped_attributes_count"] = FieldClassMetadata
	}
	return scope, classes, nil
}

func buildFamilyTraceEvents(
	contract familyTraceContract,
	input familyTraceBuildInput,
	context familyDerivationContext,
	conditions familyConditionFacts,
) ([]any, map[string]FieldClass, error) {
	if input.events == nil {
		return nil, nil, nil
	}
	if len(input.events) > contract.maxEvents {
		return nil, nil, familyBuildFailure(FamilyBuildConstraint)
	}
	events := make([]any, 0, len(input.events))
	classes := make(map[string]FieldClass)
	for index, eventInput := range input.events {
		allowed, ok := findFamilyEvent(contract.allowedEvents, eventInput.contract.id)
		if !ok || !reflect.DeepEqual(cloneFamilyEventContract(eventInput.contract), allowed) ||
			eventInput.TimeUnixNano == 0 {
			return nil, nil, familyBuildFailure(FamilyBuildInvalidTrace)
		}
		attributes, attributeClasses, err := materializeFamilyFields(
			allowed.fields,
			eventInput.values,
			selectFamilyConditionFacts(allowed.fields, conditions),
			context,
		)
		if err != nil {
			return nil, nil, err
		}
		if err := validateFamilyStructuredValue(attributes, contract.eventLimits); err != nil {
			return nil, nil, err
		}
		event := map[string]any{
			"name": allowed.name, "time_unix_nano": eventInput.TimeUnixNano, "attributes": attributes,
		}
		prefix := "/events/" + intString(index)
		classes[prefix+"/name"] = FieldClassIdentifier
		classes[prefix+"/time_unix_nano"] = FieldClassMetadata
		mergeFamilyClasses(classes, prefix+"/attributes", attributes, attributeClasses, FieldClassMetadata)
		if count, present := eventInput.DroppedAttributesCount.Get(); present {
			event["dropped_attributes_count"] = count
			classes[prefix+"/dropped_attributes_count"] = FieldClassMetadata
		}
		events = append(events, event)
	}
	return events, classes, nil
}

func buildFamilyTraceLinks(
	contract familyTraceContract,
	input familyTraceBuildInput,
	context familyDerivationContext,
	conditions familyConditionFacts,
) ([]any, map[string]FieldClass, error) {
	if input.links == nil {
		return nil, nil, nil
	}
	if len(input.links) > contract.maxLinks {
		return nil, nil, familyBuildFailure(FamilyBuildConstraint)
	}
	links := make([]any, 0, len(input.links))
	classes := make(map[string]FieldClass)
	for index, linkInput := range input.links {
		if !validateOTelID(linkInput.TraceID, 32) || !validateOTelID(linkInput.SpanID, 16) ||
			!containsString(contract.allowedLinks, linkInput.relation) {
			return nil, nil, familyBuildFailure(FamilyBuildInvalidTrace)
		}
		if traceState, present := linkInput.TraceState.Get(); present &&
			(!utf8.ValidString(traceState) || len(traceState) > 512) {
			return nil, nil, familyBuildFailure(FamilyBuildInvalidTrace)
		}
		linkContext := context
		linkContext.linkRelation = linkInput.relation
		attributes, attributeClasses, err := materializeFamilyFields(
			contract.linkFields,
			linkInput.values,
			selectFamilyConditionFacts(contract.linkFields, conditions),
			linkContext,
		)
		if err != nil {
			return nil, nil, err
		}
		if err := validateFamilyStructuredValue(attributes, contract.linkLimits); err != nil {
			return nil, nil, err
		}
		link := map[string]any{
			"trace_id": linkInput.TraceID, "span_id": linkInput.SpanID, "attributes": attributes,
		}
		prefix := "/links/" + intString(index)
		classes[prefix+"/trace_id"] = FieldClassIdentifier
		classes[prefix+"/span_id"] = FieldClassIdentifier
		mergeFamilyClasses(classes, prefix+"/attributes", attributes, attributeClasses, FieldClassMetadata)
		if traceState, present := linkInput.TraceState.Get(); present {
			link["trace_state"] = traceState
			classes[prefix+"/trace_state"] = FieldClassMetadata
		}
		if count, present := linkInput.DroppedAttributesCount.Get(); present {
			link["dropped_attributes_count"] = count
			classes[prefix+"/dropped_attributes_count"] = FieldClassMetadata
		}
		links = append(links, link)
	}
	return links, classes, nil
}

func familyTraceStatusObject(status TraceStatusInput) map[string]any {
	result := map[string]any{"code": string(status.Code())}
	if description, present := status.Description(); present {
		result["description"] = description
	}
	return result
}

func selectFamilyConditionFacts(
	descriptors []familyFieldDescriptor,
	facts familyConditionFacts,
) familyConditionFacts {
	selected := make(familyConditionFacts, 0)
	for _, fact := range facts {
		for _, descriptor := range descriptors {
			if descriptor.conditionID == fact.id {
				selected = append(selected, fact)
				break
			}
		}
	}
	return selected
}

func mergeFamilyClasses(
	target map[string]FieldClass,
	prefix string,
	value map[string]any,
	source map[string]FieldClass,
	emptyClass FieldClass,
) {
	if len(value) == 0 {
		target[prefix] = emptyClass
		return
	}
	mergePrefixedFamilyClasses(target, prefix, source)
}

func mergePrefixedFamilyClasses(
	target map[string]FieldClass,
	prefix string,
	source map[string]FieldClass,
) {
	for pointer, class := range source {
		target[prefix+pointer] = class
	}
}

func findFamilyEvent(events []familyEventContract, id string) (familyEventContract, bool) {
	for _, event := range events {
		if event.id == id {
			return cloneFamilyEventContract(event), true
		}
	}
	return familyEventContract{}, false
}

func cloneFamilyEventContract(input familyEventContract) familyEventContract {
	input.fields = cloneFamilyFieldDescriptors(input.fields)
	return input
}

func cloneFamilyTraceContract(input familyTraceContract) familyTraceContract {
	input.familyDescriptorContract = cloneFamilyDescriptorContract(input.familyDescriptorContract)
	input.allowedKinds = append([]string(nil), input.allowedKinds...)
	input.spanName = append([]spanNamePart(nil), input.spanName...)
	input.resourceFields = cloneFamilyFieldDescriptors(input.resourceFields)
	input.scopeFields = cloneFamilyFieldDescriptors(input.scopeFields)
	input.allowedLinks = append([]string(nil), input.allowedLinks...)
	input.linkFields = cloneFamilyFieldDescriptors(input.linkFields)
	input.allowedEvents = append([]familyEventContract(nil), input.allowedEvents...)
	for index := range input.allowedEvents {
		input.allowedEvents[index] = cloneFamilyEventContract(input.allowedEvents[index])
	}
	return input
}

func cloneFamilyMetricContract(input familyMetricContract) familyMetricContract {
	input.familyDescriptorContract = cloneFamilyDescriptorContract(input.familyDescriptorContract)
	return input
}

func intString(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

func validFamilySchemaURL(value string) bool {
	if value == "" || !utf8.ValidString(value) || len(value) > 512 {
		return false
	}
	parsed, err := url.ParseRequestURI(value)
	return err == nil && parsed.Scheme != "" && parsed.User == nil
}

func validW3CTraceState(value string) bool {
	if !utf8.ValidString(value) || len(value) > 512 {
		return false
	}
	parsed, err := trace.ParseTraceState(value)
	return err == nil && parsed.String() == value
}
