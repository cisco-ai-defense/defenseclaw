// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/hex"
	"math"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

func (a *APIServer) importOTLPTraceTargetV8(
	ctx context.Context,
	batch *observabilityruntime.InboundImportBatch,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
) otlpInboundTargetResult {
	result := otlpInboundTargetResult{}
	if leaf.span == nil {
		result.invalidRecord = true
		return result
	}
	policy, policyErr := inboundOptionalExportPolicyV8(leaf, match, wire)
	if policyErr != nil {
		result.invalidRecord = true
		return result
	}
	mapFailed, buildFailed, constructed := false, false, false
	handoff, err := batch.ImportTraceWithPolicy(ctx, target, authenticatedSource, policy, func(
		snapshot observabilityruntime.EmitContext,
	) (observability.Record, error) {
		result.collected = true
		input, unknownDropped, err := a.mapInboundTraceV8(
			ctx, leaf, match, target, wire, authenticatedSource, receipt, snapshot,
		)
		if err != nil {
			mapFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		result.unknownDropped = unknownDropped
		builder, err := newInboundBuilderV8()
		if err != nil {
			buildFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		record, err := builder.BuildTrace(target, input)
		if err != nil {
			buildFailed = true
			return observability.Record{}, err
		}
		constructed = true
		return record, nil
	})
	switch {
	case !result.collected && err == nil:
		return result
	case mapFailed:
		result.invalidMapped = true
	case buildFailed:
		result.invalidRecord = true
	case err != nil && constructed:
		result.recorded = true
		result.deliveryDegraded = true
	case err != nil:
		result.invalidRecord = true
	default:
		// A canonical imported span exists even when it matches no optional
		// route. Destination enqueue failures are delivery health, not a reason
		// to reclassify the accepted source leaf as malformed.
		result.recorded = true
		result.deliveryDegraded = handoff.Failed > 0 || handoff.Dropped > 0
	}
	return result
}

func (a *APIServer) mapInboundTraceV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
	snapshot observabilityruntime.EmitContext,
) (observability.InboundImportedTraceInput, uint64, error) {
	span := leaf.span
	if span == nil || !validInboundEndedSpan(leaf) {
		return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
	}
	provenance, err := inboundImportProvenanceV8(leaf, match, target, wire, authenticatedSource)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	correlation, err := inboundCorrelationWithSnapshotV8(ctx, leaf, match, authenticatedSource, snapshot)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	localProvenance, err := inboundLocalProvenanceV8(snapshot)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	aliasFields, selected, err := mapInboundAliasFieldsV8(leaf, match, target, authenticatedSource)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	directFields, directSelected, err := mapInboundFieldsFromCapabilitiesExcludingV8(
		target, target.Fields(), leaf.leafAttributes, selected,
	)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	fields := append(aliasFields, directFields...)
	for key := range directSelected {
		selected[key] = true
	}
	if override, present := match.TargetOverride(); present {
		source, state := leaf.leafAttributes.stringValue(override.Source())
		targetField, targetOK := inboundTargetFieldsByName(target)[override.Target()]
		if state != otlpTypedAttributeUnique || !targetOK || override.Normalization() != "identifier-v1" {
			return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
		}
		fields = append(fields, observability.NewInboundMappedString(targetField, source))
		selected[override.Target()] = true
	}
	if match.ClassID() == "otlp.codex.turn_span.v1" {
		capabilities := inboundTargetFieldsByName(target)
		for _, item := range []struct{ key, value string }{
			{"gen_ai.operation.name", "chat"},
		} {
			key, value := item.key, item.value
			if selected[key] {
				continue
			}
			field, available := capabilities[key]
			if !available {
				return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
			}
			fields = append(fields, observability.NewInboundMappedString(field, value))
			selected[key] = true
		}
	}
	fields, _, err = a.enrichInboundWithHookLifecycleV8(
		leaf, target, authenticatedSource, &correlation, fields, selected,
	)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	fields = addInboundContentCompanions(target, fields, selected)
	if match.Shape() != observability.InboundShapeNativeExact {
		for _, field := range target.RequiredBooleanInputFields() {
			if selected[field.FieldRef()] {
				continue
			}
			fields = append(fields, observability.NewInboundMappedBoolean(field, false))
			selected[field.FieldRef()] = true
		}
	}
	resourceFields, _, err := mapInboundFieldsFromCapabilitiesV8(
		target, target.TraceResourceFields(), leaf.resource.attributes,
	)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	resourceCustom, preservedResourceKeys, err := mapInboundTraceCustomResourceV8(
		leaf, match, target, wire,
	)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	localResource := observability.InboundLocalTraceResource{}
	if match.Shape() != observability.InboundShapeNativeExact {
		var available bool
		localResource, available = snapshot.InboundLocalTraceResource()
		if !available {
			return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
		}
	}
	spanUnknown, resourceUnknown, scopeUnknown := inboundUnknownTraceAttributeCountsV8(
		leaf, match, target, preservedResourceKeys,
	)
	events, droppedEvents, eventUnknown, err := mapInboundTraceEventsV8(target, span)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	links, droppedLinks, linkUnknown, err := mapInboundTraceLinksV8(target, span)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	status, statusUnknown, err := inboundTraceStatusV8(span.GetStatus())
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	outcome, err := inboundTraceOutcomeV8(match.OutcomeRule(), leaf.leafAttributes, status)
	if err != nil {
		return observability.InboundImportedTraceInput{}, 0, err
	}
	resourceDropped, ok := addInboundUint32(spanResourceDroppedCount(leaf), resourceUnknown)
	if !ok {
		return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
	}
	scopeDropped, ok := addInboundUint32(scopeDroppedCount(leaf), scopeUnknown)
	if !ok {
		return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
	}
	spanDropped, ok := addInboundUint32(span.GetDroppedAttributesCount(), spanUnknown)
	if !ok {
		return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
	}
	kind := inboundTraceKindV8(span.GetKind())
	if match.ClassID() == "otlp.codex.turn_span.v1" {
		// Codex exposes the whole turn as an INTERNAL implementation span.
		// This sealed binding projects that exact vendor span to the canonical
		// model client operation represented by span.model.chat.
		kind = "CLIENT"
	}
	input := observability.InboundImportedTraceInput{
		ReceiptTime: receipt.UTC(), Correlation: correlation,
		Provenance: localProvenance, Import: provenance,
		Outcome: outcome, Kind: kind,
		StartTimeUnixNano: span.GetStartTimeUnixNano(), EndTimeUnixNano: span.GetEndTimeUnixNano(),
		Flags: span.GetFlags(), Status: status,
		Resource: observability.InboundTraceResourceInput{
			DroppedAttributesCount: optionalInboundUint32(resourceDropped),
			Fields:                 resourceFields,
			Custom:                 resourceCustom,
		},
		LocalResource:          localResource,
		ScopeDroppedCount:      optionalInboundUint32(scopeDropped),
		Fields:                 fields,
		Events:                 events,
		DroppedEventsCount:     optionalInboundUint32(droppedEvents),
		Links:                  links,
		DroppedLinksCount:      optionalInboundUint32(droppedLinks),
		DroppedAttributesCount: optionalInboundUint32(spanDropped),
	}
	if parent := span.GetParentSpanId(); len(parent) != 0 {
		input.ParentSpanID = observability.Present(hex.EncodeToString(parent))
	}
	if state := span.GetTraceState(); state != "" {
		input.TraceState = observability.Present(state)
	}
	if match.Shape() == observability.InboundShapeNativeExact {
		input.NativeSpanName = observability.Present(span.GetName())
	}
	if input.Kind == "" {
		return observability.InboundImportedTraceInput{}, 0, errOTLPInboundMappingV8
	}
	return input, uint64(spanUnknown) + uint64(resourceUnknown) + uint64(scopeUnknown) + eventUnknown + linkUnknown + statusUnknown, nil
}

func inboundUnknownTraceAttributeCountsV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	preservedResourceKeys map[string]struct{},
) (uint32, uint32, uint32) {
	spanKnown := inboundKnownKeysV8(match, target, observability.InboundLocationLeafAttribute)
	resourceKnown := inboundKnownKeysV8(match, target, observability.InboundLocationResourceAttribute)
	for _, key := range leaf.resource.attributes.keys() {
		if _, registered := observability.TraceOTLPResourceAttributeKind(target.EventName(), key); registered {
			resourceKnown[key] = struct{}{}
		}
	}
	for key := range preservedResourceKeys {
		resourceKnown[key] = struct{}{}
	}
	scopeKnown := make(map[string]struct{})
	for _, key := range leaf.scope.attributes.keys() {
		if _, registered := observability.TraceOTLPScopeAttributeKind(target.EventName(), key); registered {
			scopeKnown[key] = struct{}{}
		}
	}
	return inboundUnknownAttributeCount(leaf.leafAttributes, spanKnown),
		inboundUnknownAttributeCount(leaf.resource.attributes, resourceKnown),
		inboundUnknownAttributeCount(leaf.scope.attributes, scopeKnown)
}

// mapInboundTraceCustomResourceV8 separates generated fixed and transport
// resource keys from bounded safe custom string attributes. Native exact input
// must be a reversible generated resource, so any malformed custom member or
// alias inconsistency rejects the leaf. External input retains each member only
// when the generated custom-resource constructor accepts the bounded prefix;
// rejected members remain unknown and are counted as dropped.
func mapInboundTraceCustomResourceV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
) (
	observability.Optional[observability.TelemetryCustomResourceAttributes],
	map[string]struct{},
	error,
) {
	native := match.Shape() == observability.InboundShapeNativeExact
	if native && (leaf.resource.schemaURL != wire.ResourceSchemaURL ||
		leaf.scope.schemaURL != wire.ScopeSchemaURL || leaf.scope.name != wire.ScopeName) {
		return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
			errOTLPInboundMappingV8
	}
	if native && leaf.resource.attributes.invalidCount() != 0 {
		return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
			errOTLPInboundMappingV8
	}

	known := inboundKnownKeysV8(match, target, observability.InboundLocationResourceAttribute)
	aliases := observability.TelemetryResourceCompatibilityAliases()
	preserved := make(map[string]struct{})
	compatibilityAliases := false
	if native {
		for alias, canonical := range aliases {
			aliasValue, aliasState := leaf.resource.attributes.stringValue(alias)
			canonicalValue, canonicalState := leaf.resource.attributes.stringValue(canonical)
			switch canonicalState {
			case otlpTypedAttributeUnique:
				if aliasState == otlpTypedAttributeAbsent {
					continue
				}
				if aliasState != otlpTypedAttributeUnique || aliasValue != canonicalValue {
					return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
						errOTLPInboundMappingV8
				}
				compatibilityAliases = true
			case otlpTypedAttributeAbsent:
				if aliasState != otlpTypedAttributeAbsent {
					return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
						errOTLPInboundMappingV8
				}
			default:
				return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
					errOTLPInboundMappingV8
			}
		}
		if compatibilityAliases {
			// Compatibility aliases are one generated policy bit, not
			// independently selectable keys. If enabled, every alias whose
			// canonical value exists must be present and equal.
			for alias, canonical := range aliases {
				canonicalValue, canonicalState := leaf.resource.attributes.stringValue(canonical)
				aliasValue, aliasState := leaf.resource.attributes.stringValue(alias)
				if canonicalState == otlpTypedAttributeUnique {
					if aliasState != otlpTypedAttributeUnique || aliasValue != canonicalValue {
						return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
							errOTLPInboundMappingV8
					}
					preserved[alias] = struct{}{}
				}
			}
		}
	}

	customValues := make(map[string]string)
	var sealed observability.TelemetryCustomResourceAttributes
	for _, key := range leaf.resource.attributes.keys() {
		if _, fixedOrTransport := known[key]; fixedOrTransport {
			continue
		}
		if _, alias := aliases[key]; alias {
			// External aliases are sender metadata and do not select the new
			// local process resource's generated compatibility policy.
			continue
		}
		value, state := leaf.resource.attributes.stringValue(key)
		if state != otlpTypedAttributeUnique {
			if native {
				return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
					errOTLPInboundMappingV8
			}
			continue
		}
		if native {
			customValues[key] = value
			continue
		}
		trial := make(map[string]string, len(customValues)+1)
		for acceptedKey, acceptedValue := range customValues {
			trial[acceptedKey] = acceptedValue
		}
		trial[key] = value
		candidate, candidateErr := observability.NewTelemetryCustomResourceAttributes(trial, false)
		if candidateErr != nil {
			continue
		}
		customValues = trial
		sealed = candidate
		preserved[key] = struct{}{}
	}
	if native {
		var err error
		sealed, err = observability.NewTelemetryCustomResourceAttributes(
			customValues, compatibilityAliases,
		)
		if err != nil {
			return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
				errOTLPInboundMappingV8
		}
		for key := range customValues {
			preserved[key] = struct{}{}
		}
	} else if len(customValues) == 0 {
		var err error
		sealed, err = observability.NewTelemetryCustomResourceAttributes(nil, false)
		if err != nil {
			return observability.Absent[observability.TelemetryCustomResourceAttributes](), nil,
				errOTLPInboundMappingV8
		}
	}
	return observability.Present(sealed), preserved, nil
}

func mapInboundDirectFieldsV8(
	target observability.InboundTarget,
	index otlpTypedAttributeIndex,
) ([]observability.InboundMappedField, map[string]bool, error) {
	return mapInboundFieldsFromCapabilitiesV8(target, target.Fields(), index)
}

func mapInboundFieldsFromCapabilitiesV8(
	target observability.InboundTarget,
	capabilities []observability.InboundTargetField,
	index otlpTypedAttributeIndex,
) ([]observability.InboundMappedField, map[string]bool, error) {
	return mapInboundFieldsFromCapabilitiesExcludingV8(target, capabilities, index, nil)
}

func mapInboundFieldsFromCapabilitiesExcludingV8(
	target observability.InboundTarget,
	capabilities []observability.InboundTargetField,
	index otlpTypedAttributeIndex,
	exclude map[string]bool,
) ([]observability.InboundMappedField, map[string]bool, error) {
	result := make([]observability.InboundMappedField, 0, len(capabilities))
	selected := make(map[string]bool)
	for _, field := range capabilities {
		if exclude[field.FieldRef()] {
			continue
		}
		if _, supported := target.MappedValueKind(field); !supported {
			continue
		}
		value, state := index.lookup(field.FieldRef())
		if state == otlpTypedAttributeAbsent {
			continue
		}
		if state != otlpTypedAttributeUnique {
			return nil, nil, errOTLPInboundMappingV8
		}
		mapped, err := inboundMappedFieldFromAny(target, field, value)
		if err != nil {
			return nil, nil, err
		}
		result = append(result, mapped)
		selected[field.FieldRef()] = true
	}
	return result, selected, nil
}

func mapInboundTraceEventsV8(
	target observability.InboundTarget,
	span *tracepb.Span,
) ([]observability.TraceEventInput, uint32, uint64, error) {
	if span == nil {
		return nil, 0, 0, errOTLPInboundMappingV8
	}
	byName := make(map[string]observability.InboundTraceEventTarget)
	for _, event := range target.TraceEvents() {
		byName[event.Name()] = event
	}
	dropped := uint64(span.GetDroppedEventsCount())
	unknownTotal := uint64(0)
	result := make([]observability.TraceEventInput, 0, len(span.GetEvents()))
	for _, source := range span.GetEvents() {
		capability, registered := byName[source.GetName()]
		if source == nil || !registered || source.GetTimeUnixNano() == 0 {
			dropped++
			unknownTotal++
			continue
		}
		index := newOTLPTypedAttributeIndex(source.GetAttributes())
		fields, _, err := mapInboundFieldsFromCapabilitiesV8(target, capability.Fields(), index)
		if err != nil {
			dropped++
			unknownTotal++
			continue
		}
		known := make(map[string]struct{})
		for _, field := range capability.Fields() {
			known[field.FieldRef()] = struct{}{}
		}
		unknown := inboundUnknownAttributeCount(index, known)
		unknownTotal += uint64(unknown)
		count, ok := addInboundUint32(source.GetDroppedAttributesCount(), unknown)
		if !ok {
			return nil, 0, 0, errOTLPInboundMappingV8
		}
		event, err := observability.NewInboundTraceEvent(
			capability, source.GetTimeUnixNano(), optionalInboundUint32(count), fields,
		)
		if err != nil {
			dropped++
			unknownTotal++
			continue
		}
		result = append(result, event)
	}
	if dropped > math.MaxUint32 {
		return nil, 0, 0, errOTLPInboundMappingV8
	}
	return result, uint32(dropped), unknownTotal, nil
}

func mapInboundTraceLinksV8(
	target observability.InboundTarget,
	span *tracepb.Span,
) ([]observability.TraceLinkInput, uint32, uint64, error) {
	if span == nil {
		return nil, 0, 0, errOTLPInboundMappingV8
	}
	dropped := uint64(span.GetDroppedLinksCount())
	unknownTotal := uint64(0)
	result := make([]observability.TraceLinkInput, 0, len(span.GetLinks()))
	for _, source := range span.GetLinks() {
		if source == nil || !validInboundOTelID(source.GetTraceId(), 16) || !validInboundOTelID(source.GetSpanId(), 8) {
			dropped++
			unknownTotal++
			continue
		}
		index := newOTLPTypedAttributeIndex(source.GetAttributes())
		relation, state := index.stringValue("defenseclaw.link.relation")
		if state != otlpTypedAttributeUnique {
			dropped++
			unknownTotal++
			continue
		}
		unknown := inboundUnknownAttributeCount(index, map[string]struct{}{"defenseclaw.link.relation": {}})
		unknownTotal += uint64(unknown)
		count, ok := addInboundUint32(source.GetDroppedAttributesCount(), unknown)
		if !ok {
			return nil, 0, 0, errOTLPInboundMappingV8
		}
		traceState := observability.Absent[string]()
		if source.GetTraceState() != "" {
			traceState = observability.Present(source.GetTraceState())
		}
		link, err := observability.NewInboundTraceLink(
			target, observability.InboundTraceLinkRelation(relation),
			hex.EncodeToString(source.GetTraceId()), hex.EncodeToString(source.GetSpanId()),
			traceState, optionalInboundUint32(count),
		)
		if err != nil {
			dropped++
			unknownTotal++
			continue
		}
		result = append(result, link)
	}
	if dropped > math.MaxUint32 {
		return nil, 0, 0, errOTLPInboundMappingV8
	}
	return result, uint32(dropped), unknownTotal, nil
}

func inboundUnknownAttributeCount(index otlpTypedAttributeIndex, known map[string]struct{}) uint32 {
	var count uint64
	for _, key := range index.keys() {
		if _, ok := known[key]; !ok {
			count++
		}
	}
	count += uint64(index.invalidCount())
	if count > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(count)
}

func addInboundUint32(left, right uint32) (uint32, bool) {
	result := uint64(left) + uint64(right)
	return uint32(result), result <= math.MaxUint32
}

func optionalInboundUint32(value uint32) observability.Optional[uint32] {
	if value == 0 {
		return observability.Absent[uint32]()
	}
	return observability.Present(value)
}

func inboundTraceStatusV8(status *tracepb.Status) (observability.TraceStatusInput, uint64, error) {
	if status == nil {
		return observability.NewTraceStatusUnset(), 0, nil
	}
	switch status.GetCode() {
	case tracepb.Status_STATUS_CODE_UNSET:
		// The OTel message field is meaningful only for ERROR.  Senders may
		// still populate it on UNSET/OK; drop and count that unsupported field
		// instead of rejecting an otherwise valid official protobuf span.
		return observability.NewTraceStatusUnset(), boolCount(status.GetMessage() != ""), nil
	case tracepb.Status_STATUS_CODE_OK:
		return observability.NewTraceStatusOK(), boolCount(status.GetMessage() != ""), nil
	case tracepb.Status_STATUS_CODE_ERROR:
		description := observability.Absent[string]()
		if status.GetMessage() != "" {
			description = observability.Present(status.GetMessage())
		}
		return observability.NewTraceStatusError(description), 0, nil
	default:
		return observability.TraceStatusInput{}, 0, errOTLPInboundMappingV8
	}
}

func boolCount(value bool) uint64 {
	if value {
		return 1
	}
	return 0
}

func inboundTraceOutcomeV8(
	rule observability.InboundOutcomeRule,
	attributes otlpTypedAttributeIndex,
	status observability.TraceStatusInput,
) (observability.Optional[observability.Outcome], error) {
	if fixed, ok := rule.Fixed(); ok {
		return observability.Present(fixed), nil
	}
	switch rule.Kind() {
	case observability.InboundOutcomeNativeSpan:
		value, state := attributes.stringValue("defenseclaw.outcome")
		if state != otlpTypedAttributeUnique || !observability.IsOutcome(observability.Outcome(value)) {
			return observability.Absent[observability.Outcome](), errOTLPInboundMappingV8
		}
		return observability.Present(observability.Outcome(value)), nil
	case observability.InboundOutcomeOTelStatus:
		if errorType, state := attributes.stringValue("error.type"); state == otlpTypedAttributeUnique && errorType == "policy_denied" {
			return observability.Present(observability.OutcomeDenied), nil
		} else if state != otlpTypedAttributeAbsent && state != otlpTypedAttributeUnique {
			return observability.Absent[observability.Outcome](), errOTLPInboundMappingV8
		}
		switch status.Code() {
		case observability.TraceStatusError:
			return observability.Present(observability.OutcomeFailed), nil
		case observability.TraceStatusOK, observability.TraceStatusUnset:
			return observability.Present(observability.OutcomeCompleted), nil
		}
	}
	return observability.Absent[observability.Outcome](), errOTLPInboundMappingV8
}

func inboundTraceKindV8(kind tracepb.Span_SpanKind) string {
	switch kind {
	case tracepb.Span_SPAN_KIND_INTERNAL:
		return "INTERNAL"
	case tracepb.Span_SPAN_KIND_SERVER:
		return "SERVER"
	case tracepb.Span_SPAN_KIND_CLIENT:
		return "CLIENT"
	case tracepb.Span_SPAN_KIND_PRODUCER:
		return "PRODUCER"
	case tracepb.Span_SPAN_KIND_CONSUMER:
		return "CONSUMER"
	default:
		return ""
	}
}

func spanResourceDroppedCount(leaf otlpDecodedLeaf) uint32 {
	return leaf.resource.droppedAttributesCount
}

func scopeDroppedCount(leaf otlpDecodedLeaf) uint32 { return leaf.scope.droppedAttributesCount }
