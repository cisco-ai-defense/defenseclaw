// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/google/uuid"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	"google.golang.org/protobuf/proto"
)

var errOTLPInboundMappingV8 = errors.New("OTLP v8 inbound mapping rejected its input")

type otlpInboundTargetResult struct {
	collected             bool
	recorded              bool
	deduplicated          bool
	acceptedNoObservation bool
	invalidMapped         bool
	invalidRecord         bool
	persistenceFailed     bool
	deliveryDegraded      bool
	unknownDropped        uint64
}

type otlpInboundLeafResult struct {
	primary          *otlpInboundTargetResult
	derivatives      []otlpInboundTargetResult
	hasImportTarget  bool
	hasDerivedTarget bool
}

// importDecodedOTLPRequestV8 owns OTLP-I02 through OTLP-I09 for one request.
// The official protobuf request remains request-owned, leaves are visited in
// wire order, and exactly one generation lease covers every collection check,
// typed mapping callback, canonical construction, and synchronous handoff.
func (a *APIServer) importDecodedOTLPRequestV8(
	ctx context.Context,
	message proto.Message,
	signal otelIngestSignal,
	authenticatedSource string,
	receipt time.Time,
) (otlpInboundBatchAccounting, error) {
	if a == nil || ctx == nil || message == nil || receipt.IsZero() {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(otlpInboundImportRuntime)
	if !ok || runtime == nil {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	stats, err := walkDecodedOTLPLeaves(message, signal, nil)
	if err != nil {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	accounting, err := newOTLPInboundBatchAccounting(stats.Records)
	if err != nil {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	localInstanceID := gatewaylog.SidecarInstanceID()
	classifier, err := newOTLPInboundClassifierV8(localInstanceID)
	if err != nil {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	batch, err := runtime.BeginInboundImportBatch(ctx)
	if err != nil {
		return otlpInboundBatchAccounting{}, errOTLPInboundMappingV8
	}
	defer batch.Close()

	_, walkErr := walkDecodedOTLPLeaves(message, signal, func(leaf otlpDecodedLeaf) error {
		classification, classifyErr := classifier.classify(leaf, authenticatedSource)
		if classifyErr != nil {
			return accounting.addPrimary(otlpInboundInvalidRecord)
		}
		if disposition, terminal := inboundTerminalDisposition(classifier, leaf, classification); terminal {
			return accounting.addPrimary(disposition)
		}
		correlated, correlationErr := a.correlateNativeOTLPLeafV8(
			ctx, leaf, classification.match, authenticatedSource, receipt,
		)
		if correlationErr != nil {
			if errors.Is(correlationErr, errNativeOTLPCorrelationInputV8) {
				return accounting.addPrimary(otlpInboundInvalidMappedField)
			}
			// Correlation state is part of local acceptance in v8. Never hand a
			// leaf to the runtime/provider after the occurrence transaction has
			// failed; account the leaf through the existing bounded local failure
			// disposition so batch acknowledgement remains mathematically exact.
			return accounting.addPrimary(otlpInboundLocalPersistenceFailed)
		}
		if correlated.suppressEmission {
			return accounting.addPrimary(otlpInboundExactReplaySuppressed)
		}
		leafResult := a.importClassifiedOTLPLeafV8(
			correlated.ctx, batch, leaf, classification.match, classifier.catalog.WireContract(),
			authenticatedSource, receipt,
		)
		if nativeOTLPLeafCanarySucceeded(leafResult) {
			if finalizeErr := a.finalizeNativeOTLPCustodyV8(correlated.ctx, correlated); finalizeErr != nil {
				return accounting.addPrimary(otlpInboundLocalPersistenceFailed)
			}
		}
		for _, derivative := range leafResult.derivatives {
			switch {
			case derivative.invalidMapped || derivative.invalidRecord:
				// Multi-observation targets (Codex token input/cache/output, for
				// example) may contain a valid no-observation sibling alongside
				// a malformed or authority-conflicting observation. Invalidity is
				// terminal for the target and must not be masked by that sibling.
				if err := accounting.addDerivative(otlpInboundDerivativeInvalidRecord); err != nil {
					return err
				}
			case !derivative.collected:
				if err := accounting.addDerivative(otlpInboundDerivativeCollectionDisabled); err != nil {
					return err
				}
			case derivative.recorded || derivative.deduplicated:
				if err := accounting.addDerivative(otlpInboundDerivativeRecorded); err != nil {
					return err
				}
			case derivative.acceptedNoObservation:
				if err := accounting.addDerivative(otlpInboundDerivativeNoObservation); err != nil {
					return err
				}
			case derivative.deliveryDegraded:
				if err := accounting.addDerivative(otlpInboundDerivativeDeliveryDegraded); err != nil {
					return err
				}
			default:
				if err := accounting.addDerivative(otlpInboundDerivativeInvalidRecord); err != nil {
					return err
				}
			}
		}
		unknownDropped := uint64(0)
		if leafResult.primary != nil {
			unknownDropped = leafResult.primary.unknownDropped
		} else {
			for _, derivative := range leafResult.derivatives {
				if derivative.unknownDropped > unknownDropped {
					unknownDropped = derivative.unknownDropped
				}
			}
		}
		if err := accounting.addUnknownFieldsDropped(unknownDropped); err != nil {
			return err
		}
		return accounting.addPrimary(primaryDispositionForInboundLeaf(leafResult))
	})
	if walkErr != nil || !accounting.valid() {
		return accounting, errOTLPInboundMappingV8
	}
	return accounting, nil
}

func inboundTerminalDisposition(
	classifier otlpInboundClassifierV8,
	leaf otlpDecodedLeaf,
	classification otlpInboundLeafClassification,
) (otlpInboundPrimaryDisposition, bool) {
	if hop, state := inboundForwardHop(classifier, leaf); state != otlpTypedAttributeAbsent {
		if state != otlpTypedAttributeUnique || hop < 0 || hop > int64(classifier.catalog.WireContract().MaxForwardHops) {
			return otlpInboundHopLimit, true
		}
	}
	if classification.selfEchoCandidate {
		// Echo recognition is intentionally construction-free, but it is only a
		// candidate.  Validate the complete native forwarding tuple before
		// granting the terminal self-suppression disposition.
		if _, err := inboundForwardMetadataV8(leaf, classifier.catalog.WireContract(), true); err != nil {
			return otlpInboundInvalidRecord, true
		}
		return otlpInboundSelfSuppressed, true
	}
	switch classification.identityState {
	case otlpInboundIdentityMatched:
		return "", false
	case otlpInboundIdentityAmbiguous:
		return otlpInboundAmbiguousIdentity, true
	case otlpInboundIdentityNativeMalformed:
		return otlpInboundInvalidRecord, true
	default:
		return otlpInboundUnsupportedIdentity, true
	}
}

func inboundForwardHop(
	classifier otlpInboundClassifierV8,
	leaf otlpDecodedLeaf,
) (int64, otlpTypedAttributeState) {
	index := leaf.leafAttributes
	if leaf.signal == otelSignalMetrics {
		index = leaf.resource.attributes
	}
	return index.int64Value(classifier.catalog.WireContract().ForwardHopCountKey)
}

func primaryDispositionForInboundLeaf(result otlpInboundLeafResult) otlpInboundPrimaryDisposition {
	derivedRecorded := false
	derivedCollected := false
	for _, derivative := range result.derivatives {
		derivedCollected = derivedCollected || derivative.collected
		// Optional delivery happens after a derivative has been admitted,
		// mapped, and canonically constructed.  A sibling destination failure
		// is accounted separately, but cannot rewrite the primary leaf
		// acknowledgement from derived/imported-and-derived to invalid.
		derivedRecorded = derivedRecorded || derivative.recorded || derivative.deduplicated ||
			derivative.acceptedNoObservation || derivative.deliveryDegraded
	}
	if result.primary != nil {
		primary := *result.primary
		switch {
		case primary.persistenceFailed:
			return otlpInboundLocalPersistenceFailed
		case primary.invalidMapped:
			return otlpInboundInvalidMappedField
		case primary.invalidRecord:
			return otlpInboundInvalidRecord
		case primary.recorded && derivedRecorded:
			return otlpInboundImportedAndDerived
		case primary.recorded:
			return otlpInboundImported
		case !primary.collected && derivedRecorded:
			return otlpInboundDerivedOnly
		case !primary.collected && !derivedCollected:
			return otlpInboundCollectionDisabled
		default:
			return otlpInboundInvalidRecord
		}
	}
	if derivedRecorded {
		return otlpInboundDerivedOnly
	}
	if result.hasDerivedTarget && !derivedCollected {
		return otlpInboundCollectionDisabled
	}
	return otlpInboundInvalidRecord
}

func (a *APIServer) importClassifiedOTLPLeafV8(
	ctx context.Context,
	batch *observabilityruntime.InboundImportBatch,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
) otlpInboundLeafResult {
	result := otlpInboundLeafResult{}
	for _, target := range match.Targets() {
		switch target.Role() {
		case observability.InboundTargetImport:
			result.hasImportTarget = true
			imported := otlpInboundTargetResult{invalidRecord: true}
			switch target.Signal() {
			case observability.SignalLogs:
				imported = a.importOTLPLogTargetV8(ctx, batch, leaf, match, target, wire, authenticatedSource, receipt)
			case observability.SignalTraces:
				imported = a.importOTLPTraceTargetV8(ctx, batch, leaf, match, target, wire, authenticatedSource, receipt)
			case observability.SignalMetrics:
				imported = a.importOTLPMetricTargetV8(ctx, batch, leaf, match, target, wire, authenticatedSource, receipt)
			}
			result.primary = &imported
		case observability.InboundTargetDerive:
			result.hasDerivedTarget = true
			derived := a.deriveOTLPMetricTargetV8(
				ctx, batch, leaf, match, target, wire, authenticatedSource, receipt,
			)
			result.derivatives = append(result.derivatives, derived)
		}
	}
	return result
}

func newInboundBuilderV8() (*observability.InboundImportBuilder, error) {
	return observability.NewInboundImportBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
	)
}

func inboundLocalProvenanceV8(
	snapshot observabilityruntime.EmitContext,
) (observability.InboundLocalProvenanceInput, error) {
	provenance, ok := snapshot.InboundLocalProvenance()
	if !ok {
		return observability.InboundLocalProvenanceInput{}, errOTLPInboundMappingV8
	}
	return provenance, nil
}

func inboundCorrelationWithSnapshotV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	authenticatedSource string,
	snapshot observabilityruntime.EmitContext,
) (observability.Correlation, error) {
	correlation, err := inboundCorrelationV8(ctx, leaf, match, authenticatedSource)
	if err != nil {
		return observability.Correlation{}, err
	}
	instanceID, ok := snapshot.InboundLocalInstanceID()
	if !ok {
		return observability.Correlation{}, errOTLPInboundMappingV8
	}
	correlation.SidecarInstanceID = instanceID
	return correlation, nil
}

// enrichInboundWithHookLifecycleV8 joins native Codex OTLP to hook lifecycle
// state only through an explicitly reported conversation/thread identity. The
// hook cache is the existing bounded authority for agent topology; an OTLP
// record without that identity remains un-attributed rather than receiving a
// guessed root agent.
func (a *APIServer) enrichInboundWithHookLifecycleV8(
	leaf otlpDecodedLeaf,
	target observability.InboundTarget,
	authenticatedSource string,
	correlation *observability.Correlation,
	fields []observability.InboundMappedField,
	selected map[string]bool,
) ([]observability.InboundMappedField, bool, error) {
	if correlation == nil {
		return nil, false, errOTLPInboundMappingV8
	}
	conversationID := correlation.SessionID
	if conversationID == "" {
		return fields, false, nil
	}
	meta, found := a.hookLifecycleSnapshot(authenticatedSource, conversationID, "")
	if !found {
		return fields, false, nil
	}
	mergeCorrelation := func(current *string, source string) bool {
		if source == "" {
			return true
		}
		if *current != "" && *current != source {
			return false
		}
		*current = source
		return true
	}
	if !mergeCorrelation(&correlation.SessionID, conversationID) ||
		!mergeCorrelation(&correlation.AgentID, meta.AgentID) ||
		!mergeCorrelation(&correlation.TurnID, meta.TurnID) {
		return nil, false, errOTLPInboundMappingV8
	}
	if selected == nil {
		selected = make(map[string]bool)
	}
	rootAgentID := firstNonEmpty(meta.RootAgentID, meta.AgentID)
	rootSessionID := firstNonEmpty(meta.RootSessionID, conversationID)
	authoritativeStrings := []struct{ key, value string }{
		{"gen_ai.conversation.id", conversationID},
		{"gen_ai.agent.id", meta.AgentID},
		{"gen_ai.agent.name", meta.AgentName},
		{"defenseclaw.agent.type", meta.AgentType},
		{"defenseclaw.agent.root.id", rootAgentID},
		{"defenseclaw.agent.parent.id", meta.ParentAgentID},
		{"defenseclaw.agent.lineage.provenance", meta.LineageProvenance},
		{"defenseclaw.session.root.id", rootSessionID},
		{"defenseclaw.session.parent.id", meta.ParentSessionID},
		{"defenseclaw.agent.lifecycle.id", meta.LifecycleID},
		{"defenseclaw.agent.execution.id", meta.ExecutionID},
		{"defenseclaw.turn.id", meta.TurnID},
		{"defenseclaw.agent.phase", meta.Phase},
		{"defenseclaw.connector.source", authenticatedSource},
	}
	// Hook lifecycle state is the authority for topology and execution identity
	// after an exact conversation join. A sender may repeat those canonical
	// facts, but it may not smuggle a second root/lifecycle/execution identity
	// into the body while the envelope correlation uses the hook snapshot. Check
	// direct canonical attributes even when this particular target does not
	// expose the field (agent-token metrics, for example, intentionally omit
	// depth); target capability must not turn a conflict into an accepted leaf.
	for _, item := range authoritativeStrings {
		if item.value == "" {
			continue
		}
		reportedValue, reportedState := leaf.attributes().lookup(item.key)
		if reportedState == otlpTypedAttributeAbsent {
			continue
		}
		if reportedState != otlpTypedAttributeUnique {
			return nil, false, errOTLPInboundMappingV8
		}
		reported, ok := reportedValue.GetValue().(*commonpb.AnyValue_StringValue)
		if !ok || reported.StringValue != item.value {
			return nil, false, errOTLPInboundMappingV8
		}
	}
	if meta.AgentID != "" {
		reportedDepth, depthState := leaf.attributes().int64Value("defenseclaw.agent.depth")
		if depthState != otlpTypedAttributeAbsent &&
			(depthState != otlpTypedAttributeUnique || reportedDepth != int64(meta.AgentDepth)) {
			return nil, false, errOTLPInboundMappingV8
		}
	}
	capabilities := inboundTargetFieldsByName(target)
	appendValue := func(key string, value *commonpb.AnyValue) error {
		if selected[key] || value == nil {
			return nil
		}
		field, available := capabilities[key]
		if !available {
			return nil
		}
		mapped, err := inboundMappedFieldFromAny(target, field, value)
		if err != nil {
			return err
		}
		fields = append(fields, mapped)
		selected[key] = true
		return nil
	}
	appendString := func(key, value string) error {
		if value == "" {
			return nil
		}
		return appendValue(key, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}})
	}
	for _, item := range authoritativeStrings {
		if err := appendString(item.key, item.value); err != nil {
			return nil, false, err
		}
	}
	if meta.AgentID != "" {
		if err := appendValue("defenseclaw.agent.depth", &commonpb.AnyValue{
			Value: &commonpb.AnyValue_IntValue{IntValue: int64(meta.AgentDepth)},
		}); err != nil {
			return nil, false, err
		}
	}
	return fields, true, nil
}

func selectedInboundLogTime(record *logspb.LogRecord, receipt time.Time) (time.Time, error) {
	if record != nil && record.GetTimeUnixNano() != 0 {
		return inboundTimeFromUnixNano(record.GetTimeUnixNano())
	}
	if record != nil && record.GetObservedTimeUnixNano() != 0 {
		return inboundTimeFromUnixNano(record.GetObservedTimeUnixNano())
	}
	return receipt.UTC(), nil
}

func selectedInboundMetricTime(leaf otlpDecodedLeaf, receipt time.Time) (time.Time, error) {
	var nanos uint64
	switch {
	case leaf.numberPoint != nil:
		nanos = leaf.numberPoint.GetTimeUnixNano()
	case leaf.histogramPoint != nil:
		nanos = leaf.histogramPoint.GetTimeUnixNano()
	case leaf.exponentialHistogram != nil:
		nanos = leaf.exponentialHistogram.GetTimeUnixNano()
	case leaf.summaryPoint != nil:
		nanos = leaf.summaryPoint.GetTimeUnixNano()
	}
	if nanos == 0 {
		return receipt.UTC(), nil
	}
	return inboundTimeFromUnixNano(nanos)
}

func inboundTimeFromUnixNano(nanos uint64) (time.Time, error) {
	if nanos == 0 || nanos > math.MaxInt64 {
		return time.Time{}, errOTLPInboundMappingV8
	}
	return time.Unix(0, int64(nanos)).UTC(), nil
}

func inboundImportProvenanceV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
) (observability.InboundImportProvenanceInput, error) {
	result := observability.InboundImportProvenanceInput{AuthenticatedSource: authenticatedSource}
	// service.name is provenance only when the exact generated target exposes
	// that resource capability. Merely being present on an OTLP resource does
	// not grant preservation authority.
	if inboundTargetDeclaresField(target.TraceResourceFields(), "service.name") {
		serviceName, serviceState := leaf.resource.attributes.stringValue("service.name")
		if serviceState == otlpTypedAttributeUnique {
			result.UpstreamServiceName = serviceName
		} else if serviceState != otlpTypedAttributeAbsent {
			return result, errOTLPInboundMappingV8
		}
	}
	forward, err := inboundForwardMetadataV8(leaf, wire, match.Shape() == observability.InboundShapeNativeExact)
	if err != nil {
		return result, errOTLPInboundMappingV8
	}
	result.IngressHopCount = forward.hop
	result.LastHopInstanceID = forward.instanceID
	result.LastHopDestination = forward.destination
	if match.Shape() != observability.InboundShapeNativeExact {
		return result, nil
	}
	semantic, semanticState := leaf.resource.attributes.stringValue(wire.SemanticInstanceKey)
	if semanticState != otlpTypedAttributeUnique || semantic == "" {
		return result, errOTLPInboundMappingV8
	}
	result.UpstreamInstanceID = semantic
	if leaf.signal != otelSignalMetrics {
		if recordID, state := leaf.leafAttributes.stringValue(wire.RecordIDKey); state == otlpTypedAttributeUnique {
			result.UpstreamRecordID = recordID
		} else if leaf.signal == otelSignalLogs || state != otlpTypedAttributeAbsent {
			return result, errOTLPInboundMappingV8
		}
	}
	return result, nil
}

type inboundForwardMetadata struct {
	hop         uint32
	instanceID  string
	destination string
}

func inboundForwardMetadataV8(
	leaf otlpDecodedLeaf,
	wire observability.InboundWireContract,
	required bool,
) (inboundForwardMetadata, error) {
	index := leaf.leafAttributes
	if leaf.signal == otelSignalMetrics {
		index = leaf.resource.attributes
	}
	instance, instanceState := index.stringValue(wire.ForwardInstanceKey)
	destination, destinationState := index.stringValue(wire.ForwardDestinationKey)
	hop, hopState := index.int64Value(wire.ForwardHopCountKey)
	allAbsent := instanceState == otlpTypedAttributeAbsent &&
		destinationState == otlpTypedAttributeAbsent && hopState == otlpTypedAttributeAbsent
	if allAbsent {
		if required {
			return inboundForwardMetadata{}, errOTLPInboundMappingV8
		}
		return inboundForwardMetadata{}, nil
	}
	if instanceState != otlpTypedAttributeAbsent &&
		(instanceState != otlpTypedAttributeUnique || instance == "") {
		return inboundForwardMetadata{}, errOTLPInboundMappingV8
	}
	if destinationState != otlpTypedAttributeAbsent &&
		(destinationState != otlpTypedAttributeUnique || destination == "") {
		return inboundForwardMetadata{}, errOTLPInboundMappingV8
	}
	if instanceState != otlpTypedAttributeUnique || destinationState != otlpTypedAttributeUnique ||
		hopState != otlpTypedAttributeUnique {
		return inboundForwardMetadata{}, errOTLPInboundMappingV8
	}
	if hop < 0 || hop > int64(wire.MaxForwardHops) {
		return inboundForwardMetadata{}, errOTLPInboundMappingV8
	}
	return inboundForwardMetadata{hop: uint32(hop), instanceID: instance, destination: destination}, nil
}

func inboundTargetDeclaresField(fields []observability.InboundTargetField, key string) bool {
	for _, field := range fields {
		if field.FieldRef() == key {
			return true
		}
	}
	return false
}

func inboundMatchDeclaresField(match observability.InboundMatch, key string) bool {
	for _, alias := range match.Aliases() {
		if alias.Target() == key {
			return true
		}
	}
	for _, target := range match.Targets() {
		if inboundTargetDeclaresField(target.Fields(), key) {
			return true
		}
	}
	return false
}

func inboundCorrelationV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	authenticatedSource string,
) (observability.Correlation, error) {
	// Process/run identity is trusted local correlation, not sender-derived
	// lifecycle data.  In particular the local sidecar instance establishes the
	// semantic resource identity for an external (non-native) first import.
	correlation := observability.Correlation{
		RunID: gatewaylog.ProcessRunID(), ConnectorID: authenticatedSource,
		SidecarInstanceID: gatewaylog.SidecarInstanceID(),
	}
	if leaf.span != nil {
		correlation.TraceID = hex.EncodeToString(leaf.span.GetTraceId())
		correlation.SpanID = hex.EncodeToString(leaf.span.GetSpanId())
	}
	read := func(target *string, key string) {
		if !inboundMatchDeclaresField(match, key) {
			return
		}
		if value, state := inboundGeneratedStringValue(leaf, match, key, authenticatedSource); state == otlpTypedAttributeUnique {
			*target = value
		}
	}
	read(&correlation.RunID, "defenseclaw.run.id")
	read(&correlation.RequestID, "defenseclaw.request.id")
	read(&correlation.AgentInstanceID, "defenseclaw.agent.instance_id")
	read(&correlation.PolicyID, "defenseclaw.policy.id")
	read(&correlation.PolicyVersion, "defenseclaw.policy.version")
	read(&correlation.EvaluationID, "defenseclaw.guardrail.evaluation.id")
	read(&correlation.ScanID, "defenseclaw.scan.id")
	read(&correlation.FindingOccurrenceID, "defenseclaw.finding.occurrence.id")
	read(&correlation.EnforcementActionID, "defenseclaw.enforcement.action.id")
	if values, ok := nativeOTLPCorrelationValuesFromContext(ctx, authenticatedSource); ok {
		if err := applyConnectorNativeCorrelationValuesV8(&correlation, values); err != nil {
			return observability.Correlation{}, err
		}
	} else if err := applyConnectorNativeCorrelationV8(&correlation, leaf, authenticatedSource); err != nil {
		return observability.Correlation{}, err
	}
	return correlation, nil
}

// applyConnectorNativeCorrelationV8 maps business identity only through the
// authenticated connector's reviewed profile. The generated inbound alias
// catalog remains useful for non-business protocol fields, but it must never
// turn a generic session_id, thread.id, request.id, or step value into a
// session/turn/model/tool identity for every provider.
func applyConnectorNativeCorrelationV8(
	correlation *observability.Correlation,
	leaf otlpDecodedLeaf,
	authenticatedSource string,
) error {
	if correlation == nil {
		return errOTLPInboundMappingV8
	}
	spec := connector.DefaultCorrelationSpec(authenticatedSource)
	if spec.Connector != authenticatedSource || spec.NativeTelemetry.Stability == connector.NativeTelemetryNone {
		return nil
	}
	attributes, err := nativeOTLPDeclaredAttributes(leaf, spec)
	if err != nil {
		return errOTLPInboundMappingV8
	}
	values := spec.NativeOTLPValues(attributes)
	return applyConnectorNativeCorrelationValuesV8(correlation, values)
}

// applyConnectorNativeCorrelationValuesV8 projects the exact values already
// accepted by the native occurrence transaction. Keeping this as a separate
// step prevents the canonical record from resolving a different profile than
// the durable ledger when an installed connector is version-locked.
func applyConnectorNativeCorrelationValuesV8(
	correlation *observability.Correlation,
	values []connector.CorrelationValue,
) error {
	if correlation == nil {
		return errOTLPInboundMappingV8
	}
	if err := connector.ValidateCorrelationValues(values); err != nil {
		return errOTLPInboundMappingV8
	}
	for _, value := range values {
		var destination *string
		switch value.Target {
		case connector.CorrelationTargetSession:
			destination = &correlation.SessionID
		case connector.CorrelationTargetTurn:
			destination = &correlation.TurnID
		case connector.CorrelationTargetAgent:
			destination = &correlation.AgentID
		case connector.CorrelationTargetModelRequest:
			destination = &correlation.ModelRequestID
		case connector.CorrelationTargetModelResponse:
			destination = &correlation.ModelResponseID
		case connector.CorrelationTargetTool:
			destination = &correlation.ToolInvocationID
		default:
			continue
		}
		// A profile may preserve multiple differently typed IDs for one broad
		// target. Binding order is its canonical preference: connector-specific
		// declarations follow generic fallbacks, so the last applicable value is
		// projected while every typed value remains available to the ledger.
		*destination = value.Value
	}
	return nil
}

// inboundGeneratedStringValue resolves one canonical string only through the
// exact generated direct field or alias set. It is deliberately not a global
// synonym list: a match that lacks the capability always returns absent.
func inboundGeneratedStringValue(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	targetKey string,
	authenticatedSource string,
) (string, otlpTypedAttributeState) {
	for _, alias := range match.Aliases() {
		if alias.Target() != targetKey || alias.ValueType() != observability.InboundValueString {
			continue
		}
		value, state := inboundAliasAnyValue(leaf, alias, authenticatedSource)
		if state != otlpTypedAttributeUnique {
			return "", state
		}
		text, ok := value.GetValue().(*commonpb.AnyValue_StringValue)
		if !ok {
			return "", otlpTypedAttributeInvalid
		}
		return text.StringValue, state
	}
	if inboundMatchDeclaresField(match, targetKey) {
		return leaf.attributes().stringValue(targetKey)
	}
	return "", otlpTypedAttributeAbsent
}

func (a *APIServer) importOTLPLogTargetV8(
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
	importContext, ok := target.ImportContext()
	if !ok || leaf.logRecord == nil {
		result.invalidRecord = true
		return result
	}
	metadataSeverity, err := inboundLogMetadataSeverityV8(leaf, match)
	if err != nil {
		result.invalidMapped = true
		return result
	}
	metadata, err := router.NewInboundImportedLogMetadata(
		target, importContext, metadataSeverity, authenticatedSource,
	)
	if err != nil {
		result.invalidRecord = true
		return result
	}
	mapFailed, buildFailed := false, false
	policy, err := inboundOptionalExportPolicyV8(leaf, match, wire)
	if err != nil {
		result.invalidRecord = true
		return result
	}
	outcome, emitErr := batch.EmitImportedLog(ctx, metadata, policy, func(
		snapshot observabilityruntime.EmitContext,
		admission router.Admission,
	) (observability.Record, error) {
		result.collected = true
		if admission != router.AdmissionOrdinary {
			buildFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		input, err := a.mapInboundLogV8(
			ctx, leaf, match, target, wire, authenticatedSource, receipt, snapshot,
		)
		if err != nil {
			mapFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		result.unknownDropped, err = inboundUnknownLogCountV8(leaf, match, target)
		if err != nil {
			mapFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		builder, err := newInboundBuilderV8()
		if err != nil {
			buildFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		record, err := builder.BuildLog(target, importContext, input)
		if err != nil {
			buildFailed = true
			return observability.Record{}, err
		}
		actual, actualPresent := record.Severity()
		if metadataSeverity == nil && actualPresent || metadataSeverity != nil && (!actualPresent || actual != *metadataSeverity) {
			buildFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		return record, nil
	})
	switch {
	case !result.collected && emitErr == nil:
		return result
	case mapFailed:
		result.invalidMapped = true
	case buildFailed:
		result.invalidRecord = true
	case outcome.LocalPersisted():
		result.recorded = true
		result.deliveryDegraded = emitErr != nil
	case emitErr != nil || !outcome.LocalPersisted():
		result.persistenceFailed = true
	}
	return result
}

func inboundKnownKeysV8(
	match observability.InboundMatch,
	target observability.InboundTarget,
	location observability.InboundLocation,
) map[string]struct{} {
	known := make(map[string]struct{})
	for _, predicate := range match.Predicates() {
		if predicate.Location() == location && predicate.Key() != "" && predicate.Key()[0] != '$' {
			known[predicate.Key()] = struct{}{}
		}
	}
	if location == observability.InboundLocationLeafAttribute ||
		location == observability.InboundLocationMetricPointAttribute {
		for _, field := range target.Fields() {
			known[field.FieldRef()] = struct{}{}
		}
		for _, alias := range match.Aliases() {
			for _, source := range alias.Sources() {
				if source != "" && source[0] != '$' {
					known[source] = struct{}{}
				}
			}
		}
		if override, present := match.TargetOverride(); present {
			known[override.Source()] = struct{}{}
		}
	}
	if location == observability.InboundLocationResourceAttribute {
		for _, field := range target.TraceResourceFields() {
			known[field.FieldRef()] = struct{}{}
		}
	}
	return known
}

func inboundUnknownLogCountV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
) (uint64, error) {
	count := uint64(inboundUnknownAttributeCount(
		leaf.leafAttributes,
		inboundKnownKeysV8(match, target, observability.InboundLocationLeafAttribute),
	))
	count += uint64(inboundUnknownAttributeCount(
		leaf.resource.attributes,
		inboundKnownKeysV8(match, target, observability.InboundLocationResourceAttribute),
	))
	count += uint64(leaf.scope.attributes.invalidCount() + len(leaf.scope.attributes.keys()))
	if match.Shape() != observability.InboundShapeNativeExact {
		return count, nil
	}
	text, ok := inboundLogBodyString(leaf.logRecord.GetBody())
	if !ok {
		return 0, errOTLPInboundMappingV8
	}
	var wire projectedLogRecordV8
	if err := decodeInboundStrictJSON([]byte(text), &wire); err != nil {
		return 0, err
	}
	members, err := decodeInboundJSONObject(wire.Body)
	if err != nil {
		return 0, err
	}
	knownBody := make(map[string]struct{})
	for _, field := range target.Fields() {
		knownBody[field.FieldRef()] = struct{}{}
	}
	for _, member := range members {
		if _, known := knownBody[member.name]; !known {
			count++
		}
	}
	return count, nil
}

func inboundOptionalExportPolicyV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	wire observability.InboundWireContract,
) (observabilityruntime.InboundOptionalExportPolicy, error) {
	forward, err := inboundForwardMetadataV8(leaf, wire, match.Shape() == observability.InboundShapeNativeExact)
	if err != nil {
		return observabilityruntime.InboundOptionalExportPolicy{}, errOTLPInboundMappingV8
	}
	if forward.hop == wire.MaxForwardHops {
		return observabilityruntime.SuppressAllInboundOptionalExport(), nil
	}
	if forward.instanceID == gatewaylog.SidecarInstanceID() && forward.destination != "" {
		return observabilityruntime.NewInboundOriginDestination(forward.destination)
	}
	return observabilityruntime.InboundOptionalExportPolicy{}, nil
}

func (a *APIServer) mapInboundLogV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
	snapshot observabilityruntime.EmitContext,
) (observability.InboundImportedLogInput, error) {
	provenance, err := inboundImportProvenanceV8(leaf, match, target, wire, authenticatedSource)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	timestamp, err := selectedInboundLogTime(leaf.logRecord, receipt)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	correlation, err := inboundCorrelationWithSnapshotV8(ctx, leaf, match, authenticatedSource, snapshot)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	localProvenance, err := inboundLocalProvenanceV8(snapshot)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	input := observability.InboundImportedLogInput{
		Timestamp: timestamp, ReceiptTime: receipt.UTC(),
		Correlation: correlation,
		Provenance:  localProvenance, Import: provenance,
	}
	if match.Shape() == observability.InboundShapeNativeExact {
		return mapInboundNativeLogV8(leaf, target, input)
	}
	input.Outcome = inboundFixedOutcome(match.OutcomeRule())
	input.Severity, input.LogLevel = inboundOTLPLogSeverity(leaf.logRecord)
	fields, selected, err := mapInboundAliasFieldsV8(leaf, match, target, authenticatedSource)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	// Connector aliases describe the minimum shape needed to recognize common
	// producer records. They are not an allowlist for the rest of the canonical
	// target contract. Preserve every additional, uniquely reported target field
	// (notably agent lineage, lifecycle/execution, request, turn, and operation
	// correlation) just as the trace importer does. The capability mapper still
	// rejects conflicting aliases and applies the generated field normalization;
	// unknown sender attributes remain excluded and accounted separately.
	directFields, directSelected, err := mapInboundFieldsFromCapabilitiesExcludingV8(
		target, target.Fields(), leaf.leafAttributes, selected,
	)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	fields = append(fields, directFields...)
	for key := range directSelected {
		selected[key] = true
	}
	if match.MappingStrategy() == observability.InboundMappingConnectorModelLog ||
		match.MappingStrategy() == observability.InboundMappingConnectorToolLog {
		expectedOperation := "chat"
		if match.MappingStrategy() == observability.InboundMappingConnectorToolLog {
			expectedOperation = "execute_tool"
		}
		operation, state := leaf.leafAttributes.stringValue("gen_ai.operation.name")
		if state != otlpTypedAttributeAbsent && (state != otlpTypedAttributeUnique || operation != expectedOperation) {
			return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
		}
		// Capability-preserving direct mapping may already have selected the
		// canonical operation field. Only synthesize the connector contract's
		// fixed operation when the sender omitted it; appending it twice
		// makes an otherwise valid imported record fail duplicate-field
		// validation.
		if !selected["gen_ai.operation.name"] {
			field, ok := inboundTargetFieldsByName(target)["gen_ai.operation.name"]
			if !ok {
				return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
			}
			fields = append(fields, observability.NewInboundMappedString(field, expectedOperation))
			selected["gen_ai.operation.name"] = true
		}
	}
	fields, _, err = a.enrichInboundWithHookLifecycleV8(
		leaf, target, authenticatedSource, &input.Correlation, fields, selected,
	)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	input.Fields = addInboundContentCompanions(target, fields, selected)
	return input, nil
}

func mapInboundNativeLogV8(
	leaf otlpDecodedLeaf,
	target observability.InboundTarget,
	input observability.InboundImportedLogInput,
) (observability.InboundImportedLogInput, error) {
	text, ok := inboundLogBodyString(leaf.logRecord.GetBody())
	if !ok || validateUniqueOTLPJSONMembers([]byte(text)) != nil {
		return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var wire projectedLogRecordV8
	if err := decoder.Decode(&wire); err != nil {
		return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
	}
	if token, err := decoder.Token(); !errors.Is(err, io.EOF) || token != nil {
		return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
	}
	var correlation observability.Correlation
	if err := decodeInboundStrictJSON(wire.Correlation, &correlation); err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	input.Correlation = correlation
	if severity, present, valid := projectedOptionalString(wire.Severity); present {
		if !valid {
			return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
		}
		input.Severity = observability.Present(observability.Severity(severity))
	}
	if level, present, valid := projectedOptionalString(wire.LogLevel); present {
		if !valid {
			return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
		}
		input.LogLevel = observability.Present(observability.LogLevel(level))
	}
	if outcome, present, valid := projectedOptionalString(wire.Outcome); present {
		if !valid {
			return observability.InboundImportedLogInput{}, errOTLPInboundMappingV8
		}
		input.Outcome = observability.Present(observability.Outcome(outcome))
	}
	var projection projectedLogMetadataV8
	if err := decodeInboundStrictJSON(wire.Projection, &projection); err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	input.Import.UpstreamRedactionProfile = projection.RedactionProfile
	members, err := decodeInboundJSONObject(wire.Body)
	if err != nil {
		return observability.InboundImportedLogInput{}, err
	}
	for _, field := range target.Fields() {
		if _, supported := target.MappedValueKind(field); !supported {
			continue
		}
		raw, present := inboundJSONMember(members, field.FieldRef())
		if !present {
			continue
		}
		value, err := inboundJSONAnyValue(raw, 0)
		if err != nil {
			return observability.InboundImportedLogInput{}, err
		}
		mapped, err := inboundMappedFieldFromAny(target, field, value)
		if err != nil {
			return observability.InboundImportedLogInput{}, err
		}
		input.Fields = append(input.Fields, mapped)
	}
	return input, nil
}

func decodeInboundStrictJSON(raw []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errOTLPInboundMappingV8
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return errOTLPInboundMappingV8
	}
	return nil
}

func inboundFixedOutcome(rule observability.InboundOutcomeRule) observability.Optional[observability.Outcome] {
	if outcome, ok := rule.Fixed(); ok {
		return observability.Present(outcome)
	}
	return observability.Absent[observability.Outcome]()
}

func inboundOTLPLogSeverity(record *logspb.LogRecord) (
	observability.Optional[observability.Severity],
	observability.Optional[observability.LogLevel],
) {
	if record == nil {
		return observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel]()
	}
	switch number := record.GetSeverityNumber(); {
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_FATAL:
		return observability.Present(observability.SeverityCritical), observability.Present(observability.LogLevelFatal)
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_ERROR:
		return observability.Present(observability.SeverityHigh), observability.Present(observability.LogLevelError)
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_WARN:
		return observability.Present(observability.SeverityMedium), observability.Present(observability.LogLevelWarn)
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_INFO:
		return observability.Present(observability.SeverityInfo), observability.Present(observability.LogLevelInfo)
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_DEBUG:
		return observability.Present(observability.SeverityInfo), observability.Present(observability.LogLevelDebug)
	case number >= logspb.SeverityNumber_SEVERITY_NUMBER_TRACE:
		return observability.Present(observability.SeverityInfo), observability.Present(observability.LogLevelTrace)
	default:
		return observability.Absent[observability.Severity](), observability.Absent[observability.LogLevel]()
	}
}

func inboundLogMetadataSeverityV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
) (*observability.Severity, error) {
	if match.Shape() != observability.InboundShapeNativeExact {
		severity, _ := inboundOTLPLogSeverity(leaf.logRecord)
		if value, present := severity.Get(); present {
			copyValue := value
			return &copyValue, nil
		}
		return nil, nil
	}
	text, ok := inboundLogBodyString(leaf.logRecord.GetBody())
	if !ok {
		return nil, errOTLPInboundMappingV8
	}
	decoder := json.NewDecoder(strings.NewReader(text))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var wire projectedLogRecordV8
	if err := decoder.Decode(&wire); err != nil {
		return nil, errOTLPInboundMappingV8
	}
	severity, present, valid := projectedOptionalString(wire.Severity)
	if !present {
		return nil, nil
	}
	if !valid {
		return nil, errOTLPInboundMappingV8
	}
	value := observability.Severity(severity)
	if _, ok := observability.SeverityRank(value); !ok {
		return nil, errOTLPInboundMappingV8
	}
	return &value, nil
}

func mapInboundAliasFieldsV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	authenticatedSource string,
) ([]observability.InboundMappedField, map[string]bool, error) {
	fields := inboundTargetFieldsByName(target)
	result := make([]observability.InboundMappedField, 0, len(match.Aliases()))
	selected := make(map[string]bool)
	for _, alias := range match.Aliases() {
		if strings.HasPrefix(alias.Target(), "$") {
			continue
		}
		field, ok := fields[alias.Target()]
		if !ok {
			// A match may feed multiple generated targets with different field
			// capabilities (for example, a tool span and its duration
			// derivative). An alias has authority only when this sealed target
			// exposes its target field; other source values remain unknown input
			// for this target and are handled by drop-and-count accounting.
			continue
		}
		value, state := inboundAliasAnyValue(leaf, alias, authenticatedSource)
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
		selected[alias.Target()] = true
	}
	return result, selected, nil
}

func inboundAliasAnyValue(
	leaf otlpDecodedLeaf,
	alias observability.InboundAlias,
	authenticatedSource string,
) (*commonpb.AnyValue, otlpTypedAttributeState) {
	var selected *commonpb.AnyValue
	selectedState := otlpTypedAttributeAbsent
	var fallbacks []string
	for _, source := range alias.Sources() {
		if strings.HasPrefix(source, "$") {
			fallbacks = append(fallbacks, source)
			continue
		}
		var value *commonpb.AnyValue
		var state otlpTypedAttributeState
		value, state = leaf.attributes().lookup(source)
		if state == otlpTypedAttributeAbsent {
			continue
		}
		if state != otlpTypedAttributeUnique {
			return nil, otlpTypedAttributeInvalid
		}
		value, ok := normalizeInboundAliasValueV8(value, alias, authenticatedSource)
		if !ok {
			return nil, otlpTypedAttributeInvalid
		}
		if selectedState == otlpTypedAttributeUnique && !proto.Equal(selected, value) {
			return nil, otlpTypedAttributeDuplicate
		}
		selected, selectedState = value, otlpTypedAttributeUnique
	}
	if selectedState == otlpTypedAttributeUnique {
		return selected, selectedState
	}
	for _, source := range fallbacks {
		switch source {
		case "$authenticated_source":
			return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: authenticatedSource}}, otlpTypedAttributeUnique
		case "$scalar_log_body":
			if text, ok := inboundLogBodyString(leaf.logRecord.GetBody()); ok {
				return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: text}}, otlpTypedAttributeUnique
			}
		}
	}
	return selected, selectedState
}

// normalizeInboundAliasValueV8 applies only transformations named by the
// generated alias contract. Codex emits response token counters and tool fields
// through tracing's display formatter, so numeric counters and structured tool
// payloads arrive as strings. Accept those vendor shapes only for the exact
// authenticated Codex aliases; every other source and alias retains the
// ordinary exact-arm contract.
func normalizeInboundAliasValueV8(
	value *commonpb.AnyValue,
	alias observability.InboundAlias,
	authenticatedSource string,
) (*commonpb.AnyValue, bool) {
	if authenticatedSource == "codex" {
		switch alias.ID() {
		case "codex-tool-arguments-v1":
			return normalizeCodexToolPayloadV8(value, "raw")
		case "codex-tool-result-v1":
			return normalizeCodexToolPayloadV8(value, "content")
		}
	}
	if inboundAliasValueType(value, alias.ValueType()) {
		return value, true
	}
	if authenticatedSource != "codex" || alias.Normalization() != "nonnegative-int64-v1" {
		return nil, false
	}
	switch alias.ID() {
	case "input-tokens-v1", "output-tokens-v1", "cached-input-tokens-v1":
	default:
		return nil, false
	}
	text, ok := value.GetValue().(*commonpb.AnyValue_StringValue)
	if !ok || text.StringValue == "" {
		return nil, false
	}
	for _, digit := range text.StringValue {
		if digit < '0' || digit > '9' {
			return nil, false
		}
	}
	parsed, err := strconv.ParseInt(text.StringValue, 10, 64)
	if err != nil || parsed < 0 {
		return nil, false
	}
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: parsed}}, true
}

func normalizeCodexToolPayloadV8(value *commonpb.AnyValue, scalarKey string) (*commonpb.AnyValue, bool) {
	if value == nil || (scalarKey != "raw" && scalarKey != "content") {
		return nil, false
	}
	if object, ok := value.Value.(*commonpb.AnyValue_KvlistValue); ok {
		return value, object.KvlistValue != nil
	}
	text, ok := value.Value.(*commonpb.AnyValue_StringValue)
	if !ok {
		return nil, false
	}
	if json.Valid([]byte(text.StringValue)) {
		parsed, err := inboundJSONAnyValue([]byte(text.StringValue), 0)
		if err == nil {
			if object, isObject := parsed.Value.(*commonpb.AnyValue_KvlistValue); isObject && object.KvlistValue != nil {
				return parsed, true
			}
		}
	}
	return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{
		KvlistValue: &commonpb.KeyValueList{Values: []*commonpb.KeyValue{{
			Key: scalarKey,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
				StringValue: text.StringValue,
			}},
		}}},
	}}, true
}

func inboundAliasValueType(value *commonpb.AnyValue, want observability.InboundValueType) bool {
	if value == nil {
		return false
	}
	switch want {
	case observability.InboundValueString:
		_, ok := value.Value.(*commonpb.AnyValue_StringValue)
		return ok
	case observability.InboundValueInt64:
		integer, ok := value.Value.(*commonpb.AnyValue_IntValue)
		return ok && integer.IntValue >= 0
	case observability.InboundValueDouble:
		switch number := value.Value.(type) {
		case *commonpb.AnyValue_DoubleValue:
			return !math.IsNaN(number.DoubleValue) && !math.IsInf(number.DoubleValue, 0) && number.DoubleValue > 0
		case *commonpb.AnyValue_IntValue:
			return number.IntValue > 0
		default:
			return false
		}
	case observability.InboundValueStructured:
		switch value.Value.(type) {
		case *commonpb.AnyValue_StringValue, *commonpb.AnyValue_ArrayValue, *commonpb.AnyValue_KvlistValue:
			return true
		default:
			return false
		}
	default:
		return false
	}
}

func inboundTargetFieldsByName(target observability.InboundTarget) map[string]observability.InboundTargetField {
	result := make(map[string]observability.InboundTargetField)
	for _, field := range target.Fields() {
		if _, supported := target.MappedValueKind(field); supported {
			result[field.FieldRef()] = field
		}
	}
	return result
}

func addInboundContentCompanions(
	target observability.InboundTarget,
	fields []observability.InboundMappedField,
	selected map[string]bool,
) []observability.InboundMappedField {
	capabilities := inboundTargetFieldsByName(target)
	appendBoolean := func(key string, value bool) {
		if field, ok := capabilities[key]; ok && !selected[key] {
			fields = append(fields, observability.NewInboundMappedBoolean(field, value))
			selected[key] = true
		}
	}
	appendString := func(key, value string) {
		if field, ok := capabilities[key]; ok && !selected[key] {
			fields = append(fields, observability.NewInboundMappedString(field, value))
			selected[key] = true
		}
	}
	inputReported := selected["gen_ai.input.messages"]
	outputReported := selected["gen_ai.output.messages"]
	appendBoolean("defenseclaw.telemetry.input.reported", inputReported)
	appendString("defenseclaw.content.input.state", map[bool]string{true: "preserved", false: "not_reported"}[inputReported])
	appendBoolean("defenseclaw.telemetry.output.reported", outputReported)
	appendString("defenseclaw.content.output.state", map[bool]string{true: "preserved", false: "not_reported"}[outputReported])
	appendBoolean("defenseclaw.telemetry.tokens.reported",
		selected["gen_ai.usage.input_tokens"] || selected["gen_ai.usage.output_tokens"])
	return fields
}
