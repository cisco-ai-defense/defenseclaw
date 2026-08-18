// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

func (a *APIServer) importOTLPMetricTargetV8(
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
	policy, err := inboundOptionalExportPolicyV8(leaf, match, wire)
	if err != nil {
		result.invalidRecord = true
		return result
	}
	mapFailed, buildFailed, constructed := false, false, false
	delivery, err := batch.RecordMetricWithPolicy(ctx, target, authenticatedSource, policy, func(
		snapshot observabilityruntime.EmitContext,
	) (observability.Record, error) {
		result.collected = true
		input, unknownDropped, err := mapInboundNativeMetricV8(
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
		record, err := builder.BuildMetric(target, input)
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
		result.recorded = true
		result.deliveryDegraded = delivery.Failed > 0
	}
	return result
}

func mapInboundNativeMetricV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
	snapshot observabilityruntime.EmitContext,
) (observability.InboundImportedMetricInput, uint64, error) {
	if match.Shape() != observability.InboundShapeNativeExact || leaf.metric == nil {
		return observability.InboundImportedMetricInput{}, 0, errOTLPInboundMappingV8
	}
	provenance, err := inboundImportProvenanceV8(leaf, match, target, wire, authenticatedSource)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	fields, _, err := mapInboundDirectFieldsV8(target, leaf.metricPointAttributes)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	value, err := inboundMetricPointValueV8(leaf)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	var source observability.InboundMetricSourceFacts
	switch leaf.metricShape {
	case otlpTypedMetricGauge:
		source = observability.NewInboundMetricGaugeSource(leaf.metric.GetUnit())
	case otlpTypedMetricSum:
		sum := leaf.metric.GetSum()
		if sum == nil || sum.GetAggregationTemporality() != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA {
			return observability.InboundImportedMetricInput{}, 0, errOTLPInboundMappingV8
		}
		source = observability.NewInboundMetricDeltaSumSource(leaf.metric.GetUnit(), sum.GetIsMonotonic())
	default:
		return observability.InboundImportedMetricInput{}, 0, errOTLPInboundMappingV8
	}
	unknown := inboundUnknownMetricCountV8(leaf, match, target)
	timestamp, err := selectedInboundMetricTime(leaf, receipt)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	correlation, err := inboundCorrelationWithSnapshotV8(ctx, leaf, match, authenticatedSource, snapshot)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	localProvenance, err := inboundLocalProvenanceV8(snapshot)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, err
	}
	return observability.InboundImportedMetricInput{
		Timestamp: timestamp, ReceiptTime: receipt.UTC(),
		Correlation: correlation,
		Provenance:  localProvenance, Import: provenance,
		SourcePoint: source, Value: value, Fields: fields,
	}, unknown, nil
}

func (a *APIServer) deriveOTLPMetricTargetV8(
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
	policy, err := inboundOptionalExportPolicyV8(leaf, match, wire)
	if err != nil {
		result.invalidRecord = true
		return result
	}
	variants := []string{""}
	if target.DerivationStrategy() == observability.InboundDerivationCodexTokenFields {
		variants = []string{"input", "cacheRead", "output"}
	}
	for _, variant := range variants {
		one := a.deriveOTLPMetricObservationV8(
			ctx, batch, leaf, match, target, policy, wire, authenticatedSource, receipt, variant,
		)
		result.collected = result.collected || one.collected
		result.recorded = result.recorded || one.recorded
		result.deduplicated = result.deduplicated || one.deduplicated
		result.acceptedNoObservation = result.acceptedNoObservation || one.acceptedNoObservation
		result.invalidMapped = result.invalidMapped || one.invalidMapped
		result.invalidRecord = result.invalidRecord || one.invalidRecord
		result.deliveryDegraded = result.deliveryDegraded || one.deliveryDegraded
		if one.unknownDropped > result.unknownDropped {
			result.unknownDropped = one.unknownDropped
		}
	}
	return result
}

func (a *APIServer) deriveOTLPMetricObservationV8(
	ctx context.Context,
	batch *observabilityruntime.InboundImportBatch,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	policy observabilityruntime.InboundOptionalExportPolicy,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
	variant string,
) otlpInboundTargetResult {
	result := otlpInboundTargetResult{}
	mapFailed, buildFailed, noObservation, deduplicated := false, false, false, false
	validZeroNoObservation := inboundCodexZeroTokenHistogramV8(leaf, match, target)
	delivery, recordErr := batch.RecordMetricWithPolicy(ctx, target, authenticatedSource, policy, func(
		snapshot observabilityruntime.EmitContext,
	) (observability.Record, error) {
		result.collected = true
		// A truthful Codex zero point is fully classified by the exact source
		// contract, but it has no positive counter observation to construct. Stop
		// before ordinary metric-source validation, which intentionally rejects
		// non-positive histogram sums for every other producer and class.
		if validZeroNoObservation {
			return observability.Record{}, errOTLPInboundMappingV8
		}
		input, unknownDropped, absent, duplicate, err := a.mapInboundDerivedMetricV8(
			ctx, leaf, match, target, wire, authenticatedSource, receipt, snapshot, variant,
		)
		result.unknownDropped = unknownDropped
		if absent || duplicate {
			noObservation, deduplicated = absent, duplicate
			return observability.Record{}, errOTLPInboundMappingV8
		}
		if err != nil {
			mapFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		builder, err := newInboundBuilderV8()
		if err != nil {
			buildFailed = true
			return observability.Record{}, errOTLPInboundMappingV8
		}
		record, err := builder.BuildMetric(target, input)
		if err != nil {
			buildFailed = true
			return observability.Record{}, err
		}
		return record, nil
	})
	if validZeroNoObservation && result.collected {
		// The callback's deliberate rejection is only a collection-policy probe;
		// the exact zero leaf is consumed successfully without constructing a
		// canonical counter observation.
		result.acceptedNoObservation = true
		return result
	}
	switch {
	case !result.collected && recordErr == nil:
		return result
	case deduplicated:
		result.deduplicated = true
	case noObservation:
		// Optional augmentation absent on this otherwise valid source leaf.
		// It is not a malformed derivative and its sibling may still record.
		result.acceptedNoObservation = true
	case mapFailed:
		result.invalidMapped = true
	case buildFailed:
		result.invalidRecord = true
	case recordErr != nil:
		result.deliveryDegraded = true
	default:
		result.recorded = true
		result.deliveryDegraded = delivery.Failed > 0
	}
	return result
}

func (a *APIServer) mapInboundDerivedMetricV8(
	ctx context.Context,
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	wire observability.InboundWireContract,
	authenticatedSource string,
	receipt time.Time,
	snapshot observabilityruntime.EmitContext,
	variant string,
) (observability.InboundImportedMetricInput, uint64, bool, bool, error) {
	provenance, err := inboundImportProvenanceV8(leaf, match, target, wire, authenticatedSource)
	if err != nil {
		return observability.InboundImportedMetricInput{}, 0, false, false, err
	}
	value, source, timestamp, absent, duplicate, err := a.inboundDerivedMetricSourceV8(
		leaf, match, target, authenticatedSource, receipt, variant,
	)
	unknown := inboundUnknownMetricCountV8(leaf, match, target)
	if err != nil || absent || duplicate {
		return observability.InboundImportedMetricInput{}, unknown, absent, duplicate, err
	}
	correlation, err := inboundCorrelationWithSnapshotV8(ctx, leaf, match, authenticatedSource, snapshot)
	if err != nil {
		return observability.InboundImportedMetricInput{}, unknown, false, false, err
	}
	fields, hookFound, err := a.inboundDerivedMetricFieldsV8(
		leaf, match, target, authenticatedSource, variant, &correlation,
	)
	if err != nil {
		return observability.InboundImportedMetricInput{}, unknown, false, false, err
	}
	if target.DescriptorID() == "metric.defenseclaw.agent.token.usage" && !hookFound {
		return observability.InboundImportedMetricInput{}, unknown, true, false, nil
	}
	localProvenance, err := inboundLocalProvenanceV8(snapshot)
	if err != nil {
		return observability.InboundImportedMetricInput{}, unknown, false, false, err
	}
	return observability.InboundImportedMetricInput{
		Timestamp: timestamp, ReceiptTime: receipt.UTC(),
		Correlation: correlation,
		Provenance:  localProvenance, Import: provenance,
		SourcePoint: source, Value: value, Fields: fields,
	}, unknown, false, false, nil
}

func (a *APIServer) inboundDerivedMetricSourceV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	authenticatedSource string,
	receipt time.Time,
	variant string,
) (observability.InboundMetricValue, observability.InboundMetricSourceFacts, time.Time, bool, bool, error) {
	switch target.DerivationStrategy() {
	case observability.InboundDerivationCodexTokenFields:
		aliasTarget := "gen_ai.usage.input_tokens"
		if variant == "cacheRead" {
			aliasTarget = "$derived_cached_input_tokens"
		} else if variant == "output" {
			aliasTarget = "gen_ai.usage.output_tokens"
		} else if variant != "input" {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, errOTLPInboundMappingV8
		}
		value, state := inboundAliasTargetValueV8(leaf, match, aliasTarget, authenticatedSource)
		if state == otlpTypedAttributeAbsent {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, true, false, nil
		}
		integer, ok := value.GetValue().(*commonpb.AnyValue_IntValue)
		if state != otlpTypedAttributeUnique || !ok || integer.IntValue < 0 {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, errOTLPInboundMappingV8
		}
		if integer.IntValue == 0 {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, true, false, nil
		}
		timestamp, err := selectedInboundLogTime(leaf.logRecord, receipt)
		return observability.NewInboundMetricInt64Value(integer.IntValue),
			observability.NewInboundMetricMappedFieldSource(), timestamp, false, false, err
	case observability.InboundDerivationFieldValue:
		seconds, state := inboundDurationAliasSecondsV8(leaf, match)
		if state == otlpTypedAttributeAbsent {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, true, false, nil
		}
		if state != otlpTypedAttributeUnique || seconds <= 0 || math.IsNaN(seconds) || math.IsInf(seconds, 0) {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, errOTLPInboundMappingV8
		}
		timestamp, err := selectedInboundLogTime(leaf.logRecord, receipt)
		return observability.NewInboundMetricDoubleValue(seconds),
			observability.NewInboundMetricMappedFieldSource(), timestamp, false, false, err
	case observability.InboundDerivationElapsedTime:
		if leaf.span == nil || leaf.span.GetEndTimeUnixNano() <= leaf.span.GetStartTimeUnixNano() {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, errOTLPInboundMappingV8
		}
		endTime, err := inboundTimeFromUnixNano(leaf.span.GetEndTimeUnixNano())
		if err != nil {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, err
		}
		seconds := float64(leaf.span.GetEndTimeUnixNano()-leaf.span.GetStartTimeUnixNano()) / float64(time.Second)
		return observability.NewInboundMetricDoubleValue(seconds),
			observability.NewInboundMetricElapsedTimeSource(), endTime, false, false, nil
	case observability.InboundDerivationClaudeTokenUsage:
		source, adjusted, duplicate, err := a.inboundClaudeTokenSourceV8(
			leaf, target, authenticatedSource,
		)
		if err != nil {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, err
		}
		value, err := inboundMetricPointValueV8(leaf)
		if leaf.metricShape == otlpTypedMetricHistogram && leaf.histogramPoint != nil &&
			leaf.histogramPoint.Sum != nil {
			value = observability.NewInboundMetricDoubleValue(leaf.histogramPoint.GetSum())
			err = nil
		}
		if adjusted != nil {
			value = observability.NewInboundMetricInt64Value(*adjusted)
		}
		timestamp, timestampErr := selectedInboundMetricTime(leaf, receipt)
		if err == nil {
			err = timestampErr
		}
		return value, source, timestamp, false, duplicate, err
	case observability.InboundDerivationDurationMetric:
		value, source, err := inboundDurationMetricSourceV8(leaf)
		timestamp, timestampErr := selectedInboundMetricTime(leaf, receipt)
		if err == nil {
			err = timestampErr
		}
		return value, source, timestamp, false, false, err
	default:
		return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, time.Time{}, false, false, errOTLPInboundMappingV8
	}
}

func inboundCodexZeroTokenHistogramV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
) bool {
	if match.ClassID() != "otlp.codex.token_usage.v1" ||
		target.DescriptorID() != "metric.gen_ai.client.token.usage" ||
		leaf.metricShape != otlpTypedMetricHistogram || leaf.histogramPoint == nil {
		return false
	}
	point := leaf.histogramPoint
	return point.GetCount() > 0 && point.Sum != nil && point.GetSum() == 0 &&
		!math.IsNaN(point.GetSum()) && !math.IsInf(point.GetSum(), 0)
}

func inboundMetricPointValueV8(leaf otlpDecodedLeaf) (observability.InboundMetricValue, error) {
	if leaf.numberPoint == nil {
		return observability.InboundMetricValue{}, errOTLPInboundMappingV8
	}
	switch value := leaf.numberPoint.Value.(type) {
	case *metricspb.NumberDataPoint_AsInt:
		return observability.NewInboundMetricInt64Value(value.AsInt), nil
	case *metricspb.NumberDataPoint_AsDouble:
		if math.IsNaN(value.AsDouble) || math.IsInf(value.AsDouble, 0) {
			return observability.InboundMetricValue{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMetricDoubleValue(value.AsDouble), nil
	default:
		return observability.InboundMetricValue{}, errOTLPInboundMappingV8
	}
}

func inboundDurationMetricSourceV8(
	leaf otlpDecodedLeaf,
) (observability.InboundMetricValue, observability.InboundMetricSourceFacts, error) {
	unit := leaf.metric.GetUnit()
	switch leaf.metricShape {
	case otlpTypedMetricGauge:
		value, err := inboundMetricPointValueV8(leaf)
		return value, observability.NewInboundMetricGaugeSource(unit), err
	case otlpTypedMetricSum:
		value, err := inboundMetricPointValueV8(leaf)
		if err != nil || leaf.metric.GetSum() == nil {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, errOTLPInboundMappingV8
		}
		sum := leaf.metric.GetSum()
		switch sum.GetAggregationTemporality() {
		case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA:
			return value, observability.NewInboundMetricDeltaSumSource(unit, sum.GetIsMonotonic()), nil
		case metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE:
			return value, observability.NewInboundMetricCumulativeSumSource(unit, sum.GetIsMonotonic()), nil
		default:
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, errOTLPInboundMappingV8
		}
	case otlpTypedMetricHistogram:
		point := leaf.histogramPoint
		if point == nil || point.GetCount() == 0 || point.Sum == nil || point.GetSum() <= 0 ||
			math.IsNaN(point.GetSum()) || math.IsInf(point.GetSum(), 0) {
			return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, errOTLPInboundMappingV8
		}
		return observability.NewInboundMetricDoubleValue(point.GetSum()),
			observability.NewInboundMetricHistogramMeanSource(unit, point.GetCount()), nil
	default:
		return observability.InboundMetricValue{}, observability.InboundMetricSourceFacts{}, errOTLPInboundMappingV8
	}
}

func (a *APIServer) inboundClaudeTokenSourceV8(
	leaf otlpDecodedLeaf,
	target observability.InboundTarget,
	authenticatedSource string,
) (observability.InboundMetricSourceFacts, *int64, bool, error) {
	unit := leaf.metric.GetUnit()
	switch leaf.metricShape {
	case otlpTypedMetricGauge:
		return observability.NewInboundMetricGaugeSource(unit), nil, false, nil
	case otlpTypedMetricSum:
		sum := leaf.metric.GetSum()
		if sum == nil {
			return observability.InboundMetricSourceFacts{}, nil, false, errOTLPInboundMappingV8
		}
		if sum.GetAggregationTemporality() == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA {
			return observability.NewInboundMetricDeltaSumSource(unit, sum.GetIsMonotonic()), nil, false, nil
		}
		if sum.GetAggregationTemporality() != metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_CUMULATIVE ||
			!sum.GetIsMonotonic() || leaf.numberPoint == nil {
			return observability.InboundMetricSourceFacts{}, nil, false, errOTLPInboundMappingV8
		}
		integer, ok := leaf.numberPoint.Value.(*metricspb.NumberDataPoint_AsInt)
		if !ok || integer.AsInt <= 0 {
			return observability.InboundMetricSourceFacts{}, nil, false, errOTLPInboundMappingV8
		}
		seriesKey, startTime, err := inboundProjectedCumulativeSeriesV8(
			leaf, target, authenticatedSource,
		)
		if err != nil {
			return observability.InboundMetricSourceFacts{}, nil, false, err
		}
		usage := otelTokenUsage{
			tokens: integer.AsInt, cumulative: true,
			seriesKey: seriesKey,
			startTime: startTime,
		}
		delta, emit := a.deltaOTLPCumulativeTokenUsage(usage)
		if !emit {
			return observability.NewInboundMetricCumulativeDeltaSource(unit), nil, true, nil
		}
		return observability.NewInboundMetricCumulativeDeltaSource(unit), &delta.tokens, false, nil
	case otlpTypedMetricHistogram:
		point := leaf.histogramPoint
		if point == nil || point.GetCount() == 0 || point.Sum == nil || point.GetSum() <= 0 ||
			math.IsNaN(point.GetSum()) || math.IsInf(point.GetSum(), 0) {
			return observability.InboundMetricSourceFacts{}, nil, false, errOTLPInboundMappingV8
		}
		return observability.NewInboundMetricHistogramMeanSource(unit, point.GetCount()), nil, false, nil
	default:
		return observability.InboundMetricSourceFacts{}, nil, false, errOTLPInboundMappingV8
	}
}

func inboundProjectedCumulativeSeriesV8(
	leaf otlpDecodedLeaf,
	target observability.InboundTarget,
	authenticatedSource string,
) (string, string, error) {
	projection, present := target.SourceProjectionPlan()
	if !present {
		return "", "", errOTLPInboundMappingV8
	}
	series, present := projection.CumulativeSeries()
	if !present || series.Applicability() != "monotonic-cumulative-sum" ||
		leaf.metric == nil || leaf.numberPoint == nil {
		return "", "", errOTLPInboundMappingV8
	}
	components := series.Components()
	values := make([]observability.Optional[string], 0, len(components))
	for _, component := range components {
		value, available, err := inboundProjectedSourceValueV8(
			leaf, component.SourceGroups(), component.Normalizer(), component.AllowedValues(), authenticatedSource,
		)
		if err != nil {
			return "", "", err
		}
		if !available {
			if component.Requirement() == observability.InboundSourceRequired {
				return "", "", errOTLPInboundMappingV8
			}
			values = append(values, observability.Absent[string]())
			continue
		}
		values = append(values, observability.Present(value))
	}
	framed, err := series.FrameNormalized(values)
	if err != nil {
		return "", "", errOTLPInboundMappingV8
	}
	epoch := series.ResetEpoch()
	if epoch.IsIdentity() || epoch.Role() != "reset_only" ||
		epoch.Placement() != "metric_point_start_time" || epoch.Key() != "$start_time_unix_nano" ||
		epoch.Normalization() != "unsigned-epoch-nanos-v1" {
		return "", "", errOTLPInboundMappingV8
	}
	return stableLLMEventID("otlp-metric-v8", target.MatchID(), framed),
		strconv.FormatUint(leaf.numberPoint.GetStartTimeUnixNano(), 10), nil
}

func (a *APIServer) inboundDerivedMetricFieldsV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
	authenticatedSource, variant string,
	correlation *observability.Correlation,
) ([]observability.InboundMappedField, bool, error) {
	if projection, present := target.SourceProjectionPlan(); present {
		fields, selected, err := inboundProjectedMetricFieldsV8(
			leaf, target, projection, authenticatedSource,
		)
		if err != nil {
			return nil, false, err
		}
		return a.enrichInboundWithHookLifecycleV8(
			leaf, target, authenticatedSource, correlation, fields, selected,
		)
	}
	fields := inboundTargetFieldsByName(target)
	result := make([]observability.InboundMappedField, 0, len(fields))
	selected := make(map[string]bool)
	appendValue := func(key string, value *commonpb.AnyValue) error {
		field, ok := fields[key]
		if !ok || value == nil {
			return nil
		}
		mapped, err := inboundMappedFieldFromAny(target, field, value)
		if err == nil {
			result = append(result, mapped)
			selected[key] = true
		}
		return err
	}
	for _, alias := range match.Aliases() {
		if _, ok := fields[alias.Target()]; !ok {
			continue
		}
		value, state := inboundAliasAnyValue(leaf, alias, authenticatedSource)
		if state == otlpTypedAttributeAbsent {
			continue
		}
		if state != otlpTypedAttributeUnique {
			return nil, false, errOTLPInboundMappingV8
		}
		if err := appendValue(alias.Target(), value); err != nil {
			return nil, false, err
		}
	}
	// Preserve generated target-field order.  Map iteration here would make
	// construction and rejection order process-random for the same wire leaf.
	for _, targetField := range target.Fields() {
		key := targetField.FieldRef()
		if _, supported := fields[key]; !supported {
			continue
		}
		if selected[key] || key == "gen_ai.token.type" {
			continue
		}
		value, state := leaf.attributes().lookup(key)
		if state == otlpTypedAttributeAbsent {
			continue
		}
		if state != otlpTypedAttributeUnique {
			return nil, false, errOTLPInboundMappingV8
		}
		if err := appendValue(key, value); err != nil {
			return nil, false, err
		}
	}
	appendString := func(key, value string) error {
		return appendValue(key, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}})
	}
	if !selected["gen_ai.operation.name"] &&
		(target.DerivationStrategy() == observability.InboundDerivationCodexTokenFields ||
			target.DerivationStrategy() == observability.InboundDerivationFieldValue) {
		if err := appendString("gen_ai.operation.name", "chat"); err != nil {
			return nil, false, err
		}
	}
	if variant != "" {
		if err := appendString("gen_ai.token.type", variant); err != nil {
			return nil, false, err
		}
	} else if tokenType, state := leaf.metricPointAttributes.stringValue("type"); state == otlpTypedAttributeUnique {
		if err := appendString("gen_ai.token.type", tokenType); err != nil {
			return nil, false, err
		}
	}
	result, hookFound, err := a.enrichInboundWithHookLifecycleV8(
		leaf, target, authenticatedSource, correlation, result, selected,
	)
	return result, hookFound, err
}

func inboundProjectedMetricFieldsV8(
	leaf otlpDecodedLeaf,
	target observability.InboundTarget,
	projection observability.InboundSourceProjectionPlan,
	authenticatedSource string,
) ([]observability.InboundMappedField, map[string]bool, error) {
	if projection.TargetFamily() != target.DescriptorID() {
		return nil, nil, errOTLPInboundMappingV8
	}
	targetFields := inboundTargetFieldsByName(target)
	result := make([]observability.InboundMappedField, 0, len(projection.FieldRules()))
	selected := make(map[string]bool, len(projection.FieldRules()))
	for _, rule := range projection.FieldRules() {
		if rule.Disposition() == observability.InboundProjectionOmit {
			continue
		}
		if rule.Disposition() != observability.InboundProjectionProject {
			return nil, nil, errOTLPInboundMappingV8
		}
		field, exists := targetFields[rule.Target()]
		if !exists {
			return nil, nil, errOTLPInboundMappingV8
		}
		value, present, err := inboundProjectedSourceValueV8(
			leaf, rule.SourceGroups(), rule.Normalizer(), rule.AllowedValues(), authenticatedSource,
		)
		if err != nil {
			return nil, nil, err
		}
		if !present {
			if rule.Requirement() == observability.InboundSourceRequired {
				return nil, nil, errOTLPInboundMappingV8
			}
			continue
		}
		result = append(result, observability.NewInboundMappedString(field, value))
		selected[rule.Target()] = true
	}
	return result, selected, nil
}

func inboundProjectedSourceValueV8(
	leaf otlpDecodedLeaf,
	groups []observability.InboundSourceGroup,
	normalizer observability.InboundSourceNormalizer,
	allowed []string,
	authenticatedSource string,
) (string, bool, error) {
	for _, group := range groups {
		selected := ""
		present := false
		for _, key := range group.Keys() {
			raw, available, err := inboundProjectionSourceRawV8(
				leaf, group.Placement(), key, authenticatedSource,
			)
			if err != nil {
				return "", false, err
			}
			if !available {
				continue
			}
			normalized, valid := normalizer.Normalize(raw)
			if !valid || len(allowed) != 0 && !containsInboundProjectedValueV8(allowed, normalized) {
				return "", false, errOTLPInboundMappingV8
			}
			if present && normalized != selected {
				return "", false, errOTLPInboundMappingV8
			}
			selected, present = normalized, true
		}
		if present {
			return selected, true, nil
		}
	}
	return "", false, nil
}

func inboundProjectionSourceRawV8(
	leaf otlpDecodedLeaf,
	placement observability.InboundSourcePlacement,
	key string,
	authenticatedSource string,
) (string, bool, error) {
	switch placement {
	case observability.InboundSourceMetricPointAttribute:
		value, state := leaf.metricPointAttributes.stringValue(key)
		return inboundProjectionStringStateV8(value, state)
	case observability.InboundSourceResourceAttribute:
		value, state := leaf.resource.attributes.stringValue(key)
		return inboundProjectionStringStateV8(value, state)
	case observability.InboundSourceAuthenticated:
		if key != "$authenticated_source" || authenticatedSource == "" {
			return "", false, errOTLPInboundMappingV8
		}
		return authenticatedSource, true, nil
	case observability.InboundSourceFixed:
		if key == "" {
			return "", false, errOTLPInboundMappingV8
		}
		return key, true, nil
	case observability.InboundSourceInstrumentName:
		if key != "$instrument_name" || leaf.metric == nil || leaf.metric.GetName() == "" {
			return "", false, errOTLPInboundMappingV8
		}
		return leaf.metric.GetName(), true, nil
	default:
		return "", false, errOTLPInboundMappingV8
	}
}

func inboundProjectionStringStateV8(
	value string,
	state otlpTypedAttributeState,
) (string, bool, error) {
	switch state {
	case otlpTypedAttributeAbsent:
		return "", false, nil
	case otlpTypedAttributeUnique:
		return value, true, nil
	default:
		return "", false, errOTLPInboundMappingV8
	}
}

func containsInboundProjectedValueV8(values []string, candidate string) bool {
	for _, value := range values {
		if value == candidate {
			return true
		}
	}
	return false
}

func inboundAliasTargetValueV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target string,
	authenticatedSource string,
) (*commonpb.AnyValue, otlpTypedAttributeState) {
	for _, alias := range match.Aliases() {
		if alias.Target() == target {
			return inboundAliasAnyValue(leaf, alias, authenticatedSource)
		}
	}
	return nil, otlpTypedAttributeAbsent
}

func inboundDurationAliasSecondsV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
) (float64, otlpTypedAttributeState) {
	for _, alias := range match.Aliases() {
		if alias.Target() != "$derived_duration_seconds" || alias.Normalization() != "duration-seconds-v1" {
			continue
		}
		selected := 0.0
		state := otlpTypedAttributeAbsent
		for _, source := range alias.Sources() {
			value, valueState := leaf.attributes().lookup(source)
			if valueState == otlpTypedAttributeAbsent {
				continue
			}
			if valueState != otlpTypedAttributeUnique {
				return 0, valueState
			}
			number, ok := inboundPositiveDoubleV8(value)
			if !ok {
				return 0, otlpTypedAttributeInvalid
			}
			scale := 1.0
			if strings.HasSuffix(source, "_ms") || strings.HasSuffix(source, "_milliseconds") {
				scale = 0.001
			} else if strings.HasSuffix(source, "_ns") || strings.HasSuffix(source, "_nanos") {
				scale = 0.000000001
			}
			normalized := number * scale
			if state == otlpTypedAttributeUnique && selected != normalized {
				return 0, otlpTypedAttributeDuplicate
			}
			selected, state = normalized, otlpTypedAttributeUnique
		}
		return selected, state
	}
	return 0, otlpTypedAttributeAbsent
}

func inboundPositiveDoubleV8(value *commonpb.AnyValue) (float64, bool) {
	switch typed := value.GetValue().(type) {
	case *commonpb.AnyValue_IntValue:
		return float64(typed.IntValue), typed.IntValue > 0 && typed.IntValue <= 1<<53
	case *commonpb.AnyValue_DoubleValue:
		return typed.DoubleValue, typed.DoubleValue > 0 && !math.IsNaN(typed.DoubleValue) && !math.IsInf(typed.DoubleValue, 0)
	default:
		return 0, false
	}
}

func inboundUnknownMetricCountV8(
	leaf otlpDecodedLeaf,
	match observability.InboundMatch,
	target observability.InboundTarget,
) uint64 {
	pointKnown := inboundKnownKeysV8(match, target, observability.InboundLocationMetricPointAttribute)
	resourceKnown := inboundKnownKeysV8(match, target, observability.InboundLocationResourceAttribute)
	count := uint64(inboundUnknownAttributeCount(leaf.metricPointAttributes, pointKnown)) +
		uint64(inboundUnknownAttributeCount(leaf.resource.attributes, resourceKnown)) +
		uint64(leaf.scope.attributes.invalidCount()+len(leaf.scope.attributes.keys()))
	if leaf.signal == otelSignalLogs || leaf.signal == otelSignalTraces {
		count += uint64(inboundUnknownAttributeCount(
			leaf.leafAttributes,
			inboundKnownKeysV8(match, target, observability.InboundLocationLeafAttribute),
		))
	}
	return count
}
