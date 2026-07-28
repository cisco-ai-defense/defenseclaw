// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"
)

func TestInboundImportedSignalInputsExposeNoIdentityFloorOrUntypedAuthority(t *testing.T) {
	for _, input := range []any{InboundImportedTraceInput{}, InboundImportedMetricInput{}} {
		typeOf := reflect.TypeOf(input)
		for _, forbidden := range []string{
			"Bucket", "Signal", "EventName", "Family", "Mandatory", "Floor", "Body",
			"InstrumentData", "FieldClasses", "Source", "Connector", "Action", "Phase", "Producer",
			"Protocol", "BindingID", "Mode", "Derivation", "SourceAggregateCount",
		} {
			if _, present := typeOf.FieldByName(forbidden); present {
				t.Errorf("%s exposes forbidden %s authority", typeOf.Name(), forbidden)
			}
		}
	}
	for _, value := range []any{
		InboundTraceEventTarget{}, InboundMetricValue{}, InboundMetricSourceFacts{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Errorf("%s exposes mutable field %s", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
}

func TestOTLPInboundNativeSpanRoundTripOtherInstance(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	ids := &inboundImportOccurrenceIDs{}
	builder, err := NewInboundImportBuilder(ClockFunc(func() time.Time {
		t.Fatal("imported trace consulted the producer clock")
		return time.Time{}
	}), ids)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, target := range catalog.Targets() {
		if target.Signal() != SignalTraces {
			continue
		}
		count++
		if target.Role() != InboundTargetImport {
			t.Fatalf("trace target %s role = %s", target.ID(), target.Role())
		}
		input := validInboundImportedTraceInput(t, target)
		record, buildErr := builder.BuildTrace(target, input)
		if buildErr != nil {
			t.Fatalf("target %s source %s: %v", target.ID(), input.Import.AuthenticatedSource, buildErr)
		}
		if record.Identity() != (EventIdentity{Bucket: target.Bucket(), Signal: SignalTraces, Name: target.EventName()}) ||
			record.Mandatory() || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() ||
			record.Timestamp() != time.Unix(0, int64(input.EndTimeUnixNano)).UTC() {
			t.Fatalf("target %s constructed invalid trace envelope", target.ID())
		}
		provenance := record.Provenance()
		if provenance.Producer != inboundImportProducer || provenance.Import == nil ||
			provenance.Import.BindingID != target.MatchID() || provenance.Import.Mode != ImportModeImport ||
			provenance.Import.Derivation != "" || record.Source() != SourceOTelReceiver ||
			record.Connector() != input.Import.AuthenticatedSource {
			t.Fatalf("target %s provenance = %#v", target.ID(), provenance)
		}
		body, present := record.Body()
		if !present {
			t.Fatalf("target %s omitted body", target.ID())
		}
		object, objectErr := body.Object()
		if objectErr != nil {
			t.Fatal(objectErr)
		}
		if err := verifyFamilyFieldClassCoverage(object, record.FieldClasses()); err != nil {
			t.Fatalf("target %s field classes: %v", target.ID(), err)
		}
	}
	if count != 32 || ids.count.Load() != uint64(count) {
		t.Fatalf("trace targets/IDs = %d/%d, want 32/32", count, ids.count.Load())
	}
}

func TestInboundImportedTracePreservesNativeCustomAndMergesExternalResource(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	findTrace := func(matchID string) InboundTarget {
		t.Helper()
		for _, target := range catalog.Targets() {
			if target.Signal() == SignalTraces && target.Role() == InboundTargetImport &&
				target.MatchID() == matchID {
				return target
			}
		}
		t.Fatalf("trace target for match %s not found", matchID)
		return InboundTarget{}
	}
	builder, err := NewInboundImportBuilder(
		ClockFunc(func() time.Time { return time.Time{} }), &inboundImportOccurrenceIDs{},
	)
	if err != nil {
		t.Fatal(err)
	}

	native := findTrace("otlp.native.span.v8.span.config.reload")
	nativeInput := validInboundImportedTraceInput(t, native)
	nativeCustom, err := NewTelemetryCustomResourceAttributes(
		map[string]string{"operator.profile": "upstream"}, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	nativeInput.Resource.Custom = Present(nativeCustom)
	nativeRecord, err := builder.BuildTrace(native, nativeInput)
	if err != nil {
		t.Fatal(err)
	}
	nativeResource := inboundTraceResourceObject(t, nativeRecord)
	if attributes := nativeResource["attributes"].(map[string]any); attributes["operator.profile"] != "upstream" {
		t.Fatalf("native custom resource = %#v", attributes)
	}
	if nativeResource["schema_url"] != native.snapshot.wire.ResourceSchemaURL {
		t.Fatalf("native resource schema URL = %#v", nativeResource["schema_url"])
	}

	external := findTrace("otlp.genai.span.operation.v1.span.model.chat")
	externalInput := validInboundImportedTraceInput(t, external)
	localCustom, err := NewTelemetryCustomResourceAttributes(map[string]string{
		"operator.profile": "local", "operator.region": "east",
	}, true)
	if err != nil {
		t.Fatal(err)
	}
	externalInput.LocalResource, err = NewInboundLocalTraceResourceWithCustom(
		external, externalInput.Resource.Fields, localCustom,
	)
	if err != nil {
		t.Fatal(err)
	}
	sourceCustom, err := NewTelemetryCustomResourceAttributes(
		map[string]string{"operator.profile": "source"}, false,
	)
	if err != nil {
		t.Fatal(err)
	}
	externalInput.Resource.Custom = Present(sourceCustom)
	externalRecord, err := builder.BuildTrace(external, externalInput)
	if err != nil {
		t.Fatal(err)
	}
	externalResource := inboundTraceResourceObject(t, externalRecord)
	externalAttributes := externalResource["attributes"].(map[string]any)
	if externalAttributes["operator.profile"] != "source" || externalAttributes["operator.region"] != "east" {
		t.Fatalf("external custom precedence = %#v", externalAttributes)
	}
	if externalResource["schema_url"] != external.snapshot.wire.ResourceSchemaURL {
		t.Fatalf("external resource schema URL = %#v", externalResource["schema_url"])
	}
}

func inboundTraceResourceObject(t *testing.T, record Record) map[string]any {
	t.Helper()
	body, present := record.Body()
	if !present {
		t.Fatal("trace body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	resource, ok := object["resource"].(map[string]any)
	if !ok {
		t.Fatalf("trace resource = %#v", object["resource"])
	}
	return resource
}

func TestOTLPInboundNativeMetricReversibleShapesOnly(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	ids := &inboundImportOccurrenceIDs{}
	builder, err := NewInboundImportBuilder(ClockFunc(func() time.Time {
		t.Fatal("imported metric consulted the producer clock")
		return time.Time{}
	}), ids)
	if err != nil {
		t.Fatal(err)
	}
	imports, derives := 0, 0
	for _, target := range catalog.Targets() {
		if target.Signal() != SignalMetrics {
			continue
		}
		if target.Role() == InboundTargetDerive {
			derives++
		} else {
			imports++
		}
		input := validInboundImportedMetricInput(t, target)
		record, buildErr := builder.BuildMetric(target, input)
		if buildErr != nil {
			t.Fatalf("target %s: %v", target.ID(), buildErr)
		}
		if record.Identity() != (EventIdentity{Bucket: target.Bucket(), Signal: SignalMetrics, Name: target.EventName()}) ||
			record.Mandatory() || record.IsFloorOnly() || record.Timestamp() != input.Timestamp {
			t.Fatalf("target %s constructed invalid metric envelope", target.ID())
		}
		provenance := record.Provenance()
		wantMode := ImportModeImport
		wantDerivation := ImportDerivation("")
		if target.Role() == InboundTargetDerive {
			wantMode = ImportModeDerive
			switch target.DerivationStrategy() {
			case InboundDerivationElapsedTime:
				wantDerivation = ImportDerivationElapsedTime
			case InboundDerivationClaudeTokenUsage:
				if input.SourcePoint.kind == inboundMetricSourceHistogramMean {
					wantDerivation = ImportDerivationArithmeticMean
				} else {
					wantDerivation = ImportDerivationFieldValue
				}
			default:
				wantDerivation = ImportDerivationFieldValue
			}
		}
		if provenance.Import == nil || provenance.Import.Mode != wantMode ||
			provenance.Import.Derivation != wantDerivation || provenance.Import.BindingID != target.MatchID() {
			t.Fatalf("target %s provenance = %#v", target.ID(), provenance)
		}
	}
	if imports == 0 || derives == 0 || ids.count.Load() != uint64(imports+derives) {
		t.Fatalf("metric import/derive/IDs = %d/%d/%d, want nonempty imports and derives with one ID per record", imports, derives, ids.count.Load())
	}
}

func TestInboundDerivedMetricUnitScalingAndProvenanceAreSealed(t *testing.T) {
	catalog, _ := LoadInboundCatalog()
	builder, _ := NewInboundImportBuilder(
		ClockFunc(func() time.Time { return time.Time{} }), &inboundImportOccurrenceIDs{},
	)
	duration := mustInboundImportTarget(t, catalog,
		"otlp.genai.duration.metric.v1.gen-ai-client.metric.gen_ai.client.operation.duration")
	input := validInboundImportedMetricInput(t, duration)
	input.SourcePoint = NewInboundMetricGaugeSource("ms")
	input.Value = NewInboundMetricDoubleValue(2500)
	record, err := builder.BuildMetric(duration, input)
	if err != nil {
		t.Fatal(err)
	}
	if value := inboundMetricRecordValue(t, record); value != 2.5 {
		t.Fatalf("scaled duration = %v, want 2.5", value)
	}
	if provenance := record.Provenance().Import; provenance == nil ||
		provenance.Mode != ImportModeDerive || provenance.Derivation != ImportDerivationFieldValue ||
		provenance.SourceAggregateCount.IsPresent() {
		t.Fatalf("direct duration provenance = %#v", provenance)
	}

	input = validInboundImportedMetricInput(t, duration)
	input.SourcePoint = NewInboundMetricHistogramMeanSource("ms", 2)
	input.Value = NewInboundMetricDoubleValue(5000)
	record, err = builder.BuildMetric(duration, input)
	if err != nil {
		t.Fatal(err)
	}
	count, present := record.Provenance().Import.SourceAggregateCount.Get()
	if value := inboundMetricRecordValue(t, record); value != 2.5 ||
		record.Provenance().Import.Derivation != ImportDerivationArithmeticMean || !present || count != 2 {
		t.Fatalf("mean duration value/provenance = %v/%#v", value, record.Provenance().Import)
	}
	input.SourcePoint = NewInboundMetricHistogramMeanSource("ms", 0)
	if _, err := builder.BuildMetric(duration, input); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("zero aggregate count error = %v", err)
	}
	input.SourcePoint = NewInboundMetricGaugeSource("MS")
	if _, err := builder.BuildMetric(duration, input); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("unregistered unit spelling error = %v", err)
	}

	token := mustInboundImportTarget(t, catalog,
		"otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage.metric.gen_ai.client.token.usage")
	input = validInboundImportedMetricInput(t, token)
	input.SourcePoint = NewInboundMetricGaugeSource("token")
	input.Value = NewInboundMetricInt64Value(5)
	record, err = builder.BuildMetric(token, input)
	if err != nil || record.Provenance().Import.Derivation != ImportDerivationFieldValue ||
		record.Provenance().Import.SourceAggregateCount.IsPresent() {
		t.Fatalf("direct token provenance=%#v err=%v", record.Provenance().Import, err)
	}
	input = validInboundImportedMetricInput(t, token)
	input.SourcePoint = NewInboundMetricCumulativeDeltaSource("tokens")
	input.Value = NewInboundMetricInt64Value(7)
	record, err = builder.BuildMetric(token, input)
	if err != nil || inboundMetricRecordValue(t, record) != 7 ||
		record.Provenance().Import.Derivation != ImportDerivationCumulativeDelta {
		t.Fatalf("cumulative delta record=%#v err=%v", record.Provenance().Import, err)
	}
	input.SourcePoint = NewInboundMetricCumulativeSumSource("tokens", true)
	if _, err := builder.BuildMetric(token, input); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("raw cumulative token sum error = %v", err)
	}
}

func TestInboundDerivedMetricRejectsUnsealedSourceFactsBeforeOccurrence(t *testing.T) {
	catalog, _ := LoadInboundCatalog()
	duration := mustInboundImportTarget(t, catalog,
		"otlp.genai.duration.metric.v1.gen-ai-client.metric.gen_ai.client.operation.duration")
	token := mustInboundImportTarget(t, catalog,
		"otlp.claudecode.token_usage.v1.metric.gen_ai.client.token.usage.metric.gen_ai.client.token.usage")
	elapsed := mustInboundImportTarget(t, catalog,
		"otlp.genai.span.operation.v1.span.model.chat.metric.gen_ai.client.operation.duration")
	ids := &inboundImportOccurrenceIDs{}
	builder, _ := NewInboundImportBuilder(ClockFunc(func() time.Time { return time.Time{} }), ids)

	assertRejected := func(name string, target InboundTarget, input InboundImportedMetricInput) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			before := ids.count.Load()
			_, err := builder.BuildMetric(target, input)
			if !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
				t.Fatalf("error = %v, want invalid_metric", err)
			}
			if ids.count.Load() != before {
				t.Fatalf("invalid source consumed occurrence ID: before=%d after=%d", before, ids.count.Load())
			}
		})
	}
	for _, unit := range []string{"MS", " ms", "ms ", "minute", "\xff"} {
		input := validInboundImportedMetricInput(t, duration)
		input.SourcePoint = NewInboundMetricGaugeSource(unit)
		assertRejected("unit-"+safeInboundTestName(unit), duration, input)
	}
	for name, value := range map[string]float64{
		"nan": math.NaN(), "positive-inf": math.Inf(1), "negative-inf": math.Inf(-1),
	} {
		input := validInboundImportedMetricInput(t, duration)
		input.Value = NewInboundMetricDoubleValue(value)
		assertRejected(name, duration, input)
	}
	largeInteger := validInboundImportedMetricInput(t, token)
	largeInteger.Value = NewInboundMetricInt64Value(1<<53 + 1)
	assertRejected("lossy-integer-conversion", token, largeInteger)

	zeroCount := validInboundImportedMetricInput(t, duration)
	zeroCount.SourcePoint = NewInboundMetricHistogramMeanSource("s", 0)
	assertRejected("zero-histogram-count", duration, zeroCount)
	crossUse := []struct {
		name   string
		target InboundTarget
		source InboundMetricSourceFacts
	}{
		{name: "duration-as-mapped-field", target: duration, source: NewInboundMetricMappedFieldSource()},
		{name: "token-as-histogram", target: token, source: NewInboundMetricHistogramMeanSource("token", 2)},
		{name: "elapsed-as-gauge", target: elapsed, source: NewInboundMetricGaugeSource("s")},
	}
	for _, test := range crossUse {
		input := validInboundImportedMetricInput(t, test.target)
		input.SourcePoint = test.source
		assertRejected(test.name, test.target, input)
	}

	// The generated v1 tables intentionally use scales <= 1, so a real catalog
	// cannot overflow. Exercise the normalization guard with a privately cloned
	// capability whose generated rule is made adversarial; public callers cannot
	// construct or mutate this state.
	overflowTarget := cloneInboundTargetForScaleTest(duration, math.MaxFloat64)
	overflow := validInboundImportedMetricInput(t, overflowTarget)
	overflow.SourcePoint = NewInboundMetricGaugeSource("s")
	overflow.Value = NewInboundMetricDoubleValue(2)
	assertRejected("overflow-scaling-guard", overflowTarget, overflow)
}

func cloneInboundTargetForScaleTest(target InboundTarget, scale float64) InboundTarget {
	snapshot := *target.snapshot
	snapshot.targets = append([]inboundTargetEntry(nil), target.snapshot.targets...)
	snapshot.matches = append([]inboundMatchEntry(nil), target.snapshot.matches...)
	entry := snapshot.targets[target.index]
	match := snapshot.matches[entry.matchIndex]
	entry.sourceUnitRule = cloneInboundSourceUnitRule(entry.sourceUnitRule)
	match.sourceUnitRule = cloneInboundSourceUnitRule(match.sourceUnitRule)
	for index := range entry.sourceUnitRule.accepted {
		entry.sourceUnitRule.accepted[index].scale = scale
	}
	for index := range match.sourceUnitRule.accepted {
		match.sourceUnitRule.accepted[index].scale = scale
	}
	snapshot.targets[target.index] = entry
	snapshot.matches[entry.matchIndex] = match
	return InboundTarget{snapshot: &snapshot, index: target.index}
}

func safeInboundTestName(value string) string {
	result := ""
	for _, char := range value {
		if char >= 'a' && char <= 'z' || char >= 'A' && char <= 'Z' || char >= '0' && char <= '9' {
			result += string(char)
		} else {
			result += "_"
		}
	}
	return result
}

func TestInboundImportedTraceEventLinkAndComponentCapabilitiesAreExact(t *testing.T) {
	catalog, _ := LoadInboundCatalog()
	target := mustInboundImportTarget(t, catalog,
		"otlp.native.span.v8.span.tool.execute.span.tool.execute")
	entry, _ := target.entry()
	contract := entry.descriptor.(generatedTraceFamilyContract).familyTraceContract()
	if len(target.TraceResourceFields()) == 0 || len(target.TraceEvents()) != len(contract.allowedEvents) {
		t.Fatal("trace component capabilities do not mirror generated descriptor")
	}
	eventTarget := target.TraceEvents()[0]
	eventContract := contract.allowedEvents[0]
	eventFields := requiredInboundFields(t, eventTarget.Fields(), eventContract.fields)
	event, err := NewInboundTraceEvent(eventTarget, 10, Present(uint32(2)), eventFields)
	if err != nil || event.contract.id != eventContract.id {
		t.Fatalf("event = %#v, err=%v", event, err)
	}
	if _, err := NewInboundTraceEvent(eventTarget, math.MaxUint64, Absent[uint32](), eventFields); !IsFamilyBuildError(err, FamilyBuildInvalidTrace) {
		t.Fatalf("overflow event time error = %v", err)
	}
	link, err := NewInboundTraceLink(
		target, InboundTraceLinkDerivedFrom,
		"0123456789abcdef0123456789abcdef", "fedcba9876543210",
		Present("dc=import"), Present(uint32(3)),
	)
	if err != nil || link.relation != "derived_from" {
		t.Fatalf("link = %#v, err=%v", link, err)
	}
	wrong := mustInboundImportTarget(t, catalog,
		"otlp.native.span.v8.span.model.chat.span.model.chat")
	if _, err := NewInboundTraceLink(wrong, "forged", link.TraceID, link.SpanID, Absent[string](), Absent[uint32]()); !IsFamilyBuildError(err, FamilyBuildInvalidTrace) {
		t.Fatalf("forged relation error = %v", err)
	}
	if len(eventTarget.Fields()) != 0 {
		forged := eventTarget.Fields()[0]
		forged.componentID = "another-event"
		if _, ok := target.MappedValueKind(forged); ok {
			t.Fatal("forged component field retained capability")
		}
	}
}

func TestInboundImportedSignalsRejectStructuralMismatchBeforeOccurrence(t *testing.T) {
	catalog, _ := LoadInboundCatalog()
	traceTarget := mustInboundImportTarget(t, catalog,
		"otlp.native.span.v8.span.model.chat.span.model.chat")
	metricTarget := mustInboundImportTarget(t, catalog,
		"otlp.native.metric.v8.metric.defenseclaw.activity.total.metric.defenseclaw.activity.total")
	ids := &inboundImportOccurrenceIDs{}
	builder, _ := NewInboundImportBuilder(ClockFunc(time.Now), ids)

	traceInput := validInboundImportedTraceInput(t, traceTarget)
	before := ids.count.Load()
	traceInput.ParentSpanID = Present(traceInput.Correlation.SpanID)
	if _, err := builder.BuildTrace(traceTarget, traceInput); !IsFamilyBuildError(err, FamilyBuildInvalidTrace) || ids.count.Load() != before {
		t.Fatalf("self-parent error/IDs = %v/%d", err, ids.count.Load())
	}
	traceInput = validInboundImportedTraceInput(t, traceTarget)
	traceInput.NativeSpanName = Present("forged name")
	before = ids.count.Load()
	if _, err := builder.BuildTrace(traceTarget, traceInput); !IsFamilyBuildError(err, FamilyBuildInvalidTrace) || ids.count.Load() != before {
		t.Fatalf("native name mismatch error/IDs = %v/%d", err, ids.count.Load())
	}

	metricInput := validInboundImportedMetricInput(t, metricTarget)
	metricInput.SourcePoint = NewInboundMetricDeltaSumSource("wrong-unit", true)
	before = ids.count.Load()
	if _, err := builder.BuildMetric(metricTarget, metricInput); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) || ids.count.Load() != before {
		t.Fatalf("unit mismatch error/IDs = %v/%d", err, ids.count.Load())
	}
	metricInput = validInboundImportedMetricInput(t, metricTarget)
	metricInput.SourcePoint = NewInboundMetricGaugeSource(
		metricTarget.entryMustMetricContract(t).unit,
	)
	if _, err := builder.BuildMetric(metricTarget, metricInput); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("type/temporality mismatch error = %v", err)
	}
	metricInput = validInboundImportedMetricInput(t, metricTarget)
	metricInput.Timestamp = time.Unix(-1, 0).UTC()
	before = ids.count.Load()
	if _, err := builder.BuildMetric(metricTarget, metricInput); !IsFamilyBuildError(err, FamilyBuildInvalidMetric) || ids.count.Load() != before {
		t.Fatalf("pre-epoch metric time error/IDs = %v/%d", err, ids.count.Load())
	}
}

func validInboundImportedTraceInput(t *testing.T, target InboundTarget) InboundImportedTraceInput {
	t.Helper()
	entry, ok := target.entry()
	if !ok {
		t.Fatal("invalid target")
	}
	contract := cloneFamilyTraceContract(entry.descriptor.(generatedTraceFamilyContract).familyTraceContract())
	fields := requiredInboundFields(t, target.Fields(), contract.fields)
	fields = applyInboundCrossFieldFixtures(t, fields, target.Fields(), contract.familyDescriptorContract)
	resourceFields := requiredInboundFields(t, target.TraceResourceFields(), contract.resourceFields)
	receipt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	match := target.snapshot.matches[entry.matchIndex]
	authenticatedSource := inboundTestSource(match)
	importInput := InboundImportProvenanceInput{
		AuthenticatedSource: authenticatedSource, UpstreamServiceName: "upstream-service",
	}
	if match.shape == InboundShapeNativeExact {
		importInput.UpstreamInstanceID = "upstream-instance"
		importInput.UpstreamRecordID = "upstream-span"
		importInput.UpstreamRedactionProfile = "none"
		importInput.IngressHopCount = 2
		importInput.LastHopInstanceID = "forwarder-instance"
		importInput.LastHopDestination = "otlp-primary"
	}
	outcome := Absent[Outcome]()
	status := NewTraceStatusOK()
	switch match.outcomeRule.kind {
	case InboundOutcomeOTelStatus:
		outcome = Present(OutcomeCompleted)
	case InboundOutcomeNativeSpan:
		if len(contract.outcome.allowed) == 0 {
			t.Fatal("native trace has no outcome")
		}
		outcome = Present(contract.outcome.allowed[0])
		status = NewTraceStatusUnset()
	case InboundOutcomeFixed:
		outcome = Present(match.outcomeRule.fixed)
	case InboundOutcomeForbidden:
		status = NewTraceStatusUnset()
	}
	input := InboundImportedTraceInput{
		ReceiptTime: receipt,
		Correlation: Correlation{
			RequestID: "request-1", TraceID: "0123456789abcdef0123456789abcdef",
			SpanID: "0123456789abcdef",
		},
		Provenance: InboundLocalProvenanceInput{
			BinaryVersion: "8.0.0", ConfigGeneration: 8,
			BuildCommit: "abcd", ConfigDigest: "cafe",
		},
		Import: importInput, Outcome: outcome, Kind: contract.allowedKinds[0],
		StartTimeUnixNano: uint64(receipt.Add(-2 * time.Second).UnixNano()),
		EndTimeUnixNano:   uint64(receipt.Add(-time.Second).UnixNano()),
		ParentSpanID:      Absent[string](), TraceState: Present("dc=import"), Flags: 1,
		Status: status,
		Resource: InboundTraceResourceInput{
			DroppedAttributesCount: Absent[uint32](), Fields: resourceFields,
			Custom: Absent[TelemetryCustomResourceAttributes](),
		},
		ScopeDroppedCount: Absent[uint32](), Fields: fields,
		Events: []TraceEventInput{}, DroppedEventsCount: Absent[uint32](),
		Links: []TraceLinkInput{}, DroppedLinksCount: Absent[uint32](),
		DroppedAttributesCount: Absent[uint32](),
	}
	if match.shape == InboundShapeNativeExact {
		input.NativeSpanName = Present(renderInboundTraceName(t, target, input))
	} else {
		local, err := NewInboundLocalTraceResource(target, resourceFields)
		if err != nil {
			t.Fatal(err)
		}
		input.LocalResource = local
	}
	return input
}

func renderInboundTraceName(t *testing.T, target InboundTarget, input InboundImportedTraceInput) string {
	t.Helper()
	entry, _ := target.entry()
	contract := entry.descriptor.(generatedTraceFamilyContract).familyTraceContract()
	values, provided, err := inboundMappedValues(entry.fields, contract.fields, input.Fields)
	if err != nil {
		t.Fatal(err)
	}
	conditions, err := inboundConditionFacts(contract.fields, provided, input.Outcome)
	if err != nil {
		t.Fatal(err)
	}
	envelope := inboundFamilyEnvelope(input.ReceiptTime, input.Correlation, input.Provenance, input.Import)
	attributes, _, err := materializeFamilyFields(
		contract.fields, values, conditions, familyContext(contract.familyDescriptorContract, envelope, input.Outcome),
	)
	if err != nil {
		t.Fatal(err)
	}
	name, err := renderFamilySpanName(contract.spanName, attributes)
	if err != nil {
		t.Fatal(err)
	}
	return name
}

func validInboundImportedMetricInput(t *testing.T, target InboundTarget) InboundImportedMetricInput {
	t.Helper()
	entry, ok := target.entry()
	if !ok {
		t.Fatal("invalid target")
	}
	contract := cloneFamilyMetricContract(entry.descriptor.(generatedMetricFamilyContract).familyMetricContract())
	fields := requiredInboundFields(t, target.Fields(), contract.fields)
	fields = applyInboundCrossFieldFixtures(t, fields, target.Fields(), contract.familyDescriptorContract)
	match := target.snapshot.matches[entry.matchIndex]
	importInput := InboundImportProvenanceInput{
		AuthenticatedSource: inboundTestSource(match), UpstreamServiceName: "upstream-service",
	}
	if match.shape == InboundShapeNativeExact {
		importInput.UpstreamInstanceID = "upstream-instance"
		importInput.IngressHopCount = 2
		importInput.LastHopInstanceID = "forwarder-instance"
		importInput.LastHopDestination = "otlp-primary"
	}
	source := InboundMetricSourceFacts{}
	if target.Role() == InboundTargetImport {
		switch contract.instrumentType {
		case "gauge":
			source = NewInboundMetricGaugeSource(contract.unit)
		case "counter":
			source = NewInboundMetricDeltaSumSource(contract.unit, true)
		case "updowncounter":
			source = NewInboundMetricDeltaSumSource(contract.unit, false)
		}
	} else {
		switch target.DerivationStrategy() {
		case InboundDerivationClaudeTokenUsage:
			if target.MatchID() == "otlp.codex.token_usage.v1.metric.gen_ai.client.token.usage" {
				source = NewInboundMetricHistogramMeanSource("", 1)
			} else {
				source = NewInboundMetricGaugeSource("{token}")
			}
		case InboundDerivationDurationMetric:
			source = NewInboundMetricGaugeSource("s")
		case InboundDerivationFieldValue, InboundDerivationCodexTokenFields:
			source = NewInboundMetricMappedFieldSource()
		case InboundDerivationElapsedTime:
			source = NewInboundMetricElapsedTimeSource()
		}
	}
	value := NewInboundMetricInt64Value(1)
	if contract.valueType == familyMetricNumberDouble {
		value = NewInboundMetricDoubleValue(1)
	}
	receipt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	return InboundImportedMetricInput{
		Timestamp: receipt.Add(-time.Second), ReceiptTime: receipt,
		Correlation: Correlation{},
		Provenance: InboundLocalProvenanceInput{
			BinaryVersion: "8.0.0", ConfigGeneration: 8,
			BuildCommit: "abcd", ConfigDigest: "cafe",
		},
		Import: importInput, SourcePoint: source, Value: value, Fields: fields,
	}
}

func inboundMetricRecordValue(t *testing.T, record Record) float64 {
	t.Helper()
	data, present := record.InstrumentData()
	if !present {
		t.Fatal("metric record omitted instrument data")
	}
	object, err := data.Object()
	if err != nil {
		t.Fatal(err)
	}
	switch value := object["value"].(type) {
	case json.Number:
		parsed, err := value.Float64()
		if err != nil {
			t.Fatal(err)
		}
		return parsed
	case float64:
		return value
	default:
		t.Fatalf("metric value type = %T", value)
		return 0
	}
}

func requiredInboundFields(
	t *testing.T,
	capabilities []InboundTargetField,
	descriptors []familyFieldDescriptor,
) []InboundMappedField {
	t.Helper()
	byKey := make(map[string]InboundTargetField, len(capabilities))
	for _, capability := range capabilities {
		byKey[capability.fieldRef] = capability
	}
	fields := make([]InboundMappedField, 0)
	for _, descriptor := range descriptors {
		if descriptor.source != familyValueInput || descriptor.requirement != familyRequirementRequired {
			continue
		}
		capability, ok := byKey[descriptor.key]
		if !ok {
			t.Fatalf("missing capability for required field %s", descriptor.key)
		}
		fields = append(fields, validInboundMappedField(t, capability, descriptor))
	}
	return fields
}

func applyInboundCrossFieldFixtures(
	t *testing.T,
	fields []InboundMappedField,
	capabilities []InboundTargetField,
	contract familyDescriptorContract,
) []InboundMappedField {
	t.Helper()
	byKey := make(map[string]InboundTargetField, len(capabilities))
	for _, capability := range capabilities {
		byKey[capability.fieldRef] = capability
	}
	result := append([]InboundMappedField(nil), fields...)
	for _, relation := range contract.crossFieldRelations {
		valueDescriptor := inboundDescriptorByKey(t, contract, relation.valueKey)
		codeDescriptor := inboundDescriptorByKey(t, contract, relation.codeKey)
		if valueDescriptor.source != familyValueInput || codeDescriptor.source != familyValueInput {
			continue
		}
		valueField, valueOK := byKey[relation.valueKey]
		codeField, codeOK := byKey[relation.codeKey]
		if !valueOK || !codeOK {
			t.Fatal("cross-field capability missing")
		}
		result = replaceInboundMappedField(result, valueField,
			NewInboundMappedString(valueField, relation.entries[0].value))
		result = replaceInboundMappedField(result, codeField,
			NewInboundMappedInt64(codeField, relation.entries[0].code))
	}
	return result
}

func inboundTestSource(match inboundMatchEntry) string {
	if len(match.sources) > 0 && match.sources[0] != "any_authenticated" {
		return match.sources[0]
	}
	return "codex"
}

func (target InboundTarget) entryMustMetricContract(t *testing.T) familyMetricContract {
	t.Helper()
	entry, ok := target.entry()
	if !ok {
		t.Fatal("invalid target")
	}
	return entry.descriptor.(generatedMetricFamilyContract).familyMetricContract()
}
