// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"encoding/json"
	"fmt"
	"math"
	"reflect"
	"regexp"
	"sync/atomic"
	"testing"
	"time"
)

type inboundImportOccurrenceIDs struct{ count atomic.Uint64 }

func (generator *inboundImportOccurrenceIDs) NewOccurrenceID() (string, error) {
	return fmt.Sprintf("inbound-import-%d", generator.count.Add(1)), nil
}

func TestInboundImportedLogPublicInputHasNoIdentityFloorOrRawBodyAuthority(t *testing.T) {
	inputType := reflect.TypeOf(InboundImportedLogInput{})
	for _, forbidden := range []string{
		"Bucket", "Signal", "EventName", "Family", "Mandatory", "Floor", "Body",
		"FieldClasses", "Source", "Connector", "Action", "Phase", "Producer",
	} {
		if _, present := inputType.FieldByName(forbidden); present {
			t.Errorf("InboundImportedLogInput exposes forbidden %s authority", forbidden)
		}
	}
	for _, value := range []any{
		InboundMappedField{}, inboundSealedStructuredValue{},
	} {
		typeOf := reflect.TypeOf(value)
		for index := 0; index < typeOf.NumField(); index++ {
			if typeOf.Field(index).IsExported() {
				t.Errorf("%s exposes mutable field %s", typeOf.Name(), typeOf.Field(index).Name)
			}
		}
	}
	if _, present := reflect.TypeOf(InboundLocalProvenanceInput{}).FieldByName("Producer"); present {
		t.Fatal("local inbound provenance exposes producer authority")
	}
	importType := reflect.TypeOf(InboundImportProvenanceInput{})
	for _, forbidden := range []string{"Protocol", "BindingID", "Mode", "Derivation", "SourceAggregateCount"} {
		if _, present := importType.FieldByName(forbidden); present {
			t.Errorf("import provenance exposes forbidden %s authority", forbidden)
		}
	}
}

func TestInboundImportedLogConstructsEveryGeneratedContextAsOrdinary(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(catalog.snapshot.contexts) == 0 {
		t.Fatal("import context inventory is empty")
	}
	ids := &inboundImportOccurrenceIDs{}
	builder, err := NewInboundImportBuilder(ClockFunc(func() time.Time {
		t.Fatal("imported log consulted the producer clock")
		return time.Time{}
	}), ids)
	if err != nil {
		t.Fatal(err)
	}
	seenIDs := make(map[string]struct{}, len(catalog.snapshot.contexts))
	seenMandatoryCapable := map[string]bool{
		"log.config.change.applied":     false,
		"log.enforcement.block.applied": false,
		"log.telemetry.batch.rejected":  false,
	}
	for contextIndex := range catalog.snapshot.contexts {
		target := inboundImportTargetForContext(t, catalog, contextIndex)
		context, ok := target.ImportContext()
		if !ok {
			t.Fatalf("target %s has no import context", target.ID())
		}
		input := validInboundImportedLogInput(t, target)
		contract := catalog.snapshot.targets[target.index].descriptor.familyDescriptorContract()
		fields := target.Fields()
		if len(fields) != len(contract.fields) {
			t.Fatalf("target %s field inventory drift", target.ID())
		}
		for index, field := range fields {
			kind, mappable := target.MappedValueKind(field)
			wantKind := inboundMappedKindForFamilyField(contract.fields[index])
			wantMappable := contract.fields[index].source == familyValueInput &&
				wantKind != InboundMappedValueInvalid
			if kind != map[bool]InboundMappedValueKind{true: wantKind, false: InboundMappedValueInvalid}[wantMappable] ||
				mappable != wantMappable {
				t.Fatalf("target %s field %s kind=%d/%t want=%d/%t",
					target.ID(), field.FieldRef(), kind, mappable, wantKind, wantMappable)
			}
		}
		record, buildErr := builder.BuildLog(target, context, input)
		if buildErr != nil {
			t.Fatalf("context %s target %s: %v", context.ID(), target.ID(), buildErr)
		}
		if record.Identity() != (EventIdentity{Bucket: target.Bucket(), Signal: SignalLogs, Name: target.EventName()}) ||
			record.Mandatory() || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() {
			t.Fatalf("context %s constructed invalid ordinary record", context.ID())
		}
		if record.Timestamp() != input.Timestamp {
			t.Fatalf("context %s timestamp = %s, want %s", context.ID(), record.Timestamp(), input.Timestamp)
		}
		observedAt, present := record.ObservedAt()
		if !present || observedAt != input.ReceiptTime {
			t.Fatalf("context %s observed_at = %s/%t", context.ID(), observedAt, present)
		}
		if record.RecordID() == input.Import.UpstreamRecordID || record.RecordID() == "" {
			t.Fatalf("context %s reused or omitted upstream record ID", context.ID())
		}
		if _, duplicate := seenIDs[record.RecordID()]; duplicate {
			t.Fatalf("context %s reused local record ID", context.ID())
		}
		seenIDs[record.RecordID()] = struct{}{}
		provenance := record.Provenance()
		if provenance.Producer != inboundImportProducer || provenance.ConfigGeneration != input.Provenance.ConfigGeneration ||
			record.Source() != SourceOTelReceiver || record.Connector() != input.Import.AuthenticatedSource ||
			record.Action() != "" || record.Phase() != "" ||
			provenance.Import == nil || provenance.Import.Protocol != ImportProtocolOTLP ||
			provenance.Import.BindingID != target.MatchID() || provenance.Import.Mode != ImportModeImport ||
			provenance.Import.Derivation != "" || provenance.Import.AuthenticatedSource != input.Import.AuthenticatedSource ||
			provenance.Import.UpstreamInstanceID != input.Import.UpstreamInstanceID ||
			provenance.Import.LastHopInstanceID != input.Import.LastHopInstanceID ||
			provenance.Import.IngressHopCount != input.Import.IngressHopCount {
			t.Fatalf("context %s provenance = %#v", context.ID(), provenance)
		}
		body, bodyPresent := record.Body()
		if !bodyPresent {
			t.Fatalf("context %s omitted body", context.ID())
		}
		object, objectErr := body.Object()
		if objectErr != nil {
			t.Fatal(objectErr)
		}
		if err := verifyFamilyFieldClassCoverage(object, record.FieldClasses()); err != nil {
			t.Fatalf("context %s field classes: %v", context.ID(), err)
		}
		if _, tracked := seenMandatoryCapable[target.Family()]; tracked {
			seenMandatoryCapable[target.Family()] = true
		}
	}
	if got, want := ids.count.Load(), uint64(len(catalog.snapshot.contexts)); got != want {
		t.Fatalf("occurrence IDs = %d, want one per context (%d)", got, want)
	}
	for family, seen := range seenMandatoryCapable {
		if !seen {
			t.Errorf("mandatory-capable family %s was not exercised", family)
		}
	}
}

func TestOTLPInboundNativeLogRoundTripOtherInstance(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewInboundImportBuilder(
		ClockFunc(func() time.Time { return time.Time{} }),
		&inboundImportOccurrenceIDs{},
	)
	if err != nil {
		t.Fatal(err)
	}
	count := 0
	sawImportWithDerivedSibling := false
	for _, target := range catalog.Targets() {
		if target.Signal() != SignalLogs || target.Role() != InboundTargetImport {
			continue
		}
		count++
		context, ok := target.ImportContext()
		if !ok {
			t.Fatalf("target %s has no import context", target.ID())
		}
		input := validInboundImportedLogInput(t, target)
		record, buildErr := builder.BuildLog(target, context, input)
		if buildErr != nil {
			t.Fatalf("target %s source %s: %v", target.ID(), input.Import.AuthenticatedSource, buildErr)
		}
		if record.Mandatory() || record.IsFloorOnly() || record.Provenance().Import == nil ||
			record.Provenance().Import.Mode != ImportModeImport ||
			record.Provenance().Import.BindingID != target.MatchID() {
			t.Fatalf("target %s did not retain pure import provenance", target.ID())
		}
		match := catalog.snapshot.matches[catalog.snapshot.targets[target.index].matchIndex]
		for _, siblingIndex := range match.targetIndexes {
			if catalog.snapshot.targets[siblingIndex].role == InboundTargetDerive {
				sawImportWithDerivedSibling = true
				if record.Provenance().Import.Mode != ImportModeImport ||
					record.Provenance().Import.Derivation != "" {
					t.Fatalf("target %s inherited sibling derivation provenance", target.ID())
				}
			}
		}
	}
	if count == 0 {
		t.Fatal("imported log target inventory is empty")
	}
	if !sawImportWithDerivedSibling {
		t.Fatal("no imported log target with a derived sibling was exercised")
	}
}

func TestInboundImportedLogRejectsInvalidCapabilitiesAndMappedFieldsBeforeOccurrence(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.config.change.applied.log.config.change.applied")
	context, _ := target.ImportContext()
	ids := &inboundImportOccurrenceIDs{}
	builder, err := NewInboundImportBuilder(ClockFunc(func() time.Time { return time.Now() }), ids)
	if err != nil {
		t.Fatal(err)
	}
	valid := validInboundImportedLogInput(t, target)

	assertCode := func(name string, want FamilyBuildErrorCode, mutate func(*InboundTarget, *InboundImportContext, *InboundImportedLogInput)) {
		t.Helper()
		t.Run(name, func(t *testing.T) {
			candidateTarget, candidateContext, input := target, context, valid
			input.Fields = append([]InboundMappedField(nil), valid.Fields...)
			before := ids.count.Load()
			mutate(&candidateTarget, &candidateContext, &input)
			_, buildErr := builder.BuildLog(candidateTarget, candidateContext, input)
			if !IsFamilyBuildError(buildErr, want) {
				t.Fatalf("error = %v, want %s", buildErr, want)
			}
			if ids.count.Load() != before {
				t.Fatal("invalid import consumed an occurrence ID")
			}
		})
	}

	assertCode("default target", FamilyBuildInvalidDescriptor, func(target *InboundTarget, _ *InboundImportContext, _ *InboundImportedLogInput) {
		*target = InboundTarget{}
	})
	assertCode("default context", FamilyBuildInvalidDescriptor, func(_ *InboundTarget, context *InboundImportContext, _ *InboundImportedLogInput) {
		*context = InboundImportContext{}
	})
	other := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.diagnostic.message.log.diagnostic.message")
	otherContext, _ := other.ImportContext()
	if kind, ok := target.MappedValueKind(other.Fields()[0]); ok || kind != InboundMappedValueInvalid {
		t.Fatalf("foreign field resolved as kind %d", kind)
	}
	assertCode("foreign context", FamilyBuildInvalidDescriptor, func(_ *InboundTarget, context *InboundImportContext, _ *InboundImportedLogInput) {
		*context = otherContext
	})
	assertCode("descriptor mismatch", FamilyBuildInvalidDescriptor, func(target *InboundTarget, context *InboundImportContext, _ *InboundImportedLogInput) {
		snapshot := *target.snapshot
		snapshot.targets = append([]inboundTargetEntry(nil), target.snapshot.targets...)
		snapshot.contexts = append([]inboundImportContextEntry(nil), target.snapshot.contexts...)
		snapshot.matches = append([]inboundMatchEntry(nil), target.snapshot.matches...)
		snapshot.targets[target.index].family = "log.diagnostic.message"
		*target = InboundTarget{snapshot: &snapshot, index: target.index}
		*context = InboundImportContext{snapshot: &snapshot, index: context.index}
	})
	assertCode("unknown field", FamilyBuildUnknownField, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Fields = append(input.Fields, NewInboundMappedString(other.Fields()[0], "x"))
	})
	operation := inboundTargetFieldByName(t, target, "defenseclaw.admin.operation")
	assertCode("wrong field arm", FamilyBuildInvalidType, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Fields = replaceInboundMappedField(input.Fields, operation, NewInboundMappedBoolean(operation, true))
	})
	assertCode("invalid outcome", FamilyBuildInvalidOutcome, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Outcome = Present(OutcomeFailed)
	})
	assertCode("invalid severity", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Severity = Present(Severity("WARN"))
	})
	assertCode("future timestamp", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Timestamp = input.ReceiptTime.Add(inboundMaximumFutureSkew + time.Nanosecond)
	})
	assertCode("zero receipt", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.ReceiptTime = time.Time{}
	})
	assertCode("invalid import provenance", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Import.IngressHopCount = MaxImportForwardHops + 1
	})
	assertCode("invalid local provenance", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Provenance.BinaryVersion = ""
	})
	codex := mustInboundImportTarget(t, catalog,
		"otlp.codex.user_prompt.v1.log.model.request.log.model.request")
	codexContext, _ := codex.ImportContext()
	assertCode("authenticated source mismatch", FamilyBuildInvalidDescriptor, func(target *InboundTarget, context *InboundImportContext, input *InboundImportedLogInput) {
		*target, *context = codex, codexContext
		*input = validInboundImportedLogInput(t, codex)
		input.Import.AuthenticatedSource = "claudecode"
	})
	assertCode("external provenance cannot claim native hop", FamilyBuildConstraint, func(target *InboundTarget, context *InboundImportContext, input *InboundImportedLogInput) {
		*target, *context = codex, codexContext
		*input = validInboundImportedLogInput(t, codex)
		input.Import.LastHopInstanceID = "forged-forwarder"
	})
	assertCode("native provenance requires upstream identity", FamilyBuildConstraint, func(_ *InboundTarget, _ *InboundImportContext, input *InboundImportedLogInput) {
		input.Import.UpstreamInstanceID = ""
	})
}

func TestInboundImportedLogConditionalScalarAndImmutableValueValidation(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	builder, _ := NewInboundImportBuilder(ClockFunc(func() time.Time { return time.Now() }), &inboundImportOccurrenceIDs{})

	compact := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.compat.compact_end.log.compat.compact_end")
	compactContext, _ := compact.ImportContext()
	compactInput := validInboundImportedLogInput(t, compact)
	reported := inboundTargetFieldByName(t, compact, "defenseclaw.agent.reported_cost.present")
	compactInput.Fields = replaceInboundMappedField(
		compactInput.Fields, reported, NewInboundMappedBoolean(reported, true),
	)
	if _, err := builder.BuildLog(compact, compactContext, compactInput); !IsFamilyBuildError(err, FamilyBuildMissingRequired) {
		t.Fatalf("reported-cost condition error = %v", err)
	}

	destination := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.destination.test.completed.log.destination.test.completed")
	destinationContext, _ := destination.ImportContext()
	destinationInput := validInboundImportedLogInput(t, destination)
	result := inboundTargetFieldByName(t, destination, "defenseclaw.destination.test.result")
	destinationInput.Fields = replaceInboundMappedField(
		destinationInput.Fields, result, NewInboundMappedString(result, "failed"),
	)
	if _, err := builder.BuildLog(destination, destinationContext, destinationInput); !IsFamilyBuildError(err, FamilyBuildMissingRequired) {
		t.Fatalf("destination failure condition error = %v", err)
	}

	guardrail := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.guardrail.evaluation.completed.log.guardrail.evaluation.completed")
	guardrailContext, _ := guardrail.ImportContext()
	guardrailInput := validInboundImportedLogInput(t, guardrail)
	rules := inboundTargetFieldByName(t, guardrail, "defenseclaw.guardrail.rule_ids")
	mutable := []string{"rule-1"}
	guardrailInput.Fields = append(guardrailInput.Fields, NewInboundMappedStringArray(rules, mutable))
	mutable[0] = "mutated"
	record, err := builder.BuildLog(guardrail, guardrailContext, guardrailInput)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := record.Body()
	object, _ := body.Object()
	items, ok := object["defenseclaw.guardrail.rule_ids"].([]any)
	if !ok || len(items) != 1 || items[0] != "rule-1" {
		t.Fatalf("mapped array was not snapshotted: %#v", object["defenseclaw.guardrail.rule_ids"])
	}

	invalidDouble := NewInboundMappedDouble(rules, math.NaN())
	guardrailInput = validInboundImportedLogInput(t, guardrail)
	guardrailInput.Fields = append(guardrailInput.Fields, invalidDouble)
	if _, err := builder.BuildLog(guardrail, guardrailContext, guardrailInput); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("wrong scalar type error = %v", err)
	}
}

func TestInboundImportedLogUsesAllFourSealedStructuredBindings(t *testing.T) {
	catalog, err := LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	builder, err := NewInboundImportBuilder(
		ClockFunc(func() time.Time { return time.Now() }), &inboundImportOccurrenceIDs{},
	)
	if err != nil {
		t.Fatal(err)
	}

	model := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.model.request.log.model.request")
	modelContext, _ := model.ImportContext()
	inputField := inboundTargetFieldByName(t, model, "gen_ai.input.messages")
	outputField := inboundTargetFieldByName(t, model, "gen_ai.output.messages")
	inputMessages := TelemetryStructuredGenAIInputMessages{Items: []TelemetryStructuredGenAIChatMessage{{
		Role: "user",
		Parts: TelemetryStructuredGenAIMessageParts{Items: []TelemetryStructuredGenAIMessagePart{
			TelemetryStructuredArmGenAIMessagePartText{Value: TelemetryStructuredGenAITextPart{Content: "hello"}},
		}},
	}}}
	outputMessages := TelemetryStructuredGenAIOutputMessages{Items: []TelemetryStructuredGenAIOutputMessage{{
		Role: "assistant",
		Parts: TelemetryStructuredGenAIMessageParts{Items: []TelemetryStructuredGenAIMessagePart{
			TelemetryStructuredArmGenAIMessagePartText{Value: TelemetryStructuredGenAITextPart{Content: "world"}},
		}},
		FinishReason: Present("stop"),
	}}}
	mappedInput, err := NewInboundMappedGenAIInputMessages(inputField, inputMessages)
	if err != nil {
		t.Fatal(err)
	}
	mappedOutput, err := NewInboundMappedGenAIOutputMessages(outputField, outputMessages)
	if err != nil {
		t.Fatal(err)
	}
	// Exact encoders snapshot the generated sealed inputs at the mapping boundary.
	inputMessages.Items[0].Role = "mutated"
	outputMessages.Items[0].FinishReason = Present("mutated")
	modelInput := validInboundImportedLogInput(t, model)
	modelInput.Fields = append(modelInput.Fields, mappedInput, mappedOutput)
	modelRecord, err := builder.BuildLog(model, modelContext, modelInput)
	if err != nil {
		t.Fatal(err)
	}
	modelBody, _ := modelRecord.Body()
	modelObject, _ := modelBody.Object()
	inputItems, inputOK := modelObject["gen_ai.input.messages"].([]any)
	outputItems, outputOK := modelObject["gen_ai.output.messages"].([]any)
	if !inputOK || !outputOK || len(inputItems) != 1 || len(outputItems) != 1 ||
		inputItems[0].(map[string]any)["role"] != "user" ||
		outputItems[0].(map[string]any)["finish_reason"] != "stop" {
		t.Fatalf("sealed message bindings were not preserved: input=%#v output=%#v", inputItems, outputItems)
	}

	tool := mustInboundImportTarget(t, catalog,
		"otlp.native.log.v8.log.tool.invocation.completed.log.tool.invocation.completed")
	toolContext, _ := tool.ImportContext()
	argumentsField := inboundTargetFieldByName(t, tool, "gen_ai.tool.call.arguments")
	resultField := inboundTargetFieldByName(t, tool, "gen_ai.tool.call.result")
	argumentMember, err := NewGenAIToolCallArgumentsEntryMember(
		"city", TelemetryStructuredArmGenAICanonicalJSONString{Value: "Raleigh"},
	)
	if err != nil {
		t.Fatal(err)
	}
	resultMember, err := NewGenAIToolCallResultEntryMember(
		"temperature", TelemetryStructuredArmGenAICanonicalJSONInt64{Value: 72},
	)
	if err != nil {
		t.Fatal(err)
	}
	mappedArguments, err := NewInboundMappedGenAIToolCallArguments(
		argumentsField, TelemetryStructuredGenAIToolCallArguments{
			Entries: []GenAIToolCallArgumentsEntryMemberInput{argumentMember},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	mappedResult, err := NewInboundMappedGenAIToolCallResult(
		resultField, TelemetryStructuredGenAIToolCallResult{
			Entries: []GenAIToolCallResultEntryMemberInput{resultMember},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	toolInput := validInboundImportedLogInput(t, tool)
	toolInput.Fields = append(toolInput.Fields, mappedArguments, mappedResult)
	toolRecord, err := builder.BuildLog(tool, toolContext, toolInput)
	if err != nil {
		t.Fatal(err)
	}
	toolBody, _ := toolRecord.Body()
	toolObject, _ := toolBody.Object()
	arguments, argumentsOK := toolObject["gen_ai.tool.call.arguments"].(map[string]any)
	result, resultOK := toolObject["gen_ai.tool.call.result"].(map[string]any)
	if !argumentsOK || !resultOK || arguments["city"] != "Raleigh" ||
		result["temperature"].(json.Number).String() != "72" {
		t.Fatalf("sealed tool bindings were not preserved: arguments=%#v result=%#v", arguments, result)
	}

	if _, err := NewInboundMappedGenAIOutputMessages(inputField, TelemetryStructuredGenAIOutputMessages{}); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("output messages accepted input-message field: %v", err)
	}
	if _, err := NewInboundMappedGenAIToolCallResult(argumentsField, TelemetryStructuredGenAIToolCallResult{}); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("tool result accepted arguments field: %v", err)
	}
	wrongBinding := mappedOutput
	wrongBinding.field = inputField
	modelInput = validInboundImportedLogInput(t, model)
	modelInput.Fields = append(modelInput.Fields, wrongBinding)
	if _, err := builder.BuildLog(model, modelContext, modelInput); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("wrong sealed structured binding error = %v", err)
	}
}

func inboundImportTargetForContext(t *testing.T, catalog InboundCatalog, contextIndex int) InboundTarget {
	t.Helper()
	for targetIndex, target := range catalog.snapshot.targets {
		if target.signal == SignalLogs && target.role == InboundTargetImport && target.importContextIndex == contextIndex {
			return InboundTarget{snapshot: catalog.snapshot, index: targetIndex}
		}
	}
	t.Fatalf("context %d has no imported log target", contextIndex)
	return InboundTarget{}
}

func mustInboundImportTarget(t *testing.T, catalog InboundCatalog, id string) InboundTarget {
	t.Helper()
	target, ok := catalog.Target(id)
	if !ok {
		t.Fatalf("missing target %s", id)
	}
	return target
}

func inboundTargetFieldByName(t *testing.T, target InboundTarget, key string) InboundTargetField {
	t.Helper()
	for _, field := range target.Fields() {
		if field.FieldRef() == key {
			return field
		}
	}
	t.Fatalf("target %s has no field %s", target.ID(), key)
	return InboundTargetField{}
}

func validInboundImportedLogInput(t *testing.T, target InboundTarget) InboundImportedLogInput {
	t.Helper()
	entry, ok := target.entry()
	if !ok {
		t.Fatal("invalid target")
	}
	contract := cloneFamilyDescriptorContract(entry.descriptor.familyDescriptorContract())
	fields := make([]InboundMappedField, 0)
	for _, descriptor := range contract.fields {
		if descriptor.source != familyValueInput || descriptor.requirement != familyRequirementRequired {
			continue
		}
		capability := inboundTargetFieldByName(t, target, descriptor.key)
		fields = append(fields, validInboundMappedField(t, capability, descriptor))
	}
	for _, relation := range contract.crossFieldRelations {
		valueDescriptor := inboundDescriptorByKey(t, contract, relation.valueKey)
		codeDescriptor := inboundDescriptorByKey(t, contract, relation.codeKey)
		if valueDescriptor.source == familyValueInput && codeDescriptor.source == familyValueInput {
			valueField := inboundTargetFieldByName(t, target, relation.valueKey)
			codeField := inboundTargetFieldByName(t, target, relation.codeKey)
			fields = replaceInboundMappedField(fields, valueField,
				NewInboundMappedString(valueField, relation.entries[0].value))
			fields = replaceInboundMappedField(fields, codeField,
				NewInboundMappedInt64(codeField, relation.entries[0].code))
		}
	}
	outcome := Absent[Outcome]()
	if contract.outcome.requirement == familyRequirementRequired {
		outcome = Present(contract.outcome.allowed[0])
	}
	receipt := time.Date(2026, 7, 6, 12, 0, 0, 0, time.UTC)
	authenticatedSource := "codex"
	match := target.snapshot.matches[entry.matchIndex]
	if len(match.sources) != 0 && match.sources[0] != "any_authenticated" {
		authenticatedSource = match.sources[0]
	}
	importProvenance := InboundImportProvenanceInput{
		AuthenticatedSource: authenticatedSource,
		UpstreamServiceName: "upstream-service",
	}
	if match.shape == InboundShapeNativeExact {
		importProvenance.UpstreamInstanceID = "upstream-instance"
		importProvenance.UpstreamRecordID = "123e4567-e89b-12d3-a456-426614174000"
		importProvenance.UpstreamRedactionProfile = "sensitive"
		importProvenance.IngressHopCount = 2
		importProvenance.LastHopInstanceID = "forwarder-instance"
		importProvenance.LastHopDestination = "otlp-primary"
	}
	return InboundImportedLogInput{
		Timestamp: receipt.Add(-time.Second), ReceiptTime: receipt,
		Correlation: Correlation{RequestID: "request-1", TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef"},
		Provenance: InboundLocalProvenanceInput{
			BinaryVersion: "8.0.0", ConfigGeneration: 8,
			BuildCommit: "abcd", ConfigDigest: "cafe",
		},
		Import:   importProvenance,
		Severity: Present(SeverityInfo), LogLevel: Present(LogLevelInfo),
		Outcome: outcome, Fields: fields,
	}
}

func validInboundMappedField(
	t *testing.T,
	field InboundTargetField,
	descriptor familyFieldDescriptor,
) InboundMappedField {
	t.Helper()
	switch descriptor.typeOf {
	case familyFieldString:
		return NewInboundMappedString(field, validInboundString(t, descriptor.constraints))
	case familyFieldBoolean:
		return NewInboundMappedBoolean(field, false)
	case familyFieldInt64:
		value := int64(0)
		if descriptor.constraints.hasIntMin {
			value = descriptor.constraints.intMin
		}
		return NewInboundMappedInt64(field, value)
	case familyFieldUint32:
		value := uint32(0)
		if descriptor.constraints.hasUintMin {
			value = uint32(descriptor.constraints.uintMin)
		}
		return NewInboundMappedUint32(field, value)
	case familyFieldUint64:
		value := uint64(0)
		if descriptor.constraints.hasUintMin {
			value = descriptor.constraints.uintMin
		}
		return NewInboundMappedUint64(field, value)
	case familyFieldDouble:
		value := 0.0
		if descriptor.constraints.hasFloatMin {
			value = descriptor.constraints.floatMin
		}
		return NewInboundMappedDouble(field, value)
	case familyFieldStringArray:
		items := make([]string, descriptor.constraints.minItems)
		for index := range items {
			items[index] = validInboundString(t, descriptor.constraints)
		}
		return NewInboundMappedStringArray(field, items)
	case familyFieldStructured:
		var value InboundMappedField
		var err error
		switch descriptor.key {
		case "gen_ai.input.messages":
			value, err = NewInboundMappedGenAIInputMessages(field, TelemetryStructuredGenAIInputMessages{})
		case "gen_ai.output.messages":
			value, err = NewInboundMappedGenAIOutputMessages(field, TelemetryStructuredGenAIOutputMessages{})
		case "gen_ai.tool.call.arguments":
			value, err = NewInboundMappedGenAIToolCallArguments(field, TelemetryStructuredGenAIToolCallArguments{})
		case "gen_ai.tool.call.result":
			value, err = NewInboundMappedGenAIToolCallResult(field, TelemetryStructuredGenAIToolCallResult{})
		default:
			t.Fatalf("structured field %s has no sealed inbound binding", descriptor.key)
		}
		if err != nil {
			t.Fatal(err)
		}
		return value
	default:
		t.Fatalf("unsupported field type %d", descriptor.typeOf)
		return InboundMappedField{}
	}
}

func validInboundString(t *testing.T, constraints familyFieldConstraints) string {
	t.Helper()
	if len(constraints.enum) != 0 {
		return constraints.enum[0]
	}
	pattern := (*regexp.Regexp)(nil)
	if constraints.pattern != "" {
		var err error
		pattern, err = regexp.Compile(constraints.pattern)
		if err != nil {
			t.Fatal(err)
		}
	}
	candidates := []string{
		"x", "test", "codex", "runtime-pipeline-test", "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"123e4567-e89b-12d3-a456-426614174000", "https://example.com/v1", "a/b:c_d.e-f",
	}
	for _, candidate := range candidates {
		if constraints.maxUTF8Bytes > 0 && len(candidate) > constraints.maxUTF8Bytes {
			continue
		}
		if pattern == nil || pattern.MatchString(candidate) {
			return candidate
		}
	}
	t.Fatalf("no fixture candidate for pattern %q max %d", constraints.pattern, constraints.maxUTF8Bytes)
	return ""
}

func inboundDescriptorByKey(t *testing.T, contract familyDescriptorContract, key string) familyFieldDescriptor {
	t.Helper()
	for _, descriptor := range contract.fields {
		if descriptor.key == key {
			return descriptor
		}
	}
	t.Fatalf("missing descriptor %s", key)
	return familyFieldDescriptor{}
}

func replaceInboundMappedField(
	fields []InboundMappedField,
	capability InboundTargetField,
	replacement InboundMappedField,
) []InboundMappedField {
	result := append([]InboundMappedField(nil), fields...)
	for index, field := range result {
		if field.field.descriptorID == capability.descriptorID {
			result[index] = replacement
			return result
		}
	}
	return append(result, replacement)
}
