// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"strings"
	"sync"
	"testing"
)

// recordingRejectedSink keeps the offers whose request ID carries this
// test's marker: generated-builder tests elsewhere in the package build
// refused records too and may run beside this one.
type recordingRejectedSink struct {
	marker string
	refuse bool
	mu     sync.Mutex
	got    []RejectedRecord
}

func (sink *recordingRejectedSink) ReserveRejectedRecord() bool { return !sink.refuse }

func (sink *recordingRejectedSink) OfferRejectedRecord(record RejectedRecord) {
	if requestID, _ := record.Body["defenseclaw.request.id"].(string); !strings.HasPrefix(requestID, sink.marker) {
		return
	}
	sink.mu.Lock()
	sink.got = append(sink.got, record)
	sink.mu.Unlock()
}

func (sink *recordingRejectedSink) records() []RejectedRecord {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]RejectedRecord(nil), sink.got...)
}

func rejectedTestHookDecision(requestID, result string) LogCompatHookDecisionInput {
	return LogCompatHookDecisionInput{
		Envelope: testFamilyEnvelope(), Outcome: OutcomeAllowed,
		DefenseClawRequestID: Present(requestID),
		DefenseClawHookEvent: "PreToolUse", DefenseClawHookResult: result,
		DefenseClawGuardrailEffectiveAction: "allow", DefenseClawGuardrailRawAction: "allow",
		DefenseClawSecuritySeverity: "INFO", DefenseClawGuardrailMode: "observe",
	}
}

func TestRejectedRecordOfferNamesTheFailingFieldAndKeepsClassifiedValues(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	sink := &recordingRejectedSink{marker: "rejected-capture-"}
	uninstall := InstallRejectedRecordSink(sink)
	defer uninstall()

	if _, err := builder.BuildLogCompatHookDecision(rejectedTestHookDecision("rejected-capture-ok", "ok")); err != nil {
		t.Fatal(err)
	}
	if got := sink.records(); len(got) != 0 {
		t.Fatalf("an accepted record was offered as refused: %+v", got)
	}
	_, err := builder.BuildLogCompatHookDecision(rejectedTestHookDecision("rejected-capture-bad", "success"))
	if !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("build error=%v", err)
	}
	if err.Error() != "telemetry family build failed: constraint_violation" {
		t.Fatalf("the producer's error text changed: %q", err.Error())
	}
	got := sink.records()
	if len(got) != 1 {
		t.Fatalf("offers=%d, want 1", len(got))
	}
	record := got[0]
	if record.Signal != SignalLogs || record.Reason != FamilyBuildConstraint ||
		record.Field != "defenseclaw.hook.result" || record.EventName == "" || record.Family == "" ||
		record.FamilySchemaVersion == 0 || record.ObservedAt.IsZero() {
		t.Fatalf("offered record=%+v", record)
	}
	if record.Body["defenseclaw.hook.result"] != "success" {
		t.Fatalf("refused value not captured: %v", record.Body)
	}
	if want := "telemetry family build failed: constraint_violation; field defenseclaw.hook.result"; record.ErrorText() != want {
		t.Fatalf("error text=%q want %q", record.ErrorText(), want)
	}
	if err := verifyFamilyFieldClassCoverage(record.Body, record.FieldClasses); err != nil {
		t.Fatalf("captured classes do not cover the body: %v", err)
	}
}

func TestRejectedRecordCaptureBoundsLargeValues(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	sink := &recordingRejectedSink{marker: "rejected-bounds-"}
	uninstall := InstallRejectedRecordSink(sink)
	defer uninstall()

	input := rejectedTestHookDecision("rejected-bounds-1", "success")
	input.DefenseClawGuardrailReason = Present(strings.Repeat("r", RejectedRecordMaxFieldBytes+1))
	if _, err := builder.BuildLogCompatHookDecision(input); err == nil {
		t.Fatal("refused input was accepted")
	}
	got := sink.records()
	if len(got) != 1 {
		t.Fatalf("offers=%d", len(got))
	}
	if _, kept := got[0].Body["defenseclaw.guardrail.reason"]; kept {
		t.Fatal("a value over RejectedRecordMaxFieldBytes was captured")
	}
	if len(got[0].OmittedFields) != 1 || got[0].OmittedFields[0] != "defenseclaw.guardrail.reason" {
		t.Fatalf("omitted=%v", got[0].OmittedFields)
	}
	if size := rejectedValueBytes(got[0].Body); size > RejectedRecordMaxCaptureBytes+2 {
		t.Fatalf("captured %d bytes", size)
	}
}

func TestRejectedRecordSinkUninstallRemovesOnlyItsOwnInstallation(t *testing.T) {
	first := InstallRejectedRecordSink(&recordingRejectedSink{})
	second := InstallRejectedRecordSink(&recordingRejectedSink{})
	first()
	if !RejectedRecordSinkInstalled() {
		t.Fatal("removing an older installation removed the current sink")
	}
	second()
	if RejectedRecordSinkInstalled() {
		t.Fatal("the current sink was not removed")
	}
	InstallRejectedRecordSink(nil)()
	if RejectedRecordSinkInstalled() {
		t.Fatal("a nil sink was installed")
	}
}

func TestRejectedRecordWithoutSinkCostsNothing(t *testing.T) {
	if RejectedRecordSinkInstalled() {
		t.Skip("another test has a sink installed")
	}
	builder, _ := testFamilyBuilder(t)
	input := rejectedTestHookDecision("rejected-off-1", "success")
	refused := familyBuildFailure(FamilyBuildConstraint)
	allocs := testing.AllocsPerRun(20, func() {
		offerRejectedFamilyRecord(familyDescriptorContract{}, SignalLogs, input.Envelope, nil, refused)
	})
	if allocs != 0 {
		t.Fatalf("the off path allocated %.0f times per refused record", allocs)
	}
	if _, err := builder.BuildLogCompatHookDecision(input); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("build error=%v", err)
	}
}

func TestFamilyBuildErrorFieldIsSchemaKeyOnly(t *testing.T) {
	err := withFamilyField(familyBuildFailure(FamilyBuildMissingRequired), "defenseclaw.hook.event")
	var buildError *FamilyBuildError
	if !IsFamilyBuildError(err, FamilyBuildMissingRequired) || !asFamilyBuildError(err, &buildError) ||
		buildError.Field() != "defenseclaw.hook.event" {
		t.Fatalf("field error=%#v", err)
	}
	if again := withFamilyField(err, "other"); again.(*FamilyBuildError).Field() != "defenseclaw.hook.event" {
		t.Fatal("an inner field name was replaced by an outer one")
	}
	if (*FamilyBuildError)(nil).Field() != "" {
		t.Fatal("nil error field")
	}
}

func asFamilyBuildError(err error, target **FamilyBuildError) bool {
	typed, ok := err.(*FamilyBuildError)
	if ok {
		*target = typed
	}
	return ok
}

func TestRejectedRecordNoCopyWhenTheSinkRefusesTheReservation(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	sink := &recordingRejectedSink{marker: "rejected-reserve-", refuse: true}
	uninstall := InstallRejectedRecordSink(sink)
	defer uninstall()
	if _, err := builder.BuildLogCompatHookDecision(rejectedTestHookDecision("rejected-reserve-1", "success")); err == nil {
		t.Fatal("refused input was accepted")
	}
	if got := sink.records(); len(got) != 0 {
		t.Fatalf("a refused reservation still offered %d records", len(got))
	}
}

func TestRejectedRecordCaptureSkipsAMultiMegabyteValueBeforeCopying(t *testing.T) {
	huge := strings.Repeat("x", 4<<20)
	body, _, omitted := captureRejectedFamilyValues(
		[]familyFieldDescriptor{{key: "big", fieldClass: FieldClassContent}, {key: "small", fieldClass: FieldClassMetadata}},
		familyFieldValues{{key: "big", value: huge, present: true}, {key: "small", value: "ok", present: true}},
	)
	if _, kept := body["big"]; kept || body["small"] != "ok" || len(omitted) != 1 || omitted[0] != "big" {
		t.Fatalf("body keys=%d omitted=%v", len(body), omitted)
	}
	allocs := testing.AllocsPerRun(5, func() {
		captureRejectedFamilyValues(
			[]familyFieldDescriptor{{key: "big", fieldClass: FieldClassContent}},
			familyFieldValues{{key: "big", value: huge, present: true}},
		)
	})
	if allocs > 12 {
		t.Fatalf("an oversize value was copied: %.0f allocations", allocs)
	}
}
