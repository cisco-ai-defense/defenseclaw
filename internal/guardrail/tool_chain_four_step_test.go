// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

const (
	fourStepFirstBit    = uint64(1 << 57)
	fourStepSecondBit   = uint64(1 << 58)
	fourStepThirdBit    = uint64(1 << 59)
	fourStepTerminalBit = uint64(1 << 60)
	fourStepMutationBit = uint64(1 << 61)
)

func TestFourStepAllocationFailsClosedBeforeReservedSignBit(t *testing.T) {
	definitions := ToolChainDefinitions()
	deployed := append([]ToolChainDefinition(nil), definitions...)
	definitions = append(definitions, ToolChainDefinition{
		ID: "test.four-step-capability", FourStep: true,
	})
	defer func() {
		if recovered := recover(); recovered == nil {
			t.Error("four-step allocation crossed the reserved step sign bit")
			return
		}
		for index := range deployed {
			got, want := definitions[index], deployed[index]
			if got.Step1Bit != want.Step1Bit || got.Step2Bit != want.Step2Bit ||
				got.Step3Bit != want.Step3Bit || got.Step4Bit != want.Step4Bit ||
				got.MutationBit != want.MutationBit || got.ResultBit != want.ResultBit {
				t.Fatalf("deployed slot %d was renumbered before rejection: got=%+v want=%+v",
					index, got, want)
			}
		}
	}()
	allocateToolChainBits(definitions, 0)
}

func TestUnallocatedFourStepBitsRemainInvalidAtRuntime(t *testing.T) {
	projection := ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete, DetectionStepMask: uint64(1 << 61),
	}
	if err := ValidateToolChainProjection(projection); err == nil {
		t.Fatal("unallocated future step bit was accepted before a catalog definition exists")
	}
}

func TestFourStepMatcherRequiresOrderedBoundedExactLineage(t *testing.T) {
	definition := testFourStepDefinition()
	base := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	first, second, third, final := testFourStepEvents(base, definition)

	matches := ToolChainMatches{}
	matchFourStepToolChain([]ToolChainWindowEvent{first, second, third}, final, 0, definition, &matches)
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit == 0 ||
		matches.DetectionPredecessors[0] != third.SemanticEventID ||
		matches.EnforcementPredecessors[0] != third.SemanticEventID {
		t.Fatalf("exact four-step proof did not match: %+v", matches)
	}

	for _, test := range []struct {
		name  string
		prior []ToolChainWindowEvent
		final ToolChainWindowEvent
	}{
		{name: "wrong order", prior: []ToolChainWindowEvent{second, first, third}, final: final},
		{name: "identity mismatch", prior: []ToolChainWindowEvent{first, second, withFourStepInput(third, 0, "other")}, final: final},
		{name: "ten events", prior: []ToolChainWindowEvent{first, second, third}, final: withFourStepSequence(final, 10)},
		{name: "outside time", prior: []ToolChainWindowEvent{first, second, third}, final: withFourStepTime(final, base.Add(31*time.Minute))},
	} {
		t.Run(test.name, func(t *testing.T) {
			got := ToolChainMatches{}
			matchFourStepToolChain(test.prior, test.final, 0, definition, &got)
			if got.DetectedMask&definition.ResultBit != 0 ||
				got.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatalf("invalid four-step proof matched: %+v", got)
			}
		})
	}

	finalAtNinthEvent := withFourStepSequence(final, 9)
	withinBound := ToolChainMatches{}
	matchFourStepToolChain(
		[]ToolChainWindowEvent{first, second, third}, finalAtNinthEvent, 0, definition, &withinBound,
	)
	if withinBound.DetectedMask&definition.ResultBit == 0 {
		t.Fatalf("nine-event proof was rejected: %+v", withinBound)
	}
}

func TestFourStepMatcherRejectsMutationBarriersAndUntrustedSteps(t *testing.T) {
	definition := testFourStepDefinition()
	base := time.Date(2026, 9, 12, 12, 0, 0, 0, time.UTC)
	first, second, third, final := testFourStepEvents(base, definition)
	barrier := ToolChainWindowEvent{
		SemanticEventID: "barrier", Sequence: 4, ReceivedAt: base.Add(4 * time.Second),
		Projection: ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: ToolChainArtifactMutationBarrier,
		},
	}
	exactMutation := ToolChainWindowEvent{
		SemanticEventID: "mutation", Sequence: 4, ReceivedAt: base.Add(4 * time.Second),
		Projection: testFourStepProjection(definition.MutationBit, "b", "", true),
	}
	for _, candidate := range []ToolChainWindowEvent{barrier, exactMutation} {
		matches := ToolChainMatches{}
		matchFourStepToolChain(
			[]ToolChainWindowEvent{first, second, candidate, third}, final,
			0, definition, &matches,
		)
		if matches.DetectedMask&definition.ResultBit != 0 {
			t.Fatalf("mutation barrier %s did not invalidate proof: %+v", candidate.SemanticEventID, matches)
		}
	}

	second.Projection.ParseStatus = actionfacts.StatusPartial
	second.Projection.EnforcementStepMask = 0
	matches := ToolChainMatches{}
	matchFourStepToolChain([]ToolChainWindowEvent{first, second, third}, final, 0, definition, &matches)
	if matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("partial step did not remain detection-only: %+v", matches)
	}
}

func testFourStepDefinition() ToolChainDefinition {
	return ToolChainDefinition{
		ID: "test.four-step-capability", Severity: "CRITICAL",
		EventWindow: 9, TimeWindow: 30 * time.Minute,
		Step1Bit: fourStepFirstBit, Step2Bit: fourStepSecondBit,
		Step3Bit: fourStepThirdBit, Step4Bit: fourStepTerminalBit,
		MutationBit: fourStepMutationBit, ResultBit: uint32(1 << 20),
		RequiresExactJoin: true, ArtifactMutationBarrier: true, FourStep: true,
	}
}

func testFourStepEvents(
	base time.Time,
	definition ToolChainDefinition,
) (ToolChainWindowEvent, ToolChainWindowEvent, ToolChainWindowEvent, ToolChainWindowEvent) {
	return ToolChainWindowEvent{
			SemanticEventID: "first", Sequence: 1, ReceivedAt: base,
			Projection: testFourStepProjection(definition.Step1Bit, "", "a", true),
		}, ToolChainWindowEvent{
			SemanticEventID: "second", Sequence: 3, ReceivedAt: base.Add(3 * time.Second),
			Projection: testFourStepProjection(definition.Step2Bit, "a", "b", true),
		}, ToolChainWindowEvent{
			SemanticEventID: "third", Sequence: 6, ReceivedAt: base.Add(6 * time.Second),
			Projection: testFourStepProjection(definition.Step3Bit, "b", "c", true),
		}, ToolChainWindowEvent{
			SemanticEventID: "final", Sequence: 8, ReceivedAt: base.Add(8 * time.Second),
			Projection: testFourStepProjection(definition.Step4Bit, "c", "", true),
		}
}

func testFourStepProjection(step uint64, input, output string, enforce bool) ToolChainProjection {
	projection := ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete, DetectionStepMask: step,
	}
	if enforce {
		projection.EnforcementStepMask = step
	}
	projection.EnforcementJoinDigests[0] = input
	projection.EnforcementOutputJoinDigests[0] = output
	return projection
}

func withFourStepInput(event ToolChainWindowEvent, index int, input string) ToolChainWindowEvent {
	event.Projection.EnforcementJoinDigests[index] = input
	return event
}

func withFourStepSequence(event ToolChainWindowEvent, sequence uint64) ToolChainWindowEvent {
	event.Sequence = sequence
	return event
}

func withFourStepTime(event ToolChainWindowEvent, received time.Time) ToolChainWindowEvent {
	event.ReceivedAt = received
	return event
}
