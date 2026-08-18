// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestMatchToolChainsFixedCatalog(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for _, definition := range ToolChainDefinitions() {
		t.Run(definition.ID, func(t *testing.T) {
			if definition.Severity != "HIGH" {
				t.Fatalf("severity=%q want HIGH", definition.Severity)
			}
			matches, err := MatchToolChains([]ToolChainWindowEvent{{
				SemanticEventID: "first", Sequence: 1, ReceivedAt: now,
				Projection: ToolChainProjection{
					ParseStatus:         actionfacts.StatusComplete,
					DetectionStepMask:   definition.Step1Bit,
					EnforcementStepMask: definition.Step1Bit,
				},
			}}, ToolChainWindowEvent{
				SemanticEventID: "final", Sequence: 2, ReceivedAt: now.Add(time.Second),
				Projection: ToolChainProjection{
					ParseStatus:         actionfacts.StatusComplete,
					DetectionStepMask:   definition.Step2Bit,
					EnforcementStepMask: definition.Step2Bit,
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			if matches.DetectedMask != definition.ResultBit ||
				matches.EnforcementSafeMask != definition.ResultBit {
				t.Fatalf("masks=%06b/%06b want %06b",
					matches.DetectedMask, matches.EnforcementSafeMask, definition.ResultBit)
			}
		})
	}
}

func TestMatchToolChainsUsesIndependentEarliestPredecessors(t *testing.T) {
	definition, _ := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	prior := []ToolChainWindowEvent{
		{
			SemanticEventID: "enforcement", Sequence: 4, ReceivedAt: now.Add(4 * time.Second),
			Projection: ToolChainProjection{
				ParseStatus:       actionfacts.StatusComplete,
				DetectionStepMask: definition.Step1Bit, EnforcementStepMask: definition.Step1Bit,
			},
		},
		{
			SemanticEventID: "detection", Sequence: 2, ReceivedAt: now.Add(2 * time.Second),
			Projection: ToolChainProjection{
				ParseStatus: actionfacts.StatusPartial, DetectionStepMask: definition.Step1Bit,
			},
		},
	}
	matches, err := MatchToolChains(prior, ToolChainWindowEvent{
		SemanticEventID: "final", Sequence: 5, ReceivedAt: now.Add(5 * time.Second),
		Projection: ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: definition.Step2Bit, EnforcementStepMask: definition.Step2Bit,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	index := 4
	if matches.DetectionPredecessors[index] != "detection" ||
		matches.EnforcementPredecessors[index] != "enforcement" {
		t.Fatalf("predecessors=%q/%q", matches.DetectionPredecessors[index],
			matches.EnforcementPredecessors[index])
	}
}

func TestMatchToolChainsEnforcesOrderAndBothWindows(t *testing.T) {
	now := time.Date(2026, 7, 30, 12, 0, 0, 0, time.UTC)
	for _, definition := range ToolChainDefinitions() {
		t.Run(definition.ID, func(t *testing.T) {
			final := ToolChainWindowEvent{
				SemanticEventID: "final",
				Sequence:        definition.EventWindow + 2,
				ReceivedAt:      now,
				Projection: ToolChainProjection{
					ParseStatus:       actionfacts.StatusComplete,
					DetectionStepMask: definition.Step2Bit,
				},
			}
			for name, prior := range map[string]ToolChainWindowEvent{
				"reversed": {
					SemanticEventID: "later",
					Sequence:        final.Sequence + 1,
					ReceivedAt:      now,
				},
				"event-window": {
					SemanticEventID: "old-sequence",
					Sequence:        final.Sequence - definition.EventWindow,
					ReceivedAt:      now,
				},
				"time-window": {
					SemanticEventID: "old-time",
					Sequence:        final.Sequence - 1,
					ReceivedAt:      now.Add(-definition.TimeWindow - time.Nanosecond),
				},
			} {
				t.Run(name, func(t *testing.T) {
					prior.Projection = ToolChainProjection{
						ParseStatus:       actionfacts.StatusComplete,
						DetectionStepMask: definition.Step1Bit,
					}
					matches, err := MatchToolChains([]ToolChainWindowEvent{prior}, final)
					if err != nil {
						t.Fatal(err)
					}
					if matches.DetectedMask != 0 {
						t.Fatalf("out-of-window match=%06b", matches.DetectedMask)
					}
				})
			}
		})
	}
}

func TestToolChainProjectionAndFingerprintsAreClosed(t *testing.T) {
	if err := ValidateToolChainProjection(ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: 1, EnforcementStepMask: 2,
	}); err == nil {
		t.Fatal("non-subset enforcement mask accepted")
	}
	if _, err := ToolChainRulesetFingerprint("not-a-digest"); err == nil {
		t.Fatal("invalid relevant-owner digest accepted")
	}
	digest := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	first, err := ToolChainRulesetFingerprint(digest)
	if err != nil {
		t.Fatal(err)
	}
	second, err := ToolChainFingerprint(ToolChainSecretReadThenEgress, first)
	if err != nil || len(second) != 64 {
		t.Fatalf("chain fingerprint=%q err=%v", second, err)
	}
}
