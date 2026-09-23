// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestSensitiveSQLValueCrossResourcePersistenceRequiresExactBoundedProof(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(
		ToolChainSensitiveSQLValueCrossResourcePersist,
	)
	if !ok || !definition.DetectionOnly || !definition.RequiresValueJoin ||
		!definition.RequiresDistinctResourceJoin ||
		!definition.RequiresTerminalSuccess || definition.EventWindow != 9 {
		t.Fatalf("definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const (
		sourceResource = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sinkResource   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		valueDigest    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		otherValue     = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	projection := func(step uint64, resource, value string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = resource
		result.ValueJoinDigests[index][0] = value
		return result
	}
	now := time.Date(2026, 9, 12, 15, 0, 0, 0, time.UTC)
	source := ToolChainWindowEvent{
		SemanticEventID: "source", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, sourceResource, valueDigest),
	}
	validSink := ToolChainWindowEvent{
		SemanticEventID: "sink", Sequence: 9, ReceivedAt: now.Add(time.Minute),
		Projection: projection(definition.Step2Bit, sinkResource, valueDigest),
	}

	matches, err := MatchToolChains([]ToolChainWindowEvent{source}, validSink)
	if err != nil || matches.DetectedMask&definition.ResultBit == 0 ||
		matches.EnforcementSafeMask&definition.ResultBit != 0 ||
		matches.DetectionPredecessors[index] != source.SemanticEventID {
		t.Fatalf("valid bounded match=%+v err=%v", matches, err)
	}

	for name, mutate := range map[string]func(*ToolChainWindowEvent, *ToolChainWindowEvent){
		"same resource": func(source, sink *ToolChainWindowEvent) {
			sink.Projection.EnforcementJoinDigests[index] = sourceResource
		},
		"value mismatch or key drift": func(source, sink *ToolChainWindowEvent) {
			sink.Projection.ValueJoinDigests[index][0] = otherValue
		},
		"missing source authority": func(source, sink *ToolChainWindowEvent) {
			source.Projection.ParseStatus = actionfacts.StatusPartial
		},
		"missing sink resource": func(source, sink *ToolChainWindowEvent) {
			sink.Projection.EnforcementJoinDigests[index] = ""
		},
		"outside event bound": func(source, sink *ToolChainWindowEvent) {
			sink.Sequence = 10
		},
		"outside time bound": func(source, sink *ToolChainWindowEvent) {
			sink.ReceivedAt = now.Add(31 * time.Minute)
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateSource, candidateSink := source, validSink
			mutate(&candidateSource, &candidateSink)
			got, err := MatchToolChains(
				[]ToolChainWindowEvent{candidateSource}, candidateSink,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got.DetectedMask&definition.ResultBit != 0 ||
				got.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatalf("unexpected match=%+v", got)
			}
		})
	}
}
