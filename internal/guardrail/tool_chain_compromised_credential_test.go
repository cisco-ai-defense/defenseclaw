// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestCompromisedCredentialAuthenticationRequiresExactBoundedProof(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(
		ToolChainCompromisedCredentialThenAuthenticate,
	)
	if !ok || !definition.DetectionOnly || !definition.RequiresExactJoin ||
		!definition.RequiresValueJoin || !definition.ValueJoinOwnsParseProof ||
		!definition.RequiresTerminalSuccess ||
		definition.MutationBit == 0 || definition.EventWindow != 9 {
		t.Fatalf("definition=%+v", definition)
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const (
		accountA    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		accountB    = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		credentialA = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
		credentialB = "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"
	)
	projection := func(step uint64, account, credential string) ToolChainProjection {
		result := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   step,
			EnforcementStepMask: step,
		}
		result.EnforcementJoinDigests[index] = account
		result.ValueJoinDigests[index][0] = credential
		return result
	}
	now := time.Date(2026, 9, 15, 12, 0, 0, 0, time.UTC)
	source := ToolChainWindowEvent{
		SemanticEventID: "source", Sequence: 1, ReceivedAt: now,
		Projection: projection(definition.Step1Bit, accountA, credentialA),
	}
	terminal := ToolChainWindowEvent{
		SemanticEventID: "terminal", Sequence: 9, ReceivedAt: now.Add(time.Minute),
		Projection: projection(definition.Step2Bit, accountA, credentialA),
	}

	matched, err := MatchToolChains([]ToolChainWindowEvent{source}, terminal)
	if err != nil || matched.DetectedMask&definition.ResultBit == 0 ||
		matched.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("valid match=%+v err=%v", matched, err)
	}

	for name, mutate := range map[string]func(*ToolChainWindowEvent, *ToolChainWindowEvent){
		"mismatch account": func(source, terminal *ToolChainWindowEvent) {
			terminal.Projection.EnforcementJoinDigests[index] = accountB
		},
		"mismatch credential": func(source, terminal *ToolChainWindowEvent) {
			terminal.Projection.ValueJoinDigests[index][0] = credentialB
		},
		"distance greater than eight": func(source, terminal *ToolChainWindowEvent) {
			terminal.Sequence = 10
		},
		"missing credential reference": func(source, terminal *ToolChainWindowEvent) {
			source.Projection.ValueJoinDigests[index] = ToolChainValueJoinDigests{}
		},
	} {
		t.Run(name, func(t *testing.T) {
			candidateSource, candidateTerminal := source, terminal
			mutate(&candidateSource, &candidateTerminal)
			got, err := MatchToolChains(
				[]ToolChainWindowEvent{candidateSource}, candidateTerminal,
			)
			if err != nil {
				t.Fatal(err)
			}
			if got.DetectedMask&definition.ResultBit != 0 {
				t.Fatalf("unexpected match=%+v", got)
			}
		})
	}

	intervening := ToolChainWindowEvent{
		SemanticEventID: "replacement", Sequence: 5,
		ReceivedAt: now.Add(30 * time.Second),
		Projection: projection(
			definition.Step1Bit|definition.MutationBit,
			accountA,
			credentialB,
		),
	}
	got, err := MatchToolChains([]ToolChainWindowEvent{source, intervening}, terminal)
	if err != nil {
		t.Fatal(err)
	}
	if got.DetectedMask&definition.ResultBit != 0 {
		t.Fatalf("intervening credential replacement matched: %+v", got)
	}
}
