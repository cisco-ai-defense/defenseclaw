// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// rel-1-0-10:GAP-1180: for the secret-read chain the content-free artifact
// barrier (a write anywhere between the two calls) drops only the
// enforcement join; the chain is still detected. Every other barrier chain
// keeps the barrier on both joins.
func TestMatchToolChainsSecretReadBarrierKeepsTheDetection(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	if !ok || !definition.ArtifactMutationBarrier || !definition.ArtifactMutationBarrierEnforcementOnly {
		t.Fatalf("secret-read chain definition=%+v", definition)
	}
	for _, other := range ToolChainDefinitions() {
		if other.ID != ToolChainSecretReadThenEgress && other.ArtifactMutationBarrierEnforcementOnly {
			t.Errorf("%s: only the secret-read chain keeps its detection over the barrier", other.ID)
		}
	}
	index, _ := ToolChainIndexByID(definition.ID)
	const file = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	now := time.Unix(1_800_000_000, 0).UTC()
	step := func(bit uint64, digest string) ToolChainProjection {
		projection := ToolChainProjection{
			ParseStatus:         actionfacts.StatusComplete,
			DetectionStepMask:   bit,
			EnforcementStepMask: bit,
		}
		projection.EnforcementJoinDigests[index] = digest
		return projection
	}
	read := ToolChainWindowEvent{SemanticEventID: "read", Sequence: 1, ReceivedAt: now, Projection: step(definition.Step1Bit, file)}
	write := ToolChainWindowEvent{SemanticEventID: "write", Sequence: 2, ReceivedAt: now.Add(time.Second), Projection: ToolChainProjection{
		ParseStatus: actionfacts.StatusComplete, DetectionStepMask: ToolChainArtifactMutationBarrier,
	}}
	upload := ToolChainWindowEvent{SemanticEventID: "upload", Sequence: 3, ReceivedAt: now.Add(2 * time.Second), Projection: step(definition.Step2Bit, file)}

	plain, err := MatchToolChains([]ToolChainWindowEvent{read}, upload)
	if err != nil || plain.DetectedMask&definition.ResultBit == 0 || plain.EnforcementSafeMask&definition.ResultBit == 0 {
		t.Fatalf("read then upload of one file: %+v err=%v, want detected and enforcement-safe", plain, err)
	}
	barrier, err := MatchToolChains([]ToolChainWindowEvent{read, write}, upload)
	if err != nil {
		t.Fatal(err)
	}
	if barrier.DetectedMask&definition.ResultBit == 0 || barrier.DetectionPredecessors[index] != "read" {
		t.Fatalf("a write between the read and the upload hid the chain: %+v", barrier)
	}
	if barrier.EnforcementSafeMask&definition.ResultBit != 0 {
		t.Fatalf("a write between the read and the upload kept the enforcement join: %+v", barrier)
	}
}
