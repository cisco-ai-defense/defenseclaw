// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// substrate-1:GAP-0226. A credentials-file read inside a pipeline or a
// command list parses partial (another stage has an unknown operand
// grammar). It may start the secret-read chain only when it carries the read
// file's exact identity; the egress still needs a complete parse, and the
// step never authorizes enforcement.
func TestSecretReadChainStepOneOwnsParseProofGAP0226(t *testing.T) {
	definition, ok := ToolChainDefinitionByID(ToolChainSecretReadThenEgress)
	if !ok || !definition.Step1IdentityOwnsParseProof {
		t.Fatalf("definition %+v does not let step 1 own its parse proof", definition)
	}
	index, _ := ToolChainIndexByID(ToolChainSecretReadThenEgress)
	start := time.Unix(1_800_000_000, 0)
	digest := strings.Repeat("ab", 32)
	other := strings.Repeat("cd", 32)
	read := func(status actionfacts.ParseStatus, join string) ToolChainWindowEvent {
		projection := ToolChainProjection{ParseStatus: status, DetectionStepMask: definition.Step1Bit}
		projection.EnforcementJoinDigests[index] = join
		return ToolChainWindowEvent{SemanticEventID: "read", Sequence: 1, ReceivedAt: start, Projection: projection}
	}
	egress := func(status actionfacts.ParseStatus, join string) ToolChainWindowEvent {
		projection := ToolChainProjection{ParseStatus: status, DetectionStepMask: definition.Step2Bit}
		projection.EnforcementJoinDigests[index] = join
		return ToolChainWindowEvent{SemanticEventID: "egress", Sequence: 2, ReceivedAt: start.Add(time.Second), Projection: projection}
	}
	for _, test := range []struct {
		name         string
		read, egress ToolChainWindowEvent
		want         bool
	}{
		{"complete read", read(actionfacts.StatusComplete, ""), egress(actionfacts.StatusComplete, ""), true},
		{"partial read with its identity", read(actionfacts.StatusPartial, digest), egress(actionfacts.StatusComplete, ""), true},
		{"partial read with its identity, same file uploaded", read(actionfacts.StatusPartial, digest), egress(actionfacts.StatusComplete, digest), true},
		{"partial read without identity", read(actionfacts.StatusPartial, ""), egress(actionfacts.StatusComplete, ""), false},
		{"partial read, another exact file uploaded", read(actionfacts.StatusPartial, digest), egress(actionfacts.StatusComplete, other), false},
		{"ambiguous read with identity", read(actionfacts.StatusAmbiguous, digest), egress(actionfacts.StatusComplete, ""), false},
		{"partial egress", read(actionfacts.StatusPartial, digest), egress(actionfacts.StatusPartial, ""), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			matches, err := MatchToolChains([]ToolChainWindowEvent{test.read}, test.egress)
			if err != nil {
				t.Fatal(err)
			}
			if got := matches.DetectedMask&definition.ResultBit != 0; got != test.want {
				t.Fatalf("detected = %t, want %t", got, test.want)
			}
			if matches.EnforcementSafeMask&definition.ResultBit != 0 {
				t.Fatal("a detection-only read step authorized enforcement")
			}
		})
	}
}
