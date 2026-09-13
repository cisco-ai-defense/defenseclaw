// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestResolvePendingPromotesExactADCSPFXResultToEnforcementLineage(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainADCSCertificateRequestThenPFXAuth,
	)
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	pfxDigest := strings.Repeat("a", 64)

	pre := fixture.seed(t, "adcs-pfx-resolve", correlationDigest("adcs-request-pre"))
	predecessor := guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step1Bit,
	}
	invocation := correlationDigest("adcs-request-invocation")
	prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint, Projection: predecessor,
	})
	if err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%+v err=%v", prepared, err)
	}

	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "adcs-pfx-resolve", correlationDigest("adcs-request-result"))
	resolve := ToolChainResolvePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: pre.RulesetFingerprint,
		TerminalSemanticEventID:            terminal.SemanticEventID,
		TerminalInputFingerprint:           terminal.InputFingerprint,
		SuccessfulADCSCertificatePFXDigest: pfxDigest,
	}
	resolved, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || resolved.Status != ToolChainPendingResolved ||
		resolved.Observation.Status != ToolChainObserveFresh ||
		resolved.Observation.DetectedMask != 0 {
		t.Fatalf("resolve=%+v err=%v", resolved, err)
	}

	fixture.now = fixture.now.Add(time.Second)
	sink := fixture.seed(t, "adcs-pfx-resolve", correlationDigest("adcs-auth-pre"))
	sink.Projection = guardrail.ToolChainProjection{
		ParseStatus:         actionfacts.StatusComplete,
		DetectionStepMask:   definition.Step2Bit,
		EnforcementStepMask: definition.Step2Bit,
	}
	sink.Projection.EnforcementJoinDigests[index] = pfxDigest
	sink.DenyEligible = true
	matched, err := fixture.chain.Observe(t.Context(), sink)
	if err != nil || matched.DetectedMask&definition.ResultBit == 0 ||
		matched.EnforcementSafeMask&definition.ResultBit == 0 ||
		matched.DeniedMask&definition.ResultBit == 0 {
		t.Fatalf("matched=%+v err=%v", matched, err)
	}

	encoded, err := json.Marshal(resolve)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), pfxDigest) {
		t.Fatalf("private PFX identity serialized: %s", encoded)
	}
}

func TestResolvePendingRejectsADCSPFXWithoutExactRequestPredecessor(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	pre := fixture.seed(t, "adcs-pfx-mismatch", correlationDigest("unrelated-pre"))
	invocation := correlationDigest("unrelated-invocation")
	_, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint,
		Projection:         guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "adcs-pfx-mismatch", correlationDigest("unrelated-result"))
	_, err = fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: pre.RulesetFingerprint,
		TerminalSemanticEventID:            terminal.SemanticEventID,
		TerminalInputFingerprint:           terminal.InputFingerprint,
		SuccessfulADCSCertificatePFXDigest: strings.Repeat("b", 64),
	})
	if !errors.Is(err, ErrToolChainIntegrity) {
		t.Fatalf("mismatched result error=%v", err)
	}
}

func TestResolvePendingRejectsADCSPFXLineageOnFailure(t *testing.T) {
	input := ToolChainResolvePendingInput{
		ConnectorInstanceID:                ConnectorInstanceID("0198f0c2-7b31-7a42-8c51-abcdef012345"),
		ToolInvocationDigest:               strings.Repeat("a", 64),
		Outcome:                            ToolChainPendingOutcomeFailure,
		TerminalSemanticEventID:            SemanticEventID("0198f0c2-7b31-7a42-8c51-abcdef012346"),
		TerminalInputFingerprint:           strings.Repeat("b", 64),
		SuccessfulADCSCertificatePFXDigest: strings.Repeat("c", 64),
	}
	if err := validateToolChainResolvePendingInput(input); err == nil ||
		!strings.Contains(err.Error(), "unsuccessful") {
		t.Fatalf("validation error=%v", err)
	}
}
