// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestResolvePendingPromotesExactS4UTicketResultToCacheLineage(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainS4UTicketThenKerberosSecretsdump,
	)
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	targetDigest := strings.Repeat("a", 64)
	cacheDigest := strings.Repeat("b", 64)

	pre := fixture.seed(t, "s4u-resolve", correlationDigest("s4u-request-pre"))
	predecessor := guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step1Bit,
	}
	predecessor.EnforcementJoinDigests[index] = targetDigest
	invocation := correlationDigest("s4u-request-invocation")
	prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint, Projection: predecessor,
	})
	if err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%+v err=%v", prepared, err)
	}

	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "s4u-resolve", correlationDigest("s4u-request-result"))
	resolved, err := fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: pre.RulesetFingerprint,
		TerminalSemanticEventID:                    terminal.SemanticEventID,
		TerminalInputFingerprint:                   terminal.InputFingerprint,
		SuccessfulS4UTargetPrincipalIdentityDigest: targetDigest,
		SuccessfulS4UTicketCacheDigest:             cacheDigest,
	})
	if err != nil || resolved.Status != ToolChainPendingResolved ||
		resolved.Observation.Status != ToolChainObserveFresh ||
		resolved.Observation.DetectedMask != 0 {
		t.Fatalf("resolve=%+v err=%v", resolved, err)
	}

	fixture.now = fixture.now.Add(time.Second)
	sink := fixture.seed(t, "s4u-resolve", correlationDigest("s4u-secretsdump-pre"))
	sink.Projection = guardrail.ToolChainProjection{
		ParseStatus:         actionfacts.StatusComplete,
		DetectionStepMask:   definition.Step2Bit,
		EnforcementStepMask: definition.Step2Bit,
	}
	sink.Projection.EnforcementJoinDigests[index] = cacheDigest
	sink.DenyEligible = true
	matched, err := fixture.chain.Observe(t.Context(), sink)
	if err != nil || matched.DetectedMask&definition.ResultBit == 0 ||
		matched.EnforcementSafeMask&definition.ResultBit == 0 ||
		matched.DeniedMask&definition.ResultBit == 0 {
		t.Fatalf("matched=%+v err=%v", matched, err)
	}
}

func TestResolvePendingRejectsS4UTargetMismatch(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainS4UTicketThenKerberosSecretsdump,
	)
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	pre := fixture.seed(t, "s4u-mismatch", correlationDigest("s4u-mismatch-pre"))
	projection := guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step1Bit,
	}
	projection.EnforcementJoinDigests[index] = strings.Repeat("a", 64)
	invocation := correlationDigest("s4u-mismatch-invocation")
	_, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint, Projection: projection,
	})
	if err != nil {
		t.Fatal(err)
	}
	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "s4u-mismatch", correlationDigest("s4u-mismatch-result"))
	_, err = fixture.chain.ResolvePending(t.Context(), ToolChainResolvePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: pre.RulesetFingerprint,
		TerminalSemanticEventID:                    terminal.SemanticEventID,
		TerminalInputFingerprint:                   terminal.InputFingerprint,
		SuccessfulS4UTargetPrincipalIdentityDigest: strings.Repeat("b", 64),
		SuccessfulS4UTicketCacheDigest:             strings.Repeat("c", 64),
	})
	if !errors.Is(err, ErrToolChainIntegrity) {
		t.Fatalf("mismatched result error=%v", err)
	}
}

func TestS4UResultLineageValidationRequiresSuccessfulCompletePair(t *testing.T) {
	base := ToolChainResolvePendingInput{
		ConnectorInstanceID:      ConnectorInstanceID("0198f0c2-7b31-7a42-8c51-abcdef012345"),
		ToolInvocationDigest:     strings.Repeat("a", 64),
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       strings.Repeat("b", 64),
		TerminalSemanticEventID:  SemanticEventID("0198f0c2-7b31-7a42-8c51-abcdef012346"),
		TerminalInputFingerprint: strings.Repeat("c", 64),
	}
	base.SuccessfulS4UTicketCacheDigest = strings.Repeat("d", 64)
	if err := validateToolChainResolvePendingInput(base); err == nil ||
		!strings.Contains(err.Error(), "incomplete") {
		t.Fatalf("incomplete-pair validation error=%v", err)
	}

	base.SuccessfulS4UTargetPrincipalIdentityDigest = strings.Repeat("e", 64)
	base.Outcome = ToolChainPendingOutcomeFailure
	if err := validateToolChainResolvePendingInput(base); err == nil ||
		!strings.Contains(err.Error(), "unsuccessful") {
		t.Fatalf("failure validation error=%v", err)
	}

	base.Outcome = ToolChainPendingOutcomeSuccess
	base.SuccessfulADCSCertificatePFXDigest = strings.Repeat("f", 64)
	if err := validateToolChainResolvePendingInput(base); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("ambiguous validation error=%v", err)
	}

}
