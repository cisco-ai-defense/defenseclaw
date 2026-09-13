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

func TestResolvePendingAttachesSQLProjectionOnlyAfterExactAuthoritativeSuccess(t *testing.T) {
	fixture := newToolChainFixture(t, ":memory:")
	definition, _ := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSensitiveSQLValueCrossResourcePersist,
	)
	index, _ := guardrail.ToolChainIndexByID(definition.ID)
	const (
		sourceResource = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
		sinkResource   = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
		valueDigest    = "cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc"
	)
	sourceDescriptor := ToolChainPendingSQLValueSource{
		TableClass:             actionfacts.SensitiveSQLTableCredentials,
		DatabaseIdentityDigest: strings.Repeat("d", 64),
	}
	pre := fixture.seed(t, "sql-persistence-resolve", correlationDigest("sql-source-pre"))
	invocation := correlationDigest("sql-source-invocation")
	prepared, err := fixture.chain.PreparePending(t.Context(), ToolChainPreparePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		PreSemanticEventID: pre.SemanticEventID, PreInputFingerprint: pre.InputFingerprint,
		RulesetFingerprint: pre.RulesetFingerprint,
		Projection:         guardrail.ToolChainProjection{ParseStatus: actionfacts.StatusComplete},
		SQLValueSource:     sourceDescriptor,
	})
	if err != nil || prepared.Status != ToolChainPendingPrepared {
		t.Fatalf("prepare=%+v err=%v", prepared, err)
	}
	fixture.now = fixture.now.Add(time.Second)
	terminal := fixture.seed(t, "sql-persistence-resolve", correlationDigest("sql-source-result"))
	values := guardrail.ToolChainValueJoinDigests{valueDigest}
	resolve := ToolChainResolvePendingInput{
		ConnectorInstanceID: pre.ConnectorInstanceID, ToolInvocationDigest: invocation,
		Outcome: ToolChainPendingOutcomeSuccess, RulesetFingerprint: pre.RulesetFingerprint,
		TerminalSemanticEventID:             terminal.SemanticEventID,
		TerminalInputFingerprint:            terminal.InputFingerprint,
		SuccessfulSQLValueSource:            sourceDescriptor,
		SuccessfulSQLResourceIdentityDigest: sourceResource,
		SuccessfulSQLValueDigests:           values,
	}
	mismatch := resolve
	mismatch.SuccessfulSQLValueSource.DatabaseIdentityDigest = strings.Repeat("e", 64)
	if _, err := fixture.chain.ResolvePending(t.Context(), mismatch); !errors.Is(err, ErrToolChainIntegrity) {
		t.Fatalf("descriptor mismatch error=%v", err)
	}
	resolved, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || resolved.Status != ToolChainPendingResolved ||
		resolved.Observation.Status != ToolChainObserveFresh {
		t.Fatalf("resolve=%+v err=%v", resolved, err)
	}
	if resolved.Observation.DetectedMask != 0 ||
		resolved.Observation.EnforcementSafeMask != 0 {
		t.Fatalf("source-only observation matched=%+v", resolved.Observation)
	}

	fixture.now = fixture.now.Add(time.Second)
	sink := fixture.seed(t, "sql-persistence-resolve", correlationDigest("sql-sink-result"))
	sink.Projection = guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: definition.Step2Bit,
	}
	sink.Projection.EnforcementJoinDigests[index] = sinkResource
	sink.Projection.ValueJoinDigests[index] = values
	matched, err := fixture.chain.Observe(t.Context(), sink)
	if err != nil || matched.DetectedMask&definition.ResultBit == 0 ||
		matched.EnforcementSafeMask != 0 || matched.DeniedMask != 0 {
		t.Fatalf("matched=%+v err=%v", matched, err)
	}

	replay, err := fixture.chain.ResolvePending(t.Context(), resolve)
	if err != nil || replay.Status != ToolChainPendingMissing ||
		replay.Observation.Status != "" {
		t.Fatalf("replay=%+v err=%v", replay, err)
	}
	encoded, err := json.Marshal(resolve)
	if err != nil {
		t.Fatal(err)
	}
	for _, private := range []string{
		sourceDescriptor.DatabaseIdentityDigest, sourceResource, valueDigest,
	} {
		if strings.Contains(string(encoded), private) {
			t.Fatalf("private resolve state serialized: %s", encoded)
		}
	}
}

func TestResolvePendingRejectsSQLLineageOnUnsuccessfulOutcomes(t *testing.T) {
	input := ToolChainResolvePendingInput{
		ConnectorInstanceID:      ConnectorInstanceID("0198f0c2-7b31-7a42-8c51-abcdef012345"),
		ToolInvocationDigest:     strings.Repeat("a", 64),
		Outcome:                  ToolChainPendingOutcomeFailure,
		TerminalSemanticEventID:  SemanticEventID("0198f0c2-7b31-7a42-8c51-abcdef012346"),
		TerminalInputFingerprint: strings.Repeat("b", 64),
		SuccessfulSQLValueSource: ToolChainPendingSQLValueSource{
			TableClass:             actionfacts.SensitiveSQLTableCredentials,
			DatabaseIdentityDigest: strings.Repeat("c", 64),
		},
		SuccessfulSQLResourceIdentityDigest: strings.Repeat("d", 64),
		SuccessfulSQLValueDigests: guardrail.ToolChainValueJoinDigests{
			strings.Repeat("e", 64),
		},
	}
	if err := validateToolChainResolvePendingInput(input); err == nil ||
		!strings.Contains(err.Error(), "unsuccessful") {
		t.Fatalf("validation error=%v", err)
	}
}

func TestResolvePendingRejectsAmbiguousValueLineageKinds(t *testing.T) {
	input := ToolChainResolvePendingInput{
		ConnectorInstanceID:      ConnectorInstanceID("0198f0c2-7b31-7a42-8c51-abcdef012345"),
		ToolInvocationDigest:     strings.Repeat("a", 64),
		Outcome:                  ToolChainPendingOutcomeSuccess,
		RulesetFingerprint:       strings.Repeat("b", 64),
		TerminalSemanticEventID:  SemanticEventID("0198f0c2-7b31-7a42-8c51-abcdef012346"),
		TerminalInputFingerprint: strings.Repeat("c", 64),
		SuccessfulReadPathDigest: strings.Repeat("d", 64),
		SuccessfulReadValueDigests: guardrail.ToolChainValueJoinDigests{
			strings.Repeat("e", 64),
		},
		SuccessfulSQLValueSource: ToolChainPendingSQLValueSource{
			TableClass:             actionfacts.SensitiveSQLTableCredentials,
			DatabaseIdentityDigest: strings.Repeat("f", 64),
		},
		SuccessfulSQLResourceIdentityDigest: strings.Repeat("1", 64),
		SuccessfulSQLValueDigests: guardrail.ToolChainValueJoinDigests{
			strings.Repeat("2", 64),
		},
	}
	if err := validateToolChainResolvePendingInput(input); err == nil ||
		!strings.Contains(err.Error(), "ambiguous") {
		t.Fatalf("validation error=%v", err)
	}
}
