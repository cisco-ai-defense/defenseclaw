// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestResolvePendingPromotesSensitiveSQLiteReadOnlyAfterSuccess(t *testing.T) {
	definition, ok := guardrail.ToolChainDefinitionByID(
		guardrail.ToolChainSensitiveSQLiteReadThenUnboundedDelete,
	)
	index, indexOK := guardrail.ToolChainIndexByID(definition.ID)
	if !ok || !indexOK || definition.RequiresTerminalSuccess {
		t.Fatal("missing SQLite read-delete chain")
	}
	for _, outcome := range []ToolChainPendingOutcome{
		ToolChainPendingOutcomeSuccess,
		ToolChainPendingOutcomeFailure,
		ToolChainPendingOutcomeUnknown,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			fixture := newToolChainFixture(t, ":memory:")
			databaseDigest := strings.Repeat("a", 64)
			tableDigest := actionfacts.SensitiveSQLTableIdentityDigest(
				actionfacts.SensitiveSQLTableCredentials,
			)
			joinDigest := guardrail.ToolChainDatabaseTableJoinDigest(
				databaseDigest, tableDigest,
			)
			projection := guardrail.ToolChainProjection{
				ParseStatus:       actionfacts.StatusComplete,
				DetectionStepMask: definition.Step1Bit,
			}
			projection.EnforcementJoinDigests[index] = joinDigest

			pre := fixture.seed(
				t, "sqlite-read-"+string(outcome),
				correlationDigest("sqlite-read-pre-"+string(outcome)),
			)
			invocation := correlationDigest("sqlite-read-invocation-" + string(outcome))
			prepared, err := fixture.chain.PreparePending(
				t.Context(),
				ToolChainPreparePendingInput{
					ConnectorInstanceID:  pre.ConnectorInstanceID,
					ToolInvocationDigest: invocation,
					PreSemanticEventID:   pre.SemanticEventID,
					PreInputFingerprint:  pre.InputFingerprint,
					RulesetFingerprint:   pre.RulesetFingerprint,
					Projection:           projection,
					SQLValueSource: ToolChainPendingSQLValueSource{
						TableClass:             actionfacts.SensitiveSQLTableCredentials,
						DatabaseIdentityDigest: databaseDigest,
					},
				},
			)
			if err != nil || prepared.Status != ToolChainPendingPrepared {
				t.Fatalf("prepare=%+v err=%v", prepared, err)
			}
			fixture.now = fixture.now.Add(time.Second)
			terminal := fixture.seed(
				t, "sqlite-read-"+string(outcome),
				correlationDigest("sqlite-read-result-"+string(outcome)),
			)
			resolved, err := fixture.chain.ResolvePending(
				t.Context(),
				ToolChainResolvePendingInput{
					ConnectorInstanceID:      terminal.ConnectorInstanceID,
					ToolInvocationDigest:     invocation,
					Outcome:                  outcome,
					RulesetFingerprint:       terminal.RulesetFingerprint,
					TerminalSemanticEventID:  terminal.SemanticEventID,
					TerminalInputFingerprint: terminal.InputFingerprint,
				},
			)
			if err != nil || resolved.Status != ToolChainPendingResolved {
				t.Fatalf("resolve=%+v err=%v", resolved, err)
			}
			if outcome != ToolChainPendingOutcomeSuccess {
				if resolved.Observation.Status != "" {
					t.Fatalf("unsuccessful source became observable: %+v", resolved)
				}
				return
			}
			if resolved.Observation.Status != ToolChainObserveFresh ||
				resolved.Observation.DetectedMask != 0 ||
				resolved.Observation.EnforcementSafeMask != 0 {
				t.Fatalf("successful source observation=%+v", resolved.Observation)
			}

			fixture.now = fixture.now.Add(time.Second)
			sink := fixture.seed(
				t, "sqlite-read-"+string(outcome),
				correlationDigest("sqlite-delete-pre-action-"+string(outcome)),
			)
			sink.Projection = guardrail.ToolChainProjection{
				ParseStatus:         actionfacts.StatusComplete,
				DetectionStepMask:   definition.Step2Bit,
				EnforcementStepMask: definition.Step2Bit,
			}
			sink.Projection.EnforcementJoinDigests[index] = joinDigest
			matched, err := fixture.chain.Observe(t.Context(), sink)
			if err != nil || matched.DetectedMask != definition.ResultBit ||
				matched.EnforcementSafeMask != definition.ResultBit {
				t.Fatalf("matched=%+v err=%v", matched, err)
			}
		})
	}
}
