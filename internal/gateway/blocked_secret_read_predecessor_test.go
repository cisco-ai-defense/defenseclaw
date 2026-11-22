// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// TestBlockedSecretReadPredecessorKeepsTheValueLineageStep (GAP-0549): a blocked
// read the agent runs anyway can carry value-lineage digests in its result, and
// resolving them needs step 1 of the value-lineage chain, with its path digest,
// on the pending row. The blocked projection keeps that step and the
// secret-read step, and nothing else.
func TestBlockedSecretReadPredecessorKeepsTheValueLineageStep(t *testing.T) {
	facts := actionfacts.Analyze(actionfacts.Input{
		Tool: "shell", Command: "cat /workspace/.env", CWD: "/workspace",
	})
	read := guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}
	projectTrustedActionChainSteps(&read, facts, []RuleFinding{{
		RuleID: "PATH-ENV-FILE",
	}})
	valueBit, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSensitiveReadValueExternalTransmit, 1)
	secretBit, _ := guardrail.ToolChainStepMask(guardrail.ToolChainSecretReadThenEgress, 1)
	valueIndex, _ := guardrail.ToolChainIndexByID(guardrail.ToolChainSensitiveReadValueExternalTransmit)
	if read.DetectionStepMask&valueBit == 0 || read.EnforcementJoinDigests[valueIndex] == "" {
		t.Fatalf("the allowed read has no value-lineage step 1 with a path digest: %+v", read)
	}

	kept, ok := blockedSecretReadPredecessor(read)
	if !ok {
		t.Fatal("a read with secret-read steps kept none")
	}
	if kept.DetectionStepMask&valueBit == 0 {
		t.Fatalf("value-lineage step 1 dropped from the blocked projection: %+v", kept)
	}
	if kept.EnforcementJoinDigests[valueIndex] != read.EnforcementJoinDigests[valueIndex] {
		t.Fatal("the value-lineage path digest was not kept")
	}
	if kept.DetectionStepMask&^(valueBit|secretBit) != 0 || kept.EnforcementStepMask&^(valueBit|secretBit) != 0 {
		t.Fatalf("the blocked projection kept a step beyond the two read steps: %+v", kept)
	}
	if kept.ValueJoinDigests != (guardrail.ToolChainProjection{}).ValueJoinDigests {
		t.Fatal("the blocked projection carries value digests before any result exists")
	}
	if err := guardrail.ValidateToolChainProjection(kept); err != nil {
		t.Fatalf("the blocked projection is not a valid pending projection: %v", err)
	}

	if _, ok := blockedSecretReadPredecessor(guardrail.ToolChainProjection{ParseStatus: facts.Parse.Status}); ok {
		t.Fatal("an empty projection kept a step")
	}
}
