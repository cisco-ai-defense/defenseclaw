// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

func TestSplitFourStepProjectionKeepsPreActionTerminalSeparate(t *testing.T) {
	definition := guardrail.ToolChainDefinition{
		Step1Bit: 1 << 48, Step2Bit: 1 << 49,
		Step3Bit: 1 << 50, Step4Bit: 1 << 51,
		MutationBit: 1 << 52, FourStep: true,
	}
	const input = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	const output = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	for step, want := range map[uint64]struct{ predecessor, terminal bool }{
		definition.Step1Bit: {predecessor: true},
		definition.Step2Bit: {predecessor: true, terminal: true},
		definition.Step3Bit: {predecessor: true},
		definition.Step4Bit: {terminal: true},
	} {
		projection := guardrail.ToolChainProjection{
			ParseStatus:       actionfacts.StatusComplete,
			DetectionStepMask: step, EnforcementStepMask: step,
		}
		projection.EnforcementJoinDigests[0] = input
		projection.EnforcementOutputJoinDigests[0] = output
		predecessor, terminal := splitToolChainProjectionForDefinitions(
			projection, []guardrail.ToolChainDefinition{definition},
		)
		if got := predecessor.DetectionStepMask&step != 0; got != want.predecessor {
			t.Fatalf("step %#x predecessor=%t want=%t", step, got, want.predecessor)
		}
		if got := terminal.DetectionStepMask&step != 0; got != want.terminal {
			t.Fatalf("step %#x terminal=%t want=%t", step, got, want.terminal)
		}
	}
}

func TestSplitFourStepTerminalSuccessRoutesAllStepsThroughPending(t *testing.T) {
	definition := guardrail.ToolChainDefinition{
		Step1Bit: 1 << 48, Step2Bit: 1 << 49,
		Step3Bit: 1 << 50, Step4Bit: 1 << 51,
		MutationBit: 1 << 52, FourStep: true, RequiresTerminalSuccess: true,
	}
	all := definition.Step1Bit | definition.Step2Bit | definition.Step3Bit |
		definition.Step4Bit | definition.MutationBit
	projection := guardrail.ToolChainProjection{
		ParseStatus:       actionfacts.StatusComplete,
		DetectionStepMask: all, EnforcementStepMask: all,
	}
	predecessor, terminal := splitToolChainProjectionForDefinitions(
		projection, []guardrail.ToolChainDefinition{definition},
	)
	if predecessor.DetectionStepMask != all || predecessor.EnforcementStepMask != all ||
		terminal.DetectionStepMask != 0 || terminal.EnforcementStepMask != 0 {
		t.Fatalf("success-gated split predecessor=%+v terminal=%+v", predecessor, terminal)
	}
}
