// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// GAP-0595: a proven secret-read-then-egress chain keeps its enforcement bits
// only in the strict tier (where it blocks); default and permissive keep the
// detection bits (an alert) and drop the enforcement bits.
func TestSecretReadChainEnforcesOnlyInStrictGAP0595(t *testing.T) {
	definition, ok := guardrail.ToolChainDefinitionByID(guardrail.ToolChainSecretReadThenEgress)
	if !ok || definition.DetectionOnly {
		t.Fatalf("definition %+v, want a chain that can block", definition)
	}
	steps := definition.Step1Bit | definition.Step2Bit
	for _, posture := range []string{"", "default", "permissive", "strict"} {
		projection := toolChainProjectionForNamedPosture(posture, guardrail.ToolChainProjection{
			DetectionStepMask: steps, EnforcementStepMask: steps,
		})
		if projection.DetectionStepMask&steps != steps {
			t.Fatalf("posture %q lost the detection bits: %+v", posture, projection)
		}
		wantEnforcement := uint64(0)
		if posture == "strict" {
			wantEnforcement = steps
		}
		if projection.EnforcementStepMask&steps != wantEnforcement {
			t.Fatalf("posture %q enforcement %b, want %b", posture, projection.EnforcementStepMask&steps, wantEnforcement)
		}
	}
}
