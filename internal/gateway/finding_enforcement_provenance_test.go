// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"testing"
)

func TestRuleFindingsToInspectPreservesDetectionOnlyProvenance(t *testing.T) {
	input := []RuleFinding{
		{
			RuleID:      "TRUST-DOCUMENTATION",
			Tags:        []string{"prompt-injection", "source-code"},
			enforcement: findingEnforcementDetectionOnly,
		},
		{
			RuleID:      "TRUST-OBSERVED-ACTION",
			Tags:        []string{"prompt-injection"},
			enforcement: findingEnforcementAllowed,
		},
		{
			RuleID:      "TRUST-ALREADY-TAGGED",
			Tags:        []string{"detection-only", "prompt-injection"},
			enforcement: findingEnforcementDetectionOnly,
		},
		{
			RuleID:      "TRUST-NONCANONICAL-TAG",
			Tags:        []string{"Detection-Only", "prompt-injection"},
			enforcement: findingEnforcementDetectionOnly,
		},
	}

	got := ruleFindingsToInspect(input)
	if len(got) != len(input) {
		t.Fatalf("adapted findings=%d, want %d", len(got), len(input))
	}
	if want := []string{"prompt-injection", "source-code", "detection-only"}; !reflect.DeepEqual(got[0].Tags, want) {
		t.Fatalf("detection-only tags=%v, want %v", got[0].Tags, want)
	}
	if want := []string{"prompt-injection"}; !reflect.DeepEqual(got[1].Tags, want) {
		t.Fatalf("enforcement-eligible tags=%v, want %v", got[1].Tags, want)
	}
	if want := []string{"detection-only", "prompt-injection"}; !reflect.DeepEqual(got[2].Tags, want) {
		t.Fatalf("pre-tagged detection-only tags=%v, want no duplicate: %v", got[2].Tags, want)
	}
	if want := []string{"Detection-Only", "prompt-injection", "detection-only"}; !reflect.DeepEqual(got[3].Tags, want) {
		t.Fatalf("noncanonical provenance tags=%v, want stable tag appended without clobbering: %v", got[3].Tags, want)
	}

	if !reflect.DeepEqual(input[0].Tags, []string{"prompt-injection", "source-code"}) {
		t.Fatalf("adapter mutated source tags: %v", input[0].Tags)
	}
}
