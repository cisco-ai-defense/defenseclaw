// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestProfileActionMatrix pins the action thresholds per profile. This
// is the single place posture differentiation now lives — severity
// labeling is uniform across profiles (Step 2 / rulepack_posture_test.go)
// so the only knob operators tune is how aggressively each severity is
// enforced.
//
// Expected matrix (derived from guardrailThresholds in decision.go):
//
//	severity | strict | default | permissive
//	---------|--------|---------|----------
//	CRITICAL | block  | block   | block
//	HIGH     | block  | alert   | alert
//	MEDIUM   | block  | alert   | allow
//	LOW      | alert  | allow   | allow
//	NONE     | allow  | allow   | allow
//
// CRITICAL-always-blocks is the most important invariant: a coordinated
// attack chain (correlator CORR-*, multi-category injection) must block
// in every profile regardless of operator choice.
func TestProfileActionMatrix(t *testing.T) {
	type expect struct {
		severity string
		strict   string
		def      string
		permit   string
	}
	matrix := []expect{
		{"CRITICAL", "block", "block", "block"},
		{"HIGH", "block", "alert", "alert"},
		{"MEDIUM", "block", "alert", "allow"},
		{"LOW", "alert", "allow", "allow"},
		{"NONE", "allow", "allow", "allow"},
	}

	profiles := []struct {
		name       string
		rulePack   string
		pick       func(expect) string
		overrideGC func(*config.GuardrailConfig)
	}{
		{
			name:     "strict",
			rulePack: "policies/guardrail/strict",
			pick:     func(e expect) string { return e.strict },
		},
		{
			name:     "default",
			rulePack: "policies/guardrail/default",
			pick:     func(e expect) string { return e.def },
		},
		{
			name:     "permissive",
			rulePack: "policies/guardrail/permissive",
			pick:     func(e expect) string { return e.permit },
		},
	}

	for _, profile := range profiles {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.RulePackDir = profile.rulePack

			for _, row := range matrix {
				row := row
				want := profile.pick(row)
				got := guardrailRuntimeAction(cfg, row.severity, false)
				if got != want {
					t.Errorf("severity=%s profile=%s: action=%s, want %s",
						row.severity, profile.name, got, want)
				}
			}
		})
	}
}

// TestProfile_CriticalAlwaysBlocks is the hard invariant: no profile,
// no toggle, no HILT setting short of an explicit allow-list can
// release a CRITICAL verdict. The correlator's CORR-* findings land
// at CRITICAL specifically to ride this invariant.
func TestProfile_CriticalAlwaysBlocks(t *testing.T) {
	for _, rp := range []string{
		"policies/guardrail/strict",
		"policies/guardrail/default",
		"policies/guardrail/permissive",
	} {
		cfg := &config.Config{}
		cfg.Guardrail.RulePackDir = rp
		if got := guardrailRuntimeAction(cfg, "CRITICAL", false); got != "block" {
			t.Errorf("profile=%s CRITICAL action=%s, want block", rp, got)
		}
		// Even with HILT enabled at CRITICAL threshold, a confirmable
		// CRITICAL must still block — confirm is reserved for HIGH-
		// and-below per decision.go:41.
		cfg.Guardrail.HILT.Enabled = true
		cfg.Guardrail.HILT.MinSeverity = "CRITICAL"
		if got := guardrailRuntimeAction(cfg, "CRITICAL", true); got != "block" {
			t.Errorf("profile=%s CRITICAL+HILT confirmable action=%s, want block", rp, got)
		}
	}
}

// TestProfile_HighWithHILTConfirms: a HIGH verdict with HILT enabled
// on a confirmable surface should be confirm in any profile where
// HIGH is not already a block. Strict blocks HIGH outright so HILT
// is a no-op there.
func TestProfile_HighWithHILTConfirms(t *testing.T) {
	cases := []struct {
		profile    string
		wantAction string
	}{
		{"policies/guardrail/strict", "block"},    // HIGH >= MEDIUM block threshold
		{"policies/guardrail/default", "confirm"}, // HIGH gets HILT
		{"policies/guardrail/permissive", "confirm"},
	}
	for _, c := range cases {
		cfg := &config.Config{}
		cfg.Guardrail.RulePackDir = c.profile
		cfg.Guardrail.HILT.Enabled = true
		cfg.Guardrail.HILT.MinSeverity = "HIGH"
		if got := guardrailRuntimeAction(cfg, "HIGH", true); got != c.wantAction {
			t.Errorf("profile=%s HIGH+HILT confirmable action=%s, want %s",
				c.profile, got, c.wantAction)
		}
	}
}
