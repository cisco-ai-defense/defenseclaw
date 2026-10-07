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
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/policy"
)

// TestGuardrailFallbackActionForSeverity pins the contract used by
// every gateway path that doesn't go through the Rego engine:
//
//   - regex-only deployments (guardrail.go::inspectRegexJudge)
//   - the API server's evaluate endpoint when no engine is wired
//     (api.go::evaluateGuardrailPolicy)
//
// The chain is the default rule pack's posture (block CRITICAL, alert
// MEDIUM), the same levels guardrail.rego applies without input.thresholds:
//
//	CRITICAL          -> block
//	HIGH, MEDIUM      -> alert   (HIGH does NOT hard-block here)
//	LOW, NONE, etc.   -> allow
//
// The HIGH -> alert behavior is intentional. Pre-fix, the regex
// stage hard-blocked HIGH while the Rego engine treated HIGH as
// alert; the resulting per-path divergence made it hard to predict
// what an operator would see for the same finding depending on
// which evaluation path it took. Aligning the fallback with the
// Rego chain keeps regex-only deployments honest about their
// posture (a HIGH finding is not block-worthy by itself) while
// still giving CRITICAL findings the brake they need.
//
// If you intentionally change this mapping, also update the guardrail.rego
// defaults and the documentation for `defenseclaw guardrail status`.
func TestGuardrailFallbackActionForSeverity(t *testing.T) {
	cases := []struct {
		severity string
		want     string
		note     string
	}{
		{"CRITICAL", "block", "CRITICAL is the only severity that hard-blocks on the fallback path"},
		{"critical", "block", "case insensitive"},
		{"  CRITICAL  ", "block", "whitespace trimmed"},
		{"HIGH", "alert", "HIGH alerts but does NOT block — aligns with Rego chain"},
		{"high", "alert", "case insensitive"},
		{"MEDIUM", "alert", "MEDIUM alerts"},
		{"LOW", "allow", "LOW is below alert_threshold=2"},
		{"NONE", "allow", "NONE always allows"},
		{"", "allow", "empty severity defaults to allow"},
		{"unrecognized", "allow", "unknown severity falls through to allow"},
	}

	for _, tc := range cases {
		t.Run(tc.severity, func(t *testing.T) {
			got := guardrailFallbackActionForSeverity(tc.severity)
			if got != tc.want {
				t.Errorf("guardrailFallbackActionForSeverity(%q) = %q, want %q (%s)",
					tc.severity, got, tc.want, tc.note)
			}
		})
	}
}

// defaultFallbackThresholds are the default pack's levels (block CRITICAL,
// alert MEDIUM).
var defaultFallbackThresholds = policy.ThresholdsInput{Block: severityCritical, Alert: severityMedium}

// TestFallbackGuardrailVerdict_PreservesScannerMetadata covers the
// wrapper used to coerce a scanner verdict's action to the canonical
// fallback chain without losing the rest of the verdict (severity,
// findings, reason). Without this guarantee, an incomplete
// re-mapping in one of the call sites could quietly drop the
// finding list and leave operators staring at an action with no
// supporting evidence in audit logs.
func TestFallbackGuardrailVerdict_PreservesScannerMetadata(t *testing.T) {
	in := &ScanVerdict{
		Action:   "block",
		Severity: "HIGH",
		Reason:   "secrets pattern matched",
		Findings: []string{"secrets:aws_access_key"},
		Scanner:  "regex",
	}

	out := fallbackGuardrailVerdictForThresholds(in, nil, defaultFallbackThresholds, "action", nil)
	if out == nil {
		t.Fatal("fallbackGuardrailVerdict(non-nil) returned nil")
	}
	if out.Action != "alert" {
		t.Errorf("HIGH verdict should be coerced to alert; got action=%q", out.Action)
	}
	if out.Severity != in.Severity {
		t.Errorf("severity must be preserved; got %q, want %q", out.Severity, in.Severity)
	}
	if out.Reason != in.Reason {
		t.Errorf("reason must be preserved; got %q, want %q", out.Reason, in.Reason)
	}
	if len(out.Findings) != len(in.Findings) || (len(out.Findings) > 0 && out.Findings[0] != in.Findings[0]) {
		t.Errorf("findings must be preserved; got %v, want %v", out.Findings, in.Findings)
	}
	if out.Scanner != in.Scanner {
		t.Errorf("scanner attribution must be preserved; got %q, want %q", out.Scanner, in.Scanner)
	}

	// Mutating the returned verdict must NOT mutate the caller's
	// input — fallbackGuardrailVerdict copies the struct so the
	// downstream policy chain doesn't accidentally rewrite a
	// scanner's authoritative record.
	out.Action = "mutated"
	if in.Action != "block" {
		t.Errorf("input verdict should be untouched after caller mutates output; in.Action=%q", in.Action)
	}
}

// TestFallbackGuardrailVerdict_NilInput documents the safe-default
// behavior: a nil verdict is replaced with an explicit allow. This
// keeps the fallback path safe for call sites that haven't decided
// whether the scanner produced anything yet.
func TestFallbackGuardrailVerdict_NilInput(t *testing.T) {
	out := fallbackGuardrailVerdictForThresholds(nil, nil, defaultFallbackThresholds, "action", nil)
	if out == nil {
		t.Fatal("fallbackGuardrailVerdictForThresholds(nil, defaultFallbackThresholds) must return a usable allow verdict, not nil")
	}
	if out.Action != "allow" || out.Severity != "NONE" {
		t.Errorf("nil verdict should map to allow/NONE; got action=%q severity=%q",
			out.Action, out.Severity)
	}
}

// TestFallbackGuardrailVerdict_FollowsRego pins that guardrail.cisco_trust_level
// and HILT decide the same without the Rego module as with it
// (guardrail.rego): a managed standalone host ships no .rego.
func TestFallbackGuardrailVerdict_FollowsRego(t *testing.T) {
	none := &ScanVerdict{Action: "allow", Severity: "NONE"}
	critical := &ScanVerdict{Action: "block", Severity: "CRITICAL"}
	high := &ScanVerdict{Action: "alert", Severity: "HIGH"}
	hilt := &policy.GuardrailHILTInput{Enabled: true, MinSeverity: "HIGH"}
	thresholds := func(trust string) policy.ThresholdsInput {
		return policy.ThresholdsInput{Block: severityCritical, Alert: severityMedium, CiscoTrustLevel: trust}
	}
	for _, tc := range []struct {
		name         string
		local, cisco *ScanVerdict
		trust, mode  string
		hilt         *policy.GuardrailHILTInput
		want         string
	}{
		{"full trust blocks a Cisco-only critical", none, critical, "full", "action", nil, "block"},
		{"advisory downgrades a Cisco-only block", none, critical, "advisory", "action", nil, "alert"},
		{"advisory keeps a local block", critical, critical, "advisory", "action", nil, "block"},
		{"none ignores the Cisco verdict", none, critical, "none", "action", nil, "allow"},
		{"HILT confirms at its minimum severity", high, nil, "full", "action", hilt, "confirm"},
		{"HILT does not confirm in observe mode", high, nil, "full", "observe", hilt, "alert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := fallbackGuardrailVerdictForThresholds(tc.local, tc.cisco, thresholds(tc.trust), tc.mode, tc.hilt)
			if got.Action != tc.want {
				t.Errorf("action = %q, want %q", got.Action, tc.want)
			}
		})
	}
}

// Secure Client keeps the 1.0 threshold-only answer without Rego (issue #1092).
func TestFallbackVerdict_SecureClientKeepsThresholdOnlyAnswer(t *testing.T) {
	cfg := &config.Config{DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = managed.ProfileSecureClient
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: cfg})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	critical := &ScanVerdict{Action: "block", Severity: "CRITICAL"}
	none := &ScanVerdict{Action: "allow", Severity: "NONE"}
	inspector := NewGuardrailInspector("local", nil, nil)
	inspector.SetHILTConfig(true, "HIGH")
	thresholds := policy.ThresholdsInput{Block: severityCritical, Alert: severityMedium, CiscoTrustLevel: "none"}
	if got := inspector.fallbackVerdict(none, critical, thresholds, "action"); got.Action != "allow" {
		t.Errorf("Cisco-only critical = %q, want the 1.0 answer allow", got.Action)
	}
	high := &ScanVerdict{Action: "alert", Severity: "HIGH"}
	if got := inspector.fallbackVerdict(high, nil, thresholds, "action"); got.Action != "alert" {
		t.Errorf("HIGH with HILT on = %q, want the 1.0 answer alert", got.Action)
	}
}
