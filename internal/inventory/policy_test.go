// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestEmbeddedDefaultPolicyLoadsAndValidates is a build-time smoke
// check: the YAML shipped with the binary must parse and pass every
// invariant. If this test fails the binary will fail at every fresh
// scan because the engine cannot construct ConfidenceParams.
func TestEmbeddedDefaultPolicyLoadsAndValidates(t *testing.T) {
	p, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("default policy must load: %v", err)
	}
	if p.Version != ConfidencePolicyVersion {
		t.Fatalf("default policy version mismatch: got %d, want %d", p.Version, ConfidencePolicyVersion)
	}
	if !p.IdentityPriorIsSignature() {
		t.Errorf("default policy should use signature curator_confidence as identity prior")
	}
	if p.HalfLifeHours <= 0 {
		t.Errorf("default policy must have positive half_life_hours, got %v", p.HalfLifeHours)
	}
	if _, ok := p.Detectors["process"]; !ok {
		t.Errorf("default policy must declare a `process` detector")
	}
	// Provenance: every key on the default load comes from "default".
	for k, src := range p.provenance {
		if src != "default" {
			t.Errorf("default policy key %q has provenance %q (want \"default\")", k, src)
		}
	}
}

// TestPolicyOverrideDeepMerges verifies that an operator override of
// a single detector LR leaves every other detector at the embedded
// default. This is the entire reason the loader exists -- tuning one
// dial must not require restating the whole policy.
func TestPolicyOverrideDeepMerges(t *testing.T) {
	dir := t.TempDir()
	override := filepath.Join(dir, "confidence.yaml")
	if err := os.WriteFile(override, []byte(`
version: 1
priors:
  identity: signature
  presence: 0.05
half_life_hours: 168
detectors:
  process:
    identity_lr: 12
    presence_lr: 75
penalties:
  version_conflict:
    axis: identity
    logit: -2.0
bands:
  - { min: 0.95, label: very_high }
  - { min: 0.80, label: high }
  - { min: 0.60, label: medium }
  - { min: 0.30, label: low }
  - { min: 0.00, label: very_low }
`), 0o600); err != nil {
		t.Fatalf("write override: %v", err)
	}
	p, err := LoadConfidencePolicyFromFile(override)
	if err != nil {
		t.Fatalf("load override: %v", err)
	}
	// Overridden field uses operator value.
	if got := p.Detectors["process"].IdentityLR; got != 12 {
		t.Errorf("process identity_lr: got %v, want 12", got)
	}
	// Untouched detector keeps the default. The default value for
	// `package_manifest.identity_lr` in the embedded YAML is 30.
	if got := p.Detectors["package_manifest"].IdentityLR; got != 30 {
		t.Errorf("package_manifest identity_lr should fall back to default 30, got %v", got)
	}
	// Provenance markers reflect the merge.
	if src := p.Provenance("detectors.process.identity_lr"); src != override {
		t.Errorf("provenance for overridden detector: got %q, want %q", src, override)
	}
	if src := p.Provenance("detectors.package_manifest.identity_lr"); src != "default" {
		t.Errorf("provenance for untouched detector: got %q, want \"default\"", src)
	}
}

func TestPolicyOverrideCanBeSparse(t *testing.T) {
	p, err := LoadConfidencePolicyFromBytes([]byte(`
detectors:
  process:
    identity_lr: 12
priors:
  presence: 0.07
`), "test-policy")
	if err != nil {
		t.Fatalf("load sparse override: %v", err)
	}
	if got := p.Detectors["process"].IdentityLR; got != 12 {
		t.Errorf("process identity_lr = %v, want 12", got)
	}
	if got := p.Detectors["process"].PresenceLR; got <= 0 {
		t.Errorf("process presence_lr should fall back to default, got %v", got)
	}
	if got := p.Detectors["package_manifest"].IdentityLR; got != 30 {
		t.Errorf("package_manifest identity_lr should keep default 30, got %v", got)
	}
	if got := p.Priors.Presence; got != 0.07 {
		t.Errorf("priors.presence = %v, want 0.07", got)
	}
	if !p.IdentityPriorIsSignature() {
		t.Errorf("sparse override should keep default identity prior")
	}
}

// TestPolicyValidationRejectsBadInputs is the typo / footgun guard.
// Each subtest crafts a single broken policy and asserts the loader
// surfaces a precise error message rather than silently accepting it.
func TestPolicyValidationRejectsBadInputs(t *testing.T) {
	cases := []struct {
		name    string
		yaml    string
		wantSub string
	}{
		{
			name: "wrong version",
			yaml: minimalPolicyYAML(map[string]string{"version": "999"}),
			// Intermediate parse step calls Validate and surfaces an "unsupported version" message.
			wantSub: "unsupported version",
		},
		{
			name: "negative LR",
			yaml: minimalPolicyYAMLWithDetector(`process:
    identity_lr: -1
    presence_lr: 50`),
			wantSub: "identity_lr must be > 0",
		},
		{
			name: "unknown detector key (typo)",
			yaml: minimalPolicyYAMLWithDetector(`prccess:
    identity_lr: 8
    presence_lr: 50`),
			wantSub: "unknown detector",
		},
		{
			name:    "presence prior out of range",
			yaml:    minimalPolicyYAML(map[string]string{"priors_presence": "1.5"}),
			wantSub: "priors.presence must be in (0, 1)",
		},
		{
			name:    "non-monotone bands",
			yaml:    bandsYAML([]string{"0.50", "0.60", "0.00"}),
			wantSub: "must be strictly decreasing",
		},
		{
			name: "positive penalty logit",
			yaml: minimalPolicyYAMLWithPenalty(`version_conflict:
    axis: identity
    logit: 1.5`),
			wantSub: "must be < 0",
		},
		{
			name: "unknown penalty axis",
			yaml: minimalPolicyYAMLWithPenalty(`version_conflict:
    axis: cosmic_ray
    logit: -1.5`),
			wantSub: "axis must be identity|presence|both",
		},
		{
			name: "unknown top-level key (typo guard)",
			yaml: `version: 1
priors:
  identity: signature
  presence: 0.05
half_life_hours: 168
detectors:
  process: { identity_lr: 8, presence_lr: 50 }
bands:
  - { min: 0.0, label: very_low }
detectorz:
  unrelated: true
`,
			wantSub: "field detectorz",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "p.yaml")
			if err := os.WriteFile(path, []byte(tc.yaml), 0o600); err != nil {
				t.Fatalf("write: %v", err)
			}
			_, err := LoadConfidencePolicyFromFile(path)
			if err == nil {
				t.Fatalf("expected error containing %q, got nil", tc.wantSub)
			}
			if !strings.Contains(err.Error(), tc.wantSub) {
				t.Errorf("error %q must contain %q", err.Error(), tc.wantSub)
			}
		})
	}
}

// TestPolicyMissingOverrideFileIsNotAnError documents the
// "operator's intended behavior" contract: if the override path does
// not exist, the embedded default is used silently. Any other stat
// error (e.g. permission denied) should still surface.
func TestPolicyMissingOverrideFileIsNotAnError(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "does-not-exist.yaml")
	p, err := LoadConfidencePolicyFromFile(missing)
	if err != nil {
		t.Fatalf("missing override file should fall back to default, got error: %v", err)
	}
	if !p.IdentityPriorIsSignature() {
		t.Errorf("fallback should be the default policy")
	}
}

// TestPolicyLookupAndBands exercises the convenience helpers used by
// the engine. We do not pin specific LR values here (those live in
// TestEmbeddedDefaultPolicyLoadsAndValidates) -- this test only
// proves the lookup/bands lookup paths return reasonable shapes.
func TestPolicyLookupAndBands(t *testing.T) {
	p, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	// Known detector returns its policy.
	det := p.LookupDetector("process")
	if det.IdentityLR <= 0 || det.PresenceLR <= 0 {
		t.Errorf("process detector must have positive LRs, got %+v", det)
	}
	// Unknown detector returns the neutral LR=1 fallback (so new
	// detectors added in code without policy updates score as
	// zero-info instead of crashing).
	if got := p.LookupDetector("brand_new_detector"); got.IdentityLR != 1 || got.PresenceLR != 1 {
		t.Errorf("unknown detector should fall back to LR=1, got %+v", got)
	}
	// BandFor walks top-down; 0.97 is very_high, 0.5 is low.
	if got := p.BandFor(0.97); got != "very_high" {
		t.Errorf("BandFor(0.97) = %q, want very_high", got)
	}
	if got := p.BandFor(0.5); got != "low" {
		t.Errorf("BandFor(0.5) = %q, want low", got)
	}
	if got := p.BandFor(0.0); got != "very_low" {
		t.Errorf("BandFor(0.0) = %q, want very_low", got)
	}
}

// minimalPolicyYAML helps the validation tests above produce a
// well-formed policy with a single field tweaked. It keeps each
// failure case focused on the one invariant it is exercising.
func minimalPolicyYAML(overrides map[string]string) string {
	version := "1"
	if v, ok := overrides["version"]; ok {
		version = v
	}
	presence := "0.05"
	if v, ok := overrides["priors_presence"]; ok {
		presence = v
	}
	return `version: ` + version + `
priors:
  identity: signature
  presence: ` + presence + `
half_life_hours: 168
detectors:
  process: { identity_lr: 8, presence_lr: 50 }
bands:
  - { min: 0.95, label: very_high }
  - { min: 0.00, label: very_low }
`
}

func minimalPolicyYAMLWithDetector(detectorBlock string) string {
	return `version: 1
priors:
  identity: signature
  presence: 0.05
half_life_hours: 168
detectors:
  ` + detectorBlock + `
bands:
  - { min: 0.95, label: very_high }
  - { min: 0.00, label: very_low }
`
}

func minimalPolicyYAMLWithPenalty(penaltyBlock string) string {
	return `version: 1
priors:
  identity: signature
  presence: 0.05
half_life_hours: 168
detectors:
  process: { identity_lr: 8, presence_lr: 50 }
penalties:
  ` + penaltyBlock + `
bands:
  - { min: 0.95, label: very_high }
  - { min: 0.00, label: very_low }
`
}

func bandsYAML(mins []string) string {
	body := `version: 1
priors:
  identity: signature
  presence: 0.05
half_life_hours: 168
detectors:
  process: { identity_lr: 8, presence_lr: 50 }
bands:
`
	for i, m := range mins {
		body += `  - { min: ` + m + `, label: band` + itoa(i) + ` }
`
	}
	return body
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	out := ""
	if n < 0 {
		out = "-"
		n = -n
	}
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return out + digits
}
