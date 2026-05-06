// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"math"
	"testing"
	"time"
)

// loadPolicyForTests is a tiny helper -- every confidence test needs
// the embedded default policy, and we want one place to fail fast if
// the embedded YAML is broken.
func loadPolicyForTests(t *testing.T) ConfidencePolicy {
	t.Helper()
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatalf("load default policy: %v", err)
	}
	return policy
}

// TestComputeConfidenceTable is the headline test for the engine.
// Every case constructs a tiny (signal-list, expected-band) tuple
// and asserts the engine produces the *band* we expect plus a few
// invariants on the underlying score. We do not pin exact scores
// because those move when the calibration policy changes; we pin
// bands because those are what operators actually see.
func TestComputeConfidenceTable(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	policy := loadPolicyForTests(t)
	params := ConfidenceParams{Policy: policy}

	cases := []struct {
		name              string
		signals           []AISignal
		wantIdentityBand  string
		wantPresenceBand  string
		identityFloorScor float64 // identity score must be >=
		identityCeilScor  float64 // identity score must be <=
		presenceFloorScor float64
		presenceCeilScor  float64
		// extra invariants checked by the test, e.g. "must contain
		// detector 'process' in r.Detectors".
		mustHaveDetectors []string
	}{
		{
			// One fresh process is enough to push identity to
			// very_high (LR=8 against prior 0.85 saturates the
			// upper band) but presence only reaches "high" --
			// a single observation cannot get to "very_high"
			// presence by design, two independent strong signals
			// are required (see the "gold case" below).
			name: "single live process, fresh start",
			signals: []AISignal{
				freshProcessSignal("openai", "openai", "openai", now, 1.0, MatchKindExact),
			},
			wantIdentityBand:  "very_high",
			wantPresenceBand:  "high",
			identityFloorScor: 0.85,
			identityCeilScor:  0.999,
			presenceFloorScor: 0.85,
			presenceCeilScor:  0.95,
			mustHaveDetectors: []string{"process"},
		},
		{
			// Heuristic-only signal: small LR, low quality. Identity
			// rises modestly above prior, presence stays near zero
			// after the heuristic_only penalty kicks in.
			name: "single weak shell-history hit only",
			signals: []AISignal{
				shellHistorySignal("openai", "openai-cli", now, MatchKindHeuristic),
			},
			wantIdentityBand:  "medium",
			wantPresenceBand:  "very_low",
			identityFloorScor: 0.6,
			identityCeilScor:  0.95,
			presenceCeilScor:  0.2,
		},
		{
			// Pure manifest hit: very_high identity (we know
			// what is installed) but very_low presence (no
			// proof it is currently running -- presence prior
			// 0.05 only nudged up to ~0.2 by manifest LR=5).
			name: "manifest exact + lockfile version + no process (installed but not running)",
			signals: []AISignal{
				packageManifestSignal("openai", "pypi", "openai", "1.45.0", now),
			},
			wantIdentityBand:  "very_high",
			wantPresenceBand:  "very_low",
			identityFloorScor: 0.95,
			presenceCeilScor:  0.3,
		},
		{
			// Two independent strong signals (manifest names it +
			// process is alive) push presence into very_high.
			// This is the calibration target for "obviously in use".
			name: "manifest exact + live process (the gold case)",
			signals: []AISignal{
				packageManifestSignal("openai", "pypi", "openai", "1.45.0", now),
				freshProcessSignal("openai", "openai", "openai", now, 1.0, MatchKindExact),
			},
			wantIdentityBand:  "very_high",
			wantPresenceBand:  "very_high",
			identityFloorScor: 0.99,
			presenceFloorScor: 0.95,
			mustHaveDetectors: []string{"process", "package_manifest"},
		},
		{
			// Pure manifest from 30 days ago: identity is still
			// very_high (a stale install is still the same SDK)
			// but presence decays to very_low.
			name: "old install, no fresh activity (presence decays)",
			signals: []AISignal{
				packageManifestSignal("openai", "pypi", "openai", "1.45.0", now.Add(-30*24*time.Hour)),
			},
			wantIdentityBand:  "very_high",
			wantPresenceBand:  "very_low",
			identityFloorScor: 0.95,
			presenceCeilScor:  0.3,
		},
		{
			// Two distinct lockfile-pinned versions trip the
			// version_conflict penalty (-1.5 logit on identity)
			// but two manifest hits still keep identity high.
			name: "version conflict penalty kicks in",
			signals: []AISignal{
				packageManifestSignal("openai", "pypi", "openai", "1.45.0", now),
				packageManifestSignal("openai", "pypi", "openai", "0.27.0", now),
			},
			wantIdentityBand:  "very_high",
			identityFloorScor: 0.9,
		},
		{
			// Substring-quality (0.5) process match cuts both LR
			// exponents in half, so presence drops to "low"
			// rather than the "high" of an exact-comm match.
			name: "process substring match (Quality=0.5)",
			signals: []AISignal{
				freshProcessSignal("openai", "openai-helper", "openai", now, 0.5, MatchKindSubstring),
			},
			wantIdentityBand:  "high",
			wantPresenceBand:  "low",
			identityFloorScor: 0.85,
		},
		{
			// Empty signal list reports the prior. Identity
			// without any signal-derived curator confidence falls
			// back to a neutral 0.5 -> "low" band.
			name:             "no signals at all returns priors as bands",
			signals:          nil,
			wantIdentityBand: "low",
			wantPresenceBand: "very_low",
		},
		{
			// Ten heuristic hits saturate identity (very_high)
			// but barely touch presence -- the heuristic_only
			// penalty + low LRs keep presence in "low".
			name:              "ten heuristic shell-history hits compound to very_high identity",
			signals:           tenShellHistorySignals(now),
			wantIdentityBand:  "very_high",
			identityFloorScor: 0.95,
		},
		{
			// A binary in $PATH with no live process: identity
			// rises (we know which binary), presence is medium
			// (binary_lr=50 minus heuristic factors).
			name: "binary on PATH but no process (installed, not running)",
			signals: []AISignal{
				binarySignal("openai-cli", "openai", now),
			},
			wantIdentityBand:  "very_high",
			identityFloorScor: 0.9,
		},
		{
			// Process started 3 weeks ago (3 half-lives): identity
			// stays very_high; presence decays into very_low
			// because the recency exponent collapses the LR
			// contribution to ~0.125 of its fresh value.
			name: "stale process from 3 weeks ago",
			signals: []AISignal{
				freshProcessSignal("openai", "openai", "openai", now.Add(-21*24*time.Hour), 1.0, MatchKindExact),
			},
			wantIdentityBand: "very_high",
			wantPresenceBand: "very_low",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			res := ComputeComponentConfidence(tc.signals, now, params)
			if tc.wantIdentityBand != "" && res.IdentityBand != tc.wantIdentityBand {
				t.Errorf("identity band = %q, want %q (score=%.4f)", res.IdentityBand, tc.wantIdentityBand, res.IdentityScore)
			}
			if tc.wantPresenceBand != "" && res.PresenceBand != tc.wantPresenceBand {
				t.Errorf("presence band = %q, want %q (score=%.4f)", res.PresenceBand, tc.wantPresenceBand, res.PresenceScore)
			}
			if tc.identityFloorScor > 0 && res.IdentityScore < tc.identityFloorScor {
				t.Errorf("identity score %.4f below floor %.4f", res.IdentityScore, tc.identityFloorScor)
			}
			if tc.identityCeilScor > 0 && res.IdentityScore > tc.identityCeilScor {
				t.Errorf("identity score %.4f above ceiling %.4f", res.IdentityScore, tc.identityCeilScor)
			}
			if tc.presenceFloorScor > 0 && res.PresenceScore < tc.presenceFloorScor {
				t.Errorf("presence score %.4f below floor %.4f", res.PresenceScore, tc.presenceFloorScor)
			}
			if tc.presenceCeilScor > 0 && res.PresenceScore > tc.presenceCeilScor {
				t.Errorf("presence score %.4f above ceiling %.4f", res.PresenceScore, tc.presenceCeilScor)
			}
			for _, want := range tc.mustHaveDetectors {
				found := false
				for _, got := range res.Detectors {
					if got == want {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected detector %q in result, got %v", want, res.Detectors)
				}
			}
			// Universal invariants every result must satisfy:
			if res.IdentityScore < 0 || res.IdentityScore > 1 {
				t.Errorf("identity score out of [0,1]: %v", res.IdentityScore)
			}
			if res.PresenceScore < 0 || res.PresenceScore > 1 {
				t.Errorf("presence score out of [0,1]: %v", res.PresenceScore)
			}
			if res.IdentityBand == "" {
				t.Errorf("identity band must be non-empty")
			}
			if res.PresenceBand == "" {
				t.Errorf("presence band must be non-empty")
			}
		})
	}
}

// TestRecencyFactor pins the math for the recency-decay function so
// future calibration changes don't silently shift the curve. After
// one half-life the factor is 0.5; after three half-lives it is
// 0.125; very-old observations clamp at 0.05.
func TestRecencyFactor(t *testing.T) {
	now := time.Date(2026, 5, 5, 12, 0, 0, 0, time.UTC)
	cases := []struct {
		ageHours float64
		halfLife float64
		want     float64
	}{
		{0, 168, 1.0},
		{168, 168, 0.5},
		{336, 168, 0.25},
		{504, 168, 0.125},
		{99999, 168, 0.05}, // clamped
	}
	for _, tc := range cases {
		got := recencyFactor(now.Add(time.Duration(-tc.ageHours)*time.Hour), now, tc.halfLife)
		if math.Abs(got-tc.want) > 1e-6 {
			t.Errorf("recencyFactor(age=%vh, hl=%vh) = %v, want %v", tc.ageHours, tc.halfLife, got, tc.want)
		}
	}
}

// TestPercentagePointShift is a sanity check on the renderer math:
// near the middle of the curve a +1 logit shift is roughly +25pp;
// near 0.5 the slope is steepest.
func TestPercentagePointShift(t *testing.T) {
	f := ConfidenceFactor{LogitDelta: 1.0}
	got := f.PercentagePointShift(0.5)
	if math.Abs(got-25.0) > 0.01 {
		t.Errorf("at p=0.5, +1 logit ≈ +25pp; got %.4f", got)
	}
}

// freshProcessSignal builds a process AISignal with a single
// process-evidence row, ready for ComputeComponentConfidence. It
// mimics what `detectProcesses` would emit when the kernel returns a
// matching ps row.
func freshProcessSignal(component, comm, signatureID string, started time.Time, quality float64, kind string) AISignal {
	startedCopy := started
	return AISignal{
		SignatureID:  signatureID,
		Name:         component,
		Detector:     "process",
		Confidence:   0.85,
		Source:       "process",
		FirstSeen:    started,
		LastSeen:     started,
		LastActiveAt: &startedCopy,
		Component: &AIComponent{
			Ecosystem: "process",
			Name:      component,
		},
		Evidence: []AIEvidence{{
			Type:      "process",
			ValueHash: "h",
			Quality:   quality,
			MatchKind: kind,
		}},
	}
}

func packageManifestSignal(component, ecosystem, name, version string, lastSeen time.Time) AISignal {
	return AISignal{
		SignatureID: "ai-sdks",
		Name:        component,
		Detector:    "package_manifest",
		Confidence:  0.85,
		Source:      "package",
		FirstSeen:   lastSeen,
		LastSeen:    lastSeen,
		Component: &AIComponent{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
		},
		Version: version,
		Evidence: []AIEvidence{{
			Type:      "package",
			Basename:  "package.json",
			ValueHash: "v",
			Quality:   1.0,
			MatchKind: MatchKindExact,
		}},
	}
}

func shellHistorySignal(component, pattern string, lastSeen time.Time, kind string) AISignal {
	return AISignal{
		SignatureID: "shell-hist-" + component,
		Name:        component,
		Detector:    "shell_history",
		Confidence:  0.85,
		Source:      "shell_history",
		FirstSeen:   lastSeen,
		LastSeen:    lastSeen,
		Evidence: []AIEvidence{{
			Type:      "history",
			ValueHash: pattern,
			Quality:   0.5,
			MatchKind: kind,
		}},
	}
}

func binarySignal(name, signatureID string, lastSeen time.Time) AISignal {
	return AISignal{
		SignatureID: signatureID,
		Name:        name,
		Detector:    "binary",
		Confidence:  0.85,
		Source:      "binary",
		FirstSeen:   lastSeen,
		LastSeen:    lastSeen,
		Evidence: []AIEvidence{{
			Type:      "binary",
			Basename:  name,
			ValueHash: name,
			Quality:   1.0,
			MatchKind: MatchKindExact,
		}},
	}
}

func tenShellHistorySignals(now time.Time) []AISignal {
	out := make([]AISignal, 0, 10)
	for i := 0; i < 10; i++ {
		out = append(out, shellHistorySignal("openai", "openai-cli", now, MatchKindHeuristic))
	}
	return out
}
