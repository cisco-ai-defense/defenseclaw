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

package inventory

import (
	"fmt"
	"math"
	"sort"
	"strings"
	"time"
)

// ComputeComponentConfidence is the two-axis Bayesian confidence
// engine: given every signal that maps to one component (e.g. all
// rows of `pypi/openai`), return a calibrated probability that
//
//   - this is what we *think* it is (identity_score), and
//   - it is currently usable (presence_score).
//
// The model is a textbook log-odds combination:
//
//	logit(post) = logit(prior) + sum_i quality_i * specificity_i * log(LR_i)
//
// where LR_i is read from `params.Policy.Detectors[signal.Detector]`,
// quality_i is `signal.Evidence[*].Quality` (or 1.0 when unset), and
// specificity_i is the signature's `Specificity` (defaults to 0.7
// from normalizeAISignature). Presence additionally multiplies the
// LR exponent by an exponential recency factor based on
// `Now - signal.LastSeen` (or `signal.LastActiveAt` if set).
//
// The function is pure -- no I/O, no shared state -- so callers can
// drive it from tests with synthetic time, and so the gateway and
// CLI can call it concurrently from different goroutines without
// locking.
func ComputeComponentConfidence(signals []AISignal, now time.Time, params ConfidenceParams) ConfidenceResult {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	if params.Policy.Version == 0 {
		// Defensive fallback: if a caller forgot to set the
		// policy, load the embedded default. Returning a
		// confidence with the wrong policy would silently produce
		// uncalibrated scores, which is much worse than the small
		// overhead of one YAML parse per call.
		if def, err := LoadDefaultConfidencePolicy(); err == nil {
			params.Policy = def
		}
	}
	policy := params.Policy
	res := ConfidenceResult{
		ComputedAt:        now.UTC(),
		PolicyVersion:     policy.Version,
		HalfLifeHours:     policy.HalfLifeHours,
		IdentityFactors:   []ConfidenceFactor{},
		PresenceFactors:   []ConfidenceFactor{},
		Detectors:         []string{},
	}
	// Collect the per-component identity prior. When the policy
	// uses per-signature curator confidence (the default), pick the
	// max curator_confidence across signals -- one strong signature
	// match dominates a pile of weak ones. When the policy uses a
	// numeric prior, use that uniform value instead.
	priorIdentity := identityPriorForSignals(signals, policy)
	priorPresence := policy.Priors.Presence
	res.IdentityPrior = priorIdentity
	res.PresencePrior = priorPresence
	// Empty signal list: bands reflect the priors. Returning here
	// (rather than at function entry) ensures the caller gets a
	// well-formed result with non-empty bands and the prior values
	// stamped on the output.
	if len(signals) == 0 {
		res.IdentityScore = priorIdentity
		res.PresenceScore = priorPresence
		res.IdentityBand = policy.BandFor(res.IdentityScore)
		res.PresenceBand = policy.BandFor(res.PresenceScore)
		return res
	}

	identityLogit := logit(priorIdentity)
	presenceLogit := logit(priorPresence)

	// Track which detectors contributed, for the rendered breakdown.
	detectorSet := map[string]bool{}
	// Track per-detector counts for the signature_collision penalty.
	detectorCounts := map[string]int{}

	// Process each signal's evidence rows. Note: a signal with
	// multiple evidence rows is treated as multiple independent
	// observations. This is the textbook conditional-independence
	// assumption -- it is wrong in detail (a manifest *and* a
	// lockfile for the same package are correlated) but the
	// per-detector LR has been calibrated against that overlap, so
	// the error stays small in practice.
	for _, sig := range signals {
		det := sig.Detector
		detectorSet[det] = true
		detectorCounts[det]++
		detPolicy := policy.LookupDetector(det)
		specificity := signalSpecificity(sig)
		// A signal may carry zero, one, or many evidence rows.
		// When zero (legacy detectors that never populated
		// AISignal.Evidence), use one synthetic row so the
		// detector still contributes its base LR -- otherwise the
		// engine would silently treat it as no-information.
		evidenceRows := sig.Evidence
		if len(evidenceRows) == 0 {
			evidenceRows = []AIEvidence{{
				Type:      det,
				Quality:   defaultEvidenceQuality,
				MatchKind: MatchKindExact,
			}}
		}
		for _, ev := range evidenceRows {
			quality := ev.Quality
			if quality <= 0 {
				quality = defaultEvidenceQuality
			}
			if quality > 1 {
				quality = 1
			}
			// Identity contribution: not decayed (a stale install
			// is still the same SDK).
			idExp := quality * specificity
			idDelta := idExp * math.Log(detPolicy.IdentityLR)
			identityLogit += idDelta
			res.IdentityFactors = append(res.IdentityFactors, ConfidenceFactor{
				Detector:    det,
				EvidenceID:  evidenceFingerprint(sig, ev),
				MatchKind:   evidenceMatchKind(ev),
				Quality:     quality,
				Specificity: specificity,
				LR:          detPolicy.IdentityLR,
				LogitDelta:  idDelta,
			})
			// Presence contribution: decayed by recency.
			recency := recencyFactor(observationTime(sig, ev), now, policy.HalfLifeHours)
			prExp := quality * recency
			prDelta := prExp * math.Log(detPolicy.PresenceLR)
			presenceLogit += prDelta
			res.PresenceFactors = append(res.PresenceFactors, ConfidenceFactor{
				Detector:    det,
				EvidenceID:  evidenceFingerprint(sig, ev),
				MatchKind:   evidenceMatchKind(ev),
				Quality:     quality,
				Specificity: recency, // record recency in the Specificity slot for presence factors so the renderer is uniform
				LR:          detPolicy.PresenceLR,
				LogitDelta:  prDelta,
			})
		}
	}

	// Apply negative signals. We only know how to detect a few
	// kinds here; the engine surfaces every penalty it applied so
	// the operator-facing "explain" command can show why a score
	// dropped.
	if pen, ok := policy.LookupPenalty("heuristic_only"); ok && allHeuristicOrSubstring(signals) {
		applyPenalty(&identityLogit, &presenceLogit, pen, 1, &res, "heuristic_only")
	}
	if pen, ok := policy.LookupPenalty("weak_evidence_only"); ok && allWeakEvidence(signals) {
		applyPenalty(&identityLogit, &presenceLogit, pen, 1, &res, "weak_evidence_only")
	}
	if pen, ok := policy.LookupPenalty("version_conflict"); ok {
		if n := versionConflictCount(signals); n > 0 {
			applyPenalty(&identityLogit, &presenceLogit, pen, n, &res, "version_conflict")
		}
	}

	res.Detectors = sortedKeys(detectorSet)
	res.IdentityScore = sigmoid(identityLogit)
	res.PresenceScore = sigmoid(presenceLogit)
	res.IdentityBand = policy.BandFor(res.IdentityScore)
	res.PresenceBand = policy.BandFor(res.PresenceScore)
	return res
}

// ConfidenceParams is the call-site-supplied configuration for the
// engine. `Policy` carries the loaded YAML, defaulting to the
// embedded policy if the caller forgot to set it.
type ConfidenceParams struct {
	Policy ConfidencePolicy
}

// ConfidenceResult is the output of one invocation. Both scores are
// in [0, 1]; bands are the operator-facing label (very_high, high,
// medium, low, very_low). Factors and Detectors enable the
// "explain" CLI which shows each contribution as a percentage-point
// shift in the underlying logit.
type ConfidenceResult struct {
	IdentityScore   float64            `json:"identity_score"`
	IdentityBand    string             `json:"identity_band"`
	PresenceScore   float64            `json:"presence_score"`
	PresenceBand    string             `json:"presence_band"`
	IdentityPrior   float64            `json:"identity_prior"`
	PresencePrior   float64            `json:"presence_prior"`
	IdentityFactors []ConfidenceFactor `json:"identity_factors,omitempty"`
	PresenceFactors []ConfidenceFactor `json:"presence_factors,omitempty"`
	Detectors       []string           `json:"detectors,omitempty"`
	ComputedAt      time.Time          `json:"computed_at"`
	PolicyVersion   int                `json:"policy_version"`
	HalfLifeHours   float64            `json:"half_life_hours,omitempty"`
}

// ConfidenceFactor is one row in the score breakdown. `LogitDelta`
// is the additive shift this evidence contributed to the logit; the
// "explain" UI converts it to a percentage-point shift relative to
// the current score for human readers.
type ConfidenceFactor struct {
	Detector    string  `json:"detector"`
	EvidenceID  string  `json:"evidence_id,omitempty"`
	MatchKind   string  `json:"match_kind,omitempty"`
	Quality     float64 `json:"quality"`
	Specificity float64 `json:"specificity"` // for presence factors this carries the recency factor instead
	LR          float64 `json:"lr"`
	LogitDelta  float64 `json:"logit_delta"`
}

// PercentagePointShift converts a logit delta to a percentage-point
// shift in the underlying probability *at the current score*. The
// CLI uses this for the breakdown so an operator can see at a glance
// "this lockfile match added +12pp" rather than reading raw log-odds.
//
// For renderers, score is the score *after* the factor was applied.
// We approximate the shift via the local derivative of sigmoid:
// dP/dlogit = P*(1-P). This is a first-order estimate that matches
// the actual shift to a few tenths of a percentage point for the
// values we care about; we do not need exact arithmetic for an
// operator UI.
func (f ConfidenceFactor) PercentagePointShift(score float64) float64 {
	return f.LogitDelta * score * (1 - score) * 100
}

// identityPriorForSignals selects the prior to use as `logit_0` for
// identity. With the default policy ("priors.identity: signature")
// we pick the maximum curator_confidence across signals so a strong
// signature match is not pulled down by weaker corroborating ones.
func identityPriorForSignals(signals []AISignal, policy ConfidencePolicy) float64 {
	if !policy.IdentityPriorIsSignature() {
		return policy.Priors.IdentityScalar
	}
	// We do not have direct access to the catalog here; the prior
	// is already baked into AISignal.Confidence when the engine
	// runs (set by signalFromEvidence -> matches sig.Confidence /
	// sig.CuratorConfidence). Take the max over all signals.
	best := 0.0
	for _, s := range signals {
		if s.Confidence > best {
			best = s.Confidence
		}
	}
	if best <= 0 {
		// Last-resort fallback so logit() doesn't blow up: use a
		// neutral 0.5 prior.
		best = 0.5
	}
	if best >= 1 {
		// Clamp away from 1.0 to keep log-odds finite.
		best = 0.9999
	}
	return best
}

// signalSpecificity returns the catalog-supplied Specificity for
// this signal. We do not have the AISignature here (the engine takes
// AISignal), so we use a stable per-signature heuristic: signals
// with a resolved Component are highly specific (matched a declared
// package), heuristic detectors get a slight discount.
func signalSpecificity(sig AISignal) float64 {
	if sig.Component != nil && strings.TrimSpace(sig.Component.Name) != "" {
		return 1.0
	}
	switch sig.Detector {
	case "shell_history", "env":
		return 0.5
	default:
		return 0.7
	}
}

// observationTime returns when this evidence was last observed.
// Process detectors stamp `LastActiveAt`; others fall back to
// `LastSeen` from the signal envelope.
func observationTime(sig AISignal, ev AIEvidence) time.Time {
	if sig.LastActiveAt != nil && !sig.LastActiveAt.IsZero() {
		return *sig.LastActiveAt
	}
	if !sig.LastSeen.IsZero() {
		return sig.LastSeen
	}
	return time.Time{}
}

// recencyFactor implements the exponential decay applied to
// presence likelihood ratios. After `halfLife` hours the contribution
// is halved. Returns 1.0 for fresh observations (age <= 0) and a
// small minimum of 0.05 for very old ones, so the LR never cancels
// out entirely (a year-old install is still some evidence).
func recencyFactor(observed, now time.Time, halfLife float64) float64 {
	if observed.IsZero() || halfLife <= 0 {
		return 1
	}
	age := now.Sub(observed).Hours()
	if age <= 0 {
		return 1
	}
	factor := math.Pow(0.5, age/halfLife)
	if factor < 0.05 {
		return 0.05
	}
	return factor
}

// evidenceFingerprint builds a short, stable identifier for a
// (signal, evidence) pair so the breakdown table can de-duplicate
// rows when multiple signals point at the same on-disk artifact.
func evidenceFingerprint(sig AISignal, ev AIEvidence) string {
	parts := []string{sig.SignatureID, ev.Type}
	if ev.PathHash != "" {
		parts = append(parts, ev.PathHash[:min(8, len(ev.PathHash))])
	}
	if ev.ValueHash != "" {
		parts = append(parts, ev.ValueHash[:min(8, len(ev.ValueHash))])
	}
	return strings.Join(parts, ":")
}

func evidenceMatchKind(ev AIEvidence) string {
	if ev.MatchKind == "" {
		return MatchKindExact
	}
	return ev.MatchKind
}

// allHeuristicOrSubstring returns true when every signal is from a
// known-weak detector. The penalty value defaults to -0.7 so the
// score gets noticeably (but not catastrophically) reduced.
func allHeuristicOrSubstring(signals []AISignal) bool {
	if len(signals) == 0 {
		return false
	}
	weakDetectors := map[string]bool{
		"shell_history": true,
		"env":           true,
	}
	for _, s := range signals {
		if !weakDetectors[s.Detector] {
			// At least one strong detector hit -- not a heuristic-only case.
			return false
		}
	}
	return true
}

// allWeakEvidence returns true when every evidence row is below
// quality 0.5. Used to penalize presence (you might still know what
// it is, but you have no proof it's actively usable).
func allWeakEvidence(signals []AISignal) bool {
	if len(signals) == 0 {
		return false
	}
	for _, s := range signals {
		for _, ev := range s.Evidence {
			q := ev.Quality
			if q <= 0 {
				q = defaultEvidenceQuality
			}
			if q >= 0.5 {
				return false
			}
		}
		if len(s.Evidence) == 0 {
			// Default-quality (1.0) evidence is not weak.
			return false
		}
	}
	return true
}

// versionConflictCount returns the number of distinct (non-empty)
// version strings observed across signals. Two distinct versions on
// the same component is a conflict (count=2 -> one penalty), three
// is two penalties, etc.
func versionConflictCount(signals []AISignal) int {
	seen := map[string]bool{}
	for _, s := range signals {
		v := strings.TrimSpace(s.Version)
		if v != "" {
			seen[v] = true
		}
		if s.Component != nil && strings.TrimSpace(s.Component.Version) != "" {
			seen[s.Component.Version] = true
		}
	}
	if len(seen) <= 1 {
		return 0
	}
	return len(seen) - 1
}

// applyPenalty subtracts from one or both logits and records the
// penalty in the result so the explain UI can show it.
func applyPenalty(identityLogit, presenceLogit *float64, pen PenaltyPolicy, count int, res *ConfidenceResult, name string) {
	multiplier := 1.0
	if pen.ScaleWithCount && count > 1 {
		multiplier = float64(count - 1)
	}
	delta := pen.Logit * multiplier
	switch pen.Axis {
	case PenaltyAxisIdentity:
		*identityLogit += delta
		res.IdentityFactors = append(res.IdentityFactors, ConfidenceFactor{
			Detector:   "penalty:" + name,
			LogitDelta: delta,
			LR:         math.Exp(delta),
		})
	case PenaltyAxisPresence:
		*presenceLogit += delta
		res.PresenceFactors = append(res.PresenceFactors, ConfidenceFactor{
			Detector:   "penalty:" + name,
			LogitDelta: delta,
			LR:         math.Exp(delta),
		})
	case PenaltyAxisBoth:
		*identityLogit += delta
		*presenceLogit += delta
		res.IdentityFactors = append(res.IdentityFactors, ConfidenceFactor{
			Detector:   "penalty:" + name,
			LogitDelta: delta,
			LR:         math.Exp(delta),
		})
		res.PresenceFactors = append(res.PresenceFactors, ConfidenceFactor{
			Detector:   "penalty:" + name,
			LogitDelta: delta,
			LR:         math.Exp(delta),
		})
	}
}

// logit is the standard ln(p / (1-p)) with clamping so the engine
// never has to deal with infinities. Inputs at exactly 0 or 1 are
// clamped to (1e-9, 1 - 1e-9).
func logit(p float64) float64 {
	if p <= 0 {
		p = 1e-9
	}
	if p >= 1 {
		p = 1 - 1e-9
	}
	return math.Log(p / (1 - p))
}

// sigmoid is the inverse of `logit`. Returns a probability in [0, 1].
func sigmoid(x float64) float64 {
	if x > 50 {
		return 1
	}
	if x < -50 {
		return 0
	}
	return 1 / (1 + math.Exp(-x))
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// min is a local helper so this file can compile on Go 1.20 where
// the builtin `min` is not yet available. (The repo's go.mod already
// requires 1.21+, but a small local helper documents intent.)
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// String renders a ConfidenceResult as a multi-line waterfall for
// the `agent confidence explain` CLI command. Kept on the engine
// rather than the CLI so the gateway, TUI, and Python via JSON all
// see the same canonical breakdown text when they ask for it.
func (r ConfidenceResult) String() string {
	b := &strings.Builder{}
	fmt.Fprintf(b, "Identity %.2f (%s)  prior=%.2f\n", r.IdentityScore, r.IdentityBand, r.IdentityPrior)
	for _, f := range r.IdentityFactors {
		fmt.Fprintf(b, "  + %-20s lr=%.2f  q=%.2f  spec=%.2f  Δlogit=%+.3f\n",
			f.Detector, f.LR, f.Quality, f.Specificity, f.LogitDelta)
	}
	fmt.Fprintf(b, "Presence %.2f (%s)  prior=%.2f  half-life=%.0fh\n", r.PresenceScore, r.PresenceBand, r.PresencePrior, r.HalfLifeHours)
	for _, f := range r.PresenceFactors {
		fmt.Fprintf(b, "  + %-20s lr=%.2f  q=%.2f  recency=%.2f  Δlogit=%+.3f\n",
			f.Detector, f.LR, f.Quality, f.Specificity, f.LogitDelta)
	}
	return b.String()
}
