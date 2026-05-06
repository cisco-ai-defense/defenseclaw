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
	_ "embed"
	"fmt"
	"os"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed confidence_policy.yaml
var defaultConfidencePolicyYAML []byte

// ConfidencePolicyVersion is the only schema version currently
// supported. Bumping this is a breaking change to the policy file
// shape; the loader rejects mismatched version values up front so an
// operator never silently runs with a half-applied policy.
const ConfidencePolicyVersion = 1

// confidencePolicyMaxBytes caps the size of an operator-supplied
// override file. The default policy is well under 4 KiB; 64 KiB is
// generous enough for hundreds of detector entries while keeping a
// hostile config from exhausting memory.
const confidencePolicyMaxBytes = 64 * 1024

// Allowed string values for `priors.identity` when the operator does
// not want a numeric prior. "signature" tells the engine to use each
// component's per-signature `curator_confidence` as the prior; this
// is the default and what almost every install should use.
const identityPriorSignature = "signature"

// PenaltyAxisBoth is the literal value for `penalties.<name>.axis`
// indicating the penalty applies to both identity and presence at
// once (e.g. heuristic-only matches degrade everything).
const (
	PenaltyAxisIdentity = "identity"
	PenaltyAxisPresence = "presence"
	PenaltyAxisBoth     = "both"
)

// validDetectorKeys enumerates every detector identifier the engine
// understands. Unknown keys in the YAML are rejected as typos -- this
// is the entire point of having a fixed schema rather than a
// free-form map. Keep this list in sync with the values stamped on
// `AISignal.Detector` in ai_discovery.go.
//
// IMPORTANT: detector identifiers in code (e.g. "package_manifest")
// are the *exact* keys the engine looks up here. The Bayesian model
// then weights each observation by `Quality * Specificity` so
// substring/exact distinctions do not need separate detector keys.
var validDetectorKeys = map[string]bool{
	"process":          true,
	"package_manifest": true,
	"binary":           true,
	"mcp":              true,
	"config":           true,
	"local_endpoint":   true,
	"editor_extension": true,
	"application":      true,
	"env":              true,
	"shell_history":    true,
}

// validPenaltyKeys mirrors validDetectorKeys for negative signals.
// The engine looks up these names by string when applying penalties
// during scoring (see confidence.go). Keep this list in lockstep with
// the LookupPenalty call sites in confidence.go::ComputeComponentConfidence
// — keys here that have no matching call are dead policy that mislead
// operators into believing they can tune behaviour they cannot.
//
// Dropped:
//   - "stale_binary" (was never applied; detection of a stale binary
//     requires liveness data the engine does not currently surface —
//     re-add the key only when the detector lands).
//   - "signature_collision" (the prototype implementation conflated
//     genuine independent evidence with overfitting; see the
//     explanatory comment in confidence.go::ComputeComponentConfidence).
//     Re-add when a correct dedupe-by-evidence-fingerprint
//     implementation lands AND an updated calibration test exists.
var validPenaltyKeys = map[string]bool{
	"version_conflict":   true,
	"weak_evidence_only": true,
	"heuristic_only":     true,
}

// ConfidencePolicy is the parsed, validated form of
// confidence_policy.yaml. Everything the Bayesian engine needs at
// scoring time lives here; the engine never reads the YAML directly,
// so policy edits cannot break the scoring math (only the loader's
// validation can fail).
type ConfidencePolicy struct {
	Version       int                       `yaml:"version" json:"version"`
	Priors        PriorsPolicy              `yaml:"priors" json:"priors"`
	HalfLifeHours float64                   `yaml:"half_life_hours" json:"half_life_hours"`
	Detectors     map[string]DetectorPolicy `yaml:"detectors" json:"detectors"`
	Penalties     map[string]PenaltyPolicy  `yaml:"penalties" json:"penalties"`
	Bands         []BandThreshold           `yaml:"bands" json:"bands"`
	// provenance tracks where each top-level field came from
	// ("default" or "override") so `agent confidence policy show`
	// can annotate every line. It is not parsed from YAML; the
	// loader fills it during merge. Map key is dotted path
	// (e.g. "detectors.process.identity_lr").
	provenance map[string]string
}

// PriorsPolicy carries the per-axis prior probabilities. The
// `Identity` field is parsed as YAML interface{} so it can be either
// the string "signature" or a numeric prior; we normalize at load
// time. `IdentityScalar` is set when the YAML provided a number.
type PriorsPolicy struct {
	Identity       string  `yaml:"identity" json:"identity"`           // "signature" or a stringified float
	Presence       float64 `yaml:"presence" json:"presence"`           // numeric prior, must be in (0, 1)
	IdentityScalar float64 `yaml:"-" json:"identity_scalar,omitempty"` // populated when Identity != "signature"
}

// DetectorPolicy is a single detector's likelihood ratios. Both
// fields must be > 0 (LR == 0 would mean P(obs|present) == 0, which
// is a hard "absolutely impossible" signal that we never want to
// ship in calibration data).
type DetectorPolicy struct {
	IdentityLR float64 `yaml:"identity_lr" json:"identity_lr"`
	PresenceLR float64 `yaml:"presence_lr" json:"presence_lr"`
}

// PenaltyPolicy is one negative-signal entry. Logit must be < 0
// (positive values would be boosts, which belong in detectors).
type PenaltyPolicy struct {
	Axis           string  `yaml:"axis" json:"axis"`
	Logit          float64 `yaml:"logit" json:"logit"`
	ScaleWithCount bool    `yaml:"scale_with_count" json:"scale_with_count"`
}

// BandThreshold is one entry in the score-to-label mapping. The
// loader sorts these in strictly decreasing `Min` order before
// returning, so callers can iterate top-to-bottom and pick the first
// match.
type BandThreshold struct {
	Min   float64 `yaml:"min" json:"min"`
	Label string  `yaml:"label" json:"label"`
}

// LoadDefaultConfidencePolicy returns the embedded policy. Any error
// here would be a build-time bug (the YAML is part of the binary),
// but we surface it as an error rather than panic so callers in
// constrained environments (sandboxes, restricted unmarshallers) can
// fall back gracefully.
func LoadDefaultConfidencePolicy() (ConfidencePolicy, error) {
	policy, err := parseConfidencePolicy(defaultConfidencePolicyYAML, "default", true)
	if err != nil {
		return ConfidencePolicy{}, err
	}
	if policy.provenance == nil {
		policy.provenance = map[string]string{}
	}
	for k := range collectAllKeys(policy) {
		policy.provenance[k] = "default"
	}
	return policy, nil
}

// LoadConfidencePolicyFromBytes deep-merges the supplied YAML bytes
// on top of the embedded default and returns the validated result.
// Used by the policy-validate API endpoint so an operator can
// dry-run a candidate policy file without writing it to disk on
// the gateway host. `source` is surfaced in error messages.
func LoadConfidencePolicyFromBytes(raw []byte, source string) (ConfidencePolicy, error) {
	if int64(len(raw)) > confidencePolicyMaxBytes {
		return ConfidencePolicy{}, fmt.Errorf(
			"confidence policy: %s exceeds %d bytes", source, confidencePolicyMaxBytes)
	}
	base, err := LoadDefaultConfidencePolicy()
	if err != nil {
		return ConfidencePolicy{}, err
	}
	if len(raw) == 0 {
		return base, nil
	}
	override, err := parseConfidencePolicy(raw, source, false)
	if err != nil {
		return ConfidencePolicy{}, err
	}
	merged := mergeConfidencePolicy(base, override, source)
	if err := finalizeConfidencePolicy(&merged); err != nil {
		return ConfidencePolicy{}, err
	}
	return merged, nil
}

// LoadConfidencePolicyFromFile reads `path` and deep-merges it on
// top of the embedded default. Missing fields in the override fall
// back to the default; unknown top-level keys (or unknown detector /
// penalty names) cause a hard error so a typo never silently breaks
// scoring.
func LoadConfidencePolicyFromFile(path string) (ConfidencePolicy, error) {
	base, err := LoadDefaultConfidencePolicy()
	if err != nil {
		return ConfidencePolicy{}, err
	}
	if path == "" {
		return base, nil
	}
	info, err := os.Stat(path)
	if err != nil {
		// Missing override file is not an error -- the default
		// policy is the operator's intended behavior. Other
		// stat failures (permission, etc.) are surfaced.
		if os.IsNotExist(err) {
			return base, nil
		}
		return ConfidencePolicy{}, fmt.Errorf("confidence policy: stat %s: %w", path, err)
	}
	if info.IsDir() {
		return ConfidencePolicy{}, fmt.Errorf("confidence policy: %s is a directory", path)
	}
	if info.Size() > confidencePolicyMaxBytes {
		return ConfidencePolicy{}, fmt.Errorf(
			"confidence policy: %s exceeds %d bytes", path, confidencePolicyMaxBytes)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return ConfidencePolicy{}, fmt.Errorf("confidence policy: read %s: %w", path, err)
	}
	if len(raw) == 0 {
		return base, nil
	}
	override, err := parseConfidencePolicy(raw, path, false)
	if err != nil {
		return ConfidencePolicy{}, err
	}
	merged := mergeConfidencePolicy(base, override, path)
	if err := finalizeConfidencePolicy(&merged); err != nil {
		return ConfidencePolicy{}, err
	}
	return merged, nil
}

// Provenance returns the source ("default" or the override file
// path) for a given dotted policy key, or "" if not tracked. Used by
// `agent confidence policy show` to annotate every line so an
// operator can see at a glance which fields they actually changed.
func (p ConfidencePolicy) Provenance(key string) string {
	if p.provenance == nil {
		return ""
	}
	return p.provenance[key]
}

// IdentityPriorIsSignature reports whether the loaded policy uses
// per-signature curator_confidence as the identity prior (the
// default). When false, IdentityScalar should be used as a uniform
// prior across all components.
func (p ConfidencePolicy) IdentityPriorIsSignature() bool {
	return strings.EqualFold(strings.TrimSpace(p.Priors.Identity), identityPriorSignature)
}

// Validate enforces every invariant the engine relies on. Loaders
// call it; tests call it directly with crafted inputs to make sure
// the ruleset stays exhaustive.
func (p ConfidencePolicy) Validate() error {
	if p.Version != ConfidencePolicyVersion {
		return fmt.Errorf("confidence policy: unsupported version %d (want %d)", p.Version, ConfidencePolicyVersion)
	}
	if !p.IdentityPriorIsSignature() {
		if p.Priors.IdentityScalar <= 0 || p.Priors.IdentityScalar >= 1 {
			return fmt.Errorf("confidence policy: priors.identity must be \"signature\" or a number in (0, 1), got %q", p.Priors.Identity)
		}
	}
	if p.Priors.Presence <= 0 || p.Priors.Presence >= 1 {
		return fmt.Errorf("confidence policy: priors.presence must be in (0, 1), got %v", p.Priors.Presence)
	}
	if p.HalfLifeHours <= 0 {
		return fmt.Errorf("confidence policy: half_life_hours must be > 0, got %v", p.HalfLifeHours)
	}
	if len(p.Detectors) == 0 {
		return fmt.Errorf("confidence policy: detectors map must not be empty")
	}
	for name, det := range p.Detectors {
		if !validDetectorKeys[name] {
			return fmt.Errorf("confidence policy: unknown detector %q (typo? expected one of: %s)", name, sortedKeysCSV(validDetectorKeys))
		}
		if det.IdentityLR <= 0 {
			return fmt.Errorf("confidence policy: detectors.%s.identity_lr must be > 0, got %v", name, det.IdentityLR)
		}
		if det.PresenceLR <= 0 {
			return fmt.Errorf("confidence policy: detectors.%s.presence_lr must be > 0, got %v", name, det.PresenceLR)
		}
	}
	for name, pen := range p.Penalties {
		if !validPenaltyKeys[name] {
			return fmt.Errorf("confidence policy: unknown penalty %q (typo? expected one of: %s)", name, sortedKeysCSV(validPenaltyKeys))
		}
		switch pen.Axis {
		case PenaltyAxisIdentity, PenaltyAxisPresence, PenaltyAxisBoth:
		default:
			return fmt.Errorf("confidence policy: penalties.%s.axis must be identity|presence|both, got %q", name, pen.Axis)
		}
		if pen.Logit >= 0 {
			return fmt.Errorf("confidence policy: penalties.%s.logit must be < 0 (use detectors.* for boosts), got %v", name, pen.Logit)
		}
	}
	if len(p.Bands) == 0 {
		return fmt.Errorf("confidence policy: bands must not be empty")
	}
	for i := 1; i < len(p.Bands); i++ {
		if p.Bands[i-1].Min <= p.Bands[i].Min {
			return fmt.Errorf("confidence policy: bands must be strictly decreasing in min (bands[%d].min=%v >= bands[%d].min=%v)", i, p.Bands[i].Min, i-1, p.Bands[i-1].Min)
		}
	}
	last := p.Bands[len(p.Bands)-1]
	if last.Min != 0 {
		return fmt.Errorf("confidence policy: lowest band must have min=0 (got %v) so every score has a label", last.Min)
	}
	for i, band := range p.Bands {
		if strings.TrimSpace(band.Label) == "" {
			return fmt.Errorf("confidence policy: bands[%d].label is required", i)
		}
	}
	return nil
}

// LookupDetector returns the configured detector policy for the
// given detector identifier, falling back to a neutral LR=1 (no
// information) when the key is absent. Returning the neutral value
// rather than an error lets calibration callers gracefully ignore
// detectors that the engine has not been told about yet -- new
// detectors added in code automatically score as zero-info until the
// policy file catches up.
func (p ConfidencePolicy) LookupDetector(name string) DetectorPolicy {
	if det, ok := p.Detectors[name]; ok {
		return det
	}
	return DetectorPolicy{IdentityLR: 1, PresenceLR: 1}
}

// LookupPenalty returns the configured penalty for `name` and a
// presence flag. Callers that want a "no penalty" default if missing
// should check `ok` and skip the application.
func (p ConfidencePolicy) LookupPenalty(name string) (PenaltyPolicy, bool) {
	pen, ok := p.Penalties[name]
	return pen, ok
}

// BandFor returns the label whose min threshold is the largest value
// <= score. Bands are pre-sorted by Validate so this is just a
// linear walk.
func (p ConfidencePolicy) BandFor(score float64) string {
	for _, band := range p.Bands {
		if score >= band.Min {
			return band.Label
		}
	}
	if len(p.Bands) > 0 {
		return p.Bands[len(p.Bands)-1].Label
	}
	return ""
}

// parseConfidencePolicy is the inner YAML decoder shared by the
// embedded-default and operator-override paths. `source` is used in
// error messages so an operator with a broken override can find the
// failing file immediately.
//
// We do two decode passes:
//  1. Strict decode into the typed struct -- this is the typo guard
//     that rejects unknown top-level fields (yaml.v3 supports this
//     via Decoder.KnownFields). This pass fails the load if the
//     operator misspelled "detectors" as "detectorz".
//  2. If the strict pass succeeded, walk the YAML node tree once to
//     recover a numeric `priors.identity` value (which the typed
//     struct decoded as the empty string) so operators can write
//     either `identity: signature` or `identity: 0.5`.
func parseConfidencePolicy(raw []byte, source string, validate bool) (ConfidencePolicy, error) {
	var policy ConfidencePolicy
	dec := yaml.NewDecoder(strings.NewReader(string(raw)))
	dec.KnownFields(true)
	if err := dec.Decode(&policy); err != nil {
		return ConfidencePolicy{}, fmt.Errorf("confidence policy: %s: %w", source, err)
	}
	// Second pass into a node so we can support numeric
	// `priors.identity` (the strict struct decode treats it as a
	// string and leaves it empty when the YAML had a number).
	var node yaml.Node
	if err := yaml.Unmarshal(raw, &node); err != nil {
		return ConfidencePolicy{}, fmt.Errorf("confidence policy: %s: parse: %w", source, err)
	}
	if policy.Priors.Identity == "" {
		if num, ok := lookupNumericPolicyField(&node, "priors", "identity"); ok {
			policy.Priors.IdentityScalar = num
			policy.Priors.Identity = fmt.Sprintf("%g", num)
		} else if validate {
			policy.Priors.Identity = identityPriorSignature
		}
	} else if !strings.EqualFold(policy.Priors.Identity, identityPriorSignature) {
		// Operator wrote a stringified number (yaml.v3 sometimes
		// decodes 0.5 into a string when surrounded by quotes).
		// Tolerate both styles.
		var f float64
		if _, err := fmt.Sscan(policy.Priors.Identity, &f); err == nil {
			policy.Priors.IdentityScalar = f
		}
	}
	if validate {
		if err := finalizeConfidencePolicy(&policy); err != nil {
			return ConfidencePolicy{}, err
		}
	}
	return policy, nil
}

func finalizeConfidencePolicy(policy *ConfidencePolicy) error {
	if policy == nil {
		return fmt.Errorf("confidence policy: missing policy")
	}
	if err := policy.Validate(); err != nil {
		return err
	}
	// Sort bands strictly decreasing. Validate already enforced
	// the invariant, but YAML preserves source order; sorting here
	// keeps lookup deterministic after both default loads and
	// override merges.
	sort.Slice(policy.Bands, func(i, j int) bool {
		return policy.Bands[i].Min > policy.Bands[j].Min
	})
	return nil
}

// mergeConfidencePolicy deep-merges `override` on top of `base`.
// Top-level fields are replaced when present; the detector and
// penalty maps are merged key-by-key (an operator override of a
// single detector's identity_lr leaves all other detectors at the
// default). The `bands` list, in contrast, is replaced wholesale
// when the override provides one (because partial band lists almost
// always indicate operator confusion).
func mergeConfidencePolicy(base, override ConfidencePolicy, source string) ConfidencePolicy {
	out := base
	if out.provenance == nil {
		out.provenance = map[string]string{}
	}
	if override.Version != 0 {
		out.Version = override.Version
		out.provenance["version"] = source
	}
	if override.HalfLifeHours != 0 {
		out.HalfLifeHours = override.HalfLifeHours
		out.provenance["half_life_hours"] = source
	}
	if strings.TrimSpace(override.Priors.Identity) != "" {
		out.Priors.Identity = override.Priors.Identity
		out.Priors.IdentityScalar = override.Priors.IdentityScalar
		out.provenance["priors.identity"] = source
	}
	if override.Priors.Presence != 0 {
		out.Priors.Presence = override.Priors.Presence
		out.provenance["priors.presence"] = source
	}
	if len(override.Detectors) > 0 {
		if out.Detectors == nil {
			out.Detectors = map[string]DetectorPolicy{}
		}
		for k, v := range override.Detectors {
			merged := out.Detectors[k]
			if v.IdentityLR != 0 {
				merged.IdentityLR = v.IdentityLR
				out.provenance["detectors."+k+".identity_lr"] = source
			}
			if v.PresenceLR != 0 {
				merged.PresenceLR = v.PresenceLR
				out.provenance["detectors."+k+".presence_lr"] = source
			}
			out.Detectors[k] = merged
		}
	}
	if len(override.Penalties) > 0 {
		if out.Penalties == nil {
			out.Penalties = map[string]PenaltyPolicy{}
		}
		for k, v := range override.Penalties {
			merged := out.Penalties[k]
			if v.Axis != "" {
				merged.Axis = v.Axis
				out.provenance["penalties."+k+".axis"] = source
			}
			if v.Logit != 0 {
				merged.Logit = v.Logit
				out.provenance["penalties."+k+".logit"] = source
			}
			if v.ScaleWithCount {
				merged.ScaleWithCount = true
			}
			out.Penalties[k] = merged
		}
	}
	if len(override.Bands) > 0 {
		out.Bands = make([]BandThreshold, len(override.Bands))
		copy(out.Bands, override.Bands)
		out.provenance["bands"] = source
	}
	return out
}

// lookupNumericPolicyField walks a yaml.Node tree to recover a
// numeric value at the given path. Returns (0, false) when the path
// does not resolve to a number. Used to gracefully accept a numeric
// `priors.identity` even though the typed struct decodes it as a
// string.
func lookupNumericPolicyField(n *yaml.Node, path ...string) (float64, bool) {
	cur := n
	if cur != nil && cur.Kind == yaml.DocumentNode && len(cur.Content) > 0 {
		cur = cur.Content[0]
	}
	for _, key := range path {
		if cur == nil || cur.Kind != yaml.MappingNode {
			return 0, false
		}
		var next *yaml.Node
		for i := 0; i+1 < len(cur.Content); i += 2 {
			if cur.Content[i].Value == key {
				next = cur.Content[i+1]
				break
			}
		}
		if next == nil {
			return 0, false
		}
		cur = next
	}
	if cur == nil {
		return 0, false
	}
	var f float64
	if _, err := fmt.Sscan(cur.Value, &f); err != nil {
		return 0, false
	}
	return f, true
}

// collectAllKeys enumerates every dotted policy field in `p` so
// `LoadDefaultConfidencePolicy` can stamp each one with provenance
// "default". The set is also used by `agent confidence policy show`
// to know which keys to render.
func collectAllKeys(p ConfidencePolicy) map[string]struct{} {
	keys := map[string]struct{}{
		"version":         {},
		"priors.identity": {},
		"priors.presence": {},
		"half_life_hours": {},
		"bands":           {},
	}
	for name := range p.Detectors {
		keys["detectors."+name+".identity_lr"] = struct{}{}
		keys["detectors."+name+".presence_lr"] = struct{}{}
	}
	for name := range p.Penalties {
		keys["penalties."+name+".axis"] = struct{}{}
		keys["penalties."+name+".logit"] = struct{}{}
	}
	return keys
}

// sortedKeysCSV returns a stable, comma-separated list of map keys
// for use in error messages. Putting this on its own function keeps
// the validate methods readable.
func sortedKeysCSV(m map[string]bool) string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return strings.Join(out, ", ")
}
