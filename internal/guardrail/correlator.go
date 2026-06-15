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

package guardrail

import (
	_ "embed"
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

//go:embed defaults/correlation-patterns.yaml
var defaultCorrelationPatternsYAML []byte

// DefaultCorrelationPatterns returns the pattern set shipped in
// internal/guardrail/defaults/correlation-patterns.yaml. Wiring code
// in the sidecar calls this at boot; tests that need the default set
// can reuse it rather than re-embedding the file.
func DefaultCorrelationPatterns() (*CorrelationPatternSet, error) {
	return LoadCorrelationPatterns(defaultCorrelationPatternsYAML)
}

// CorrelationFinding is the subset of a persisted scan_findings row
// that the correlator needs. Defined here (rather than reused from
// internal/audit) so this package stays free of audit dependencies
// — the audit store adapts its row type to this via a thin shim.
type CorrelationFinding struct {
	ID                  string
	RuleID              string
	Category            string
	Severity            string
	DataAxis            []DataAxis
	ToolCapabilityClass ToolCapabilityClass
	ContentFingerprint  string
	ExternalEndpoint    string
	TurnID              int
}

// CorrelationPattern is the YAML-declared rule for matching a sequence
// of findings in a session's sliding window. At most one of `AllOf`
// or `Sequence` should be non-empty.
type CorrelationPattern struct {
	ID              string           `yaml:"id"`
	Description     string           `yaml:"description,omitempty"`
	WindowEvents    int              `yaml:"window_events"`
	SeverityOnMatch string           `yaml:"severity_on_match"`
	AllOf           []PatternClause  `yaml:"all_of,omitempty"`
	Sequence        []SequenceClause `yaml:"sequence,omitempty"`
	FingerprintLink []PatternClause  `yaml:"fingerprint_chain,omitempty"`
	// Ordered, when set on an `all_of` pattern, requires the clauses to
	// match distinct findings in temporal (arrival) order rather than
	// as an unordered conjunction. Default false preserves the legacy
	// unordered behavior and is fully backward compatible.
	Ordered bool `yaml:"ordered,omitempty"`
}

// PatternClause matches any single finding in the window. A clause
// fires when ALL of its declared predicates hold on that finding.
// Empty fields are "don't care".
type PatternClause struct {
	// Axis requires the finding to carry this data_axis label.
	Axis DataAxis `yaml:"axis,omitempty"`
	// ToolCapabilityClass requires the finding's tool_capability_class
	// to match this value.
	ToolCapabilityClass ToolCapabilityClass `yaml:"tool_capability_class,omitempty"`
	// WithRuleMatch requires the finding's rule_id to be in this list.
	// Useful for narrowing e.g. "exec_shell capability with one of
	// the destructive rule IDs" rather than "any exec_shell call".
	WithRuleMatch []string `yaml:"with_rule_match,omitempty"`
	// MinSeverity requires the finding's severity rank to be >= this
	// label's rank (NONE/LOW/MEDIUM/HIGH/CRITICAL).
	MinSeverity string `yaml:"min_severity,omitempty"`
}

// SequenceClause is a single step in a severity-ordered chain. The
// window must contain findings whose severities match the sequence
// in temporal order — attacker iterating on a prompt typically goes
// MEDIUM -> HIGH -> HIGH.
type SequenceClause struct {
	Severity string `yaml:"severity"`
}

// CorrelationPatternSet is the YAML root.
type CorrelationPatternSet struct {
	Patterns []CorrelationPattern `yaml:"patterns"`
}

// LoadCorrelationPatterns parses a YAML pattern file.
func LoadCorrelationPatterns(data []byte) (*CorrelationPatternSet, error) {
	var set CorrelationPatternSet
	if err := yaml.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("correlation: parse patterns: %w", err)
	}
	for i := range set.Patterns {
		p := &set.Patterns[i]
		if p.WindowEvents <= 0 {
			p.WindowEvents = 20
		}
		if p.SeverityOnMatch == "" {
			p.SeverityOnMatch = "CRITICAL"
		}
	}
	return &set, nil
}

// Match returns the subset of CorrelationFindings that contributed to
// pattern `p` firing on `window`, or nil if the pattern did not match.
// The window is expected to be in newest-first order (the sliding
// window's natural projection from ListRecentFindingsInSession).
func (p *CorrelationPattern) Match(window []CorrelationFinding) []CorrelationFinding {
	if len(window) == 0 {
		return nil
	}
	if p.WindowEvents > 0 && len(window) > p.WindowEvents {
		window = window[:p.WindowEvents]
	}

	if len(p.FingerprintLink) > 0 {
		return p.matchFingerprintLink(window)
	}
	if len(p.AllOf) > 0 {
		if p.Ordered {
			return p.matchOrderedAllOf(window)
		}
		return p.matchAllOf(window)
	}
	if len(p.Sequence) > 0 {
		return p.matchSequence(window)
	}
	return nil
}

func (p *CorrelationPattern) matchAllOf(window []CorrelationFinding) []CorrelationFinding {
	var contributing []CorrelationFinding
	seen := map[string]bool{}
	for _, clause := range p.AllOf {
		idx := -1
		for i := range window {
			if clauseMatches(clause, &window[i]) {
				idx = i
				break
			}
		}
		if idx < 0 {
			return nil
		}
		if !seen[window[idx].ID] {
			seen[window[idx].ID] = true
			contributing = append(contributing, window[idx])
		}
	}
	return contributing
}

// matchOrderedAllOf is the order-aware variant of matchAllOf. The
// AllOf clauses must be satisfied by DISTINCT findings appearing in
// temporal order: clause[0] must match a finding that arrived no later
// than the finding matching clause[1], and so on. Ordering keys on the
// window's arrival order (newest-first, reversed here to oldest-first,
// exactly as matchSequence does) because scan_findings.turn_id is not
// populated today; TurnID would be a future tiebreak but is uniformly
// zero across all connectors, so arrival order is authoritative.
//
// Same-arrival (same timestamp) findings are allowed to satisfy
// adjacent clauses — the order constraint is non-decreasing, mirroring
// the reflexive Eventually semantics of the symbolic trifecta model.
func (p *CorrelationPattern) matchOrderedAllOf(window []CorrelationFinding) []CorrelationFinding {
	// Window is newest-first; walk oldest-first so clause direction
	// matches temporal order.
	ordered := make([]CorrelationFinding, len(window))
	for i, f := range window {
		ordered[len(window)-1-i] = f
	}

	step := 0
	var contributing []CorrelationFinding
	for i := range ordered {
		if step >= len(p.AllOf) {
			break
		}
		if clauseMatches(p.AllOf[step], &ordered[i]) {
			contributing = append(contributing, ordered[i])
			step++
		}
	}
	if step < len(p.AllOf) {
		return nil
	}
	return contributing
}

func (p *CorrelationPattern) matchSequence(window []CorrelationFinding) []CorrelationFinding {
	// Window is newest-first; walk oldest-first so sequence direction
	// matches temporal order.
	ordered := make([]CorrelationFinding, len(window))
	for i, f := range window {
		ordered[len(window)-1-i] = f
	}

	step := 0
	var contributing []CorrelationFinding
	for i := range ordered {
		if step >= len(p.Sequence) {
			break
		}
		want := strings.ToUpper(strings.TrimSpace(p.Sequence[step].Severity))
		if strings.ToUpper(ordered[i].Severity) == want {
			contributing = append(contributing, ordered[i])
			step++
		}
	}
	if step < len(p.Sequence) {
		return nil
	}
	return contributing
}

func (p *CorrelationPattern) matchFingerprintLink(window []CorrelationFinding) []CorrelationFinding {
	// Each clause independently matches some finding; the link fires
	// only when all matched findings share a non-empty content_fingerprint.
	matched := make([]*CorrelationFinding, 0, len(p.FingerprintLink))
	for _, clause := range p.FingerprintLink {
		var hit *CorrelationFinding
		for i := range window {
			if clauseMatches(clause, &window[i]) && window[i].ContentFingerprint != "" {
				hit = &window[i]
				break
			}
		}
		if hit == nil {
			return nil
		}
		matched = append(matched, hit)
	}
	sharedFP := matched[0].ContentFingerprint
	for _, m := range matched[1:] {
		if m.ContentFingerprint != sharedFP {
			return nil
		}
	}
	out := make([]CorrelationFinding, len(matched))
	for i, m := range matched {
		out[i] = *m
	}
	return out
}

func clauseMatches(c PatternClause, f *CorrelationFinding) bool {
	if c.Axis != "" {
		hasAxis := false
		for _, a := range f.DataAxis {
			if a == c.Axis {
				hasAxis = true
				break
			}
		}
		if !hasAxis {
			return false
		}
	}
	if c.ToolCapabilityClass != "" && f.ToolCapabilityClass != c.ToolCapabilityClass {
		return false
	}
	if len(c.WithRuleMatch) > 0 {
		found := false
		for _, r := range c.WithRuleMatch {
			if r == f.RuleID {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	if c.MinSeverity != "" {
		if severityRankCorrelator[strings.ToUpper(f.Severity)] < severityRankCorrelator[strings.ToUpper(c.MinSeverity)] {
			return false
		}
	}
	return true
}

// severityRankCorrelator mirrors the gateway package's rank ordering
// so correlation patterns see the same CRITICAL > HIGH > MEDIUM
// comparison. Duplicated here to keep the guardrail package free of
// gateway imports; the test TestCorrelatorSeverityOrderMatchesGateway
// (in gateway_test wiring) pins them together.
var severityRankCorrelator = map[string]int{
	"NONE":     0,
	"LOW":      1,
	"MEDIUM":   2,
	"HIGH":     3,
	"CRITICAL": 4,
}

// Evaluate runs every pattern in `patterns` against `window` and
// returns the set of (pattern, contributing findings) for those that
// matched. The caller is responsible for writing synthetic CORR-*
// findings back into the store when a match fires.
func Evaluate(patterns []CorrelationPattern, window []CorrelationFinding) []CorrelationMatch {
	var out []CorrelationMatch
	for i := range patterns {
		if contributing := patterns[i].Match(window); contributing != nil {
			out = append(out, CorrelationMatch{
				Pattern:      patterns[i],
				Contributing: contributing,
			})
		}
	}
	return out
}

// CorrelationMatch is what a pattern produces on match.
type CorrelationMatch struct {
	Pattern      CorrelationPattern
	Contributing []CorrelationFinding
}

// SyntheticFindingRuleID returns the CORR-<PATTERN_ID> rule id used
// for meta-findings written back into scan_findings.
func (m CorrelationMatch) SyntheticFindingRuleID() string {
	return "CORR-" + strings.ToUpper(strings.ReplaceAll(m.Pattern.ID, "_", "-"))
}
