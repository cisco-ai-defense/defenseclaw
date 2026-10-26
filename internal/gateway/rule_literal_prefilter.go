// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"regexp/syntax"
	"sort"
	"strings"
	"sync"
	"unicode"
	"unicode/utf8"
)

// A rule's regular expression can match only text that holds one of its
// required literals. Go's regexp runs a full NFA pass over text that has no
// match at all, about 10 ms per rule per MB, so a post-tool scan of a large
// result spent seconds proving that hundreds of rules do not match
// (GAP-1230, GAP-1735, GAP-1217). The rule scan now checks each rule's
// required literals with one substring search first and runs the regexp only
// when one is present. The check is exact in one direction: a text it skips
// cannot match the rule, so no finding changes.

// maxRuleLiteralAlternatives bounds the literal set of an alternation or a
// character class; a part with more alternatives requires nothing.
const maxRuleLiteralAlternatives = 32

// maxRuleLiteralSets bounds how many literal sets a rule checks.
const maxRuleLiteralSets = 8

// ruleLiteralPlans caches the plan of each rule pattern, keyed by its source
// text. Every generation compile copies the rule regexps, so a key per
// *regexp.Regexp kept every reloaded generation alive (GAP-1933); the source
// keys are bounded by the distinct patterns.
var ruleLiteralPlans sync.Map

// ruleLiteralPlan is what a text must hold for a regexp to match it: for each
// set, one of its case-folded literals. A nil plan requires nothing (the
// regexp always runs); a plan with an empty set matches no text.
type ruleLiteralPlan [][]string

// ruleRequiredLiterals returns the plan of pattern.
func ruleRequiredLiterals(pattern *regexp.Regexp) ruleLiteralPlan {
	if pattern == nil {
		return nil
	}
	source := pattern.String()
	if cached, ok := ruleLiteralPlans.Load(source); ok {
		return cached.(ruleLiteralPlan)
	}
	var plan ruleLiteralPlan
	if parsed, err := syntax.Parse(source, syntax.Perl); err == nil {
		if found, ok := requiredLiteralPlan(parsed.Simplify()); ok {
			plan = strongestLiteralSets(found, maxRuleLiteralSets)
		}
	}
	ruleLiteralPlans.Store(source, plan)
	return plan
}

// requiredLiteralPlan returns literal sets every match of re satisfies: it
// holds one literal of each set.
func requiredLiteralPlan(re *syntax.Regexp) (ruleLiteralPlan, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		literal := foldRuleText(string(re.Rune))
		return ruleLiteralPlan{{literal}}, literal != ""
	case syntax.OpCharClass:
		set, ok := charClassLiterals(re.Rune)
		return ruleLiteralPlan{set}, ok
	case syntax.OpCapture, syntax.OpPlus:
		return requiredLiteralPlan(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return requiredLiteralPlan(re.Sub[0])
		}
	case syntax.OpConcat:
		if concatNeverMatches(re) {
			// No text matches (the shipped "a^" placeholder of an
			// expression-only rule): an empty set skips the regexp.
			return ruleLiteralPlan{{}}, true
		}
		var plan ruleLiteralPlan
		for _, sub := range re.Sub {
			if found, ok := requiredLiteralPlan(sub); ok {
				plan = append(plan, found...)
			}
		}
		return plan, plan != nil
	case syntax.OpAlternate:
		// A match satisfies one alternative, so it holds a literal of that
		// alternative's strongest set.
		var union []string
		for _, sub := range re.Sub {
			found, ok := requiredLiteralPlan(sub)
			if !ok {
				return nil, false
			}
			best := strongestLiteralSets(found, 1)
			if len(best[0]) == 0 {
				continue // this alternative matches no text
			}
			union = append(union, best[0]...)
		}
		if len(union) > maxRuleLiteralAlternatives {
			return nil, false
		}
		return ruleLiteralPlan{union}, true
	}
	return nil, false
}

// charClassLiterals returns the folded runes of a small character class.
func charClassLiterals(ranges []rune) ([]string, bool) {
	count := 0
	for i := 0; i+1 < len(ranges); i += 2 {
		count += int(ranges[i+1]-ranges[i]) + 1
		if count > maxRuleLiteralAlternatives {
			return nil, false
		}
	}
	seen := make(map[string]bool, count)
	var set []string
	for i := 0; i+1 < len(ranges); i += 2 {
		for r := ranges[i]; r <= ranges[i+1]; r++ {
			literal := string(foldRuleRune(r))
			if !seen[literal] {
				seen[literal] = true
				set = append(set, literal)
			}
		}
	}
	return set, len(set) > 0
}

// strongestLiteralSets keeps at most limit sets of plan, an impossible
// (empty) set first, then the sets whose shortest literal is longest.
func strongestLiteralSets(plan ruleLiteralPlan, limit int) ruleLiteralPlan {
	ranked := append(ruleLiteralPlan(nil), plan...)
	sort.SliceStable(ranked, func(i, j int) bool {
		return literalSetStrength(ranked[i]) > literalSetStrength(ranked[j])
	})
	if len(ranked) > limit {
		ranked = ranked[:limit]
	}
	return ranked
}

func literalSetStrength(set []string) int {
	if len(set) == 0 {
		return 1 << 30
	}
	shortest := -1
	for _, literal := range set {
		if shortest < 0 || len(literal) < shortest {
			shortest = len(literal)
		}
	}
	return shortest
}

// concatNeverMatches reports a concatenation that needs the start of the
// text after it has read a literal, which no text satisfies.
func concatNeverMatches(re *syntax.Regexp) bool {
	consumed := false
	for _, sub := range re.Sub {
		switch sub.Op {
		case syntax.OpLiteral:
			consumed = true
		case syntax.OpBeginText:
			if consumed {
				return true
			}
		}
	}
	return false
}

// foldRuleRune maps a rune to the smallest rune of its case-folding orbit,
// so a case-insensitive literal and every text it matches fold to the same
// string (Kelvin sign K, long s and ASCII letters included).
func foldRuleRune(r rune) rune {
	if r < utf8.RuneSelf {
		if 'a' <= r && r <= 'z' {
			return r - 'a' + 'A'
		}
		return r
	}
	smallest := r
	for folded := unicode.SimpleFold(r); folded != r; folded = unicode.SimpleFold(folded) {
		if folded < smallest {
			smallest = folded
		}
	}
	return smallest
}

func foldRuleText(text string) string {
	return strings.Map(foldRuleRune, text)
}

// ruleScanText is one text a rule scan reads, folded once on first use.
type ruleScanText struct {
	text   string
	folded string
	ready  bool
}

// mayMatch reports whether pattern can match the text: false only when the
// text misses every literal of one of the pattern's required sets.
func (t *ruleScanText) mayMatch(pattern *regexp.Regexp) bool {
	plan := ruleRequiredLiterals(pattern)
	if plan == nil {
		return true
	}
	if !t.ready {
		t.folded, t.ready = foldRuleText(t.text), true
	}
	for _, set := range plan {
		found := false
		for _, literal := range set {
			if strings.Contains(t.folded, literal) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
