// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"regexp"
	"regexp/syntax"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
)

// indexEffectRuleSeverity is the highest severity categories give each rule
// id (upper case) among the rules that can fire on a tool call, built once
// per generation (GAP-2208). A rule with an expression is judged by it on
// the tool call: it is live unless its compiled program is false for every
// input (expression: false, false && ..., GAP-2207). A rule with no
// expression is judged by its pattern: live unless the pattern matches no
// text (a^, the pack tombstone). A pack rule always has a compiled pattern;
// a rule built in the package without one reads as live, as before. With no
// compiler (a generation whose compile failed) an expression reads as live,
// except the literal tombstone false.
func indexEffectRuleSeverity(categories []ruleCategory, compiler *semantic.Compiler) map[string]string {
	index := map[string]string{}
	for _, category := range categories {
		for _, rule := range category.Rules {
			if !effectRuleLive(rule, compiler) {
				continue
			}
			id := strings.ToUpper(rule.ID)
			severity := strings.ToUpper(strings.TrimSpace(rule.Severity))
			if decide.ParseSeverity(severity) > decide.ParseSeverity(index[id]) {
				index[id] = severity
			}
		}
	}
	return index
}

func effectRuleLive(rule PatternRule, compiler *semantic.Compiler) bool {
	if expression := strings.TrimSpace(rule.Expression); expression != "" {
		if compiler == nil {
			return expression != "false"
		}
		program, code := compiler.Compile(expression)
		return code == semantic.CompileOK && !program.NeverTrue()
	}
	return rule.Pattern == nil || !patternNeverMatches(rule.Pattern)
}

// maxPatternLivenessStates bounds the program states patternNeverMatches
// visits (counted work, never wall clock); past it the pattern reads as live.
const maxPatternLivenessStates = 1 << 16

// patternNeverMatches reports a pattern no text matches: no path of its
// compiled program reaches a match once the steps that can never hold are
// cut (a ^ or \A after a consumed character, a character after $ or \z, an
// empty character class). Every other assertion reads as satisfiable, so
// the answer is true only when no input can match.
func patternNeverMatches(re *regexp.Regexp) bool {
	parsed, err := syntax.Parse(re.String(), syntax.Perl)
	if err != nil {
		return false
	}
	prog, err := syntax.Compile(parsed.Simplify())
	if err != nil {
		return false
	}
	type state struct {
		pc              uint32
		consumed, ended bool
	}
	seen := map[state]bool{}
	stack := []state{{pc: uint32(prog.Start)}}
	for len(stack) > 0 {
		s := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if seen[s] {
			continue
		}
		if len(seen) >= maxPatternLivenessStates {
			return false
		}
		seen[s] = true
		inst := prog.Inst[s.pc]
		switch inst.Op {
		case syntax.InstMatch:
			return false
		case syntax.InstFail:
		case syntax.InstAlt, syntax.InstAltMatch:
			stack = append(stack, state{inst.Out, s.consumed, s.ended}, state{inst.Arg, s.consumed, s.ended})
		case syntax.InstCapture, syntax.InstNop:
			stack = append(stack, state{inst.Out, s.consumed, s.ended})
		case syntax.InstEmptyWidth:
			op := syntax.EmptyOp(inst.Arg)
			if op&syntax.EmptyBeginText != 0 && s.consumed {
				continue
			}
			stack = append(stack, state{inst.Out, s.consumed, s.ended || op&syntax.EmptyEndText != 0})
		case syntax.InstRune:
			if s.ended || len(inst.Rune) == 0 {
				continue
			}
			stack = append(stack, state{inst.Out, true, false})
		case syntax.InstRune1, syntax.InstRuneAny, syntax.InstRuneAnyNotNL:
			if s.ended {
				continue
			}
			stack = append(stack, state{inst.Out, true, false})
		default:
			return false
		}
	}
	return true
}

// effectRuleSeverity is the highest severity a generation (and each member
// of a profile combination) gives rule id among its live rules; "" when no
// live tool-call rule has that id. A tombstone (a rule that can never fire)
// is not authority for an effects finding (GAP-2198, GAP-2207). The lookup
// is the generation's index (GAP-2208).
func effectRuleSeverity(g *compiledRulePackCategories, id string) string {
	if g == nil {
		return ""
	}
	index := g.effectSeverity
	if index == nil {
		// A generation built without the compile (a package test literal, the
		// legacy view after a failed compile) is indexed here.
		index = indexEffectRuleSeverity(g.categories, nil)
	}
	best := index[strings.ToUpper(id)]
	for _, member := range g.members {
		if s := effectRuleSeverity(member, id); decide.ParseSeverity(s) > decide.ParseSeverity(best) {
			best = s
		}
	}
	return best
}

// effectRuleScope is one profile's share of an effects finding: the
// severity that profile's own pack gives the finding's rule, and the
// profile the finding is attributed to ("" for one pack).
type effectRuleScope struct {
	profile, severity string
}

// effectRuleScopes are the profiles an effects finding of rule id is
// counted for. One pack: the pack, when its rule is live. A strictest
// combination (a meet) of named members: each member whose own pack has the
// rule live, with that member's severity, so a member whose pack turns the
// rule off never counts the finding (GAP-2206). The effects lane reads the
// call once, at the outermost dispatch; this scopes its finding the way the
// member scans scope theirs (finding.profile).
func effectRuleScopes(g *compiledRulePackCategories, id string) []effectRuleScope {
	if g == nil {
		return nil
	}
	if len(g.members) == 0 || len(g.memberNames) < len(g.members) {
		if severity := effectRuleSeverity(g, id); severity != "" {
			return []effectRuleScope{{severity: severity}}
		}
		return nil
	}
	var scopes []effectRuleScope
	for i, member := range g.members {
		if severity := effectRuleSeverity(member, id); severity != "" {
			scopes = append(scopes, effectRuleScope{profile: g.memberNames[i], severity: severity})
		}
	}
	return scopes
}
