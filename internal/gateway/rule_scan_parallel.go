// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/rxprefilter"
)

const (
	// parallelRuleScanMinText is the text size from which the rules of one
	// scan are matched on several goroutines. Below it the scan is a few
	// microseconds and stays on the calling goroutine, as before.
	parallelRuleScanMinText = 64 << 10
	// parallelRuleScanMaxWorkers bounds the goroutines of one scan.
	parallelRuleScanMaxWorkers = 8
)

// ruleScanEligible reports whether rule is checked against the text in this
// scan: its category (or, for a migrated literal rule, the rule itself) is
// allowed by options.
func ruleScanEligible(options ruleScanOptions, cat *ruleCategory, rule *PatternRule) bool {
	categoryAllowed := options.allowsCategory(cat.Name)
	if !categoryAllowed && !options.allowsMigratedLiteralRule(cat.Name) {
		return false
	}
	if !categoryAllowed && !rule.migratedLiteral {
		return false
	}
	return options.allows(rule.ID, rule.ToolCallOnly)
}

// ruleScanMatches holds the first accepted match of the rules of one scan
// that were matched ahead of the scan loop (scanRuleMatchesInParallel). A rule
// that is absent is matched by the loop itself.
type ruleScanMatches map[*PatternRule][]int

// scanRuleMatchesInParallel matches the rules of a large text on several
// goroutines, with the checks the scan loop makes (the required literals of
// the rule, then its first accepted match), and returns the answers for the
// loop to read in rule order. The loop still decides in order which rule
// reports (a rule ID reports once), so the findings are the ones a sequential
// scan makes; only the time to match 100 or more rules against a text of
// hundreds of kilobytes is spent on several cores. A text under
// parallelRuleScanMinText returns nil. A rule whose match panics is left to
// the loop, which then fails in its own goroutine as it always did.
func scanRuleMatchesInParallel(
	generation *compiledRulePackCategories,
	options ruleScanOptions,
	seen map[string]bool,
	text *ruleScanText,
	scan *rxprefilter.Text,
) ruleScanMatches {
	workers := min(runtime.GOMAXPROCS(0), parallelRuleScanMaxWorkers)
	if len(text.text) < parallelRuleScanMinText || workers < 2 {
		return nil
	}
	var todo []*PatternRule
	for categoryIndex := range generation.categories {
		cat := &generation.categories[categoryIndex]
		for ruleIndex := range cat.Rules {
			rule := &cat.Rules[ruleIndex]
			if rule.Pattern != nil && !seen[rule.ID] && ruleScanEligible(options, cat, rule) {
				todo = append(todo, rule)
			}
		}
	}
	workers = min(workers, len(todo))
	if workers < 2 {
		return nil
	}
	type answer struct {
		loc  []int
		done bool
	}
	answers := make([]answer, len(todo))
	var next atomic.Int64
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				index := int(next.Add(1)) - 1
				if index >= len(todo) {
					return
				}
				func() {
					defer func() { _ = recover() }()
					rule := todo[index]
					var loc []int
					if text.mayMatch(rule.Pattern) {
						loc = firstAcceptedRuleMatchIn(*rule, scan)
					}
					answers[index] = answer{loc: loc, done: true}
				}()
			}
		}()
	}
	wg.Wait()
	matches := make(ruleScanMatches, len(todo))
	for index, rule := range todo {
		if answers[index].done {
			matches[rule] = answers[index].loc
		}
	}
	return matches
}

// match is the first accepted match of rule in the text: the answer matched
// ahead when there is one, else the answer of the checks the loop makes.
func (m ruleScanMatches) match(rule *PatternRule, text *ruleScanText, scan *rxprefilter.Text) []int {
	if loc, ok := m[rule]; ok {
		return loc
	}
	if !text.mayMatch(rule.Pattern) {
		return nil
	}
	return firstAcceptedRuleMatchIn(*rule, scan)
}
