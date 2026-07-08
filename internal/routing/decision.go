// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routing

import (
	"sort"
	"strings"
)

// DecisionResult is the output of the decision engine.
type DecisionResult struct {
	DecisionName string
	ModelRefs    []string
}

// Decide evaluates decision rules against matched signals, returning the
// highest-priority match. Returns nil when no decision matches.
func Decide(signals *SignalResult, decisions []DecisionRule) *DecisionResult {
	if len(decisions) == 0 {
		return nil
	}

	sorted := make([]DecisionRule, len(decisions))
	copy(sorted, decisions)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].Priority > sorted[j].Priority
	})

	matched := make(map[string]bool)
	for _, s := range signals.MatchedKeywords {
		matched[s] = true
	}
	for _, s := range signals.MatchedEmbeddings {
		matched[s] = true
	}
	for _, s := range signals.MatchedDomains {
		matched[s] = true
	}

	for _, d := range sorted {
		if len(d.Conditions) == 0 {
			return &DecisionResult{DecisionName: d.Name, ModelRefs: d.ModelRefs}
		}
		if evaluateConditions(d, matched) {
			return &DecisionResult{DecisionName: d.Name, ModelRefs: d.ModelRefs}
		}
	}

	return nil
}

func evaluateConditions(d DecisionRule, matched map[string]bool) bool {
	op := strings.ToUpper(d.Operator)
	if op == "OR" {
		for _, c := range d.Conditions {
			if matched[c.Name] {
				return true
			}
		}
		return false
	}
	// Default: AND
	for _, c := range d.Conditions {
		if !matched[c.Name] {
			return false
		}
	}
	return true
}
