// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package engine

import (
	"context"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// signalMatcher evaluates routing.signals.keywords on classifier text.
// Keywords match as case-insensitive substrings (S12 GAP-0002: word
// boundaries missed common inflections and keywords ending in punctuation).
type signalMatcher struct {
	signals []compiledSignal
}

type compiledSignal struct {
	name     string
	keywords []string
	all      bool // AND
}

func newSignalMatcher(cfg config.RoutingSignalConfig) *signalMatcher {
	m := &signalMatcher{}
	for _, s := range cfg.Keywords {
		cs := compiledSignal{name: strings.TrimSpace(s.Name), all: strings.EqualFold(strings.TrimSpace(s.Operator), "AND")}
		for _, k := range s.Keywords {
			if k = strings.ToLower(strings.TrimSpace(k)); k != "" {
				cs.keywords = append(cs.keywords, k)
			}
		}
		m.signals = append(m.signals, cs)
	}
	return m
}

// Match returns the names of the signals that match text.
func (m *signalMatcher) Match(text string) map[string]bool {
	if m == nil || len(m.signals) == 0 || text == "" {
		return nil
	}
	lower := strings.ToLower(text)
	var out map[string]bool
	for _, s := range m.signals {
		hit := s.all
		for _, k := range s.keywords {
			found := strings.Contains(lower, k)
			if s.all && !found {
				hit = false
				break
			}
			if !s.all && found {
				hit = true
				break
			}
		}
		if hit && len(s.keywords) > 0 {
			if out == nil {
				out = map[string]bool{}
			}
			out[s.name] = true
		}
	}
	return out
}

type compiledCondition struct {
	kind string
	name string
}

type compiledDecision struct {
	name       string
	priority   int
	order      int
	all        bool
	conditions []compiledCondition
	aliases    []string
}

// rulesClassifier evaluates routing.decisions in-process: highest priority
// first, list order breaks ties; a decision without conditions is not
// matched here, its first alias is the configured default (as in the vLLM
// translation).
type rulesClassifier struct {
	decisions []compiledDecision
}

func newRulesClassifier(cfg config.RoutingConfig) *rulesClassifier {
	c := &rulesClassifier{}
	for i, d := range cfg.Decisions {
		if len(d.Conditions) == 0 {
			continue
		}
		op := strings.ToUpper(strings.TrimSpace(d.Operator))
		cd := compiledDecision{name: d.Name, priority: d.Priority, order: i, all: op != "OR"}
		for _, cond := range d.Conditions {
			cd.conditions = append(cd.conditions, compiledCondition{kind: strings.ToLower(strings.TrimSpace(cond.Type)), name: strings.TrimSpace(cond.Name)})
		}
		for _, ref := range d.ModelRefs {
			cd.aliases = append(cd.aliases, strings.TrimSpace(ref))
		}
		c.decisions = append(c.decisions, cd)
	}
	sort.SliceStable(c.decisions, func(a, b int) bool { return c.decisions[a].priority > c.decisions[b].priority })
	return c
}

// unconditionalDefault returns the first alias of the first decision with
// no conditions, the explicit fallback of a routing config.
func unconditionalDefault(cfg config.RoutingConfig) string {
	for _, d := range cfg.Decisions {
		if len(d.Conditions) == 0 && len(d.ModelRefs) > 0 {
			return strings.TrimSpace(d.ModelRefs[0])
		}
	}
	return ""
}

func (c *rulesClassifier) Name() string { return SourceRules }

func (c *rulesClassifier) Classify(_ context.Context, in ClassifyInput) (ClassifyResult, error) {
	for _, d := range c.decisions {
		if d.matches(in) {
			return ClassifyResult{Aliases: d.aliases, Confidence: 1, RuleID: d.name, Category: d.name}, nil
		}
	}
	return ClassifyResult{Confidence: -1}, nil
}

func (d compiledDecision) matches(in ClassifyInput) bool {
	for _, cond := range d.conditions {
		hit := cond.matches(in)
		if d.all && !hit {
			return false
		}
		if !d.all && hit {
			return true
		}
	}
	return d.all
}

func (c compiledCondition) matches(in ClassifyInput) bool {
	switch c.kind {
	case config.RoutingConditionKeyword:
		return in.Signals[c.name]
	case config.RoutingConditionConnector:
		return strings.EqualFold(in.Connector, c.name)
	case config.RoutingConditionAPIFamily:
		return in.APIFamily == c.name
	case config.RoutingConditionRequest:
		switch c.name {
		case "has_tools":
			return in.HasTools
		case "tool_turn":
			return in.ToolTurn
		case "has_images":
			return in.HasImages
		case "long_context":
			return in.LongContext
		}
	}
	return false
}
