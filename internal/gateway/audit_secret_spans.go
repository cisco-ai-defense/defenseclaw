// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"sort"
	"strings"
)

// guardrailSecretSpans is the redaction engine's secret classifier
// (GAP-0426): the byte ranges of text that a rule of the secret category of
// any published rule pack (the process pack and every connector's) matches
// and accepts, exactly as the hook's scan does. The audit store and every
// destination used their own detector list only, so a value the hook flagged
// HIGH as a secret (SERVICE_API_TOKEN=<40 hex>, rule SEC-HEX-SECRET) was
// stored in clear in llm_prompt, llm_response and tool_invocation rows. With
// this classifier the projection replaces every such span, whatever the
// value's shape. Redaction is not detection, so it runs in managed mode too.
func guardrailSecretSpans(text string) [][2]int {
	if len(text) < 8 {
		return nil
	}
	var spans [][2]int
	seen := make(map[string]struct{})
	for _, generation := range auditSecretRuleGenerations() {
		for categoryIndex := range generation.categories {
			category := &generation.categories[categoryIndex]
			if category.Name != "secret" {
				continue
			}
			for ruleIndex := range category.Rules {
				rule := &category.Rules[ruleIndex]
				// A tool-call-only rule judges what a call does, not a value
				// in text; the hook never runs it on prompts or results.
				if rule.Pattern == nil || rule.ToolCallOnly || strings.EqualFold(rule.Severity, "INFO") {
					continue
				}
				// The same rule in several packs runs once.
				identity := rule.ID + "\x00" + rule.Pattern.String()
				if _, done := seen[identity]; done {
					continue
				}
				seen[identity] = struct{}{}
				for _, loc := range rule.Pattern.FindAllStringIndex(text, maxEntityMatchesPerRule) {
					if loc[1] <= loc[0] || !acceptedRuleMatchAt(rule.ID, text, text[loc[0]:loc[1]], loc[0], loc[1]) {
						continue
					}
					spans = append(spans, [2]int{auditSecretValueStart(text, loc[0], loc[1]), loc[1]})
				}
			}
		}
	}
	return mergeAuditSecretSpans(spans)
}

// mergeAuditSecretSpans sorts spans and merges the overlapping ones, so one
// value matched by several rules costs one match of the field's budget.
func mergeAuditSecretSpans(spans [][2]int) [][2]int {
	if len(spans) < 2 {
		return spans
	}
	sort.Slice(spans, func(i, j int) bool {
		if spans[i][0] != spans[j][0] {
			return spans[i][0] < spans[j][0]
		}
		return spans[i][1] > spans[j][1]
	})
	merged := spans[:1]
	for _, span := range spans[1:] {
		last := &merged[len(merged)-1]
		if span[0] < last[1] {
			if span[1] > last[1] {
				last[1] = span[1]
			}
			continue
		}
		merged = append(merged, span)
	}
	return merged
}

// auditSecretRuleGenerations is the process rule generation and every
// connector's, each once.
func auditSecretRuleGenerations() []*compiledRulePackCategories {
	generations := []*compiledRulePackCategories{snapshotRulePackGeneration("")}
	ruleCategoriesMu.RLock()
	connectors := make([]string, 0, len(connectorRuleGenerations))
	for connector := range connectorRuleGenerations {
		connectors = append(connectors, connector)
	}
	ruleCategoriesMu.RUnlock()
	for _, connector := range connectors {
		generation := snapshotRulePackGeneration(connector)
		duplicate := generation == nil
		for _, seen := range generations {
			duplicate = duplicate || seen == generation
		}
		if !duplicate {
			generations = append(generations, generation)
		}
	}
	return generations
}

// auditSecretValueStart keeps a rule match's label readable: the key of an
// assignment (SERVICE_API_TOKEN=) or an Authorization or Bearer prefix stays,
// and the replacement covers the value. The label is the text before the
// match's first '=' or ':' only when it is a short key that names a
// credential; any other match (a JWT, a connection string, a provider token)
// and any value shorter than 8 bytes is replaced whole.
func auditSecretValueStart(text string, start, end int) int {
	match := text[start:end]
	value := 0
	if cut := strings.IndexAny(match, "=:"); cut > 0 && auditSecretLabel(match[:cut]) {
		value = cut + 1
	}
	for value < len(match) && strings.ContainsRune(" \t\"'", rune(match[value])) {
		value++
	}
	for _, scheme := range []string{"bearer", "basic", "token"} {
		if len(match)-value > len(scheme) && strings.EqualFold(match[value:value+len(scheme)], scheme) &&
			(match[value+len(scheme)] == ' ' || match[value+len(scheme)] == '\t') {
			value += len(scheme)
			for value < len(match) && (match[value] == ' ' || match[value] == '\t') {
				value++
			}
			break
		}
	}
	if len(match)-value < 8 {
		return start
	}
	return start + value
}

// auditSecretLabel reports whether label (the text before a separator) is a
// key that names a credential: at most 64 identifier bytes, optionally quoted,
// with a credential word in it.
func auditSecretLabel(label string) bool {
	label = strings.TrimRight(label, " \t")
	label = strings.Trim(label, "\"'")
	if label == "" || len(label) > 64 || strings.HasPrefix(label, "eyJ") {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (c < '0' || c > '9') && c != '_' && c != '-' && c != '.' {
			return false
		}
	}
	lower := strings.ToLower(label)
	for _, word := range []string{"token", "secret", "key", "pass", "pwd", "auth", "bearer", "credential"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	return false
}
