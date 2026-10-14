// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
)

// WarnRuleNotBlocking identifies a custom rule that can record a tool-call
// finding but has no semantic expression with which to block that call.
const WarnRuleNotBlocking = "rule_not_blocking"

// RuleNotBlockingWarnings names the enabled custom-pack rules whose pattern
// alone cannot block tool calls. The pack summary is the gateway's source of
// truth for how many operator rules are alert-only.
func RuleNotBlockingWarnings(cfg *config.Config) ([]Warning, int, error) {
	if cfg == nil {
		return nil, 0, nil
	}
	var names []string
	for name := range cfg.Guardrail.CustomPacks {
		names = append(names, name)
	}
	sort.Strings(names)
	var warnings []Warning
	count := 0
	for _, name := range names {
		pack, err := guardrail.LoadRulePack(cfg.Guardrail.CustomPacks[name].Path)
		if err != nil {
			return nil, 0, fmt.Errorf("custom pack %s: %w", name, err)
		}
		alertOnly := pack.Summary().AlertOnlyRuleCount
		count += alertOnly
		if alertOnly == 0 {
			continue
		}
		var ids []string
		for _, file := range pack.RuleFiles {
			if file == nil {
				continue
			}
			for _, rule := range file.Rules {
				if (rule.Enabled == nil || *rule.Enabled) && strings.TrimSpace(rule.Expression) == "" &&
					(&guardrail.RulePack{RuleFiles: []*guardrail.RulesFileYAML{{Category: file.Category, Rules: []guardrail.RuleDefYAML{rule}}}}).Summary().AlertOnlyRuleCount == 1 {
					ids = append(ids, rule.ID)
				}
			}
		}
		sort.Strings(ids)
		prefix := fmt.Sprintf("custom pack %s has %d detection-only rule(s) that cannot block tool calls: ", boundedText(name, 128), alertOnly)
		var group string
		for _, id := range ids {
			next := id
			if group != "" {
				next = group + ", " + id
			}
			if len(prefix)+len(next) > 512 && group != "" {
				warnings = append(warnings, Warning{Code: WarnRuleNotBlocking, Subject: boundedText(name, 128), Message: prefix + group})
				group = id
			} else {
				group = next
			}
		}
		if group != "" {
			warnings = append(warnings, Warning{Code: WarnRuleNotBlocking, Subject: boundedText(name, 128), Message: prefix + group})
		}
	}
	return warnings, count, nil
}

func limitBundleWarnings(warnings []Warning) []Warning {
	if len(warnings) <= MaxWarnings {
		return warnings
	}
	dropped := len(warnings) - (MaxWarnings - 1)
	return append(warnings[:MaxWarnings-1], Warning{Code: WarnTruncated,
		Message: fmt.Sprintf("%d more bundle warnings are not listed", dropped)})
}
