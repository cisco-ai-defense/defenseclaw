// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package benchmark

import (
	"fmt"
	"path/filepath"
	"sort"

	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
)

type Inventory struct {
	SchemaVersion string                   `json:"schema_version"`
	Profiles      []ProfileInventory       `json:"profiles"`
	CodeGuard     []CodeGuardRuleInventory `json:"codeguard"`
}

type ProfileInventory struct {
	Profile           string          `json:"profile"`
	Digest            string          `json:"digest"`
	RuleCount         int             `json:"rule_count"`
	EnabledRuleCount  int             `json:"enabled_rule_count"`
	SemanticRuleCount int             `json:"semantic_rule_count"`
	Rules             []RuleInventory `json:"rules"`
}

type RuleInventory struct {
	ID           string   `json:"id"`
	Category     string   `json:"category"`
	Enabled      bool     `json:"enabled"`
	Semantic     bool     `json:"semantic"`
	ToolCallOnly bool     `json:"tool_call_only"`
	Severity     string   `json:"severity"`
	Tags         []string `json:"tags,omitempty"`
}

type CodeGuardRuleInventory struct {
	ID         string   `json:"id"`
	Severity   string   `json:"severity"`
	Extensions []string `json:"extensions,omitempty"`
}

func BuildInventory(repoRoot string) (Inventory, error) {
	return BuildInventoryWithPolicyRoot(repoRoot, "")
}

// BuildInventoryWithPolicyRoot inventories a candidate policy tree without
// requiring it to replace the repository's shipped policies. Relative roots
// are resolved from repoRoot.
func BuildInventoryWithPolicyRoot(repoRoot, policyRoot string) (Inventory, error) {
	if policyRoot == "" {
		policyRoot = filepath.Join(repoRoot, "policies", "guardrail")
	} else if !filepath.IsAbs(policyRoot) {
		policyRoot = filepath.Join(repoRoot, policyRoot)
	}
	inventory := Inventory{SchemaVersion: SchemaVersion}
	for _, profile := range []string{"default", "permissive", "strict"} {
		pack, err := guardrail.LoadRulePack(filepath.Join(policyRoot, profile))
		if err != nil {
			return Inventory{}, fmt.Errorf("load %s rule pack: %w", profile, err)
		}
		profileInventory := ProfileInventory{Profile: profile, Digest: pack.Summary().Digest}
		for _, ruleFile := range pack.RuleFiles {
			for _, definition := range ruleFile.Rules {
				enabled := definition.Enabled == nil || *definition.Enabled
				entry := RuleInventory{
					ID:           definition.ID,
					Category:     ruleFile.Category,
					Enabled:      enabled,
					Semantic:     definition.Expression != "",
					ToolCallOnly: definition.ToolCallOnly,
					Severity:     definition.Severity,
					Tags:         append([]string(nil), definition.Tags...),
				}
				profileInventory.Rules = append(profileInventory.Rules, entry)
				profileInventory.RuleCount++
				if enabled {
					profileInventory.EnabledRuleCount++
					if entry.Semantic {
						profileInventory.SemanticRuleCount++
					}
				}
			}
		}
		sort.Slice(profileInventory.Rules, func(i, j int) bool {
			return profileInventory.Rules[i].ID < profileInventory.Rules[j].ID
		})
		inventory.Profiles = append(inventory.Profiles, profileInventory)
	}
	for _, rule := range scanner.BuiltinRulesMeta() {
		inventory.CodeGuard = append(inventory.CodeGuard, CodeGuardRuleInventory{
			ID:         rule.ID,
			Severity:   string(rule.Severity),
			Extensions: append([]string(nil), rule.Extensions...),
		})
	}
	sort.Slice(inventory.CodeGuard, func(i, j int) bool { return inventory.CodeGuard[i].ID < inventory.CodeGuard[j].ID })
	return inventory, nil
}
