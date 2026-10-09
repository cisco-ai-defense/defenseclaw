// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

// A v8 copy may tune built-in action rules. Rebase carries those fields while
// still taking new semantic expressions for rules the operator left untouched.
func TestRebasePreservesBuiltInRuleEdits(t *testing.T) {
	old, err := os.ReadFile(filepath.Join("legacy08", "commands.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var custom yaml.Node
	if err := yaml.Unmarshal(old, &custom); err != nil {
		t.Fatal(err)
	}
	var edited *yaml.Node
	for _, rule := range yamlRulesSequence(&custom).Content {
		if yamlScalarField(rule, "id") == "CMD-RM-RF" {
			edited = rule
			break
		}
	}
	if edited == nil {
		t.Fatal("0.8.x rule missing")
	}
	setYAMLScalarField(edited, "severity", "LOW", "!!str")
	setYAMLScalarField(edited, "title", "Operator marker rule", "!!str")
	setYAMLScalarField(edited, "pattern", "operator-marker", "!!str")
	setYAMLScalarField(edited, "expression", "f.commands.exists(c, c.program == 'marker')", "!!str")
	var source bytes.Buffer
	if err := yaml.NewEncoder(&source).Encode(&custom); err != nil {
		t.Fatal(err)
	}
	index, err := shippedRuleIndex()
	if err != nil {
		t.Fatal(err)
	}
	rebased, err := rebaseRuleFile(index.defaultFiles["command"], source.Bytes(), "command", &RulePackRebase{})
	if err != nil {
		t.Fatal(err)
	}
	var result RulesFileYAML
	if err := yaml.Unmarshal(rebased, &result); err != nil {
		t.Fatal(err)
	}
	for _, rule := range result.Rules {
		if rule.ID == "CMD-RM-RF" {
			if rule.Severity != "LOW" || rule.Title != "Operator marker rule" ||
				rule.Pattern != "operator-marker" || rule.Expression != "f.commands.exists(c, c.program == 'marker')" {
				t.Fatalf("operator edits lost: %+v", rule)
			}
		}
	}
}

func TestRebaseEditedPatternDoesNotInheritSemanticExpression(t *testing.T) {
	old, err := os.ReadFile(filepath.Join("legacy08", "commands.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var custom yaml.Node
	if err := yaml.Unmarshal(old, &custom); err != nil {
		t.Fatal(err)
	}
	for _, rule := range yamlRulesSequence(&custom).Content {
		if yamlScalarField(rule, "id") == "CMD-RM-RF" {
			setYAMLScalarField(rule, "pattern", "operator-marker", "!!str")
			break
		}
	}
	var source bytes.Buffer
	if err := yaml.NewEncoder(&source).Encode(&custom); err != nil {
		t.Fatal(err)
	}
	index, err := shippedRuleIndex()
	if err != nil {
		t.Fatal(err)
	}
	rebased, err := rebaseRuleFile(index.defaultFiles["command"], source.Bytes(), "command", &RulePackRebase{})
	if err != nil {
		t.Fatal(err)
	}
	var result RulesFileYAML
	if err := yaml.Unmarshal(rebased, &result); err != nil {
		t.Fatal(err)
	}
	for _, rule := range result.Rules {
		if rule.ID == "CMD-RM-RF" {
			if rule.Pattern != "operator-marker" || rule.Expression != "" {
				t.Fatalf("edited pattern inherited unrelated expression: %+v", rule)
			}
			return
		}
	}
	t.Fatal("rebased rule missing")
}
