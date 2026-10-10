// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	policyassets "github.com/defenseclaw/defenseclaw/policies"
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

// An edited 0.8.x pattern does not inherit the 1.0 expression, yet it blocked
// on its own: a literal gets the expression it implies and any other pattern
// is named alert-only, so the rule neither stops blocking nor goes unnamed
// (GAP-1314).
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
		switch yamlScalarField(rule, "id") {
		case "CMD-RM-RF":
			setYAMLScalarField(rule, "pattern", "operator-marker", "!!str")
		case "CMD-SUDO":
			setYAMLScalarField(rule, "pattern", "operator-marker-[0-9]+", "!!str")
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
	plan := &RulePackRebase{}
	rebased, err := rebaseRuleFile(index.defaultFiles["command"], source.Bytes(), "command", plan)
	if err != nil {
		t.Fatal(err)
	}
	var result RulesFileYAML
	if err := yaml.Unmarshal(rebased, &result); err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"CMD-RM-RF": "f.commands.exists(c, 'operator-marker' in c.argv)",
		"CMD-SUDO":  "",
	}
	for _, rule := range result.Rules {
		if expression, ok := want[rule.ID]; ok {
			if rule.Expression != expression {
				t.Fatalf("%s expression %q, want %q", rule.ID, rule.Expression, expression)
			}
			delete(want, rule.ID)
		}
	}
	if len(want) != 0 {
		t.Fatalf("rebased rules missing: %v", want)
	}
	if !slices.Equal(plan.Expressed, []string{"CMD-RM-RF"}) || !slices.Equal(plan.AlertOnly, []string{"CMD-SUDO"}) {
		t.Fatalf("expressed %v alert-only %v", plan.Expressed, plan.AlertOnly)
	}
}

// GAP-1228: the 0.8.9 macOS upgrade shape. A full copy of the 0.8.9 default
// pack (its action files are legacy08 byte for byte) plus the operator's own
// file: one plain-regex CRITICAL rule in its own category, no expression. On
// 0.8.9 it blocked a Claude Code tool call; the rebase must give it an
// expression, and must not take any shipped rule of the copy for one of the
// operator's.
func TestRebaseOfAZeroEightNineDefaultCopyKeepsTheOperatorRuleBlocking(t *testing.T) {
	dir := t.TempDir()
	write := func(rel string, data []byte) {
		t.Helper()
		target := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(target, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	files, err := policyassets.Files()
	if err != nil {
		t.Fatal(err)
	}
	for _, file := range files {
		if rel, ok := strings.CutPrefix(file.Path, "guardrail/default/"); ok {
			write(rel, file.Data)
		}
	}
	for _, name := range legacy08FileNames {
		data, err := legacy08RuleFiles.ReadFile("legacy08/" + name)
		if err != nil {
			t.Fatal(err)
		}
		write("rules/"+name, data)
	}
	write("rules/upg89-marker.yaml", []byte("version: 1\ncategory: upg89-marker\nrules:\n"+
		"  - id: UPG89-MARKER-BLOCK\n    pattern: \"upg89-block-marker\"\n    title: \"Marker\"\n"+
		"    severity: CRITICAL\n    confidence: 0.99\n    tags: [marker]\n"))

	before, err := LoadRulePack(dir)
	if err != nil {
		t.Fatal(err)
	}
	if summary := before.Summary(); summary.AlertOnlyRuleCount != 1 {
		t.Fatalf("the 0.8.9 copy: %d alert-only rules, want the operator rule counted", summary.AlertOnlyRuleCount)
	}
	plan, err := PlanRulePackRebase(dir)
	if err != nil || plan == nil {
		t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
	}
	if !slices.Equal(plan.Expressed, []string{"UPG89-MARKER-BLOCK"}) || len(plan.AlertOnly) != 0 || len(plan.Carried) != 0 {
		t.Fatalf("expressed %v alert-only %v carried %v; want only the operator rule expressed",
			plan.Expressed, plan.AlertOnly, plan.Carried)
	}
	var marker RulesFileYAML
	if err := yaml.Unmarshal(plan.Files["rules/upg89-marker.yaml"], &marker); err != nil || len(marker.Rules) != 1 ||
		marker.Rules[0].Expression != "f.commands.exists(c, 'upg89-block-marker' in c.argv)" {
		t.Fatalf("rebased marker rule %+v, %v", marker.Rules, err)
	}
}
