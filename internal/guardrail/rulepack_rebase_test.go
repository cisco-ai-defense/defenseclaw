// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"bytes"
	"fmt"
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

// GAP-1339: 0.8.x took a pack with two rule files of one category (its gateway
// enforced only the last of them); 1.0 refuses it, so the upgrade stopped.
// The rebase merges them into the first file of the category, keeping every
// rule, and a merge it can not do safely names the edit instead.
func TestRebaseMergesRuleFilesThatShareACategory(t *testing.T) {
	rule := func(id, pattern, severity string) string {
		return fmt.Sprintf("  - id: %s\n    pattern: %q\n    title: \"Marker\"\n    severity: %s\n    confidence: 0.9\n    tags: [marker]\n",
			id, pattern, severity)
	}
	file := func(category string, rules ...string) string {
		return "version: 1\ncategory: " + category + "\nrules:\n" + strings.Join(rules, "")
	}
	many := make([]string, maxRulesPerFile)
	for i := range many {
		many[i] = rule(fmt.Sprintf("ACME-%d", i), fmt.Sprintf("acme-%d", i), "LOW")
	}
	a, b, c := rule("ACME-A", "acme-a", "HIGH"), rule("ACME-B", "acme-b[0-9]", "LOW"), rule("ACME-C", "acme-c", "MEDIUM")
	cases := []struct {
		name        string
		defaultCopy bool
		files       map[string]string
		want        map[string]string // rule ID -> severity in the 1.0 copy ("" any)
		gone        []string
		merged      string
		err         string
	}{
		{name: "two files of a category of yours",
			files: map[string]string{"rules/a.yaml": file("acme", a), "rules/b.yaml": file("acme", b)},
			want:  map[string]string{"ACME-A": "HIGH", "ACME-B": "LOW"}, gone: []string{"rules/b.yaml"},
			merged: `rules/b.yaml (category "acme") merged into rules/a.yaml; 1 rule(s) kept`},
		{name: "default pack copy plus a file of its command category", defaultCopy: true,
			files:  map[string]string{"rules/upg89b-marker.yaml": file("command", rule("UPG89B-MARKER", "upg89b-block-marker", "CRITICAL"))},
			want:   map[string]string{"UPG89B-MARKER": "CRITICAL", "CMD-RM-RF": ""},
			gone:   []string{"rules/upg89b-marker.yaml"},
			merged: `rules/upg89b-marker.yaml (category "command") merged into rules/commands.yaml; 1 rule(s) kept`},
		{name: "three files",
			files: map[string]string{"rules/a.yaml": file("acme", a), "rules/b.yaml": file("acme", b), "rules/c.yaml": file("acme", c)},
			want:  map[string]string{"ACME-A": "HIGH", "ACME-B": "LOW", "ACME-C": "MEDIUM"},
			gone:  []string{"rules/b.yaml", "rules/c.yaml"}},
		{name: "case and spacing",
			files: map[string]string{"rules/a.yaml": file("Acme", a), "rules/b.yaml": file(`" acme "`, b)},
			want:  map[string]string{"ACME-A": "HIGH", "ACME-B": "LOW"}, gone: []string{"rules/b.yaml"}},
		{name: "rule ID collision",
			files: map[string]string{"rules/a.yaml": file("acme", a), "rules/b.yaml": file("acme", a, rule("ACME-A", "acme-z", "MEDIUM"))},
			want:  map[string]string{"ACME-A": "HIGH", "ACME-A-b": "MEDIUM"}, gone: []string{"rules/b.yaml"},
			merged: `rules/b.yaml (category "acme") merged into rules/a.yaml; 1 rule(s) kept, 1 identical one(s) were ` +
				`already there (renamed, as rules/a.yaml has the ID: ACME-A is now ACME-A-b)`},
		{name: "distinct categories are not merged",
			files: map[string]string{"rules/a.yaml": file("acme", a), "rules/b.yaml": file("acme-other", b)},
			want:  map[string]string{"ACME-A": "HIGH", "ACME-B": "LOW"}},
		{name: "too many rules for one file",
			files: map[string]string{"rules/a.yaml": file("acme", many...), "rules/b.yaml": file("acme", b)},
			err:   "Categories must be unique in 1.0: move the rules of rules/b.yaml into rules/a.yaml and delete rules/b.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			files := map[string][]byte{}
			if tc.defaultCopy {
				shipped, err := policyassets.Files()
				if err != nil {
					t.Fatal(err)
				}
				for _, f := range shipped {
					if rel, ok := strings.CutPrefix(f.Path, "guardrail/default/"); ok {
						files[rel] = f.Data
					}
				}
				for _, name := range legacy08FileNames {
					if files["rules/"+name], err = legacy08RuleFiles.ReadFile("legacy08/" + name); err != nil {
						t.Fatal(err)
					}
				}
			}
			for rel, data := range tc.files {
				files[rel] = []byte(data)
			}
			for rel, data := range files {
				target := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			plan, err := PlanRulePackRebase(dir)
			if tc.err != "" {
				if err == nil || !strings.Contains(err.Error(), tc.err) {
					t.Fatalf("PlanRulePackRebase = %v, want an error naming the edit %q", err, tc.err)
				}
				return
			}
			if err != nil || plan == nil || plan.Files == nil {
				t.Fatalf("PlanRulePackRebase = %+v, %v", plan, err)
			}
			if tc.merged == "" && len(tc.gone) == 0 && len(plan.Merged) > 0 {
				t.Errorf("merged %q, want no merge", plan.Merged)
			}
			if tc.merged != "" && !slices.Contains(plan.Merged, tc.merged) {
				t.Errorf("merged %q, want %q", plan.Merged, tc.merged)
			}
			copyDir := t.TempDir()
			for rel, data := range plan.Files {
				target := filepath.Join(copyDir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(target, data, 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for _, rel := range tc.gone {
				if _, ok := plan.Files[rel]; ok {
					t.Errorf("%s is still in the 1.0 copy", rel)
				}
			}
			pack, err := LoadRulePack(copyDir)
			if err != nil {
				t.Fatalf("the 1.0 copy does not load: %v", err)
			}
			if got := pack.FilesDigest(); got != plan.Digest {
				t.Errorf("digest %s, plan pins %s", got, plan.Digest)
			}
			got := map[string]RuleDefYAML{}
			for _, ruleFile := range pack.RuleFiles {
				for _, r := range ruleFile.Rules {
					got[r.ID] = r
				}
			}
			for id, severity := range tc.want {
				r, ok := got[id]
				if !ok || (severity != "" && r.Severity != severity) || (r.Enabled != nil && !*r.Enabled) {
					t.Errorf("rule %s in the 1.0 copy: %+v (present %v), want enabled with severity %q", id, r, ok, severity)
				}
			}
			if marker, ok := got["UPG89B-MARKER"]; ok && marker.Expression == "" {
				t.Errorf("the marker rule has no expression, so it no longer blocks a tool call: %+v", marker)
			}
		})
	}
}
