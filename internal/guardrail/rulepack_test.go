// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package guardrail

import (
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func mustLoadRulePack(t *testing.T, dir string) *RulePack {
	t.Helper()
	pack, err := LoadRulePack(dir)
	if err != nil {
		t.Fatalf("LoadRulePack(%q): %v", dir, err)
	}
	if pack == nil {
		t.Fatalf("LoadRulePack(%q) returned nil without error", dir)
	}
	return pack
}

func writeRulePackFile(t *testing.T, root, rel, body string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func requireRulePackError(t *testing.T, err error, code string) *RulePackError {
	t.Helper()
	if err == nil {
		t.Fatal("expected an error")
	}
	var packErr *RulePackError
	if !errors.As(err, &packErr) {
		t.Fatalf("error type = %T, want *RulePackError: %v", err, err)
	}
	if code != "" && packErr.Code != code {
		t.Fatalf("error code = %q, want %q (%v)", packErr.Code, code, packErr)
	}
	if packErr.Path == "" || packErr.Reason == "" {
		t.Fatalf("unsafe/incomplete RulePackError: %#v", packErr)
	}
	return packErr
}

func TestLoadRulePackEmbeddedIsValidated(t *testing.T) {
	pack := mustLoadRulePack(t, "")
	if err := pack.Validate(); err != nil {
		t.Fatalf("embedded pack validation: %v", err)
	}
	if pack.Suppressions == nil || pack.SensitiveTools == nil {
		t.Fatal("embedded components are missing")
	}
	for _, name := range knownJudgeNames {
		if pack.JudgeConfigs[name] == nil {
			t.Fatalf("embedded judge %q is missing", name)
		}
	}
	if pack.ExfilJudge() == nil || pack.ExfilJudge().SingleCategoryMaxSev != "HIGH" {
		t.Fatal("embedded exfil fallback is missing or weakened")
	}
	if pack.RuleFiles != nil || pack.LocalPatterns != nil {
		t.Fatal("embedded pack should retain compiled gateway rule/local-pattern fallbacks")
	}

	summary := pack.Summary()
	if summary.JudgeCount != 4 || summary.JudgeCategoryCount == 0 ||
		summary.SuppressionCount == 0 || summary.SensitiveToolCount == 0 {
		t.Fatalf("unexpected embedded summary: %+v", summary)
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, summary.Digest); !matched {
		t.Fatalf("digest = %q, want 64 lowercase hex characters", summary.Digest)
	}
	if again := pack.Summary(); again != summary {
		t.Fatalf("summary is not deterministic:\nfirst=%+v\nagain=%+v", summary, again)
	}
}

func TestLoadRulePackShippedProfiles(t *testing.T) {
	repositoryRoot := filepath.Clean(filepath.Join("..", ".."))
	embedded := mustLoadRulePack(t, "")
	for _, profile := range []string{"default", "permissive", "strict"} {
		t.Run(profile, func(t *testing.T) {
			pack := mustLoadRulePack(t, filepath.Join(repositoryRoot, "policies", "guardrail", profile))
			if err := pack.Validate(); err != nil {
				t.Fatalf("shipped profile validation: %v", err)
			}
			if len(pack.RuleFiles) == 0 {
				t.Fatal("shipped profile did not load any rule files")
			}
			if pack.LocalPatterns == nil {
				t.Fatal("shipped local patterns were not loaded")
			}
			if pack.ExfilJudge() == nil {
				t.Fatal("missing shipped judge/exfil embedded fallback")
			}
			if pack.ExfilJudge().SystemPrompt != embedded.ExfilJudge().SystemPrompt {
				t.Fatal("missing exfil component did not inherit the embedded baseline")
			}
		})
	}
}

func TestLoadRulePackPartialOverlayInheritanceAndCustomCategory(t *testing.T) {
	dir := t.TempDir()
	writeRulePackFile(t, dir, "rules/custom.yaml", validRulesYAML("operator-custom", "CUSTOM-1"))

	embedded := mustLoadRulePack(t, "")
	pack := mustLoadRulePack(t, dir)
	if pack.Suppressions == nil || pack.Suppressions.Version != embedded.Suppressions.Version {
		t.Fatal("missing suppressions did not inherit embedded defaults")
	}
	if pack.SensitiveTools == nil || len(pack.SensitiveTools.Tools) != len(embedded.SensitiveTools.Tools) {
		t.Fatal("missing sensitive-tools did not inherit embedded defaults")
	}
	for _, name := range knownJudgeNames {
		if pack.JudgeConfigs[name] == nil {
			t.Fatalf("missing judge %q did not inherit embedded defaults", name)
		}
	}
	if len(pack.RuleFiles) != 1 || pack.RuleFiles[0].Category != "operator-custom" {
		t.Fatalf("custom category was not loaded: %+v", pack.RuleFiles)
	}
	if !filepath.IsAbs(pack.RuleFiles[0].SourcePath) {
		t.Fatalf("SourcePath = %q, want absolute path", pack.RuleFiles[0].SourcePath)
	}
}

func TestLoadRulePackPresentComponentReplacesDefault(t *testing.T) {
	dir := t.TempDir()
	writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips: []
finding_suppressions: []
tool_suppressions: []
`)
	pack := mustLoadRulePack(t, dir)
	if got := pack.Summary().SuppressionCount; got != 0 {
		t.Fatalf("suppression count = %d, want replacement component to be empty", got)
	}
	if pack.ExfilJudge() == nil || pack.SensitiveTools == nil {
		t.Fatal("unrelated missing components did not inherit defaults")
	}
}

func TestLoadRulePackDirectoryAndInventoryFailures(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "missing")
	_, err := LoadRulePack(missing)
	requireRulePackError(t, err, "directory_not_found")

	file := filepath.Join(t.TempDir(), "pack")
	if err := os.WriteFile(file, []byte("not a directory"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err = LoadRulePack(file)
	requireRulePackError(t, err, "not_directory")

	empty := t.TempDir()
	_, err = LoadRulePack(empty)
	requireRulePackError(t, err, "inventory_empty")

	nonYAML := t.TempDir()
	writeRulePackFile(t, nonYAML, "README.md", "not a component")
	_, err = LoadRulePack(nonYAML)
	requireRulePackError(t, err, "inventory_empty")

	for _, rel := range []string{
		"unknown.yaml",
		"suppressions.yml",
		"judge/custom.yaml",
		"rules/custom.yml",
		"rules/nested/custom.yaml",
		"rules/custom.YAML",
	} {
		t.Run(rel, func(t *testing.T) {
			dir := t.TempDir()
			writeRulePackFile(t, dir, rel, "version: 1\n")
			_, err := LoadRulePack(dir)
			requireRulePackError(t, err, "inventory_unexpected")
		})
	}
}

func TestReadRulePackFileRejectsSymlinkReplacement(t *testing.T) {
	dir := t.TempDir()
	const rel = "suppressions.yaml"
	writeRulePackFile(t, dir, rel, "version: 1\n")

	inventory, err := inspectRulePackDirectory(dir)
	if err != nil {
		t.Fatalf("inspectRulePackDirectory: %v", err)
	}
	file := inventory.files[rel]

	target := filepath.Join(t.TempDir(), "replacement.yaml")
	if err := os.WriteFile(target, []byte("version: 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(file.full); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, file.full); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err = readRulePackFile(file)
	requireRulePackError(t, err, "file_type")
}

func TestLoadRulePackAcceptsSymlinkedRootDirectory(t *testing.T) {
	target := t.TempDir()
	writeRulePackFile(t, target, "rules/custom.yaml", validRulesYAML("custom", "ROOT-SYMLINK"))
	linkParent := t.TempDir()
	link := filepath.Join(linkParent, "pack")
	if err := os.Symlink(target, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	pack := mustLoadRulePack(t, link)
	if len(pack.RuleFiles) != 1 || len(pack.RuleFiles[0].Rules) != 1 ||
		pack.RuleFiles[0].Rules[0].ID != "ROOT-SYMLINK" {
		t.Fatalf("symlinked root loaded unexpected rules: %#v", pack.RuleFiles)
	}
}

func TestLoadRulePackRejectsNestedSymlinkDirectory(t *testing.T) {
	target := t.TempDir()
	writeRulePackFile(t, target, "custom.yaml", validRulesYAML("custom", "NESTED-SYMLINK"))
	packDir := t.TempDir()
	if err := os.Symlink(target, filepath.Join(packDir, "rules")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	_, err := LoadRulePack(packDir)
	requireRulePackError(t, err, "file_type")
}

func TestSafeInventoryPathRejectsTraversal(t *testing.T) {
	for _, candidate := range []string{"..", "../secret.yaml", "rules/../../secret.yaml"} {
		if got := safeInventoryPath(candidate); got != "." {
			t.Errorf("safeInventoryPath(%q) = %q, want .", candidate, got)
		}
	}
	if got := safeInventoryPath("rules/command.yaml"); got != "rules/command.yaml" {
		t.Errorf("safeInventoryPath(valid) = %q", got)
	}
}

func TestLoadRulePackStrictYAML(t *testing.T) {
	tests := []struct {
		name string
		body string
		code string
	}{
		{name: "syntax", body: "{{not yaml", code: "yaml_invalid"},
		{name: "unknown field", body: "version: 1\nsecret_value: TOP-SECRET-VALUE\n", code: "yaml_invalid"},
		{name: "wrong type", body: "version: string\n", code: "yaml_invalid"},
		{name: "duplicate key", body: "version: 1\nversion: 1\n", code: "yaml_invalid"},
		{name: "two documents", body: "version: 1\n---\nversion: 1\n", code: "yaml_documents"},
		{name: "empty trailing document", body: "version: 1\n---\n", code: "yaml_documents"},
		{name: "trailing garbage", body: "version: 1\n...\ngarbage\n", code: "yaml_documents"},
		{name: "empty", body: "", code: "yaml_empty"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRulePackFile(t, dir, "suppressions.yaml", test.body)
			_, err := LoadRulePack(dir)
			packErr := requireRulePackError(t, err, test.code)
			serialized, marshalErr := json.Marshal(packErr)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			for _, forbidden := range []string{dir, "TOP-SECRET-VALUE", "{{not yaml"} {
				if strings.Contains(err.Error(), forbidden) || strings.Contains(string(serialized), forbidden) {
					t.Fatalf("safe error leaked source content/path: error=%v json=%s", err, serialized)
				}
			}
		})
	}
}

func TestLoadRulePackRuleValidation(t *testing.T) {
	tooLongPattern := strings.Repeat("a", maxRegexBytes+1)
	tests := []struct {
		name string
		body string
		code string
	}{
		{name: "version", body: strings.Replace(validRulesYAML("custom", "R-1"), "version: 1", "version: 2", 1), code: "version"},
		{name: "blank category", body: strings.Replace(validRulesYAML("custom", "R-1"), "category: custom", "category: '   '", 1), code: "validation"},
		{name: "blank id", body: strings.Replace(validRulesYAML("custom", "R-1"), "id: R-1", "id: ''", 1), code: "validation"},
		{name: "numeric id type", body: strings.Replace(validRulesYAML("custom", "R-1"), "id: R-1", "id: 123", 1), code: "yaml_invalid"},
		{name: "blank pattern", body: strings.Replace(validRulesYAML("custom", "R-1"), "pattern: 'a+'", "pattern: ''", 1), code: "validation"},
		{name: "invalid regex", body: strings.Replace(validRulesYAML("custom", "R-1"), "pattern: 'a+'", "pattern: '['", 1), code: "regex"},
		{name: "oversized regex", body: strings.Replace(validRulesYAML("custom", "R-1"), "pattern: 'a+'", "pattern: '"+tooLongPattern+"'", 1), code: "pattern_size_limit"},
		{name: "blank title", body: strings.Replace(validRulesYAML("custom", "R-1"), "title: valid", "title: ''", 1), code: "validation"},
		{name: "severity", body: strings.Replace(validRulesYAML("custom", "R-1"), "severity: HIGH", "severity: SEVERE", 1), code: "severity"},
		{name: "confidence low", body: strings.Replace(validRulesYAML("custom", "R-1"), "confidence: 0.5", "confidence: -0.1", 1), code: "confidence"},
		{name: "confidence high", body: strings.Replace(validRulesYAML("custom", "R-1"), "confidence: 0.5", "confidence: 1.1", 1), code: "confidence"},
		{name: "confidence nan", body: strings.Replace(validRulesYAML("custom", "R-1"), "confidence: 0.5", "confidence: .nan", 1), code: "confidence"},
		{name: "missing confidence", body: strings.Replace(validRulesYAML("custom", "R-1"), "    confidence: 0.5\n", "", 1), code: "validation"},
		{name: "empty tags", body: strings.Replace(validRulesYAML("custom", "R-1"), "tags: [test]", "tags: []", 1), code: "validation"},
		{name: "blank tag", body: strings.Replace(validRulesYAML("custom", "R-1"), "tags: [test]", "tags: ['']", 1), code: "validation"},
		{name: "numeric tag type", body: strings.Replace(validRulesYAML("custom", "R-1"), "tags: [test]", "tags: [123]", 1), code: "yaml_invalid"},
		{name: "all disabled", body: strings.Replace(validRulesYAML("custom", "R-1"), "    pattern:", "    enabled: false\n    pattern:", 1), code: "empty_category"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			writeRulePackFile(t, dir, "rules/custom.yaml", test.body)
			_, err := LoadRulePack(dir)
			requireRulePackError(t, err, test.code)
		})
	}
}

func TestLoadRulePackDuplicateRulesAndCategories(t *testing.T) {
	t.Run("duplicate rule id", func(t *testing.T) {
		dir := t.TempDir()
		body := validRulesYAML("custom", "R-1") + `  - id: R-1
    pattern: 'b+'
    title: second
    severity: MEDIUM
    confidence: 0.4
    tags: [test]
`
		writeRulePackFile(t, dir, "rules/a.yaml", body)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_rule_id")
	})
	t.Run("duplicate category", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/a.yaml", validRulesYAML("custom", "R-1"))
		writeRulePackFile(t, dir, "rules/b.yaml", validRulesYAML("custom", "R-2"))
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_category")
	})
	t.Run("duplicate id across categories", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/a.yaml", validRulesYAML("one", "R-1"))
		writeRulePackFile(t, dir, "rules/b.yaml", validRulesYAML("two", "R-1"))
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_rule_id")
	})
	t.Run("duplicate id ignores surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		body := validRulesYAML("custom", "R-1") + `  - id: ' R-1 '
    pattern: 'b+'
    title: second
    severity: MEDIUM
    confidence: 0.4
    tags: [test]
`
		writeRulePackFile(t, dir, "rules/a.yaml", body)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_rule_id")
	})
}

func TestLoadRulePackComponentValidation(t *testing.T) {
	t.Run("local patterns version only", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/local-patterns.yaml", "version: 1\n")
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("local patterns cannot clear every family", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/local-patterns.yaml", `version: 1
injection: []
injection_regexes: []
pii_requests: []
pii_data_regexes: []
secrets: []
exfiltration: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("local patterns can clear one family", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/local-patterns.yaml", "version: 1\nsecrets: []\n")
		pack := mustLoadRulePack(t, dir)
		if pack.LocalPatterns == nil || pack.LocalPatterns.Secrets == nil ||
			len(pack.LocalPatterns.Secrets) != 0 {
			t.Fatalf("explicit partial clear was not preserved: %#v", pack.LocalPatterns)
		}
		if pack.LocalPatterns.Injection != nil {
			t.Fatalf("omitted family should retain nil/inherit semantics: %#v", pack.LocalPatterns.Injection)
		}
	})
	t.Run("local pattern regex", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/local-patterns.yaml", "version: 1\ninjection_regexes: ['[']\n")
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "regex")
	})
	t.Run("local pattern blank", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "rules/local-patterns.yaml", "version: 1\nsecrets: ['  ']\n")
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("judge missing enabled", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "judge/injection.yaml", `version: 1
name: injection
system_prompt: prompt
categories:
  Test:
    finding_id: CUSTOM-JUDGE-1
    severity: HIGH
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("judge name mismatch", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "judge/injection.yaml", `version: 1
name: wrong
enabled: true
system_prompt: prompt
categories:
  Test:
    finding_id: CUSTOM-JUDGE-1
    severity: HIGH
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("judge severity", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "judge/injection.yaml", `version: 1
name: injection
enabled: true
system_prompt: prompt
categories:
  Test:
    finding_id: CUSTOM-JUDGE-1
    severity: INVALID
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "severity")
	})
	t.Run("judge duplicate finding id ignores surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "judge/injection.yaml", `version: 1
name: injection
enabled: true
system_prompt: prompt
categories:
  First:
    finding_id: CUSTOM-JUDGE-1
    severity: HIGH
  Second:
    finding_id: ' CUSTOM-JUDGE-1 '
    severity: HIGH
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_finding_id")
	})
	t.Run("suppression regex", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips:
  - id: CUSTOM
    pattern: '['
    context: test
    applies_to: []
finding_suppressions: []
tool_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "regex")
	})
	t.Run("suppression lists are required", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips: []
finding_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("pre-judge strip empty applies_to", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips:
  - id: CUSTOM
    pattern: 'a+'
    context: test
    applies_to: []
finding_suppressions: []
tool_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("pre-judge strip duplicate applies_to", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips:
  - id: CUSTOM
    pattern: 'a+'
    context: test
    applies_to: [pii, pii]
finding_suppressions: []
tool_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("pre-judge strip unsupported applies_to", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips:
  - id: CUSTOM
    pattern: 'a+'
    context: test
    applies_to: [unknown]
finding_suppressions: []
tool_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("tool suppression duplicate suppress_findings", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips: []
finding_suppressions: []
tool_suppressions:
  - tool_pattern: 'custom'
    suppress_findings: [CUSTOM-1, CUSTOM-1]
    reason: test
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("suppression ids ignore surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips:
  - id: CUSTOM
    pattern: 'a+'
    context: test
    applies_to: [pii]
finding_suppressions:
  - id: ' CUSTOM '
    finding_pattern: 'b+'
    entity_pattern: 'c+'
    reason: test
tool_suppressions: []
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_suppression_id")
	})
	t.Run("suppressed finding ids ignore surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "suppressions.yaml", `version: 1
pre_judge_strips: []
finding_suppressions: []
tool_suppressions:
  - tool_pattern: 'custom'
    suppress_findings: [CUSTOM-1, ' CUSTOM-1 ']
    reason: test
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("sensitive tool duplicate", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "sensitive-tools.yaml", `version: 1
tools:
  - name: custom
    result_inspection: true
    judge_result: false
  - name: custom
    result_inspection: false
    judge_result: true
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_tool")
	})
	t.Run("sensitive tool duplicate ignores surrounding whitespace", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "sensitive-tools.yaml", `version: 1
tools:
  - name: custom
    result_inspection: true
    judge_result: false
  - name: ' custom '
    result_inspection: true
    judge_result: false
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "duplicate_tool")
	})
	t.Run("sensitive tool missing boolean", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "sensitive-tools.yaml", `version: 1
tools:
  - name: custom
    result_inspection: true
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
	t.Run("judge result requires result inspection", func(t *testing.T) {
		dir := t.TempDir()
		writeRulePackFile(t, dir, "sensitive-tools.yaml", `version: 1
tools:
  - name: custom
    result_inspection: false
    judge_result: true
`)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "validation")
	})
}

func TestLoadRulePackLimits(t *testing.T) {
	t.Run("file size", func(t *testing.T) {
		dir := t.TempDir()
		body := "version: 1\n#" + strings.Repeat("x", maxRulePackFileBytes)
		writeRulePackFile(t, dir, "suppressions.yaml", body)
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "file_size_limit")
	})
	t.Run("file count", func(t *testing.T) {
		dir := t.TempDir()
		for index := 0; index < maxRulePackFiles+1; index++ {
			name := filepath.ToSlash(filepath.Join("rules", "rule-"+leftPad(index)+".yaml"))
			writeRulePackFile(t, dir, name, validRulesYAML("category-"+leftPad(index), "RULE-"+leftPad(index)))
		}
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "file_count_limit")
	})
	t.Run("aggregate size", func(t *testing.T) {
		dir := t.TempDir()
		padding := strings.Repeat("x", maxRulePackFileBytes-1024)
		for index := 0; index < 5; index++ {
			body := validRulesYAML("category-"+leftPad(index), "RULE-"+leftPad(index)) + "\n#" + padding
			writeRulePackFile(t, dir, filepath.ToSlash(filepath.Join("rules", "rule-"+leftPad(index)+".yaml")), body)
		}
		_, err := LoadRulePack(dir)
		requireRulePackError(t, err, "aggregate_size_limit")
	})
}

func TestRulePackSummaryIsSafeAndContentSensitive(t *testing.T) {
	dir := t.TempDir()
	const secretPattern = "DO-NOT-EXPOSE-THIS-PATTERN"
	body := strings.Replace(validRulesYAML("custom", "R-1"), "'a+'", "'"+secretPattern+"'", 1)
	writeRulePackFile(t, dir, "rules/custom.yaml", body)
	pack := mustLoadRulePack(t, dir)
	summary := pack.Summary()
	encoded, err := json.Marshal(summary)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secretPattern) || strings.Contains(string(encoded), dir) {
		t.Fatalf("summary leaked content/path: %s", encoded)
	}

	dir2 := t.TempDir()
	writeRulePackFile(t, dir2, "rules/custom.yaml", validRulesYAML("custom", "R-1"))
	pack2 := mustLoadRulePack(t, dir2)
	if pack2.Summary().Digest == summary.Digest {
		t.Fatal("digest did not change when rule semantics changed")
	}
}

func TestRulePackNilAndHelpers(t *testing.T) {
	var pack *RulePack
	requireRulePackError(t, pack.Validate(), "validation")
	if pack.PIIJudge() != nil || pack.InjectionJudge() != nil ||
		pack.ToolInjectionJudge() != nil || pack.ExfilJudge() != nil ||
		pack.LookupSensitiveTool("x") != nil {
		t.Fatal("nil rule pack helper returned a value")
	}
	if pack.String() != "RulePack{nil}" {
		t.Fatalf("nil String = %q", pack.String())
	}
	if matched, _ := regexp.MatchString(`^[0-9a-f]{64}$`, pack.Summary().Digest); !matched {
		t.Fatalf("nil digest = %q", pack.Summary().Digest)
	}
}

func TestRulePackValidateRejectsProgrammaticNonFiniteConfidence(t *testing.T) {
	pack := mustLoadRulePack(t, "")
	pack.RuleFiles = []*RulesFileYAML{{
		Version:  1,
		Category: "custom",
		Rules: []RuleDefYAML{{
			ID:         "CUSTOM-1",
			Pattern:    "a+",
			Title:      "valid",
			Severity:   "HIGH",
			Confidence: math.Inf(1),
			Tags:       []string{"test"},
		}},
	}}
	requireRulePackError(t, pack.Validate(), "confidence")
}

func TestEffectiveSeverity(t *testing.T) {
	category := JudgeCategory{
		Severity:           "LOW",
		SeverityDefault:    "MEDIUM",
		SeverityPrompt:     "HIGH",
		SeverityCompletion: "CRITICAL",
	}
	if got := category.EffectiveSeverity("prompt", "NONE"); got != "HIGH" {
		t.Fatalf("prompt severity = %q", got)
	}
	if got := category.EffectiveSeverity("completion", "NONE"); got != "CRITICAL" {
		t.Fatalf("completion severity = %q", got)
	}
	if got := category.EffectiveSeverity("other", "NONE"); got != "MEDIUM" {
		t.Fatalf("default severity = %q", got)
	}
}

func validRulesYAML(category, id string) string {
	return `version: 1
category: ` + category + `
rules:
  - id: ` + id + `
    pattern: 'a+'
    title: valid
    severity: HIGH
    confidence: 0.5
    tags: [test]
`
}

func leftPad(value int) string {
	return fmt.Sprintf("%04d", value)
}
