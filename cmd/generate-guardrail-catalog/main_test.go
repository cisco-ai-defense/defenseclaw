// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRuleRequiresToolCallBoundaryForExpression(t *testing.T) {
	rule := validGeneratorRule()
	rule.Expression = "true"
	if err := validateRule("commands.yaml", &rule); err == nil ||
		!strings.Contains(err.Error(), "expression requires tool_call_only") {
		t.Fatalf("validateRule() error = %v", err)
	}

	rule.ToolCallOnly = true
	if err := validateRule("commands.yaml", &rule); err != nil {
		t.Fatalf("validate tool-call semantic rule: %v", err)
	}
	rule.Expression = ""
	if err := validateRule("commands.yaml", &rule); err != nil {
		t.Fatalf("validate tool-call regex fallback: %v", err)
	}
	rule.expressionSet = true
	for _, expression := range []string{"", "   ", " true", "true "} {
		rule.Expression = expression
		if err := validateRule("commands.yaml", &rule); err == nil {
			t.Fatalf("validateRule(expression=%q) unexpectedly succeeded", expression)
		}
	}
}

func TestDecodeRulesFileTracksAndTypesExpression(t *testing.T) {
	path := filepath.Join(t.TempDir(), "commands.yaml")
	base := `version: 1
category: command
rules:
  - id: SEMANTIC
    pattern: a+
    title: valid
    severity: HIGH
    confidence: 0.9
    tags: [test]
`
	if err := os.WriteFile(path, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	file, err := decodeRulesFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if file.Rules[0].expressionSet {
		t.Fatal("absent expression marked present")
	}

	for _, scalar := range []string{"''", "true", "123"} {
		body := strings.Replace(base, "    title:", "    expression: "+scalar+"\n    title:", 1)
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		file, err = decodeRulesFile(path)
		if scalar == "''" {
			if err != nil {
				t.Fatal(err)
			}
			if !file.Rules[0].expressionSet {
				t.Fatal("explicit empty expression not marked present")
			}
			continue
		}
		if err == nil || !strings.Contains(err.Error(), "expression must be a string") {
			t.Fatalf("decodeRulesFile(expression=%s) error = %v", scalar, err)
		}
	}
}

func TestRenderCatalogIncludesOnlyPresentSemanticMetadata(t *testing.T) {
	semantic := validGeneratorRule()
	semantic.Expression = "f.parse.status == 1"
	semantic.ToolCallOnly = true
	plain := validGeneratorRule()
	plain.ID = "PLAIN"

	rendered, err := renderCatalog([]rulesFile{{
		Version:  1,
		Category: "command",
		Rules:    []ruleDef{semantic, plain},
	}})
	if err != nil {
		t.Fatal(err)
	}
	source := string(rendered)
	if !strings.Contains(source, `Expression: "f.parse.status == 1", ToolCallOnly: true`) {
		t.Fatalf("generated metadata missing:\n%s", source)
	}
	plainLine := ""
	for _, line := range strings.Split(source, "\n") {
		if strings.Contains(line, `ID: "PLAIN"`) {
			plainLine = line
			break
		}
	}
	if plainLine == "" {
		t.Fatal("plain rule missing from generated source")
	}
	if strings.Contains(plainLine, "Expression:") || strings.Contains(plainLine, "ToolCallOnly:") {
		t.Fatalf("plain rule gained semantic metadata: %s", plainLine)
	}
}

func TestValidateSemanticCatalogCompilesDisabledExpressions(t *testing.T) {
	disabled := false
	rule := validGeneratorRule()
	rule.Enabled = &disabled
	rule.Expression = "f.missing"
	rule.ToolCallOnly = true
	err := validateSemanticCatalog([]rulesFile{{
		Version:  1,
		Category: "command",
		Rules:    []ruleDef{rule},
	}})
	if err == nil || !strings.Contains(err.Error(), "invalid semantic expression (type)") {
		t.Fatalf("validateSemanticCatalog() error = %v", err)
	}
}

func validGeneratorRule() ruleDef {
	return ruleDef{
		ID:         "SEMANTIC",
		Pattern:    "a+",
		Title:      "valid",
		Severity:   "HIGH",
		Confidence: 0.9,
		Tags:       []string{"test"},
	}
}
