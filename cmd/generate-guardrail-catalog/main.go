// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Command generate-guardrail-catalog compiles the shipped default rule-pack
// YAML into the immutable Go fallback used by the gateway.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"go/format"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

const generatedOutput = "internal/gateway/rules_catalog_generated.go"

var catalogSources = []struct {
	filename string
	category string
}{
	{filename: "secrets.yaml", category: "secret"},
	{filename: "commands.yaml", category: "command"},
	{filename: "sensitive-paths.yaml", category: "sensitive-path"},
	{filename: "c2.yaml", category: "c2"},
	{filename: "cognitive.yaml", category: "cognitive-file"},
	{filename: "trust-exploit.yaml", category: "trust-exploit"},
	{filename: "enterprise-data.yaml", category: "enterprise-data"},
}

type rulesFile struct {
	Version  int       `yaml:"version"`
	Category string    `yaml:"category"`
	Rules    []ruleDef `yaml:"rules"`
}

type ruleDef struct {
	ID         string   `yaml:"id"`
	Enabled    *bool    `yaml:"enabled,omitempty"`
	Pattern    string   `yaml:"pattern"`
	Title      string   `yaml:"title"`
	Severity   string   `yaml:"severity"`
	Confidence float64  `yaml:"confidence"`
	Tags       []string `yaml:"tags"`
}

func main() {
	check := flag.Bool("check", false, "fail if the generated Go catalog is stale")
	root := flag.String("root", ".", "repository root")
	flag.Parse()

	if err := run(*root, *check); err != nil {
		fmt.Fprintf(os.Stderr, "guardrail catalog generation failed: %v\n", err)
		os.Exit(1)
	}
}

func run(root string, check bool) error {
	root, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve repository root: %w", err)
	}
	if _, err := os.Stat(filepath.Join(root, "go.mod")); err != nil {
		return fmt.Errorf("repository root %q: %w", root, err)
	}

	catalog, err := loadCatalog(root)
	if err != nil {
		return err
	}
	rendered, err := renderCatalog(catalog)
	if err != nil {
		return err
	}

	output := filepath.Join(root, generatedOutput)
	if check {
		current, err := os.ReadFile(output)
		if err != nil {
			return fmt.Errorf("read generated catalog: %w", err)
		}
		if !bytes.Equal(current, rendered) {
			return fmt.Errorf("%s is stale; run make generate-guardrail-catalog", generatedOutput)
		}
		return nil
	}

	if err := os.WriteFile(output, rendered, 0o644); err != nil {
		return fmt.Errorf("write generated catalog: %w", err)
	}
	return nil
}

func loadCatalog(root string) ([]rulesFile, error) {
	rulesDir := filepath.Join(root, "policies", "guardrail", "default", "rules")
	if err := checkInventory(rulesDir); err != nil {
		return nil, err
	}

	seenIDs := make(map[string]string)
	catalog := make([]rulesFile, 0, len(catalogSources))
	for _, source := range catalogSources {
		path := filepath.Join(rulesDir, source.filename)
		file, err := decodeRulesFile(path)
		if err != nil {
			return nil, err
		}
		if file.Version != 1 {
			return nil, fmt.Errorf("%s: version is %d, want 1", source.filename, file.Version)
		}
		if file.Category != source.category {
			return nil, fmt.Errorf("%s: category is %q, want %q", source.filename, file.Category, source.category)
		}
		if len(file.Rules) == 0 {
			return nil, fmt.Errorf("%s: rules must not be empty", source.filename)
		}

		enabled := 0
		for index := range file.Rules {
			rule := &file.Rules[index]
			if err := validateRule(source.filename, rule); err != nil {
				return nil, err
			}
			if previous, ok := seenIDs[rule.ID]; ok {
				return nil, fmt.Errorf("%s: duplicate rule id %q (already in %s)", source.filename, rule.ID, previous)
			}
			seenIDs[rule.ID] = source.filename
			if rule.Enabled == nil || *rule.Enabled {
				enabled++
			}
		}
		if enabled == 0 {
			return nil, fmt.Errorf("%s: category has no enabled rules", source.filename)
		}
		catalog = append(catalog, file)
	}
	return catalog, nil
}

func checkInventory(rulesDir string) error {
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return fmt.Errorf("read default rules directory: %w", err)
	}
	expected := map[string]bool{"local-patterns.yaml": true}
	for _, source := range catalogSources {
		expected[source.filename] = true
	}
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		if !expected[entry.Name()] {
			return fmt.Errorf("default rules inventory contains unowned file %s", entry.Name())
		}
		delete(expected, entry.Name())
	}
	for filename := range expected {
		return fmt.Errorf("default rules inventory is missing %s", filename)
	}
	return nil
}

func decodeRulesFile(path string) (rulesFile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return rulesFile{}, fmt.Errorf("read %s: %w", filepath.Base(path), err)
	}
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)

	var file rulesFile
	if err := decoder.Decode(&file); err != nil {
		return rulesFile{}, fmt.Errorf("parse %s: %w", filepath.Base(path), err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err != nil {
			return rulesFile{}, fmt.Errorf("parse trailing document in %s: %w", filepath.Base(path), err)
		}
		return rulesFile{}, fmt.Errorf("%s: multiple YAML documents are not allowed", filepath.Base(path))
	}
	return file, nil
}

func validateRule(filename string, rule *ruleDef) error {
	if strings.TrimSpace(rule.ID) == "" {
		return fmt.Errorf("%s: rule id must not be empty", filename)
	}
	if strings.TrimSpace(rule.Pattern) == "" {
		return fmt.Errorf("%s: rule %s pattern must not be empty", filename, rule.ID)
	}
	if _, err := regexp.Compile(rule.Pattern); err != nil {
		return fmt.Errorf("%s: rule %s pattern: %w", filename, rule.ID, err)
	}
	if strings.TrimSpace(rule.Title) == "" {
		return fmt.Errorf("%s: rule %s title must not be empty", filename, rule.ID)
	}
	switch rule.Severity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
	default:
		return fmt.Errorf("%s: rule %s has invalid severity %q", filename, rule.ID, rule.Severity)
	}
	if math.IsNaN(rule.Confidence) || math.IsInf(rule.Confidence, 0) ||
		rule.Confidence < 0 || rule.Confidence > 1 {
		return fmt.Errorf("%s: rule %s confidence must be finite and between 0 and 1", filename, rule.ID)
	}
	if len(rule.Tags) == 0 {
		return fmt.Errorf("%s: rule %s tags must not be empty", filename, rule.ID)
	}
	for _, tag := range rule.Tags {
		if strings.TrimSpace(tag) == "" {
			return fmt.Errorf("%s: rule %s contains an empty tag", filename, rule.ID)
		}
	}
	return nil
}

func renderCatalog(catalog []rulesFile) ([]byte, error) {
	var out strings.Builder
	out.WriteString(`// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

// Code generated by cmd/generate-guardrail-catalog; DO NOT EDIT.

package gateway

import "regexp"

// defaultRuleCategories is generated from the enabled rules in
// policies/guardrail/default/rules/*.yaml. The YAML catalog is authoritative.
var defaultRuleCategories = []ruleCategory{
`)
	for _, file := range catalog {
		fmt.Fprintf(&out, "\t{\n\t\tName: %s,\n\t\tRules: []PatternRule{\n", strconv.Quote(file.Category))
		for _, rule := range file.Rules {
			if rule.Enabled != nil && !*rule.Enabled {
				continue
			}
			fmt.Fprintf(
				&out,
				"\t\t\t{ID: %s, Pattern: regexp.MustCompile(%s), Title: %s, Severity: %s, Confidence: %s, Tags: []string{%s}},\n",
				strconv.Quote(rule.ID),
				strconv.Quote(rule.Pattern),
				strconv.Quote(rule.Title),
				strconv.Quote(rule.Severity),
				strconv.FormatFloat(rule.Confidence, 'f', -1, 64),
				quoteStrings(rule.Tags),
			)
		}
		out.WriteString("\t\t},\n\t},\n")
	}
	out.WriteString("}\n")

	formatted, err := format.Source([]byte(out.String()))
	if err != nil {
		return nil, fmt.Errorf("format generated Go catalog: %w", err)
	}
	return formatted, nil
}

func quoteStrings(values []string) string {
	quoted := make([]string, len(values))
	for index, value := range values {
		quoted[index] = strconv.Quote(value)
	}
	return strings.Join(quoted, ", ")
}
