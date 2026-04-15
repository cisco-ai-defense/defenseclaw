// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"
)

//go:embed rulepack_defaults
var embeddedDefaults embed.FS

// ---------------------------------------------------------------------------
// YAML schema types — these map 1:1 to the rule pack YAML files
// ---------------------------------------------------------------------------

// RuleFileYAML is the on-disk schema for a pattern rule file (rules/*.yaml).
type RuleFileYAML struct {
	Version  int            `yaml:"version"`
	Category string         `yaml:"category"`
	Rules    []RuleEntryYAML `yaml:"rules"`
}

// RuleEntryYAML is a single pattern rule entry in a YAML file.
type RuleEntryYAML struct {
	ID         string   `yaml:"id"`
	Pattern    string   `yaml:"pattern"`
	Title      string   `yaml:"title"`
	Severity   string   `yaml:"severity"`
	Confidence float64  `yaml:"confidence"`
	Tags       []string `yaml:"tags"`
	Enabled    *bool    `yaml:"enabled,omitempty"`
}

// JudgeConfigYAML is the on-disk schema for a judge config file (judge/*.yaml).
type JudgeConfigYAML struct {
	Version      int                       `yaml:"version"`
	Name         string                    `yaml:"name"`
	Enabled      *bool                     `yaml:"enabled,omitempty"`
	SystemPrompt string                    `yaml:"system_prompt"`
	Categories   map[string]JudgeCategoryYAML `yaml:"categories"`

	MinCategoriesForHigh    int    `yaml:"min_categories_for_high,omitempty"`
	SingleCategoryMaxSev    string `yaml:"single_category_max_severity,omitempty"`
}

// JudgeCategoryYAML defines one judge detection category.
type JudgeCategoryYAML struct {
	FindingID          string `yaml:"finding_id"`
	SeverityDefault    string `yaml:"severity_default,omitempty"`
	SeverityPrompt     string `yaml:"severity_prompt,omitempty"`
	SeverityCompletion string `yaml:"severity_completion,omitempty"`
	Severity           string `yaml:"severity,omitempty"`
	Enabled            *bool  `yaml:"enabled,omitempty"`
}

// SuppressionFileYAML is the on-disk schema for suppressions.yaml.
type SuppressionFileYAML struct {
	Version              int                    `yaml:"version"`
	PreJudgeStrips       []PreJudgeStripYAML    `yaml:"pre_judge_strips"`
	FindingSuppressions  []FindingSuppressionYAML `yaml:"finding_suppressions"`
	ToolSuppressions     []ToolSuppressionYAML  `yaml:"tool_suppressions"`
}

// PreJudgeStripYAML defines a pattern to strip from content before judging.
type PreJudgeStripYAML struct {
	ID        string   `yaml:"id"`
	Pattern   string   `yaml:"pattern"`
	Context   string   `yaml:"context"`
	AppliesTo []string `yaml:"applies_to"`
}

// FindingSuppressionYAML suppresses a finding if the entity matches.
type FindingSuppressionYAML struct {
	ID             string `yaml:"id"`
	FindingPattern string `yaml:"finding_pattern"`
	EntityPattern  string `yaml:"entity_pattern"`
	Condition      string `yaml:"condition,omitempty"`
	Reason         string `yaml:"reason"`
}

// ToolSuppressionYAML suppresses findings for specific tools.
type ToolSuppressionYAML struct {
	ToolPattern      string   `yaml:"tool_pattern"`
	SuppressFindings []string `yaml:"suppress_findings"`
	Reason           string   `yaml:"reason"`
}

// SensitiveToolsFileYAML is the on-disk schema for sensitive-tools.yaml.
type SensitiveToolsFileYAML struct {
	Version int                  `yaml:"version"`
	Tools   []SensitiveToolYAML  `yaml:"tools"`
}

// SensitiveToolYAML defines a tool whose results need elevated scrutiny.
type SensitiveToolYAML struct {
	Name              string `yaml:"name"`
	ResultInspection  bool   `yaml:"result_inspection"`
	JudgeResult       bool   `yaml:"judge_result"`
	MinEntitiesAlert  int    `yaml:"min_entities_for_alert,omitempty"`
}

// LocalPatternsFileYAML is the on-disk schema for local-patterns.yaml.
type LocalPatternsFileYAML struct {
	Version          int      `yaml:"version"`
	Injection        []string `yaml:"injection"`
	InjectionRegexes []string `yaml:"injection_regexes"`
	PIIRequests      []string `yaml:"pii_requests"`
	PIIDataRegexes   []string `yaml:"pii_data_regexes"`
	Secrets          []string `yaml:"secrets"`
	Exfiltration     []string `yaml:"exfiltration"`
}

// ---------------------------------------------------------------------------
// Compiled rule pack — the runtime representation
// ---------------------------------------------------------------------------

// RulePack holds the fully loaded and compiled rule pack for the guardrail
// runtime. It is safe for concurrent read access. Write access (Reload) is
// serialized via the mutex.
type RulePack struct {
	mu sync.RWMutex

	dir string // on-disk path; empty = use embedded defaults

	PatternRules   []PatternRule
	RuleCategories []RuleCategory

	LocalPatterns *CompiledLocalPatterns

	JudgeConfigs map[string]*CompiledJudgeConfig

	Suppressions *CompiledSuppressions

	SensitiveTools map[string]*SensitiveToolYAML

	loadErrors []string
}

// RuleCategory groups pattern rules under a named category.
type RuleCategory struct {
	Name  string
	Rules []PatternRule
}

// CompiledLocalPatterns holds the compiled local pattern arrays.
type CompiledLocalPatterns struct {
	Injection        []string
	InjectionRegexes []*regexp.Regexp
	PIIRequests      []string
	PIIDataRegexes   []*regexp.Regexp
	Secrets          []string
	Exfiltration     []string
}

// CompiledJudgeConfig is the runtime version of a judge config.
type CompiledJudgeConfig struct {
	Name                 string
	Enabled              bool
	SystemPrompt         string
	Categories           map[string]*CompiledJudgeCategory
	MinCategoriesForHigh int
	SingleCategoryMaxSev string
}

// CompiledJudgeCategory is a single judge category with resolved severities.
type CompiledJudgeCategory struct {
	FindingID          string
	SeverityDefault    string
	SeverityPrompt     string
	SeverityCompletion string
	Enabled            bool
}

// CompiledSuppressions holds compiled suppression rules.
type CompiledSuppressions struct {
	PreJudgeStrips      []CompiledPreJudgeStrip
	FindingSuppressions []CompiledFindingSuppression
	ToolSuppressions    []CompiledToolSuppression
}

// CompiledPreJudgeStrip is a compiled pre-judge strip rule.
type CompiledPreJudgeStrip struct {
	ID        string
	Pattern   *regexp.Regexp
	AppliesTo []string
}

// CompiledFindingSuppression is a compiled finding suppression rule.
type CompiledFindingSuppression struct {
	ID             string
	FindingPattern string
	EntityPattern  *regexp.Regexp
	Condition      string
	Reason         string
}

// CompiledToolSuppression is a compiled tool suppression rule.
type CompiledToolSuppression struct {
	ToolPattern      *regexp.Regexp
	SuppressFindings []string
	Reason           string
}

// ---------------------------------------------------------------------------
// Loading
// ---------------------------------------------------------------------------

// LoadRulePack loads a rule pack from the given directory. If the directory
// is empty or does not exist, embedded defaults are used. Validation errors
// are collected (not fatal) and individual components fall back to defaults.
func LoadRulePack(dir string) *RulePack {
	rp := &RulePack{dir: dir}
	rp.load()
	return rp
}

// Reload re-reads all rule pack files from disk. Thread-safe.
func (rp *RulePack) Reload() error {
	rp.mu.Lock()
	defer rp.mu.Unlock()
	rp.load()
	if len(rp.loadErrors) > 0 {
		return fmt.Errorf("rulepack: %d validation errors during reload", len(rp.loadErrors))
	}
	return nil
}

// LoadErrors returns any validation errors from the last load.
func (rp *RulePack) LoadErrors() []string {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return append([]string{}, rp.loadErrors...)
}

// GetPatternRules returns all compiled pattern rules.
func (rp *RulePack) GetPatternRules() []PatternRule {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.PatternRules
}

// GetRuleCategories returns rule categories for ScanAllRules.
func (rp *RulePack) GetRuleCategories() []RuleCategory {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.RuleCategories
}

// GetLocalPatterns returns the compiled local patterns.
func (rp *RulePack) GetLocalPatterns() *CompiledLocalPatterns {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.LocalPatterns
}

// GetJudgeConfig returns a judge config by name.
func (rp *RulePack) GetJudgeConfig(name string) *CompiledJudgeConfig {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.JudgeConfigs[name]
}

// GetSuppressions returns compiled suppressions.
func (rp *RulePack) GetSuppressions() *CompiledSuppressions {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.Suppressions
}

// GetSensitiveTool returns the config for a sensitive tool, or nil.
func (rp *RulePack) GetSensitiveTool(name string) *SensitiveToolYAML {
	rp.mu.RLock()
	defer rp.mu.RUnlock()
	return rp.SensitiveTools[name]
}

func (rp *RulePack) load() {
	rp.loadErrors = nil
	rp.PatternRules = nil
	rp.RuleCategories = nil
	rp.LocalPatterns = nil
	rp.JudgeConfigs = make(map[string]*CompiledJudgeConfig)
	rp.Suppressions = &CompiledSuppressions{}
	rp.SensitiveTools = make(map[string]*SensitiveToolYAML)

	rp.loadPatternRules()
	rp.loadLocalPatterns()
	rp.loadJudgeConfigs()
	rp.loadSuppressions()
	rp.loadSensitiveTools()
}

// readFile reads from the on-disk directory first, falling back to embedded.
func (rp *RulePack) readFile(relPath string) ([]byte, error) {
	if rp.dir != "" {
		fullPath := filepath.Join(rp.dir, relPath)
		data, err := os.ReadFile(fullPath)
		if err == nil {
			return data, nil
		}
		if !os.IsNotExist(err) {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("read %s: %v", relPath, err))
		}
	}
	return fs.ReadFile(embeddedDefaults, filepath.Join("rulepack_defaults", relPath))
}

// listDir lists files in a subdirectory, preferring on-disk then embedded.
func (rp *RulePack) listDir(relDir string) ([]string, error) {
	var files []string

	if rp.dir != "" {
		fullDir := filepath.Join(rp.dir, relDir)
		entries, err := os.ReadDir(fullDir)
		if err == nil {
			for _, e := range entries {
				if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
					files = append(files, e.Name())
				}
			}
			if len(files) > 0 {
				return files, nil
			}
		}
	}

	entries, err := fs.ReadDir(embeddedDefaults, filepath.Join("rulepack_defaults", relDir))
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if !e.IsDir() && strings.HasSuffix(e.Name(), ".yaml") {
			files = append(files, e.Name())
		}
	}
	return files, nil
}

func (rp *RulePack) loadPatternRules() {
	files, err := rp.listDir("rules")
	if err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("list rules/: %v", err))
		return
	}

	categoryMap := make(map[string][]PatternRule)

	for _, name := range files {
		if name == "local-patterns.yaml" {
			continue
		}
		data, err := rp.readFile(filepath.Join("rules", name))
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("read rules/%s: %v", name, err))
			continue
		}

		var rf RuleFileYAML
		if err := yaml.Unmarshal(data, &rf); err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("parse rules/%s: %v", name, err))
			continue
		}

		for _, entry := range rf.Rules {
			if entry.Enabled != nil && !*entry.Enabled {
				continue
			}
			compiled, err := regexp.Compile(entry.Pattern)
			if err != nil {
				rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("rule %s: invalid regex: %v", entry.ID, err))
				continue
			}
			pr := PatternRule{
				ID:         entry.ID,
				Pattern:    compiled,
				Title:      entry.Title,
				Severity:   entry.Severity,
				Confidence: entry.Confidence,
				Tags:       entry.Tags,
			}
			rp.PatternRules = append(rp.PatternRules, pr)

			cat := rf.Category
			if cat == "" {
				cat = strings.TrimSuffix(name, ".yaml")
			}
			categoryMap[cat] = append(categoryMap[cat], pr)
		}
	}

	for cat, rules := range categoryMap {
		rp.RuleCategories = append(rp.RuleCategories, RuleCategory{Name: cat, Rules: rules})
	}
}

func (rp *RulePack) loadLocalPatterns() {
	data, err := rp.readFile(filepath.Join("rules", "local-patterns.yaml"))
	if err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("read rules/local-patterns.yaml: %v", err))
		return
	}

	var lp LocalPatternsFileYAML
	if err := yaml.Unmarshal(data, &lp); err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("parse rules/local-patterns.yaml: %v", err))
		return
	}

	compiled := &CompiledLocalPatterns{
		Injection:    lp.Injection,
		PIIRequests:  lp.PIIRequests,
		Secrets:      lp.Secrets,
		Exfiltration: lp.Exfiltration,
	}

	for _, p := range lp.InjectionRegexes {
		re, err := regexp.Compile(p)
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("local-patterns injection_regex %q: %v", p, err))
			continue
		}
		compiled.InjectionRegexes = append(compiled.InjectionRegexes, re)
	}

	for _, p := range lp.PIIDataRegexes {
		re, err := regexp.Compile(p)
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("local-patterns pii_data_regex %q: %v", p, err))
			continue
		}
		compiled.PIIDataRegexes = append(compiled.PIIDataRegexes, re)
	}

	rp.LocalPatterns = compiled
}

func (rp *RulePack) loadJudgeConfigs() {
	files, err := rp.listDir("judge")
	if err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("list judge/: %v", err))
		return
	}

	for _, name := range files {
		data, err := rp.readFile(filepath.Join("judge", name))
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("read judge/%s: %v", name, err))
			continue
		}

		var jc JudgeConfigYAML
		if err := yaml.Unmarshal(data, &jc); err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("parse judge/%s: %v", name, err))
			continue
		}

		enabled := true
		if jc.Enabled != nil {
			enabled = *jc.Enabled
		}

		compiled := &CompiledJudgeConfig{
			Name:                 jc.Name,
			Enabled:              enabled,
			SystemPrompt:         jc.SystemPrompt,
			Categories:           make(map[string]*CompiledJudgeCategory),
			MinCategoriesForHigh: jc.MinCategoriesForHigh,
			SingleCategoryMaxSev: jc.SingleCategoryMaxSev,
		}

		for catName, cat := range jc.Categories {
			catEnabled := true
			if cat.Enabled != nil {
				catEnabled = *cat.Enabled
			}

			sevDefault := cat.SeverityDefault
			if sevDefault == "" {
				sevDefault = cat.Severity
			}

			compiled.Categories[catName] = &CompiledJudgeCategory{
				FindingID:          cat.FindingID,
				SeverityDefault:    sevDefault,
				SeverityPrompt:     cat.SeverityPrompt,
				SeverityCompletion: cat.SeverityCompletion,
				Enabled:            catEnabled,
			}
		}

		rp.JudgeConfigs[jc.Name] = compiled
	}
}

func (rp *RulePack) loadSuppressions() {
	data, err := rp.readFile("suppressions.yaml")
	if err != nil {
		return
	}

	var sf SuppressionFileYAML
	if err := yaml.Unmarshal(data, &sf); err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("parse suppressions.yaml: %v", err))
		return
	}

	compiled := &CompiledSuppressions{}

	for _, strip := range sf.PreJudgeStrips {
		re, err := regexp.Compile(strip.Pattern)
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("suppression %s: invalid regex: %v", strip.ID, err))
			continue
		}
		compiled.PreJudgeStrips = append(compiled.PreJudgeStrips, CompiledPreJudgeStrip{
			ID:        strip.ID,
			Pattern:   re,
			AppliesTo: strip.AppliesTo,
		})
	}

	for _, fs := range sf.FindingSuppressions {
		re, err := regexp.Compile(fs.EntityPattern)
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("suppression %s: invalid regex: %v", fs.ID, err))
			continue
		}
		compiled.FindingSuppressions = append(compiled.FindingSuppressions, CompiledFindingSuppression{
			ID:             fs.ID,
			FindingPattern: fs.FindingPattern,
			EntityPattern:  re,
			Condition:      fs.Condition,
			Reason:         fs.Reason,
		})
	}

	for _, ts := range sf.ToolSuppressions {
		re, err := regexp.Compile(ts.ToolPattern)
		if err != nil {
			rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("tool suppression %q: invalid regex: %v", ts.ToolPattern, err))
			continue
		}
		compiled.ToolSuppressions = append(compiled.ToolSuppressions, CompiledToolSuppression{
			ToolPattern:      re,
			SuppressFindings: ts.SuppressFindings,
			Reason:           ts.Reason,
		})
	}

	rp.Suppressions = compiled
}

func (rp *RulePack) loadSensitiveTools() {
	data, err := rp.readFile("sensitive-tools.yaml")
	if err != nil {
		return
	}

	var sf SensitiveToolsFileYAML
	if err := yaml.Unmarshal(data, &sf); err != nil {
		rp.loadErrors = append(rp.loadErrors, fmt.Sprintf("parse sensitive-tools.yaml: %v", err))
		return
	}

	for i := range sf.Tools {
		t := &sf.Tools[i]
		rp.SensitiveTools[t.Name] = t
	}
}
