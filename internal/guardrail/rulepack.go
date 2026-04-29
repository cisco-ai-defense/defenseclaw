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

package guardrail

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed defaults
var defaultsFS embed.FS

// ---------------------------------------------------------------------------
// YAML schema types
// ---------------------------------------------------------------------------

// RulePack is the top-level container loaded from a rule-pack directory.
type RulePack struct {
	Suppressions   *SuppressionsConfig
	JudgeConfigs   map[string]*JudgeYAML
	SensitiveTools *SensitiveToolsConfig
	RuleFiles      []*RulesFileYAML
	// Taint holds STATE-bound configuration for the session-level taint
	// tracker. Policy decision knobs (escalation steps, mode, confidence
	// thresholds) live in OPA Rego data, NOT here. May be nil if no
	// taint.yaml is present and no embedded default applies.
	Taint *TaintStateConfig
}

// SuppressionsConfig maps to suppressions.yaml.
type SuppressionsConfig struct {
	Version          int                  `yaml:"version"`
	PreJudgeStrips   []PreJudgeStrip      `yaml:"pre_judge_strips"`
	FindingSupps     []FindingSuppression `yaml:"finding_suppressions"`
	ToolSuppressions []ToolSuppression    `yaml:"tool_suppressions"`
}

type PreJudgeStrip struct {
	ID        string   `yaml:"id"`
	Pattern   string   `yaml:"pattern"`
	Context   string   `yaml:"context"`
	AppliesTo []string `yaml:"applies_to"`
}

type FindingSuppression struct {
	ID             string `yaml:"id"`
	FindingPattern string `yaml:"finding_pattern"`
	EntityPattern  string `yaml:"entity_pattern"`
	Condition      string `yaml:"condition,omitempty"`
	Reason         string `yaml:"reason"`
}

type ToolSuppression struct {
	ToolPattern      string   `yaml:"tool_pattern"`
	SuppressFindings []string `yaml:"suppress_findings"`
	Reason           string   `yaml:"reason"`
}

// JudgeYAML maps to judge/*.yaml files.
type JudgeYAML struct {
	Version              int                      `yaml:"version"`
	Name                 string                   `yaml:"name"`
	Enabled              bool                     `yaml:"enabled"`
	SystemPrompt         string                   `yaml:"system_prompt"`
	AdjudicationPrompt   string                   `yaml:"adjudication_prompt,omitempty"`
	Categories           map[string]JudgeCategory `yaml:"categories"`
	MinCategoriesForHigh int                      `yaml:"min_categories_for_high,omitempty"`
	SingleCategoryMaxSev string                   `yaml:"single_category_max_severity,omitempty"`
}

type JudgeCategory struct {
	FindingID          string `yaml:"finding_id"`
	Severity           string `yaml:"severity,omitempty"`
	SeverityDefault    string `yaml:"severity_default,omitempty"`
	SeverityPrompt     string `yaml:"severity_prompt,omitempty"`
	SeverityCompletion string `yaml:"severity_completion,omitempty"`
	Enabled            bool   `yaml:"enabled,omitempty"`
}

// RulesFileYAML maps to a rules/*.yaml file (e.g. rules/commands.yaml).
type RulesFileYAML struct {
	Version  int           `yaml:"version"`
	Category string        `yaml:"category"`
	Rules    []RuleDefYAML `yaml:"rules"`

	// SourcePath is the absolute path the file was read from. The
	// ``yaml:"-"`` tag keeps it out of serialized output so round-
	// tripping (e.g., TUI viewer → Marshal → display) doesn't leak
	// the operator's filesystem layout into a rule-pack YAML. The
	// TUI's rule-pack editor uses this to launch ``$EDITOR`` on
	// the exact file that backs the highlighted rule.
	SourcePath string `yaml:"-"`
}

// RuleDefYAML is a single detection rule definition in YAML.
type RuleDefYAML struct {
	ID         string   `yaml:"id"`
	Pattern    string   `yaml:"pattern"`
	Title      string   `yaml:"title"`
	Severity   string   `yaml:"severity"`
	Confidence float64  `yaml:"confidence"`
	Tags       []string `yaml:"tags"`
}

// SensitiveToolsConfig maps to sensitive-tools.yaml.
type SensitiveToolsConfig struct {
	Version int             `yaml:"version"`
	Tools   []SensitiveTool `yaml:"tools"`
}

type SensitiveTool struct {
	Name             string `yaml:"name"`
	ResultInspection bool   `yaml:"result_inspection"`
	JudgeResult      bool   `yaml:"judge_result"`
	MinEntitiesAlert int    `yaml:"min_entities_for_alert,omitempty"`
}

// TaintStateConfig maps to taint.yaml. It is intentionally state-bound:
// only knobs needed by the in-memory tracker live here. Anything the
// Rego policy uses to make decisions (escalation step counts, mode,
// confidence thresholds) lives in OPA data and is loaded separately.
type TaintStateConfig struct {
	Version               int      `yaml:"version"`
	FlagDecayEvents       int      `yaml:"flag_decay_events"`
	FileTaintDecayEvents  int      `yaml:"file_taint_decay_events"`
	SensitiveFiles        []string `yaml:"sensitive_files"`
	NetworkExclusions     []string `yaml:"network_exclusions"`
	SessionIdleTTLSeconds int      `yaml:"session_idle_ttl_seconds"`
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

// LoadRulePack loads a rule pack from the given directory. Missing files are
// filled from compiled-in defaults. Corrupt YAML files log a warning and
// fall back to the embedded default for that file.
func LoadRulePack(dir string) *RulePack {
	rp := &RulePack{
		JudgeConfigs: make(map[string]*JudgeYAML),
	}

	rp.Suppressions = loadYAML[SuppressionsConfig](dir, "suppressions.yaml")
	rp.SensitiveTools = loadYAML[SensitiveToolsConfig](dir, "sensitive-tools.yaml")
	rp.Taint = loadYAML[TaintStateConfig](dir, "taint.yaml")

	for _, name := range []string{"pii", "injection", "tool-injection"} {
		jc := loadYAML[JudgeYAML](dir, filepath.Join("judge", name+".yaml"))
		if jc != nil {
			rp.JudgeConfigs[name] = jc
		}
	}

	rp.RuleFiles = loadRuleFiles(dir)

	return rp
}

// loadRuleFiles reads all rules/*.yaml files from the rule-pack directory.
// Returns nil if none are found — callers should fall back to hardcoded rules.
func loadRuleFiles(dir string) []*RulesFileYAML {
	if dir == "" {
		return nil
	}
	rulesDir := filepath.Join(dir, "rules")
	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil
	}
	var files []*RulesFileYAML
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".yaml" {
			continue
		}
		full := filepath.Join(rulesDir, e.Name())
		data, err := os.ReadFile(full)
		if err != nil {
			log.Printf("guardrail: read rules/%s: %v", e.Name(), err)
			continue
		}
		var rf RulesFileYAML
		if err := yaml.Unmarshal(data, &rf); err != nil {
			log.Printf("guardrail: parse rules/%s: %v", e.Name(), err)
			continue
		}
		if rf.Version != 1 {
			log.Printf("guardrail: rules/%s version %d unsupported, skipping", e.Name(), rf.Version)
			continue
		}
		// Record where the file came from so downstream surfaces
		// (notably the TUI's rule-pack editor) can round-trip edits
		// to the exact file without guessing a path from category.
		rf.SourcePath = full
		files = append(files, &rf)
	}
	return files
}

// loadYAML tries disk first, then embedded default.
func loadYAML[T any](dir, relPath string) *T {
	if dir != "" {
		full := filepath.Join(dir, relPath)
		if data, err := os.ReadFile(full); err == nil {
			var out T
			if err := yaml.Unmarshal(data, &out); err != nil {
				log.Printf("guardrail: corrupt %s, using default: %v", full, err)
			} else {
				return &out
			}
		}
	}

	embeddedPath := filepath.Join("defaults", relPath)
	data, err := fs.ReadFile(defaultsFS, embeddedPath)
	if err != nil {
		return nil
	}
	var out T
	if err := yaml.Unmarshal(data, &out); err != nil {
		log.Printf("guardrail: corrupt embedded %s: %v", embeddedPath, err)
		return nil
	}
	return &out
}

// LookupSensitiveTool returns the config for a tool name, or nil.
func (rp *RulePack) LookupSensitiveTool(name string) *SensitiveTool {
	if rp == nil || rp.SensitiveTools == nil {
		return nil
	}
	for i := range rp.SensitiveTools.Tools {
		if rp.SensitiveTools.Tools[i].Name == name {
			return &rp.SensitiveTools.Tools[i]
		}
	}
	return nil
}

// PIIJudge returns the PII judge config, or nil.
func (rp *RulePack) PIIJudge() *JudgeYAML {
	if rp == nil {
		return nil
	}
	return rp.JudgeConfigs["pii"]
}

// InjectionJudge returns the injection judge config, or nil.
func (rp *RulePack) InjectionJudge() *JudgeYAML {
	if rp == nil {
		return nil
	}
	return rp.JudgeConfigs["injection"]
}

// ToolInjectionJudge returns the tool-injection judge config, or nil.
func (rp *RulePack) ToolInjectionJudge() *JudgeYAML {
	if rp == nil {
		return nil
	}
	return rp.JudgeConfigs["tool-injection"]
}

// EffectiveSeverity returns the severity for a PII category based on
// direction (prompt vs completion). Falls back to SeverityDefault, then
// Severity, then the provided fallback.
func (c *JudgeCategory) EffectiveSeverity(direction, fallback string) string {
	switch direction {
	case "prompt":
		if c.SeverityPrompt != "" {
			return c.SeverityPrompt
		}
	case "completion":
		if c.SeverityCompletion != "" {
			return c.SeverityCompletion
		}
	}
	if c.SeverityDefault != "" {
		return c.SeverityDefault
	}
	if c.Severity != "" {
		return c.Severity
	}
	return fallback
}

// Validate checks basic integrity of the rule pack. Logs warnings but
// does not return errors — the rule pack degrades gracefully.
//
// As a side effect, every regex pattern referenced by the rule pack is
// compiled here (via compileRegex, which memoizes). This surfaces bad
// patterns at load time as a warning — previously an invalid pattern
// would silently be skipped on every request with no operator signal.
func (rp *RulePack) Validate() {
	if rp == nil {
		return
	}
	if rp.Suppressions != nil && rp.Suppressions.Version != 1 {
		log.Printf("guardrail: suppressions.yaml version %d unsupported, expected 1", rp.Suppressions.Version)
	}
	for name, jc := range rp.JudgeConfigs {
		if jc.Version != 1 {
			log.Printf("guardrail: judge/%s.yaml version %d unsupported, expected 1", name, jc.Version)
		}
		if jc.SystemPrompt == "" {
			log.Printf("guardrail: judge/%s.yaml has empty system_prompt", name)
		}
	}

	if rp.Suppressions != nil {
		for _, s := range rp.Suppressions.PreJudgeStrips {
			checkPattern("pre_judge_strip", s.ID, s.Pattern)
		}
		for _, s := range rp.Suppressions.FindingSupps {
			checkPattern("finding_suppression:finding_pattern", s.ID, s.FindingPattern)
			checkPattern("finding_suppression:entity_pattern", s.ID, s.EntityPattern)
		}
		for _, s := range rp.Suppressions.ToolSuppressions {
			checkPattern("tool_suppression:tool_pattern", s.ToolPattern, s.ToolPattern)
		}
	}

	for _, rf := range rp.RuleFiles {
		for _, r := range rf.Rules {
			checkPattern("rule:"+rf.Category, r.ID, r.Pattern)
		}
	}

	if rp.Taint != nil {
		if rp.Taint.Version != 1 {
			log.Printf("guardrail: taint.yaml version %d unsupported, expected 1", rp.Taint.Version)
		}
		if rp.Taint.FlagDecayEvents < 0 {
			log.Printf("guardrail: taint.yaml flag_decay_events must be non-negative; got %d", rp.Taint.FlagDecayEvents)
		}
		if rp.Taint.FileTaintDecayEvents < 0 {
			log.Printf("guardrail: taint.yaml file_taint_decay_events must be non-negative; got %d", rp.Taint.FileTaintDecayEvents)
		}
	}
}

// checkPattern compiles pattern and logs a warning if it is invalid.
// Uses regexp.Compile directly (not compileRegex) so validation surfaces
// the exact error message. compileRegex will itself cache the negative
// result the first time it's queried for an invalid pattern in a hot path.
func checkPattern(kind, id, pattern string) {
	if pattern == "" {
		return
	}
	if _, err := regexp.Compile(pattern); err != nil {
		log.Printf("guardrail: %s %q has invalid regex %q: %v", kind, id, pattern, err)
	}
}

// String returns a concise summary of what was loaded.
func (rp *RulePack) String() string {
	if rp == nil {
		return "RulePack{nil}"
	}
	nSupp := 0
	if rp.Suppressions != nil {
		nSupp = len(rp.Suppressions.FindingSupps) + len(rp.Suppressions.PreJudgeStrips) + len(rp.Suppressions.ToolSuppressions)
	}
	nTools := 0
	if rp.SensitiveTools != nil {
		nTools = len(rp.SensitiveTools.Tools)
	}
	nRuleFiles := len(rp.RuleFiles)
	nRules := 0
	for _, rf := range rp.RuleFiles {
		nRules += len(rf.Rules)
	}
	taintLoaded := false
	if rp.Taint != nil {
		taintLoaded = true
	}
	return fmt.Sprintf("RulePack{judges=%d, suppressions=%d, sensitive_tools=%d, rule_files=%d, rules=%d, taint=%v}",
		len(rp.JudgeConfigs), nSupp, nTools, nRuleFiles, nRules, taintLoaded)
}
