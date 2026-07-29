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
	"bytes"
	"crypto/sha256"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"math"
	"os"
	"path"
	"path/filepath"
	"reflect"
	"regexp"
	"sort"
	"strings"

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
	// LocalPatterns is the operator-tunable pattern list parsed from
	// rules/local-patterns.yaml. The bundled defaults mirror the
	// hardcoded gateway baseline 1:1; if an operator drops a custom
	// file at <dir>/rules/local-patterns.yaml the gateway will swap
	// the matching globals on load (see gateway.ApplyLocalPatternsOverride).
	// Nil when no YAML is found, which signals "keep the compiled-in
	// defaults" — explicitly different from an empty struct, which
	// would override every field to empty.
	LocalPatterns *LocalPatterns
}

// RulePackError is the safe, machine-readable error returned by the strict
// loader and validator. Path is always relative to the rule-pack root (or "."
// for the root itself), and Reason never contains YAML values, regexes,
// prompts, absolute filesystem paths, or wrapped operating-system errors.
type RulePackError struct {
	Path   string `json:"path"`
	Code   string `json:"code"`
	Reason string `json:"reason"`
}

func (e *RulePackError) Error() string {
	if e == nil {
		return "rule pack error"
	}
	return fmt.Sprintf("rule pack %s at %s: %s", e.Code, e.Path, e.Reason)
}

// RulePackSummary is a deterministic, value-safe description of the loaded
// RulePack suitable for operator-facing JSON. Rule counts describe YAML
// overrides loaded into RuleFiles; compiled gateway fallback rules are outside
// this package and are not counted. Digest fingerprints the complete loaded
// RulePack, but none of the source regexes, prompts, suppression values, tool
// names, or filesystem paths are exposed.
type RulePackSummary struct {
	JudgeCount         int    `json:"judge_count"`
	JudgeCategoryCount int    `json:"judge_category_count"`
	RuleFileCount      int    `json:"rule_file_count"`
	RuleCount          int    `json:"rule_count"`
	EnabledRuleCount   int    `json:"enabled_rule_count"`
	LocalPatternCount  int    `json:"local_pattern_count"`
	SuppressionCount   int    `json:"suppression_count"`
	SensitiveToolCount int    `json:"sensitive_tool_count"`
	Digest             string `json:"digest"`
}

// LocalPatterns mirrors `rules/local-patterns.yaml`. Each field corresponds
// to a package-level variable in internal/gateway/guardrail.go; the gateway
// snapshots these into its scanner state at load time.
//
// Semantics for each field:
//   - nil slice  → "field absent in YAML, retain compiled-in default"
//   - []string{} → "field explicitly emptied by operator, override to nothing"
//   - non-empty  → "operator override, replace compiled-in default wholesale"
//
// This three-state representation (nil vs empty vs populated) matters
// because the bundled YAML deliberately omits fields the operator did
// not intend to customize — e.g. a permissive profile that wants to
// loosen only `pii_requests` shouldn't accidentally drop the secrets
// or exfiltration baselines just because their keys are missing.
type LocalPatterns struct {
	Version          int      `yaml:"version"`
	Injection        []string `yaml:"injection,omitempty"`
	InjectionRegexes []string `yaml:"injection_regexes,omitempty"`
	PIIRequests      []string `yaml:"pii_requests,omitempty"`
	PIIDataRegexes   []string `yaml:"pii_data_regexes,omitempty"`
	Secrets          []string `yaml:"secrets,omitempty"`
	Exfiltration     []string `yaml:"exfiltration,omitempty"`
}

// SuppressionsConfig maps to suppressions.yaml.
type SuppressionsConfig struct {
	Version          int                  `yaml:"version"`
	PreJudgeStrips   []PreJudgeStrip      `yaml:"pre_judge_strips"`
	FindingSupps     []FindingSuppression `yaml:"finding_suppressions"`
	ToolSuppressions []ToolSuppression    `yaml:"tool_suppressions"`

	decoded                bool `yaml:"-"`
	preJudgeStripsSet      bool `yaml:"-"`
	findingSuppressionsSet bool `yaml:"-"`
	toolSuppressionsSet    bool `yaml:"-"`
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
	// MinCategoriesForCritical is the threshold at which a judge verdict
	// escalates to CRITICAL. Previously hardcoded as `len(findings) >= 3`
	// in the injection judge and `len(findings) >= 2` in the exfil judge;
	// moving to YAML lets operators tune per profile and lets the two
	// judges share a common verdict-derivation code path. Value of 0
	// means "never escalate to CRITICAL from this judge alone" (the
	// correlator still can, via cross-finding patterns).
	MinCategoriesForCritical int `yaml:"min_categories_for_critical,omitempty"`

	decoded    bool `yaml:"-"`
	enabledSet bool `yaml:"-"`
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
	Enabled    *bool    `yaml:"enabled,omitempty"`
	Pattern    string   `yaml:"pattern"`
	Title      string   `yaml:"title"`
	Severity   string   `yaml:"severity"`
	Confidence float64  `yaml:"confidence"`
	Tags       []string `yaml:"tags"`

	decoded       bool `yaml:"-"`
	confidenceSet bool `yaml:"-"`
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

	decoded             bool `yaml:"-"`
	resultInspectionSet bool `yaml:"-"`
	judgeResultSet      bool `yaml:"-"`
}

// ---------------------------------------------------------------------------
// Loader
// ---------------------------------------------------------------------------

const (
	maxRulePackFiles            = 64
	maxRulePackInventoryEntries = 4096
	maxRulePackFileBytes        = 1 << 20 // 1 MiB
	maxRulePackAggregateBytes   = 4 << 20 // 4 MiB
	maxRulePackRules            = 4096
	maxRulesPerFile             = 2048
	maxJudgeCategories          = 256
	maxSuppressions             = 4096
	maxSensitiveTools           = 2048
	maxLocalPatterns            = 4096
	maxRegexBytes               = 2048
)

var knownJudgeNames = []string{"exfil", "injection", "pii", "tool-injection"}

type diskRulePackFile struct {
	relPath string
	full    string
	size    int64
}

var errRulePackFileType = errors.New("rule-pack component is not a regular file")

type rulePackInventory struct {
	files     map[string]diskRulePackFile
	ruleFiles []string
	totalSize int64
}

// LoadRulePack loads and validates a rule pack. An empty dir selects the
// validated embedded defaults. A non-empty directory is an operator-supplied
// overlay: omitted built-in components inherit the embedded version, while a
// present unreadable, malformed, unsupported, or invalid component fails
// closed. At least one recognized component must be present.
func LoadRulePack(dir string) (*RulePack, error) {
	rp, err := loadEmbeddedRulePack()
	if err != nil {
		return nil, err
	}
	if dir == "" {
		if err := rp.Validate(); err != nil {
			return nil, err
		}
		return rp, nil
	}

	inventory, err := inspectRulePackDirectory(dir)
	if err != nil {
		return nil, err
	}
	if len(inventory.files) == 0 {
		return nil, rulePackErr(".", "inventory_empty", "directory contains no recognized rule-pack component")
	}

	var bytesRead int64
	decode := func(rel string, out any) error {
		file, ok := inventory.files[rel]
		if !ok {
			return rulePackErr(rel, "internal", "recognized component was not inventoried")
		}
		data, err := readRulePackFile(file)
		if err != nil {
			return err
		}
		bytesRead += int64(len(data))
		if bytesRead > maxRulePackAggregateBytes {
			return rulePackErr(".", "aggregate_size_limit", "rule-pack YAML exceeds the aggregate byte limit")
		}
		return decodeStrictYAML(data, rel, out)
	}

	if _, ok := inventory.files["suppressions.yaml"]; ok {
		var cfg SuppressionsConfig
		if err := decode("suppressions.yaml", &cfg); err != nil {
			return nil, err
		}
		rp.Suppressions = &cfg
	}
	if _, ok := inventory.files["sensitive-tools.yaml"]; ok {
		var cfg SensitiveToolsConfig
		if err := decode("sensitive-tools.yaml", &cfg); err != nil {
			return nil, err
		}
		rp.SensitiveTools = &cfg
	}
	for _, name := range knownJudgeNames {
		rel := path.Join("judge", name+".yaml")
		if _, ok := inventory.files[rel]; !ok {
			continue
		}
		var cfg JudgeYAML
		if err := decode(rel, &cfg); err != nil {
			return nil, err
		}
		rp.JudgeConfigs[name] = &cfg
	}
	if _, ok := inventory.files["rules/local-patterns.yaml"]; ok {
		var cfg LocalPatterns
		if err := decode("rules/local-patterns.yaml", &cfg); err != nil {
			return nil, err
		}
		rp.LocalPatterns = &cfg
	}

	sort.Strings(inventory.ruleFiles)
	rp.RuleFiles = make([]*RulesFileYAML, 0, len(inventory.ruleFiles))
	for _, rel := range inventory.ruleFiles {
		var cfg RulesFileYAML
		if err := decode(rel, &cfg); err != nil {
			return nil, err
		}
		full := inventory.files[rel].full
		if absolute, absErr := filepath.Abs(full); absErr == nil {
			full = absolute
		}
		cfg.SourcePath = full
		rp.RuleFiles = append(rp.RuleFiles, &cfg)
	}

	if err := rp.Validate(); err != nil {
		return nil, err
	}
	return rp, nil
}

func loadEmbeddedRulePack() (*RulePack, error) {
	rp := &RulePack{JudgeConfigs: make(map[string]*JudgeYAML, len(knownJudgeNames))}

	suppressions, err := decodeEmbeddedYAML[SuppressionsConfig]("suppressions.yaml")
	if err != nil {
		return nil, err
	}
	rp.Suppressions = suppressions

	tools, err := decodeEmbeddedYAML[SensitiveToolsConfig]("sensitive-tools.yaml")
	if err != nil {
		return nil, err
	}
	rp.SensitiveTools = tools

	for _, name := range knownJudgeNames {
		rel := path.Join("judge", name+".yaml")
		judge, err := decodeEmbeddedYAML[JudgeYAML](rel)
		if err != nil {
			return nil, err
		}
		rp.JudgeConfigs[name] = judge
	}
	return rp, nil
}

func decodeEmbeddedYAML[T any](rel string) (*T, error) {
	embeddedPath := path.Join("defaults", rel)
	data, err := fs.ReadFile(defaultsFS, embeddedPath)
	if err != nil {
		return nil, rulePackErr(rel, "embedded_read", "embedded component is unavailable")
	}
	if len(data) > maxRulePackFileBytes {
		return nil, rulePackErr(rel, "file_size_limit", "embedded component exceeds the per-file byte limit")
	}
	var out T
	if err := decodeStrictYAML(data, rel, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

func inspectRulePackDirectory(dir string) (*rulePackInventory, error) {
	info, err := os.Stat(dir)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, rulePackErr(".", "directory_not_found", "rule-pack directory does not exist")
		}
		return nil, rulePackErr(".", "directory_unreadable", "rule-pack directory cannot be inspected")
	}
	if !info.IsDir() {
		return nil, rulePackErr(".", "not_directory", "rule-pack path is not a directory")
	}
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, rulePackErr(".", "directory_unreadable", "rule-pack directory cannot be inspected")
	}

	inventory := &rulePackInventory{files: make(map[string]diskRulePackFile)}
	entries := 0
	err = filepath.WalkDir(resolvedDir, func(full string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return rulePackErr(safeRelativePath(resolvedDir, full), "inventory_unreadable", "rule-pack inventory cannot be inspected")
		}
		if full == resolvedDir {
			return nil
		}
		entries++
		if entries > maxRulePackInventoryEntries {
			return rulePackErr(".", "inventory_limit", "rule-pack inventory contains too many entries")
		}

		rel, relErr := filepath.Rel(resolvedDir, full)
		if relErr != nil {
			return rulePackErr(".", "inventory_unreadable", "rule-pack inventory cannot be normalized")
		}
		rel = filepath.ToSlash(rel)
		if entry.Type()&os.ModeSymlink != 0 {
			return rulePackErr(safeInventoryPath(rel), "file_type", "component must be a regular file")
		}
		extension := strings.ToLower(path.Ext(rel))
		if extension != ".yaml" && extension != ".yml" {
			return nil
		}
		if !isRecognizedRulePackYAML(rel) {
			return rulePackErr(safeInventoryPath(rel), "inventory_unexpected", "unexpected YAML component")
		}

		fileInfo, infoErr := entry.Info()
		if infoErr != nil {
			return rulePackErr(rel, "file_unreadable", "component cannot be inspected")
		}
		if entry.Type()&os.ModeSymlink != 0 || !fileInfo.Mode().IsRegular() {
			return rulePackErr(rel, "file_type", "component must be a regular file")
		}
		if fileInfo.Size() > maxRulePackFileBytes {
			return rulePackErr(rel, "file_size_limit", "component exceeds the per-file byte limit")
		}
		if len(inventory.files) >= maxRulePackFiles {
			return rulePackErr(".", "file_count_limit", "rule pack contains too many YAML components")
		}
		inventory.totalSize += fileInfo.Size()
		if inventory.totalSize > maxRulePackAggregateBytes {
			return rulePackErr(".", "aggregate_size_limit", "rule-pack YAML exceeds the aggregate byte limit")
		}
		inventory.files[rel] = diskRulePackFile{relPath: rel, full: full, size: fileInfo.Size()}
		if strings.HasPrefix(rel, "rules/") && rel != "rules/local-patterns.yaml" {
			inventory.ruleFiles = append(inventory.ruleFiles, rel)
		}
		return nil
	})
	if err != nil {
		var packErr *RulePackError
		if errors.As(err, &packErr) {
			return nil, packErr
		}
		return nil, rulePackErr(".", "inventory_unreadable", "rule-pack inventory cannot be inspected")
	}
	return inventory, nil
}

func isRecognizedRulePackYAML(rel string) bool {
	if path.Ext(rel) != ".yaml" {
		return false
	}
	switch rel {
	case "suppressions.yaml", "sensitive-tools.yaml", "rules/local-patterns.yaml":
		return true
	}
	for _, name := range knownJudgeNames {
		if rel == path.Join("judge", name+".yaml") {
			return true
		}
	}
	return path.Dir(rel) == "rules" && path.Base(rel) != "local-patterns.yaml"
}

func readRulePackFile(file diskRulePackFile) ([]byte, error) {
	handle, err := openRulePackFile(file.full)
	if err != nil {
		if errors.Is(err, errRulePackFileType) {
			return nil, rulePackErr(file.relPath, "file_type", "component must be a regular file")
		}
		return nil, rulePackErr(file.relPath, "file_unreadable", "component cannot be read")
	}
	defer handle.Close()

	info, err := handle.Stat()
	if err != nil || !info.Mode().IsRegular() {
		return nil, rulePackErr(file.relPath, "file_type", "component must be a regular file")
	}
	if info.Size() > maxRulePackFileBytes {
		return nil, rulePackErr(file.relPath, "file_size_limit", "component exceeds the per-file byte limit")
	}
	data, err := io.ReadAll(io.LimitReader(handle, maxRulePackFileBytes+1))
	if err != nil {
		return nil, rulePackErr(file.relPath, "file_unreadable", "component cannot be read")
	}
	if len(data) > maxRulePackFileBytes {
		return nil, rulePackErr(file.relPath, "file_size_limit", "component exceeds the per-file byte limit")
	}
	return data, nil
}

func decodeStrictYAML(data []byte, rel string, out any) error {
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(out); err != nil {
		if errors.Is(err, io.EOF) {
			return rulePackErr(rel, "yaml_empty", "component must contain one YAML document")
		}
		return rulePackErr(rel, "yaml_invalid", "YAML is invalid or does not match the expected schema")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return rulePackErr(rel, "yaml_documents", "component must contain exactly one YAML document")
	}

	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil {
		return rulePackErr(rel, "yaml_invalid", "YAML is invalid or does not match the expected schema")
	}
	outType := reflect.TypeOf(out)
	if outType == nil || outType.Kind() != reflect.Pointer ||
		!yamlNodeMatchesType(yamlDocumentRoot(&document), outType.Elem()) {
		return rulePackErr(rel, "yaml_invalid", "YAML is invalid or does not match the expected schema")
	}
	markDecodedPresence(out, &document)
	return nil
}

// yamlNodeMatchesType closes yaml.v3's permissive scalar coercions (for
// example, an integer ID being converted to a Go string). KnownFields closes
// object shape; this pass makes scalar and collection types exact.
func yamlNodeMatchesType(node *yaml.Node, expected reflect.Type) bool {
	if node == nil || node.Kind == yaml.AliasNode {
		return false
	}
	for expected.Kind() == reflect.Pointer {
		expected = expected.Elem()
	}
	switch expected.Kind() {
	case reflect.Struct:
		if node.Kind != yaml.MappingNode {
			return false
		}
		fields := make(map[string]reflect.Type)
		for index := 0; index < expected.NumField(); index++ {
			field := expected.Field(index)
			if field.PkgPath != "" {
				continue
			}
			tag := strings.Split(field.Tag.Get("yaml"), ",")[0]
			if tag == "-" {
				continue
			}
			if tag == "" {
				tag = strings.ToLower(field.Name)
			}
			fields[tag] = field.Type
		}
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" {
				return false
			}
			fieldType, ok := fields[key.Value]
			if !ok || !yamlNodeMatchesType(value, fieldType) {
				return false
			}
		}
		return true
	case reflect.Slice:
		if node.Kind != yaml.SequenceNode {
			return false
		}
		for _, child := range node.Content {
			if !yamlNodeMatchesType(child, expected.Elem()) {
				return false
			}
		}
		return true
	case reflect.Map:
		if expected.Key().Kind() != reflect.String || node.Kind != yaml.MappingNode {
			return false
		}
		for index := 0; index+1 < len(node.Content); index += 2 {
			key, value := node.Content[index], node.Content[index+1]
			if key.Kind != yaml.ScalarNode || key.ShortTag() != "!!str" ||
				!yamlNodeMatchesType(value, expected.Elem()) {
				return false
			}
		}
		return true
	case reflect.String:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!str"
	case reflect.Bool:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!bool"
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return node.Kind == yaml.ScalarNode && node.ShortTag() == "!!int"
	case reflect.Float32, reflect.Float64:
		return node.Kind == yaml.ScalarNode &&
			(node.ShortTag() == "!!float" || node.ShortTag() == "!!int")
	default:
		return false
	}
}

func markDecodedPresence(out any, document *yaml.Node) {
	root := yamlDocumentRoot(document)
	switch typed := out.(type) {
	case *SuppressionsConfig:
		typed.decoded = true
		typed.preJudgeStripsSet = yamlMappingHas(root, "pre_judge_strips")
		typed.findingSuppressionsSet = yamlMappingHas(root, "finding_suppressions")
		typed.toolSuppressionsSet = yamlMappingHas(root, "tool_suppressions")
	case *JudgeYAML:
		typed.decoded = true
		typed.enabledSet = yamlMappingHas(root, "enabled")
	case *RulesFileYAML:
		rules := yamlMappingValue(root, "rules")
		if rules == nil || rules.Kind != yaml.SequenceNode {
			return
		}
		for i := range typed.Rules {
			if i >= len(rules.Content) {
				break
			}
			ruleNode := rules.Content[i]
			typed.Rules[i].decoded = true
			typed.Rules[i].confidenceSet = yamlMappingHas(ruleNode, "confidence")
		}
	case *SensitiveToolsConfig:
		tools := yamlMappingValue(root, "tools")
		if tools == nil || tools.Kind != yaml.SequenceNode {
			return
		}
		for i := range typed.Tools {
			if i >= len(tools.Content) {
				break
			}
			toolNode := tools.Content[i]
			typed.Tools[i].decoded = true
			typed.Tools[i].resultInspectionSet = yamlMappingHas(toolNode, "result_inspection")
			typed.Tools[i].judgeResultSet = yamlMappingHas(toolNode, "judge_result")
		}
	}
}

func yamlDocumentRoot(document *yaml.Node) *yaml.Node {
	if document == nil {
		return nil
	}
	if document.Kind == yaml.DocumentNode && len(document.Content) == 1 {
		return document.Content[0]
	}
	return document
}

func yamlMappingHas(node *yaml.Node, key string) bool {
	return yamlMappingValue(node, key) != nil
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func safeRelativePath(root, full string) string {
	rel, err := filepath.Rel(root, full)
	if err != nil {
		return "."
	}
	return safeInventoryPath(filepath.ToSlash(rel))
}

func safeInventoryPath(rel string) string {
	rel = path.Clean(strings.TrimSpace(rel))
	if rel == "." || rel == "" || strings.HasPrefix(rel, "../") || path.IsAbs(rel) {
		return "."
	}
	parts := strings.Split(rel, "/")
	for _, part := range parts {
		if part == "" || part == ".." || len(part) > 128 {
			return "."
		}
		for _, r := range part {
			if !(r >= 'a' && r <= 'z') && !(r >= 'A' && r <= 'Z') &&
				!(r >= '0' && r <= '9') && r != '.' && r != '-' && r != '_' {
				return "."
			}
		}
	}
	return rel
}

func rulePackErr(rel, code, reason string) *RulePackError {
	return &RulePackError{Path: safeInventoryPath(rel), Code: code, Reason: reason}
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

// ExfilJudge returns the data-exfiltration judge config, or nil. The
// exfil judge asks the LLM directly whether a prompt is trying to
// read or exfiltrate sensitive files / credentials / secrets — the
// question that the injection judge ("are you overriding my
// instructions?") and the PII judge ("did the text emit literal
// PII?") both fail to answer for polite-tone /etc/passwd-shaped
// prompts.
func (rp *RulePack) ExfilJudge() *JudgeYAML {
	if rp == nil {
		return nil
	}
	return rp.JudgeConfigs["exfil"]
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

// Validate checks the complete effective rule pack. Validation is fail-closed:
// the first error is returned as a value-safe RulePackError and no invalid
// pack is returned by LoadRulePack.
func (rp *RulePack) Validate() error {
	if rp == nil {
		return rulePackErr(".", "validation", "rule pack must not be nil")
	}
	if err := rp.validateJudges(); err != nil {
		return err
	}
	if err := rp.validateRuleFiles(); err != nil {
		return err
	}
	if err := rp.validateLocalPatterns(); err != nil {
		return err
	}
	if err := rp.validateSuppressions(); err != nil {
		return err
	}
	return rp.validateSensitiveTools()
}

func (rp *RulePack) validateRuleFiles() error {
	seenCategories := make(map[string]struct{}, len(rp.RuleFiles))
	seenIDs := make(map[string]struct{})
	totalRules := 0
	for fileIndex, ruleFile := range rp.RuleFiles {
		rel := ruleFileValidationPath(ruleFile, fileIndex)
		if ruleFile == nil {
			return rulePackErr(rel, "validation", "rule file must not be null")
		}
		if ruleFile.Version != 1 {
			return rulePackErr(rel, "version", "version must be 1")
		}
		category := strings.TrimSpace(ruleFile.Category)
		if category == "" {
			return rulePackErr(rel, "validation", "category must not be blank")
		}
		if _, exists := seenCategories[category]; exists {
			return rulePackErr(rel, "duplicate_category", "category duplicates another rule file")
		}
		seenCategories[category] = struct{}{}
		if len(ruleFile.Rules) > maxRulesPerFile {
			return rulePackErr(rel, "rule_count_limit", "rule file contains too many rules")
		}
		totalRules += len(ruleFile.Rules)
		if totalRules > maxRulePackRules {
			return rulePackErr(".", "rule_count_limit", "rule pack contains too many rules")
		}

		enabled := 0
		for ruleIndex := range ruleFile.Rules {
			rule := &ruleFile.Rules[ruleIndex]
			ruleID := strings.TrimSpace(rule.ID)
			if ruleID == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("rule %d id must not be blank", ruleIndex))
			}
			if _, exists := seenIDs[ruleID]; exists {
				return rulePackErr(rel, "duplicate_rule_id", fmt.Sprintf("rule %d id duplicates another rule", ruleIndex))
			}
			seenIDs[ruleID] = struct{}{}
			if err := validateRequiredRegex(rel, fmt.Sprintf("rule %d pattern", ruleIndex), rule.Pattern); err != nil {
				return err
			}
			if strings.TrimSpace(rule.Title) == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("rule %d title must not be blank", ruleIndex))
			}
			if !validSeverity(rule.Severity) {
				return rulePackErr(rel, "severity", fmt.Sprintf("rule %d severity must be LOW, MEDIUM, HIGH, or CRITICAL", ruleIndex))
			}
			if rule.decoded && !rule.confidenceSet {
				return rulePackErr(rel, "validation", fmt.Sprintf("rule %d confidence is required", ruleIndex))
			}
			if math.IsNaN(rule.Confidence) || math.IsInf(rule.Confidence, 0) ||
				rule.Confidence < 0 || rule.Confidence > 1 {
				return rulePackErr(rel, "confidence", fmt.Sprintf("rule %d confidence must be finite and between 0 and 1", ruleIndex))
			}
			if len(rule.Tags) == 0 {
				return rulePackErr(rel, "validation", fmt.Sprintf("rule %d tags must not be empty", ruleIndex))
			}
			seenTags := make(map[string]struct{}, len(rule.Tags))
			for tagIndex, tag := range rule.Tags {
				tag = strings.TrimSpace(tag)
				if tag == "" {
					return rulePackErr(rel, "validation", fmt.Sprintf("rule %d tag %d must not be blank", ruleIndex, tagIndex))
				}
				if _, exists := seenTags[tag]; exists {
					return rulePackErr(rel, "validation", fmt.Sprintf("rule %d tags must be unique", ruleIndex))
				}
				seenTags[tag] = struct{}{}
			}
			if rule.Enabled == nil || *rule.Enabled {
				enabled++
			}
		}
		if enabled == 0 {
			return rulePackErr(rel, "empty_category", "category must contain at least one enabled rule")
		}
	}
	return nil
}

func (rp *RulePack) validateJudges() error {
	if rp.JudgeConfigs == nil {
		return rulePackErr("judge", "validation", "judge configurations are required")
	}
	for _, required := range knownJudgeNames {
		if rp.JudgeConfigs[required] == nil {
			return rulePackErr(path.Join("judge", required+".yaml"), "validation", "required judge configuration is missing")
		}
	}
	if len(rp.JudgeConfigs) > len(knownJudgeNames) {
		return rulePackErr("judge", "inventory_unexpected", "unexpected judge configuration")
	}

	names := make([]string, 0, len(rp.JudgeConfigs))
	for name := range rp.JudgeConfigs {
		names = append(names, name)
	}
	sort.Strings(names)
	seenFindingIDs := make(map[string]struct{})
	totalCategories := 0
	for _, name := range names {
		judge := rp.JudgeConfigs[name]
		rel := path.Join("judge", safeJudgeName(name)+".yaml")
		if judge == nil {
			return rulePackErr(rel, "validation", "judge configuration must not be null")
		}
		if judge.Version != 1 {
			return rulePackErr(rel, "version", "version must be 1")
		}
		if judge.decoded && !judge.enabledSet {
			return rulePackErr(rel, "validation", "enabled is required")
		}
		if strings.TrimSpace(judge.Name) == "" || judge.Name != name {
			return rulePackErr(rel, "validation", "judge name must match its component name")
		}
		if strings.TrimSpace(judge.SystemPrompt) == "" {
			return rulePackErr(rel, "validation", "system_prompt must not be blank")
		}
		if len(judge.Categories) == 0 {
			return rulePackErr(rel, "validation", "categories must not be empty")
		}
		totalCategories += len(judge.Categories)
		if totalCategories > maxJudgeCategories {
			return rulePackErr("judge", "category_count_limit", "rule pack contains too many judge categories")
		}
		if judge.MinCategoriesForHigh < 0 || judge.MinCategoriesForCritical < 0 {
			return rulePackErr(rel, "validation", "category thresholds must not be negative")
		}
		if judge.MinCategoriesForHigh > len(judge.Categories) ||
			judge.MinCategoriesForCritical > len(judge.Categories) {
			return rulePackErr(rel, "validation", "category threshold exceeds category count")
		}
		if judge.SingleCategoryMaxSev != "" && !validSeverity(judge.SingleCategoryMaxSev) {
			return rulePackErr(rel, "severity", "single_category_max_severity must be LOW, MEDIUM, HIGH, or CRITICAL")
		}

		categoryNames := make([]string, 0, len(judge.Categories))
		for category := range judge.Categories {
			categoryNames = append(categoryNames, category)
		}
		sort.Strings(categoryNames)
		for categoryIndex, categoryName := range categoryNames {
			category := judge.Categories[categoryName]
			if strings.TrimSpace(categoryName) == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("category %d name must not be blank", categoryIndex))
			}
			findingID := strings.TrimSpace(category.FindingID)
			if findingID == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("category %d finding_id must not be blank", categoryIndex))
			}
			if _, exists := seenFindingIDs[findingID]; exists {
				return rulePackErr(rel, "duplicate_finding_id", fmt.Sprintf("category %d finding_id duplicates another category", categoryIndex))
			}
			seenFindingIDs[findingID] = struct{}{}
			severities := []string{
				category.Severity,
				category.SeverityDefault,
				category.SeverityPrompt,
				category.SeverityCompletion,
			}
			hasSeverity := false
			for _, severity := range severities {
				if severity == "" {
					continue
				}
				hasSeverity = true
				if !validSeverity(severity) {
					return rulePackErr(rel, "severity", fmt.Sprintf("category %d contains an invalid severity", categoryIndex))
				}
			}
			if !hasSeverity {
				return rulePackErr(rel, "severity", fmt.Sprintf("category %d must define a severity", categoryIndex))
			}
		}
	}
	return nil
}

func (rp *RulePack) validateLocalPatterns() error {
	if rp.LocalPatterns == nil {
		return nil
	}
	if rp.LocalPatterns.Version != 1 {
		return rulePackErr("rules/local-patterns.yaml", "version", "version must be 1")
	}
	fields := []struct {
		name    string
		values  []string
		regexes bool
	}{
		{name: "injection", values: rp.LocalPatterns.Injection},
		{name: "injection_regexes", values: rp.LocalPatterns.InjectionRegexes, regexes: true},
		{name: "pii_requests", values: rp.LocalPatterns.PIIRequests},
		{name: "pii_data_regexes", values: rp.LocalPatterns.PIIDataRegexes, regexes: true},
		{name: "secrets", values: rp.LocalPatterns.Secrets},
		{name: "exfiltration", values: rp.LocalPatterns.Exfiltration},
	}
	total := 0
	configuredFields := 0
	for _, field := range fields {
		if field.values != nil {
			configuredFields++
		}
		total += len(field.values)
		if total > maxLocalPatterns {
			return rulePackErr("rules/local-patterns.yaml", "pattern_count_limit", "local pattern set contains too many entries")
		}
		seen := make(map[string]struct{}, len(field.values))
		for index, value := range field.values {
			if strings.TrimSpace(value) == "" {
				return rulePackErr("rules/local-patterns.yaml", "validation", fmt.Sprintf("%s entry %d must not be blank", field.name, index))
			}
			if len(value) > maxRegexBytes {
				return rulePackErr("rules/local-patterns.yaml", "pattern_size_limit", fmt.Sprintf("%s entry %d exceeds 2048 bytes", field.name, index))
			}
			if _, exists := seen[value]; exists {
				return rulePackErr("rules/local-patterns.yaml", "validation", fmt.Sprintf("%s entries must be unique", field.name))
			}
			seen[value] = struct{}{}
			if field.regexes {
				if _, err := regexp.Compile(value); err != nil {
					return rulePackErr("rules/local-patterns.yaml", "regex", fmt.Sprintf("%s entry %d is not a valid Go regular expression", field.name, index))
				}
			}
		}
	}
	if configuredFields == 0 {
		return rulePackErr("rules/local-patterns.yaml", "validation", "at least one local pattern family must be configured")
	}
	if configuredFields == len(fields) && total == 0 {
		return rulePackErr("rules/local-patterns.yaml", "validation", "local pattern set must not clear every pattern family")
	}
	return nil
}

func (rp *RulePack) validateSuppressions() error {
	const rel = "suppressions.yaml"
	if rp.Suppressions == nil {
		return rulePackErr(rel, "validation", "suppressions configuration is required")
	}
	cfg := rp.Suppressions
	if cfg.Version != 1 {
		return rulePackErr(rel, "version", "version must be 1")
	}
	if cfg.decoded &&
		(!cfg.preJudgeStripsSet || !cfg.findingSuppressionsSet || !cfg.toolSuppressionsSet) {
		return rulePackErr(rel, "validation", "all suppression lists are required")
	}
	total := len(cfg.PreJudgeStrips) + len(cfg.FindingSupps) + len(cfg.ToolSuppressions)
	if total > maxSuppressions {
		return rulePackErr(rel, "suppression_count_limit", "configuration contains too many suppressions")
	}
	seenIDs := make(map[string]struct{}, len(cfg.PreJudgeStrips)+len(cfg.FindingSupps))
	for index, suppression := range cfg.PreJudgeStrips {
		suppressionID := strings.TrimSpace(suppression.ID)
		if suppressionID == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d id must not be blank", index))
		}
		if _, exists := seenIDs[suppressionID]; exists {
			return rulePackErr(rel, "duplicate_suppression_id", fmt.Sprintf("pre_judge_strip %d id duplicates another suppression", index))
		}
		seenIDs[suppressionID] = struct{}{}
		if err := validateRequiredRegex(rel, fmt.Sprintf("pre_judge_strip %d pattern", index), suppression.Pattern); err != nil {
			return err
		}
		if strings.TrimSpace(suppression.Context) == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d context must not be blank", index))
		}
		if len(suppression.AppliesTo) == 0 {
			return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d applies_to must not be empty", index))
		}
		seenTargets := make(map[string]struct{}, len(suppression.AppliesTo))
		for appliesIndex, appliesTo := range suppression.AppliesTo {
			if strings.TrimSpace(appliesTo) == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d applies_to entry %d must not be blank", index, appliesIndex))
			}
			if !knownJudgeName(appliesTo) {
				return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d applies_to entry %d is unsupported", index, appliesIndex))
			}
			if _, exists := seenTargets[appliesTo]; exists {
				return rulePackErr(rel, "validation", fmt.Sprintf("pre_judge_strip %d applies_to entries must be unique", index))
			}
			seenTargets[appliesTo] = struct{}{}
		}
	}
	for index, suppression := range cfg.FindingSupps {
		suppressionID := strings.TrimSpace(suppression.ID)
		if suppressionID == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("finding_suppression %d id must not be blank", index))
		}
		if _, exists := seenIDs[suppressionID]; exists {
			return rulePackErr(rel, "duplicate_suppression_id", fmt.Sprintf("finding_suppression %d id duplicates another suppression", index))
		}
		seenIDs[suppressionID] = struct{}{}
		if err := validateRequiredRegex(rel, fmt.Sprintf("finding_suppression %d finding_pattern", index), suppression.FindingPattern); err != nil {
			return err
		}
		if err := validateRequiredRegex(rel, fmt.Sprintf("finding_suppression %d entity_pattern", index), suppression.EntityPattern); err != nil {
			return err
		}
		if suppression.Condition != "" &&
			suppression.Condition != "is_epoch" &&
			suppression.Condition != "is_platform_id" {
			return rulePackErr(rel, "validation", fmt.Sprintf("finding_suppression %d condition is unsupported", index))
		}
		if strings.TrimSpace(suppression.Reason) == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("finding_suppression %d reason must not be blank", index))
		}
	}
	seenToolPatterns := make(map[string]struct{}, len(cfg.ToolSuppressions))
	for index, suppression := range cfg.ToolSuppressions {
		if err := validateRequiredRegex(rel, fmt.Sprintf("tool_suppression %d tool_pattern", index), suppression.ToolPattern); err != nil {
			return err
		}
		if _, exists := seenToolPatterns[suppression.ToolPattern]; exists {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool_suppression %d duplicates another tool pattern", index))
		}
		seenToolPatterns[suppression.ToolPattern] = struct{}{}
		if len(suppression.SuppressFindings) == 0 {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool_suppression %d suppress_findings must not be empty", index))
		}
		seenFindings := make(map[string]struct{}, len(suppression.SuppressFindings))
		for findingIndex, finding := range suppression.SuppressFindings {
			findingID := strings.TrimSpace(finding)
			if findingID == "" {
				return rulePackErr(rel, "validation", fmt.Sprintf("tool_suppression %d suppress_findings entry %d must not be blank", index, findingIndex))
			}
			if _, exists := seenFindings[findingID]; exists {
				return rulePackErr(rel, "validation", fmt.Sprintf("tool_suppression %d suppress_findings entries must be unique", index))
			}
			seenFindings[findingID] = struct{}{}
		}
		if strings.TrimSpace(suppression.Reason) == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool_suppression %d reason must not be blank", index))
		}
	}
	return nil
}

func (rp *RulePack) validateSensitiveTools() error {
	const rel = "sensitive-tools.yaml"
	if rp.SensitiveTools == nil {
		return rulePackErr(rel, "validation", "sensitive-tools configuration is required")
	}
	cfg := rp.SensitiveTools
	if cfg.Version != 1 {
		return rulePackErr(rel, "version", "version must be 1")
	}
	if len(cfg.Tools) == 0 {
		return rulePackErr(rel, "validation", "tools must not be empty")
	}
	if len(cfg.Tools) > maxSensitiveTools {
		return rulePackErr(rel, "tool_count_limit", "configuration contains too many sensitive tools")
	}
	seenNames := make(map[string]struct{}, len(cfg.Tools))
	for index, tool := range cfg.Tools {
		toolName := strings.TrimSpace(tool.Name)
		if toolName == "" {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool %d name must not be blank", index))
		}
		if _, exists := seenNames[toolName]; exists {
			return rulePackErr(rel, "duplicate_tool", fmt.Sprintf("tool %d name duplicates another tool", index))
		}
		seenNames[toolName] = struct{}{}
		if tool.decoded && (!tool.resultInspectionSet || !tool.judgeResultSet) {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool %d inspection booleans are required", index))
		}
		if !tool.ResultInspection && !tool.JudgeResult {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool %d must enable at least one inspection mode", index))
		}
		if tool.JudgeResult && !tool.ResultInspection {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool %d judge_result requires result_inspection", index))
		}
		if tool.MinEntitiesAlert < 0 {
			return rulePackErr(rel, "validation", fmt.Sprintf("tool %d min_entities_for_alert must not be negative", index))
		}
	}
	return nil
}

func validateRequiredRegex(rel, field, pattern string) error {
	if strings.TrimSpace(pattern) == "" {
		return rulePackErr(rel, "validation", field+" must not be blank")
	}
	if len(pattern) > maxRegexBytes {
		return rulePackErr(rel, "pattern_size_limit", field+" exceeds 2048 bytes")
	}
	if _, err := regexp.Compile(pattern); err != nil {
		return rulePackErr(rel, "regex", field+" is not a valid Go regular expression")
	}
	return nil
}

func validSeverity(severity string) bool {
	switch severity {
	case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return true
	default:
		return false
	}
}

func knownJudgeName(name string) bool {
	for _, known := range knownJudgeNames {
		if name == known {
			return true
		}
	}
	return false
}

func ruleFileValidationPath(ruleFile *RulesFileYAML, index int) string {
	if ruleFile != nil && ruleFile.SourcePath != "" {
		base := filepath.Base(ruleFile.SourcePath)
		if safe := safeInventoryPath(path.Join("rules", base)); safe != "." {
			return safe
		}
	}
	return path.Join("rules", fmt.Sprintf("component-%d.yaml", index))
}

func safeJudgeName(name string) string {
	for _, known := range knownJudgeNames {
		if name == known {
			return known
		}
	}
	return "component"
}

// Summary returns deterministic counts and a SHA-256 fingerprint of the
// complete loaded RulePack configuration. Rule counts cover loaded YAML
// overrides, not compiled gateway fallback rules. Source paths are excluded.
func (rp *RulePack) Summary() RulePackSummary {
	if rp == nil {
		var summary RulePackSummary
		sum := sha256.Sum256([]byte("null"))
		summary.Digest = hex.EncodeToString(sum[:])
		return summary
	}
	summary := rp.counts()

	ruleFiles := make([]RulesFileYAML, 0, len(rp.RuleFiles))
	for _, ruleFile := range rp.RuleFiles {
		if ruleFile == nil {
			continue
		}
		cloned := *ruleFile
		cloned.SourcePath = ""
		ruleFiles = append(ruleFiles, cloned)
	}
	canonical := struct {
		Suppressions   *SuppressionsConfig
		JudgeConfigs   map[string]*JudgeYAML
		SensitiveTools *SensitiveToolsConfig
		RuleFiles      []RulesFileYAML
		LocalPatterns  *LocalPatterns
	}{
		Suppressions:   rp.Suppressions,
		JudgeConfigs:   rp.JudgeConfigs,
		SensitiveTools: rp.SensitiveTools,
		RuleFiles:      ruleFiles,
		LocalPatterns:  rp.LocalPatterns,
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		encoded = []byte("invalid")
	}
	sum := sha256.Sum256(encoded)
	summary.Digest = hex.EncodeToString(sum[:])
	return summary
}

func (rp *RulePack) counts() RulePackSummary {
	var summary RulePackSummary
	if rp == nil {
		return summary
	}
	summary.JudgeCount = len(rp.JudgeConfigs)
	for _, judge := range rp.JudgeConfigs {
		if judge != nil {
			summary.JudgeCategoryCount += len(judge.Categories)
		}
	}
	summary.RuleFileCount = len(rp.RuleFiles)
	for _, ruleFile := range rp.RuleFiles {
		if ruleFile == nil {
			continue
		}
		summary.RuleCount += len(ruleFile.Rules)
		for index := range ruleFile.Rules {
			if ruleFile.Rules[index].Enabled == nil || *ruleFile.Rules[index].Enabled {
				summary.EnabledRuleCount++
			}
		}
	}
	if patterns := rp.LocalPatterns; patterns != nil {
		summary.LocalPatternCount =
			len(patterns.Injection) +
				len(patterns.InjectionRegexes) +
				len(patterns.PIIRequests) +
				len(patterns.PIIDataRegexes) +
				len(patterns.Secrets) +
				len(patterns.Exfiltration)
	}
	if suppressions := rp.Suppressions; suppressions != nil {
		summary.SuppressionCount =
			len(suppressions.PreJudgeStrips) +
				len(suppressions.FindingSupps) +
				len(suppressions.ToolSuppressions)
	}
	if tools := rp.SensitiveTools; tools != nil {
		summary.SensitiveToolCount = len(tools.Tools)
	}
	return summary
}

// String returns a concise, value-safe summary of what was loaded.
func (rp *RulePack) String() string {
	if rp == nil {
		return "RulePack{nil}"
	}
	summary := rp.counts()
	return fmt.Sprintf("RulePack{judges=%d, suppressions=%d, sensitive_tools=%d, rule_files=%d, rules=%d}",
		summary.JudgeCount,
		summary.SuppressionCount,
		summary.SensitiveToolCount,
		summary.RuleFileCount,
		summary.RuleCount,
	)
}
