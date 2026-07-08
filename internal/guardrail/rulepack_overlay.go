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
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"gopkg.in/yaml.v3"
)

const (
	maxManagedOverlayBytes = 1024 * 1024
	maxManagedOverlayRules = 1000
	maxManagedRuleIDRunes  = 128
	maxManagedTitleRunes   = 256
	maxManagedPatternRunes = 2048
	maxManagedTags         = 32
	maxManagedTagRunes     = 128
)

// ManagedRulePackStatus identifies the exact Agent Control rule artifact
// installed into the process at startup/config activation.
type ManagedRulePackStatus struct {
	Present        bool   `json:"present"`
	ArtifactDigest string `json:"artifact_digest,omitempty"`
}

// AgentControlRulePackStatus returns the digest of the configured
// agent-control.yaml overlay. The strict loader rejects multiple copies.
func AgentControlRulePackStatus(overlayDirs []string) (ManagedRulePackStatus, error) {
	var activePath string
	for _, dir := range overlayDirs {
		candidate := filepath.Join(strings.TrimSpace(dir), "rules", "agent-control.yaml")
		info, err := os.Lstat(candidate)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return ManagedRulePackStatus{}, err
		}
		if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
			return ManagedRulePackStatus{}, fmt.Errorf("guardrail: managed Agent Control rule artifact must be a regular file: %s", candidate)
		}
		activePath = candidate
	}
	if activePath == "" {
		return ManagedRulePackStatus{}, nil
	}
	raw, err := safefile.ReadRegular(activePath, maxManagedOverlayBytes)
	if err != nil {
		return ManagedRulePackStatus{}, err
	}
	sum := sha256.Sum256(raw)
	return ManagedRulePackStatus{
		Present:        true,
		ArtifactDigest: "sha256:" + hex.EncodeToString(sum[:]),
	}, nil
}

// LoadRulePackWithOverlays loads the operator-selected base pack with its
// existing permissive behavior, then strictly loads rules-only overlay
// directories in order. It never lets a managed overlay replace suppressions,
// judge prompts, sensitive tools, or local patterns.
func LoadRulePackWithOverlays(baseDir string, overlayDirs []string) (*RulePack, error) {
	base := LoadRulePack(baseDir)
	if len(overlayDirs) == 0 {
		return base, nil
	}

	result := *base
	result.RuleFiles = append([]*RulesFileYAML(nil), base.RuleFiles...)
	seenRuleIDs := make(map[string]struct{})
	agentControlCategorySeen := false
	totalBytes := int64(0)
	totalRules := 0
	for _, overlayDir := range overlayDirs {
		dir := strings.TrimSpace(overlayDir)
		if dir == "" {
			return nil, fmt.Errorf("guardrail: rule-pack overlay directory cannot be empty")
		}
		files, usedBytes, usedRules, err := loadRuleOverlayDir(
			dir,
			seenRuleIDs,
			&agentControlCategorySeen,
			totalBytes,
			totalRules,
		)
		if err != nil {
			return nil, err
		}
		totalBytes += usedBytes
		totalRules += usedRules
		result.RuleFiles = append(result.RuleFiles, files...)
	}
	return &result, nil
}

func loadRuleOverlayDir(
	dir string,
	seenRuleIDs map[string]struct{},
	agentControlCategorySeen *bool,
	priorBytes int64,
	priorRules int,
) ([]*RulesFileYAML, int64, int, error) {
	info, err := os.Lstat(dir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("guardrail: rule-pack overlay %s: %w", dir, err)
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, 0, 0, fmt.Errorf("guardrail: rule-pack overlay %s must be a real directory", dir)
	}
	rootEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("guardrail: read rule-pack overlay %s: %w", dir, err)
	}
	for _, entry := range rootEntries {
		if entry.Name() != "rules" || !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
			return nil, 0, 0, fmt.Errorf("guardrail: overlay %s may contain only a real rules directory", dir)
		}
	}
	rulesDir := filepath.Join(dir, "rules")
	rulesInfo, err := os.Lstat(rulesDir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("guardrail: overlay %s requires rules directory: %w", dir, err)
	}
	if !rulesInfo.IsDir() || rulesInfo.Mode()&os.ModeSymlink != 0 {
		return nil, 0, 0, fmt.Errorf("guardrail: overlay %s rules path must be a real directory", dir)
	}

	entries, err := os.ReadDir(rulesDir)
	if err != nil {
		return nil, 0, 0, fmt.Errorf("guardrail: read overlay rules %s: %w", rulesDir, err)
	}
	var files []*RulesFileYAML
	var usedBytes int64
	usedRules := 0
	for _, entry := range entries {
		if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || filepath.Ext(entry.Name()) != ".yaml" {
			return nil, 0, 0, fmt.Errorf("guardrail: overlay rules %s contains unsupported entry %s", rulesDir, entry.Name())
		}
		path := filepath.Join(rulesDir, entry.Name())
		fileInfo, err := entry.Info()
		if err != nil {
			return nil, 0, 0, fmt.Errorf("guardrail: stat overlay rule file %s: %w", path, err)
		}
		if !fileInfo.Mode().IsRegular() {
			return nil, 0, 0, fmt.Errorf("guardrail: overlay rule file %s must be regular", path)
		}
		if priorBytes+usedBytes+fileInfo.Size() > maxManagedOverlayBytes {
			return nil, 0, 0, fmt.Errorf("guardrail: managed overlays exceed %d bytes", maxManagedOverlayBytes)
		}
		raw, err := safefile.ReadRegular(path, maxManagedOverlayBytes-priorBytes-usedBytes)
		if err != nil {
			return nil, 0, 0, fmt.Errorf("guardrail: read overlay rule file %s: %w", path, err)
		}
		usedBytes += int64(len(raw))
		var file RulesFileYAML
		dec := yaml.NewDecoder(bytes.NewReader(raw))
		dec.KnownFields(true)
		if err := dec.Decode(&file); err != nil {
			return nil, 0, 0, fmt.Errorf("guardrail: parse overlay rule file %s: %w", path, err)
		}
		var extra interface{}
		if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
			if err == nil {
				err = fmt.Errorf("multiple YAML documents are not allowed")
			}
			return nil, 0, 0, fmt.Errorf("guardrail: parse overlay rule file %s: %w", path, err)
		}
		if err := validateManagedRulesFile(&file, seenRuleIDs, priorRules+usedRules); err != nil {
			return nil, 0, 0, fmt.Errorf("guardrail: overlay rule file %s: %w", path, err)
		}
		if file.Category == "agent-control" && entry.Name() != "agent-control.yaml" {
			return nil, 0, 0, fmt.Errorf("guardrail: reserved category agent-control must use rules/agent-control.yaml")
		}
		if entry.Name() == "agent-control.yaml" && file.Category != "agent-control" {
			return nil, 0, 0, fmt.Errorf("guardrail: rules/agent-control.yaml must use reserved category agent-control")
		}
		if file.Category == "agent-control" {
			if *agentControlCategorySeen {
				return nil, 0, 0, fmt.Errorf("guardrail: reserved category agent-control may appear only once across managed overlays")
			}
			*agentControlCategorySeen = true
		}
		usedRules += len(file.Rules)
		file.SourcePath = path
		files = append(files, &file)
	}
	return files, usedBytes, usedRules, nil
}

func validateManagedRulesFile(file *RulesFileYAML, seenRuleIDs map[string]struct{}, priorRules int) error {
	if file.Version != 1 {
		return fmt.Errorf("version must be 1")
	}
	if strings.TrimSpace(file.Category) == "" {
		return fmt.Errorf("category is required")
	}
	if len(file.Rules) == 0 {
		return fmt.Errorf("rules must contain at least one entry")
	}
	if priorRules+len(file.Rules) > maxManagedOverlayRules {
		return fmt.Errorf("managed overlays exceed %d rules", maxManagedOverlayRules)
	}
	for i := range file.Rules {
		rule := &file.Rules[i]
		rule.ID = strings.TrimSpace(rule.ID)
		if rule.ID == "" || utf8.RuneCountInString(rule.ID) > maxManagedRuleIDRunes {
			return fmt.Errorf("rules[%d].id must contain 1-%d characters", i, maxManagedRuleIDRunes)
		}
		if _, duplicate := seenRuleIDs[rule.ID]; duplicate {
			return fmt.Errorf("duplicate rule id %q", rule.ID)
		}
		seenRuleIDs[rule.ID] = struct{}{}
		if rule.Pattern == "" || utf8.RuneCountInString(rule.Pattern) > maxManagedPatternRunes {
			return fmt.Errorf("rules[%d].pattern must contain 1-%d characters", i, maxManagedPatternRunes)
		}
		if _, err := regexp.Compile(rule.Pattern); err != nil {
			return fmt.Errorf("rules[%d].pattern is not valid Go RE2 syntax", i)
		}
		if strings.TrimSpace(rule.Title) == "" || utf8.RuneCountInString(rule.Title) > maxManagedTitleRunes {
			return fmt.Errorf("rules[%d].title must contain 1-%d characters", i, maxManagedTitleRunes)
		}
		switch rule.Severity {
		case "LOW", "MEDIUM", "HIGH", "CRITICAL":
		default:
			return fmt.Errorf("rules[%d].severity must be LOW, MEDIUM, HIGH, or CRITICAL", i)
		}
		if math.IsNaN(rule.Confidence) || math.IsInf(rule.Confidence, 0) || rule.Confidence < 0 || rule.Confidence > 1 {
			return fmt.Errorf("rules[%d].confidence must be finite and between 0 and 1", i)
		}
		if len(rule.Tags) > maxManagedTags {
			return fmt.Errorf("rules[%d].tags exceeds %d entries", i, maxManagedTags)
		}
		for tagIndex := range rule.Tags {
			rule.Tags[tagIndex] = strings.TrimSpace(rule.Tags[tagIndex])
			if rule.Tags[tagIndex] == "" || utf8.RuneCountInString(rule.Tags[tagIndex]) > maxManagedTagRunes {
				return fmt.Errorf("rules[%d].tags[%d] must contain 1-%d characters", i, tagIndex, maxManagedTagRunes)
			}
		}
	}
	return nil
}
