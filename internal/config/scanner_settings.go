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

package config

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

// Recommended scanner settings (the skill-scanner "Lowest FPR" setup):
// the quiet policy with the LLM judge on, findings at HIGH and above block,
// and MEDIUM findings go to the review queue (the warn verdict).
const (
	SkillScannerPolicyQuiet  = "quiet"
	SkillScannerPolicyCustom = "custom"

	DefaultSkillScannerPolicy         = SkillScannerPolicyQuiet
	DefaultSkillScannerFailOnSeverity = "HIGH"
	DefaultSkillScannerReviewQueueMin = "MEDIUM"
	// RecommendedSkillScannerJudgeModel is the judge model the scanner's
	// recommended settings were measured against.
	RecommendedSkillScannerJudgeModel = "anthropic/claude-sonnet-5-5"

	defaultSkillScannerScanTimeoutS = 300
	maxScannerAssetFileBytes        = 16 << 20
)

// SkillScannerPolicyPresets are the policy names the scanner ships.
var SkillScannerPolicyPresets = []string{"strict", "balanced", "permissive", "low-noise", SkillScannerPolicyQuiet}

var scannerSeverityRank = map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

// IsSkillScannerPolicyPreset reports whether name is a shipped preset.
func IsSkillScannerPolicyPreset(name string) bool {
	for _, preset := range SkillScannerPolicyPresets {
		if name == preset {
			return true
		}
	}
	return false
}

// EffectivePolicy is the policy the scanner runs with: "" is the
// recommended quiet preset. A v8 source may still hold a policy file path
// here; it is returned unchanged.
func (c SkillScannerConfig) EffectivePolicy() string {
	if policy := strings.TrimSpace(c.Policy); policy != "" {
		return policy
	}
	return DefaultSkillScannerPolicy
}

// EffectiveJudgeSource is judge_source, or, when unset, override for a
// populated scanners.skill_scanner.llm block and inherit otherwise (the v8
// meaning of a non-empty block).
func (c SkillScannerConfig) EffectiveJudgeSource() string {
	return effectiveJudgeSource(c.JudgeSource, c.LLM)
}

// EffectiveJudgeSource is the MCP scanner's judge source (see the skill
// scanner's).
func (c MCPScannerConfig) EffectiveJudgeSource() string {
	return effectiveJudgeSource(c.JudgeSource, c.LLM)
}

func effectiveJudgeSource(source string, llm LLMConfig) string {
	if source = strings.TrimSpace(source); source != "" {
		return source
	}
	if llmBlockSet(llm) {
		return ScannerJudgeOverride
	}
	return ScannerJudgeInherit
}

func llmBlockSet(llm LLMConfig) bool {
	return llm.Model != "" || llm.Provider != "" || llm.APIKey != "" || llm.APIKeyEnv != "" ||
		llm.BaseURL != "" || llm.InstanceName != "" || llm.Region != "" ||
		llm.Bedrock != nil || llm.Vertex != nil || llm.Azure != nil
}

// EffectiveFailOnSeverity is the blocking gate DefenseClaw applies to the
// skill scanner's findings (HIGH by default). It is never passed to the
// scanner, whose --fail-on-severity exit code would turn findings into a
// scan error.
func (c SkillScannerConfig) EffectiveFailOnSeverity() string {
	if sev := strings.ToUpper(strings.TrimSpace(c.FailOnSeverity)); sev != "" {
		return sev
	}
	return DefaultSkillScannerFailOnSeverity
}

// EffectiveReviewQueueMin starts the review (warn) band, MEDIUM by default.
func (c SkillScannerConfig) EffectiveReviewQueueMin() string {
	if sev := strings.ToUpper(strings.TrimSpace(c.ReviewQueueMin)); sev != "" {
		return sev
	}
	return DefaultSkillScannerReviewQueueMin
}

// ScanTimeoutSeconds bounds one skill scan (timeouts.scan_s, default 300).
func (c SkillScannerConfig) ScanTimeoutSeconds() int {
	if c.Timeouts.ScanS > 0 {
		return c.Timeouts.ScanS
	}
	return defaultSkillScannerScanTimeoutS
}

// VirusTotalEnabled reports analyzers.virustotal.enabled; the v8
// use_virustotal key is migration input that still counts until the
// config_version 9 migration rewrites it.
func (c SkillScannerConfig) VirusTotalEnabled() bool {
	return c.Analyzers.VirusTotal.Enabled || c.UseVirusTotal
}

// AIDefenseEnabled reports analyzers.aidefense.enabled (or the v8
// use_aidefense key).
func (c SkillScannerConfig) AIDefenseEnabled() bool {
	return c.Analyzers.AIDefense.Enabled || c.UseAIDefense
}

// VirusTotalKeyEnvName is the env var holding the VirusTotal key.
func (c SkillScannerConfig) VirusTotalKeyEnvName() string {
	if name := strings.TrimSpace(c.Analyzers.VirusTotal.APIKeyEnv); name != "" {
		return name
	}
	if name := strings.TrimSpace(c.VirusTotalKeyEnv); name != "" {
		return name
	}
	return "VIRUSTOTAL_API_KEY"
}

// DerivedAdmissionActions is admission.skill.actions when that map is
// unset: severities at or above the gate quarantine, the review band warns
// and anything below is allowed. An explicit admission.skill.actions wins.
func (c SkillScannerConfig) DerivedAdmissionActions() AdmissionActionMap {
	gate := scannerSeverityRank[c.EffectiveFailOnSeverity()]
	review := scannerSeverityRank[c.EffectiveReviewQueueMin()]
	action := func(severity string) *AdmissionAction {
		rank := scannerSeverityRank[severity]
		switch {
		case rank >= gate:
			return &AdmissionAction{Shorthand: AdmissionActionQuarantine}
		case rank >= review:
			return &AdmissionAction{Shorthand: AdmissionActionWarn}
		default:
			return &AdmissionAction{Shorthand: AdmissionActionAllow}
		}
	}
	return AdmissionActionMap{
		Critical: action("CRITICAL"),
		High:     action("HIGH"),
		Medium:   action("MEDIUM"),
		Low:      action("LOW"),
		Info:     action("INFO"),
	}
}

// EffectiveAnalyzers is the analyzer list the MCP scanner runs, or nil for
// auto (YARA, plus the LLM when its model and key are ready). Names are
// trimmed, lower-cased and de-duplicated. "auto" alone, "" and an empty list
// mean auto; "auto" inside a list (what the v8 setup wizard wrote as
// "auto,llm") stands for YARA, so YARA is never dropped.
func (c MCPScannerConfig) EffectiveAnalyzers() []string {
	var names []string
	seen := map[string]bool{}
	add := func(name string) {
		if !seen[name] {
			seen[name] = true
			names = append(names, name)
		}
	}
	auto := false
	for _, raw := range c.Analyzers {
		for _, part := range strings.Split(raw, ",") {
			name := strings.ToLower(strings.TrimSpace(part))
			switch name {
			case "":
			case "auto":
				auto = true
			default:
				add(name)
			}
		}
	}
	if len(names) == 0 {
		return nil
	}
	if auto && !seen["yara"] {
		names = append([]string{"yara"}, names...)
	}
	return names
}

// Validate checks the cross-field scanner rules the schema cannot express.
func (s ScannersConfig) Validate() error {
	skill := s.SkillScanner
	if policy := strings.TrimSpace(skill.Policy); policy == SkillScannerPolicyCustom {
		if strings.TrimSpace(skill.PolicyFile.Path) == "" || strings.TrimSpace(skill.PolicyFile.Digest) == "" {
			return errors.New("config: scanners.skill_scanner.policy custom needs policy_file.path and policy_file.digest")
		}
	} else if !skill.PolicyFile.IsZero() {
		return errors.New("config: scanners.skill_scanner.policy_file is only used with policy: custom")
	}
	for field, value := range map[string]string{
		"fail_on_severity": skill.FailOnSeverity, "review_queue_min": skill.ReviewQueueMin,
	} {
		if v := strings.ToUpper(strings.TrimSpace(value)); v != "" {
			if _, ok := scannerSeverityRank[v]; !ok {
				return fmt.Errorf("config: scanners.skill_scanner.%s must be CRITICAL, HIGH, MEDIUM, LOW or INFO", field)
			}
		}
	}
	if scannerSeverityRank[skill.EffectiveReviewQueueMin()] > scannerSeverityRank[skill.EffectiveFailOnSeverity()] {
		return errors.New("config: scanners.skill_scanner.review_queue_min must not be above fail_on_severity")
	}
	for _, judge := range []struct {
		path, source string
		llm          LLMConfig
	}{
		{"scanners.skill_scanner", skill.JudgeSource, skill.LLM},
		{"scanners.mcp_scanner", s.MCPScanner.JudgeSource, s.MCPScanner.LLM},
	} {
		switch strings.TrimSpace(judge.source) {
		case "":
		case ScannerJudgeInherit:
			if llmBlockSet(judge.llm) {
				return fmt.Errorf("config: %s.judge_source inherit uses the top-level llm block; empty %s.llm or set judge_source: override", judge.path, judge.path)
			}
		case ScannerJudgeOverride:
			if strings.TrimSpace(judge.llm.Model) == "" {
				return fmt.Errorf("config: %s.judge_source override needs %s.llm.model", judge.path, judge.path)
			}
		default:
			return fmt.Errorf("config: %s.judge_source must be inherit or override", judge.path)
		}
	}
	return nil
}

// ReadVerified reads the referenced file and checks it against Digest
// ("sha256:<hex>"). A mismatch, a missing digest or an unreadable file is an
// error, so callers fail closed.
func (r AssetFileRef) ReadVerified() ([]byte, error) {
	want, ok := strings.CutPrefix(strings.ToLower(strings.TrimSpace(r.Digest)), "sha256:")
	if !ok || len(want) != sha256.Size*2 {
		return nil, fmt.Errorf("%s: digest must be sha256:<64 hex>", r.Path)
	}
	f, err := os.Open(r.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxScannerAssetFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxScannerAssetFileBytes {
		return nil, fmt.Errorf("%s: larger than %d bytes", r.Path, maxScannerAssetFileBytes)
	}
	sum := sha256.Sum256(data)
	if got := hex.EncodeToString(sum[:]); got != want {
		return nil, fmt.Errorf("%s: digest mismatch (file is sha256:%s)", r.Path, got)
	}
	return data, nil
}
