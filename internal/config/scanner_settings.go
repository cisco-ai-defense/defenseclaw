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
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/viper"
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

// VirusTotalKeyEnvName is the env var holding the VirusTotal key.
func (c SkillScannerConfig) VirusTotalKeyEnvName() string {
	if name := strings.TrimSpace(c.Analyzers.VirusTotal.APIKeyEnv); name != "" {
		return name
	}
	return "VIRUSTOTAL_API_KEY"
}

// foldV8ScannerKeys reads the v8 spellings of the VirusTotal and AI Defense
// settings (use_virustotal, use_aidefense, virustotal_api_key_env and the
// inline virustotal_api_key) from the loaded source into the config_version 9
// model. A gateway-managed config_version 8 file is rewritten by the in-memory
// migration before it is decoded; a Secure Client document is not, and a
// config_version 9 source cannot carry them (the schema rejects them). A key
// written under analyzers wins.
func foldV8ScannerKeys(cfg *Config) {
	const skill = "scanners.skill_scanner."
	sc := &cfg.Scanners.SkillScanner
	if !viper.IsSet(skill+"analyzers.virustotal.enabled") && viper.GetBool(skill+"use_virustotal") {
		sc.Analyzers.VirusTotal.Enabled = true
	}
	if !viper.IsSet(skill+"analyzers.aidefense.enabled") && viper.GetBool(skill+"use_aidefense") {
		sc.Analyzers.AIDefense.Enabled = true
	}
	if sc.Analyzers.VirusTotal.APIKeyEnv == "" {
		sc.Analyzers.VirusTotal.APIKeyEnv = strings.TrimSpace(viper.GetString(skill + "virustotal_api_key_env"))
	}
	sc.legacyVirusTotalKey = viper.GetString(skill + "virustotal_api_key")
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

// scannersInvalid is a cross-field scanner violation as a safe diagnostic:
// the key it is about, what is wrong and what is allowed. A bare error here
// read only "configuration could not be compiled safely" at $ (GAP-0128).
func scannersInvalid(key, summary, expected string) error {
	return &V8SemanticError{
		Path:     "$." + key,
		Summary:  summary,
		Expected: expected,
		Action:   "correct the value, then run again",
	}
}

// Validate checks the cross-field scanner rules the schema cannot express.
// Every refusal is a *V8SemanticError naming the key.
func (s ScannersConfig) Validate() error {
	skill := s.SkillScanner
	const skillKey = "scanners.skill_scanner"
	if policy := strings.TrimSpace(skill.Policy); policy == SkillScannerPolicyCustom {
		if strings.TrimSpace(skill.PolicyFile.Path) == "" || strings.TrimSpace(skill.PolicyFile.Digest) == "" {
			return scannersInvalid(skillKey+".policy_file",
				"policy: custom needs policy_file.path and policy_file.digest",
				"scanners.skill_scanner.policy_file with a path and a sha256:<hex> digest, or another policy")
		}
	} else if !skill.PolicyFile.IsZero() {
		return scannersInvalid(skillKey+".policy_file",
			"policy_file is only used with policy: custom",
			"no policy_file, or scanners.skill_scanner.policy: custom")
	}
	for _, field := range []struct{ name, value string }{
		{"fail_on_severity", skill.FailOnSeverity}, {"review_queue_min", skill.ReviewQueueMin},
	} {
		if v := strings.ToUpper(strings.TrimSpace(field.value)); v != "" {
			if _, ok := scannerSeverityRank[v]; !ok {
				return scannersInvalid(skillKey+"."+field.name,
					field.name+" is not a severity",
					"CRITICAL, HIGH, MEDIUM, LOW or INFO")
			}
		}
	}
	if scannerSeverityRank[skill.EffectiveReviewQueueMin()] > scannerSeverityRank[skill.EffectiveFailOnSeverity()] {
		return scannersInvalid(skillKey+".review_queue_min",
			"review_queue_min "+skill.EffectiveReviewQueueMin()+" is above fail_on_severity "+skill.EffectiveFailOnSeverity(),
			"review_queue_min at or below fail_on_severity")
	}
	for _, judge := range []struct {
		path, source string
		llm          LLMConfig
	}{
		{skillKey, skill.JudgeSource, skill.LLM},
		{"scanners.mcp_scanner", s.MCPScanner.JudgeSource, s.MCPScanner.LLM},
	} {
		switch strings.TrimSpace(judge.source) {
		case "":
		case ScannerJudgeInherit:
			if llmBlockSet(judge.llm) {
				return scannersInvalid(judge.path+".llm",
					"judge_source: inherit uses the top-level llm block, but "+judge.path+".llm is set",
					"an empty "+judge.path+".llm, or judge_source: override")
			}
		case ScannerJudgeOverride:
			if strings.TrimSpace(judge.llm.Model) == "" {
				return scannersInvalid(judge.path+".llm.model",
					"judge_source: override needs a model",
					judge.path+".llm.model set")
			}
		default:
			return scannersInvalid(judge.path+".judge_source",
				"judge_source is not recognised",
				"inherit or override")
		}
	}
	return nil
}

// CheckPinnedFiles reads every scanner file the config pins, the custom skill
// scanner policy and the MCP scanner extra YARA rules, and checks it against
// its digest. A scan loads these files only from bytes that match, so a pin
// that does not match its file, or a file edited in place under its pin,
// failed every scan while the config applied with no warning. The managed
// lifecycle preflight and every gateway reload check it; a reload it refuses
// keeps the previous generation (GAP-0664).
func (s ScannersConfig) CheckPinnedFiles() error {
	check := func(key string, ref AssetFileRef) error {
		if _, err := ref.ReadVerified(); err != nil {
			return fmt.Errorf("%s: %v; a scan loads the file only when it matches its digest, so pin the sha256 of the file, or restore the file the digest pins", key, err)
		}
		return nil
	}
	if strings.TrimSpace(s.SkillScanner.Policy) == SkillScannerPolicyCustom && !s.SkillScanner.PolicyFile.IsZero() {
		if err := check("scanners.skill_scanner.policy_file", s.SkillScanner.PolicyFile); err != nil {
			return err
		}
	}
	for index, ref := range s.MCPScanner.YARA.ExtraRules {
		if err := check(fmt.Sprintf("scanners.mcp_scanner.yara.extra_rules[%d]", index), ref); err != nil {
			return err
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
