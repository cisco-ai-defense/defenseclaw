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

package scanner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

// liteLLMModel returns the model string shaped for LiteLLM /
// provider-native routers. LiteLLM accepts “"provider/model-id"“
// directly — the same shape DefenseClaw uses in config. A bare
// “llm.Model“ with a separate “llm.Provider“ gets stitched into
// “"<provider>/<model>"“. Empty models are passed through unchanged
// (the caller should handle that case).
func liteLLMModel(llm config.LLMConfig) string {
	model := llm.Model
	if model != "" && llm.Provider != "" && !strings.Contains(model, "/") {
		return llm.Provider + "/" + model
	}
	return model
}

func skillScannerSupportsLLMProvider(provider string) bool {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "", "anthropic", "openai":
		return true
	default:
		return false
	}
}

// extractJSON finds the first top-level JSON object in data.
// Scanner CLIs sometimes print progress text to stdout before the JSON;
// this isolates the `{...}` payload so json.Unmarshal succeeds.
// extractJSON locates the first balanced JSON object in data by tracking
// brace depth while skipping string literals.
func extractJSON(data []byte) []byte {
	start := bytes.IndexByte(data, '{')
	if start < 0 {
		return data
	}
	depth := 0
	inString := false
	escaped := false
	for i := start; i < len(data); i++ {
		b := data[i]
		if escaped {
			escaped = false
			continue
		}
		if b == '\\' && inString {
			escaped = true
			continue
		}
		if b == '"' {
			inString = !inString
			continue
		}
		if inString {
			continue
		}
		switch b {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return data[start : i+1]
			}
		}
	}
	return data
}

// SkillScanner shells out to the Python “cisco-ai-skill-scanner“ CLI.
//
// The LLM-facing surface is driven by the unified “config.LLMConfig“
// (top-level “llm:“ merged with “scanners.skill.llm:“ overrides,
// resolved once by “Config.ResolveLLM“). “InspectLLM“ is kept as a
// deprecated back-compat field: old callers that constructed the
// scanner with an “InspectLLMConfig“ still work because
// “NewSkillScanner“ translates it into “LLM“ on the way in. New
// call sites should use “NewSkillScannerFromLLM“ and pass the
// resolved unified config directly.
type SkillScanner struct {
	Config         config.SkillScannerConfig
	LLM            config.LLMConfig
	InspectLLM     config.InspectLLMConfig // Deprecated: populated only for back-compat; do not read.
	CiscoAIDefense config.CiscoAIDefenseConfig
}

// inspectToLLM copies the legacy “InspectLLMConfig“ shape into the
// unified “LLMConfig“ so the scanner can drive everything off a
// single structure internally. Kept local so “config“ doesn't grow
// another conversion helper for a shape we plan to retire.
func inspectToLLM(il config.InspectLLMConfig) config.LLMConfig {
	return config.LLMConfig{
		Model:      il.Model,
		Provider:   il.Provider,
		APIKey:     il.APIKey,
		APIKeyEnv:  il.APIKeyEnv,
		BaseURL:    il.BaseURL,
		Timeout:    il.Timeout,
		MaxRetries: il.MaxRetries,
	}
}

// NewSkillScanner is the back-compat constructor. Accepts the legacy
// “InspectLLMConfig“ shape and translates it into the unified
// “LLMConfig“ internally so downstream code only needs one path.
// New callers should use “NewSkillScannerFromLLM“ and pass
// “Config.ResolveLLM("scanners.skill")“ directly.
func NewSkillScanner(cfg config.SkillScannerConfig, llm config.InspectLLMConfig, aid config.CiscoAIDefenseConfig) *SkillScanner {
	if cfg.Binary == "" {
		cfg.Binary = "skill-scanner"
	}
	return &SkillScanner{
		Config:         cfg,
		LLM:            inspectToLLM(llm),
		InspectLLM:     llm,
		CiscoAIDefense: aid,
	}
}

// NewSkillScannerFromLLM constructs a scanner directly from the
// resolved unified LLM config. Preferred constructor — call sites
// should resolve once via “rootCfg.ResolveLLM("scanners.skill")“ and
// pass the result here so per-scanner overrides on top of the
// top-level “llm:“ block are honored.
func NewSkillScannerFromLLM(cfg config.SkillScannerConfig, llm config.LLMConfig, aid config.CiscoAIDefenseConfig) *SkillScanner {
	if cfg.Binary == "" {
		cfg.Binary = "skill-scanner"
	}
	return &SkillScanner{
		Config:         cfg,
		LLM:            llm,
		CiscoAIDefense: aid,
	}
}

func (s *SkillScanner) Name() string               { return "skill-scanner" }
func (s *SkillScanner) Version() string            { return "1.0.0" }
func (s *SkillScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *SkillScanner) buildArgs(target string) []string {
	args := []string{"scan", "--format", "json"}
	llmProvider := strings.ToLower(strings.TrimSpace(s.LLM.Provider))
	useLLM := s.Config.UseLLM && skillScannerSupportsLLMProvider(llmProvider)

	if useLLM {
		args = append(args, "--use-llm")
	}
	if s.Config.UseBehavioral {
		args = append(args, "--use-behavioral")
	}
	if s.Config.EnableMeta {
		args = append(args, "--enable-meta")
	}
	if s.Config.UseTrigger {
		args = append(args, "--use-trigger")
	}
	if s.Config.UseVirusTotal {
		args = append(args, "--use-virustotal")
	}
	if s.Config.UseAIDefense {
		args = append(args, "--use-aidefense")
	}
	if useLLM && llmProvider != "" {
		args = append(args, "--llm-provider", llmProvider)
	}
	if s.Config.LLMConsensus > 0 {
		args = append(args, "--llm-consensus-runs", strconv.Itoa(s.Config.LLMConsensus))
	}
	if s.Config.Policy != "" {
		args = append(args, "--policy", s.Config.Policy)
	}
	if s.Config.Lenient {
		args = append(args, "--lenient")
	}

	args = append(args, target)
	return args
}

// scanEnv returns the process environment with skill-scanner-specific
// API keys injected from config. Values already present in the
// environment are not overwritten.
func (s *SkillScanner) scanEnv() []string {
	env := os.Environ()

	inject := []struct {
		envVar string
		value  string
	}{
		// skill-scanner's bespoke env vars. The underlying Python
		// scanner reads these directly today — we keep writing them
		// until skill-scanner migrates to provider-native env vars.
		// ``LiteLLMModel`` stitches bare model + provider into
		// ``provider/model`` when needed so LiteLLM can route it.
		{"SKILL_SCANNER_LLM_API_KEY", s.LLM.ResolvedAPIKey()},
		{"SKILL_SCANNER_LLM_MODEL", liteLLMModel(s.LLM)},
		{"VIRUSTOTAL_API_KEY", s.Config.ResolvedVirusTotalKey()},
		{"AI_DEFENSE_API_KEY", s.CiscoAIDefense.ResolvedAPIKey()},
	}

	existing := make(map[string]bool)
	for _, e := range env {
		for i := 0; i < len(e); i++ {
			if e[i] == '=' {
				existing[e[:i]] = true
				break
			}
		}
	}

	for _, kv := range inject {
		if kv.value != "" && !existing[kv.envVar] {
			env = append(env, kv.envVar+"="+kv.value)
		}
	}

	if !existing["NO_COLOR"] {
		env = append(env, "NO_COLOR=1")
	}
	if !existing["TERM"] {
		env = append(env, "TERM=dumb")
	}

	return env
}

func (s *SkillScanner) Scan(ctx context.Context, target string) (*ScanResult, error) {
	start := time.Now()
	ctx, sp := BeginScanSpan(ctx, s.Name(), target, InferTargetType(s.Name()), AgentIdentity{})
	exitCode := 0
	var scanErr error
	var result *ScanResult
	defer func() {
		FinishScanSpan(sp, result, exitCode, scanErr)
	}()

	args := s.buildArgs(target)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)
	stderrStr := stderr.String()

	result = &ScanResult{
		Scanner:    s.Name(),
		Target:     target,
		Timestamp:  start,
		Duration:   duration,
		TargetType: InferTargetType(s.Name()),
	}

	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		}
		if errors.Is(err, exec.ErrNotFound) {
			scanErr = fmt.Errorf("scanner: %s not found at %q — install with: uv pip install cisco-ai-skill-scanner", s.Name(), s.Config.Binary)
			return nil, scanErr
		}
		if exitCode != 0 {
			EmitSubprocessExitFromContext(ctx, s.Config.Binary, exitCode, stderrStr)
		}
		if stdout.Len() == 0 {
			scanErr = fmt.Errorf("scanner: %s failed: %s", s.Name(), stderrStr)
			return nil, scanErr
		}
	}

	result.ExitCode = exitCode
	if exitCode != 0 {
		result.ScanError = stderrStr
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseSkillOutput(stdout.Bytes())
		if parseErr != nil {
			scanErr = fmt.Errorf("scanner: failed to parse %s output: %w (stderr=%s)", s.Name(), parseErr, stderrStr)
			return nil, scanErr
		}
		result.Findings = findings
	}

	return result, nil
}

type skillOutput struct {
	Findings []skillFinding `json:"findings"`
}

type skillFinding struct {
	ID          string `json:"id"`
	Severity    string `json:"severity"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Location    string `json:"location"`
	Remediation string `json:"remediation"`
	RuleID      string `json:"rule_id"`
	Category    string `json:"category"`
	Line        int    `json:"line"`
}

func parseSkillOutput(data []byte) ([]Finding, error) {
	clean := extractJSON(ansiRe.ReplaceAll(data, nil))
	var out skillOutput
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		var ln *int
		if f.Line > 0 {
			v := f.Line
			ln = &v
		}
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "skill-scanner",
			RuleID:      f.RuleID,
			Category:    f.Category,
			LineNumber:  ln,
		})
	}
	return findings, nil
}
