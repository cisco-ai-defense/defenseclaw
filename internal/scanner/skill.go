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
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

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

type SkillScanner struct {
	Config         config.SkillScannerConfig
	InspectLLM     config.InspectLLMConfig
	CiscoAIDefense config.CiscoAIDefenseConfig
}

func NewSkillScanner(cfg config.SkillScannerConfig, llm config.InspectLLMConfig, aid config.CiscoAIDefenseConfig) *SkillScanner {
	if cfg.Binary == "" {
		cfg.Binary = "skill-scanner"
	}
	return &SkillScanner{Config: cfg, InspectLLM: llm, CiscoAIDefense: aid}
}

func (s *SkillScanner) Name() string               { return "skill-scanner" }
func (s *SkillScanner) Version() string            { return "1.0.0" }
func (s *SkillScanner) SupportedTargets() []string { return []string{"skill"} }

func (s *SkillScanner) buildArgs(target string) []string {
	args := []string{"scan", "--format", "json"}

	if s.Config.UseLLM {
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
	if s.InspectLLM.Provider != "" {
		args = append(args, "--llm-provider", s.InspectLLM.Provider)
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
		{"SKILL_SCANNER_LLM_API_KEY", s.InspectLLM.ResolvedAPIKey()},
		{"SKILL_SCANNER_LLM_MODEL", s.InspectLLM.Model},
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

	args := s.buildArgs(target)
	cmd := exec.CommandContext(ctx, s.Config.Binary, args...)
	cmd.Env = s.scanEnv()

	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	duration := time.Since(start)

	result := &ScanResult{
		Scanner:   s.Name(),
		Target:    target,
		Timestamp: start,
		Duration:  duration,
	}

	if err != nil {
		if errors.Is(err, exec.ErrNotFound) {
			return nil, fmt.Errorf("scanner: %s not found at %q — install with: uv pip install cisco-ai-skill-scanner", s.Name(), s.Config.Binary)
		}
		if stdout.Len() == 0 {
			return nil, fmt.Errorf("scanner: %s failed: %s", s.Name(), stderr.String())
		}
	}

	if stdout.Len() > 0 {
		findings, parseErr := parseSkillOutput(stdout.Bytes())
		if parseErr != nil {
			return nil, fmt.Errorf("scanner: failed to parse %s output: %w", s.Name(), parseErr)
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
}

func parseSkillOutput(data []byte) ([]Finding, error) {
	clean := extractJSON(ansiRe.ReplaceAll(data, nil))
	var out skillOutput
	if err := json.Unmarshal(clean, &out); err != nil {
		return nil, err
	}

	findings := make([]Finding, 0, len(out.Findings))
	for _, f := range out.Findings {
		findings = append(findings, Finding{
			ID:          f.ID,
			Severity:    Severity(f.Severity),
			Title:       f.Title,
			Description: f.Description,
			Location:    f.Location,
			Remediation: f.Remediation,
			Scanner:     "skill-scanner",
		})
	}
	return findings, nil
}
