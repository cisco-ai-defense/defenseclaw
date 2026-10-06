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
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestNewSkillScanner_DefaultBinary(t *testing.T) {
	ss := NewSkillScannerFromLLM(config.SkillScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	if ss.Config.Binary != "skill-scanner" {
		t.Errorf("expected default binary 'skill-scanner', got %q", ss.Config.Binary)
	}
}

// The scanner environment comes from config only: a shell value of a
// scanner variable never wins over config, and other scanner variables
// from the gateway's environment are dropped.
func TestSkillScanner_ScanEnv_ConfigOnly(t *testing.T) {
	t.Setenv("SKILL_SCANNER_LLM_MODEL", "other")
	t.Setenv("ENABLE_LLM_ANALYZER", "1")
	t.Setenv("AI_DEFENSE_API_KEY", "shell-key")

	ss := NewSkillScannerFromLLM(
		config.SkillScannerConfig{UseLLM: true},
		config.LLMConfig{APIKey: "test-llm-key", Model: "gpt-4o"},
		config.CiscoAIDefenseConfig{},
	)

	found := map[string][]string{}
	for _, e := range ss.scanEnv() {
		if name, value, ok := strings.Cut(e, "="); ok {
			found[name] = append(found[name], value)
		}
	}
	if got := found["SKILL_SCANNER_LLM_MODEL"]; len(got) != 1 || got[0] != "gpt-4o" {
		t.Errorf("SKILL_SCANNER_LLM_MODEL = %q, want only the config model", got)
	}
	if got := found["SKILL_SCANNER_LLM_API_KEY"]; len(got) != 1 || got[0] != "test-llm-key" {
		t.Errorf("SKILL_SCANNER_LLM_API_KEY = %q", got)
	}
	for _, name := range []string{"ENABLE_LLM_ANALYZER", "AI_DEFENSE_API_KEY"} {
		if _, ok := found[name]; ok {
			t.Errorf("%s leaked from the gateway environment", name)
		}
	}
	if len(found["PATH"]) == 0 {
		t.Error("PATH must pass through")
	}
}

// Every provider gets the judge: anthropic/openai by flag, openai-compatible
// servers (vLLM) by base URL and served model name, and the rest (Bedrock,
// Vertex, Azure, ...) by their LiteLLM model prefix.
func TestSkillScanner_BuildArgsJudgeForEveryProvider(t *testing.T) {
	cases := []struct {
		llm          config.LLMConfig
		wantProvider string
		wantEnv      string
	}{
		{config.LLMConfig{Provider: "bedrock", Model: "us.anthropic.claude-haiku"}, "", "SKILL_SCANNER_LLM_MODEL=bedrock/us.anthropic.claude-haiku"},
		{config.LLMConfig{Provider: "vllm", Model: "gemma-4", BaseURL: "http://127.0.0.1:8000/v1"}, "openai-compatible", "SKILL_SCANNER_LLM_BASE_URL=http://127.0.0.1:8000/v1"},
		{config.LLMConfig{Provider: "anthropic", Model: "claude-sonnet-5-5", APIKey: "k"}, "anthropic", "SKILL_SCANNER_LLM_MODEL=anthropic/claude-sonnet-5-5"},
	}
	for _, tc := range cases {
		ss := NewSkillScannerFromLLM(config.SkillScannerConfig{UseLLM: true}, tc.llm, config.CiscoAIDefenseConfig{})
		args := strings.Join(ss.buildArgs("/tmp/skill", "quiet"), " ")
		if !strings.Contains(args, "--use-llm") || !strings.Contains(args, "--policy quiet") {
			t.Fatalf("%s: judge or policy missing: %s", tc.llm.Provider, args)
		}
		if strings.Contains(args, "--fail-on-severity") {
			t.Fatalf("%s: the gate must never be passed to the scanner: %s", tc.llm.Provider, args)
		}
		if got := strings.Contains(args, "--llm-provider"); got != (tc.wantProvider != "") ||
			(tc.wantProvider != "" && !strings.Contains(args, "--llm-provider "+tc.wantProvider)) {
			t.Fatalf("%s: --llm-provider wrong: %s", tc.llm.Provider, args)
		}
		if env := strings.Join(ss.scanEnv(), "\n"); !strings.Contains(env, tc.wantEnv) {
			t.Fatalf("%s: env missing %s", tc.llm.Provider, tc.wantEnv)
		}
	}
}

func TestNewMCPScanner_DefaultBinary(t *testing.T) {
	// The MCP scanner routes through the SDK-backed Python CLI
	// (defenseclaw mcp scan), so the empty default and the legacy
	// "mcp-scanner" value both coerce to "defenseclaw".
	ms := NewMCPScannerFromLLM(config.MCPScannerConfig{}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	if ms.Config.Binary != "defenseclaw" {
		t.Errorf("expected default binary 'defenseclaw', got %q", ms.Config.Binary)
	}

	legacy := NewMCPScannerFromLLM(config.MCPScannerConfig{Binary: "mcp-scanner"}, config.LLMConfig{}, config.CiscoAIDefenseConfig{})
	if legacy.Config.Binary != "defenseclaw" {
		t.Errorf("legacy 'mcp-scanner' must coerce to 'defenseclaw', got %q", legacy.Config.Binary)
	}
}

// The MCP scanner no longer injects MCP_SCANNER_* environment
// variables: it shells out to "defenseclaw mcp scan", which resolves
// LLM and Cisco AI Defense credentials from its own config. The
// former TestMCPScanner_ScanEnv_* tests were removed with scanEnv.
