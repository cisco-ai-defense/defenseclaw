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
	"os"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func TestNewSkillScanner_DefaultBinary(t *testing.T) {
	ss := NewSkillScanner(config.SkillScannerConfig{}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})
	if ss.Config.Binary != "skill-scanner" {
		t.Errorf("expected default binary 'skill-scanner', got %q", ss.Config.Binary)
	}
}

func TestNewSkillScanner_CustomBinary(t *testing.T) {
	ss := NewSkillScanner(
		config.SkillScannerConfig{Binary: "custom-scanner"},
		config.InspectLLMConfig{},
		config.CiscoAIDefenseConfig{},
	)
	if ss.Config.Binary != "custom-scanner" {
		t.Errorf("expected 'custom-scanner', got %q", ss.Config.Binary)
	}
}

func TestNewSkillScanner_StoresCommonConfigs(t *testing.T) {
	llm := config.InspectLLMConfig{Provider: "anthropic", Model: "claude-sonnet-4-20250514", APIKey: "sk-test"}
	aid := config.CiscoAIDefenseConfig{Endpoint: "https://custom.endpoint", APIKey: "aid-key"}

	ss := NewSkillScanner(config.SkillScannerConfig{}, llm, aid)

	if ss.InspectLLM.Provider != "anthropic" {
		t.Errorf("InspectLLM.Provider = %q, want 'anthropic'", ss.InspectLLM.Provider)
	}
	if ss.InspectLLM.Model != "claude-sonnet-4-20250514" {
		t.Errorf("InspectLLM.Model = %q, want 'claude-sonnet-4-20250514'", ss.InspectLLM.Model)
	}
	if ss.CiscoAIDefense.Endpoint != "https://custom.endpoint" {
		t.Errorf("CiscoAIDefense.Endpoint = %q", ss.CiscoAIDefense.Endpoint)
	}
}

func TestSkillScanner_ScanEnv_InjectsLLMKey(t *testing.T) {
	t.Setenv("SKILL_SCANNER_LLM_API_KEY", "")
	os.Unsetenv("SKILL_SCANNER_LLM_API_KEY")

	llm := config.InspectLLMConfig{APIKey: "test-llm-key", Model: "gpt-4o"}
	ss := NewSkillScanner(config.SkillScannerConfig{}, llm, config.CiscoAIDefenseConfig{})

	env := ss.scanEnv()

	found := map[string]string{}
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			found[parts[0]] = parts[1]
		}
	}

	if found["SKILL_SCANNER_LLM_API_KEY"] != "test-llm-key" {
		t.Errorf("expected SKILL_SCANNER_LLM_API_KEY='test-llm-key', got %q", found["SKILL_SCANNER_LLM_API_KEY"])
	}
	if found["SKILL_SCANNER_LLM_MODEL"] != "gpt-4o" {
		t.Errorf("expected SKILL_SCANNER_LLM_MODEL='gpt-4o', got %q", found["SKILL_SCANNER_LLM_MODEL"])
	}
}

func TestSkillScanner_ScanEnv_InjectsCiscoKey(t *testing.T) {
	os.Unsetenv("AI_DEFENSE_API_KEY")

	aid := config.CiscoAIDefenseConfig{APIKey: "cisco-key-direct", APIKeyEnv: ""}
	ss := NewSkillScanner(config.SkillScannerConfig{}, config.InspectLLMConfig{}, aid)

	env := ss.scanEnv()

	for _, e := range env {
		if strings.HasPrefix(e, "AI_DEFENSE_API_KEY=") {
			val := strings.TrimPrefix(e, "AI_DEFENSE_API_KEY=")
			if val != "cisco-key-direct" {
				t.Errorf("expected 'cisco-key-direct', got %q", val)
			}
			return
		}
	}
	t.Error("AI_DEFENSE_API_KEY not found in scanEnv()")
}

func TestSkillScanner_BuildArgsUsesSupportedLLMProvider(t *testing.T) {
	ss := NewSkillScannerFromLLM(
		config.SkillScannerConfig{UseLLM: true},
		config.LLMConfig{Provider: "Anthropic", Model: "claude-3-5-sonnet"},
		config.CiscoAIDefenseConfig{},
	)

	got := strings.Join(ss.buildArgs("/tmp/skill"), " ")
	if !strings.Contains(got, "--use-llm") {
		t.Fatalf("expected --use-llm in args: %s", got)
	}
	if !strings.Contains(got, "--llm-provider anthropic") {
		t.Fatalf("expected normalized supported provider in args: %s", got)
	}
}

func TestSkillScanner_BuildArgsSkipsUnsupportedInheritedLLMProvider(t *testing.T) {
	ss := NewSkillScannerFromLLM(
		config.SkillScannerConfig{UseLLM: true},
		config.LLMConfig{Provider: "bedrock", Model: "bedrock/us.anthropic.claude-3-5-haiku-20241022-v1:0"},
		config.CiscoAIDefenseConfig{},
	)

	got := strings.Join(ss.buildArgs("/tmp/skill"), " ")
	if strings.Contains(got, "--use-llm") {
		t.Fatalf("did not expect --use-llm for unsupported provider: %s", got)
	}
	if strings.Contains(got, "--llm-provider") || strings.Contains(got, "bedrock") {
		t.Fatalf("did not expect unsupported provider in args: %s", got)
	}
}

func TestNewMCPScanner_DefaultBinary(t *testing.T) {
	ms := NewMCPScanner(config.MCPScannerConfig{}, config.InspectLLMConfig{}, config.CiscoAIDefenseConfig{})
	if ms.Config.Binary != "mcp-scanner" {
		t.Errorf("expected default binary 'mcp-scanner', got %q", ms.Config.Binary)
	}
}

func TestNewMCPScanner_StoresCommonConfigs(t *testing.T) {
	llm := config.InspectLLMConfig{Provider: "openai", Model: "gpt-4o", APIKey: "sk-openai"}
	aid := config.CiscoAIDefenseConfig{Endpoint: "https://eu.api.example.com", APIKey: "eu-key"}

	ms := NewMCPScanner(config.MCPScannerConfig{}, llm, aid)

	if ms.InspectLLM.Provider != "openai" {
		t.Errorf("InspectLLM.Provider = %q, want 'openai'", ms.InspectLLM.Provider)
	}
	if ms.CiscoAIDefense.Endpoint != "https://eu.api.example.com" {
		t.Errorf("CiscoAIDefense.Endpoint = %q", ms.CiscoAIDefense.Endpoint)
	}
}

func TestMCPScanner_ScanEnv_InjectsCommonKeys(t *testing.T) {
	os.Unsetenv("MCP_SCANNER_API_KEY")
	os.Unsetenv("MCP_SCANNER_LLM_API_KEY")
	os.Unsetenv("MCP_SCANNER_LLM_MODEL")
	os.Unsetenv("MCP_SCANNER_LLM_BASE_URL")

	llm := config.InspectLLMConfig{APIKey: "llm-key", Model: "gpt-4o", BaseURL: "https://custom.llm"}
	aid := config.CiscoAIDefenseConfig{APIKey: "aid-key", APIKeyEnv: "", Endpoint: "https://ep.example.com"}

	ms := NewMCPScanner(config.MCPScannerConfig{}, llm, aid)
	env := ms.scanEnv()

	found := map[string]string{}
	for _, e := range env {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			found[parts[0]] = parts[1]
		}
	}

	if found["MCP_SCANNER_API_KEY"] != "aid-key" {
		t.Errorf("expected MCP_SCANNER_API_KEY='aid-key', got %q", found["MCP_SCANNER_API_KEY"])
	}
	if found["MCP_SCANNER_ENDPOINT"] != "https://ep.example.com" {
		t.Errorf("expected MCP_SCANNER_ENDPOINT endpoint, got %q", found["MCP_SCANNER_ENDPOINT"])
	}
	if found["MCP_SCANNER_LLM_API_KEY"] != "llm-key" {
		t.Errorf("expected MCP_SCANNER_LLM_API_KEY='llm-key', got %q", found["MCP_SCANNER_LLM_API_KEY"])
	}
	if found["MCP_SCANNER_LLM_MODEL"] != "gpt-4o" {
		t.Errorf("expected MCP_SCANNER_LLM_MODEL='gpt-4o', got %q", found["MCP_SCANNER_LLM_MODEL"])
	}
	if found["MCP_SCANNER_LLM_BASE_URL"] != "https://custom.llm" {
		t.Errorf("expected MCP_SCANNER_LLM_BASE_URL='https://custom.llm', got %q", found["MCP_SCANNER_LLM_BASE_URL"])
	}
}

func TestMCPScanner_ScanEnv_ResolvesKeyFromEnv(t *testing.T) {
	t.Setenv("TEST_MCP_CISCO_ENV_KEY", "resolved-from-env")
	os.Unsetenv("MCP_SCANNER_API_KEY")

	aid := config.CiscoAIDefenseConfig{APIKey: "fallback", APIKeyEnv: "TEST_MCP_CISCO_ENV_KEY"}
	ms := NewMCPScanner(config.MCPScannerConfig{}, config.InspectLLMConfig{}, aid)

	env := ms.scanEnv()

	for _, e := range env {
		if strings.HasPrefix(e, "MCP_SCANNER_API_KEY=") {
			val := strings.TrimPrefix(e, "MCP_SCANNER_API_KEY=")
			if val != "resolved-from-env" {
				t.Errorf("expected 'resolved-from-env', got %q", val)
			}
			return
		}
	}
	t.Error("MCP_SCANNER_API_KEY not found in scanEnv()")
}
