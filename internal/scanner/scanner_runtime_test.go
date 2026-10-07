// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"reflect"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0132: the standalone Windows payload's embedded scanner runtime is
// told which scanner to run, takes the judge from config-derived variables,
// and never sees a shell's SKILL_SCANNER_* or DEFENSECLAW_* settings.
func TestScannerRuntimeCommandLines(t *testing.T) {
	runtimeBinary := "C:/Program Files/Cisco/DefenseClaw/bin/defenseclaw-scanners.exe"
	skill := &SkillScanner{Config: config.SkillScannerConfig{Binary: runtimeBinary}}
	if got := skill.commandArgs("C:/s", "quiet"); got[0] != "skill-scanner" || got[1] != "scan" {
		t.Fatalf("skill args = %v", got)
	}
	plain := &SkillScanner{Config: config.SkillScannerConfig{Binary: "skill-scanner"}}
	if got := plain.commandArgs("C:/s", "quiet"); got[0] != "scan" {
		t.Fatalf("plain skill args = %v", got)
	}

	t.Setenv("DEFENSECLAW_SCANNER_LLM_MODEL", "from-shell")
	t.Setenv("SKILL_SCANNER_LLM_MODEL", "from-shell")
	mcp := &MCPScanner{
		Config: config.MCPScannerConfig{Binary: runtimeBinary, Analyzers: []string{"yara", "llm"}},
		LLM:    config.LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", APIKey: "k", Region: "us-east-1"},
	}
	want := []string{"mcp-scan", "--json", "--analyzers", "yara,llm", "https://mcp.example.test/mcp"}
	if got := mcp.commandArgs("https://mcp.example.test/mcp"); !reflect.DeepEqual(got, want) {
		t.Fatalf("mcp args = %v, want %v", got, want)
	}
	env := strings.Join(mcp.runtimeEnv(), "\n")
	for _, wantLine := range []string{
		"DEFENSECLAW_SCANNER_LLM_MODEL=bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0",
		"DEFENSECLAW_SCANNER_LLM_API_KEY=k",
		"AWS_REGION=us-east-1",
	} {
		if !strings.Contains(env, wantLine) {
			t.Fatalf("runtime env lacks %q", wantLine)
		}
	}
	if strings.Contains(env, "from-shell") {
		t.Fatal("a shell scanner variable reached the runtime")
	}

	plugin := &PluginScanner{BinaryPath: runtimeBinary, IncludeSelf: true}
	if _, args := plugin.pluginScanCommand("C:/p"); !reflect.DeepEqual(args, []string{"plugin-scan", "C:/p", "--include-self"}) {
		t.Fatalf("plugin args = %v", args)
	}
}
