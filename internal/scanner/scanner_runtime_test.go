// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
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
	// GAP-0274: the runtime gets the whole scanners.mcp_scanner block, so
	// the pinned extra YARA rules reach the scan.
	includeBundled := false
	rule := config.AssetFileRef{Path: `C:\ProgramData\Acme\mcp-marker.yar`, Digest: "sha256:" + strings.Repeat("ab", 32)}
	mcp := &MCPScanner{
		Config: config.MCPScannerConfig{
			Binary: runtimeBinary, Analyzers: []string{"yara", "llm"},
			YARA: config.MCPScannerYARAConfig{IncludeBundled: &includeBundled, ExtraRules: []config.AssetFileRef{rule}},
		},
		LLM: config.LLMConfig{Model: "bedrock/us.anthropic.claude-haiku-4-5-20251001-v1:0", APIKey: "k", Region: "us-east-1"},
	}
	args, err := mcp.commandArgs("https://mcp.example.test/mcp")
	if err != nil || len(args) != 4 || args[0] != "mcp-scan" || args[1] != "--settings" || args[3] != "https://mcp.example.test/mcp" {
		t.Fatalf("mcp args = %v (%v)", args, err)
	}
	var settings struct {
		Analyzers []string `json:"analyzers"`
		Binary    *string  `json:"binary"`
		YARA      struct {
			IncludeBundled *bool `json:"include_bundled"`
			ExtraRules     []struct {
				Path   string `json:"path"`
				Digest string `json:"digest"`
			} `json:"extra_rules"`
		} `json:"yara"`
	}
	if err := json.Unmarshal([]byte(args[2]), &settings); err != nil {
		t.Fatalf("settings %q: %v", args[2], err)
	}
	if !reflect.DeepEqual(settings.Analyzers, []string{"yara", "llm"}) || settings.Binary != nil ||
		settings.YARA.IncludeBundled == nil || *settings.YARA.IncludeBundled ||
		len(settings.YARA.ExtraRules) != 1 || settings.YARA.ExtraRules[0].Path != rule.Path || settings.YARA.ExtraRules[0].Digest != rule.Digest {
		t.Fatalf("runtime settings = %s", args[2])
	}
	// GAP-0296: the runtime also gets the rule pack the CLI overlays.
	mcp.RulePack = MCPRulePack{
		Dir:   `C:\ProgramData\DefenseClaw\policies\guardrail\strict`,
		Rules: []config.GuardrailRulesConfig{{Disable: []string{"SEC-X"}}},
	}
	args, err = mcp.commandArgs("https://mcp.example.test/mcp")
	if err != nil || len(args) != 6 || args[3] != "--rule-pack" || args[5] != "https://mcp.example.test/mcp" ||
		!strings.Contains(args[4], `"rules":[{"disable":["SEC-X"]}]`) {
		t.Fatalf("mcp args with a rule pack = %v (%v)", args, err)
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
	// Python's platform.machine() needs PROCESSOR_ARCHITECTURE on Windows.
	t.Setenv("PROCESSOR_ARCHITECTURE", "AMD64")
	if !strings.Contains(strings.Join(skill.scanEnv(), "\n"), "PROCESSOR_ARCHITECTURE=AMD64") {
		t.Fatal("the scanner environment drops PROCESSOR_ARCHITECTURE")
	}

	plugin := &PluginScanner{BinaryPath: runtimeBinary, IncludeSelf: true}
	if _, args := plugin.pluginScanCommand("C:/p"); !reflect.DeepEqual(args, []string{"plugin-scan", "C:/p", "--include-self"}) {
		t.Fatalf("plugin args = %v", args)
	}
}
