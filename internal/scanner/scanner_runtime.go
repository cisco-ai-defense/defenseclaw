// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"gopkg.in/yaml.v3"
)

// scannerRuntimeName is the standalone Windows enterprise payload's scanner
// runtime (cmd/defenseclaw-scanners): one executable that carries the Python
// scanners and is told which one to run by its first argument.
const scannerRuntimeName = "defenseclaw-scanners"

// usesScannerRuntime reports whether binary is the embedded scanner runtime.
func usesScannerRuntime(binary string) bool {
	base := strings.ToLower(filepath.Base(strings.TrimSpace(binary)))
	return base == scannerRuntimeName || base == scannerRuntimeName+".exe"
}

// scannerNotFound is the error of a scanner binary that does not exist. On
// a host with a managed scanner runtime it says why that runtime was not
// used: a scan never falls back to a PATH lookup there, and the bare name it
// reported before (skill-scanner not found at "skill-scanner") hid the cause
// (GAP-0686). hint is the generic remedy.
func scannerNotFound(name, binary, hint string) error {
	if problem := scannerRuntimeProblem(); problem != nil && !usesScannerRuntime(binary) {
		return fmt.Errorf("scanner: %s: the managed scanner runtime cannot be run (%v); run the DefenseClaw Setup with /repair", name, problem)
	}
	return fmt.Errorf("scanner: %s not found at %q — %s", name, binary, hint)
}

// runtimeSettings is scanners.mcp_scanner as JSON with config.yaml's keys,
// which the runtime's mcp-scan reads with the config loader's own parser.
// It is the whole block, so a key like yara.extra_rules reaches the scan as
// it does on the Python CLI path (GAP-0274). binary is the runtime itself, and
// the judge (llm, judge_source) comes resolved through runtimeEnv.
func (s *MCPScanner) runtimeSettings() (string, error) {
	block := s.Config
	block.Analyzers = block.EffectiveAnalyzers()
	encoded, err := yaml.Marshal(block)
	if err != nil {
		return "", err
	}
	var settings map[string]any
	if err := yaml.Unmarshal(encoded, &settings); err != nil {
		return "", err
	}
	for _, key := range []string{"binary", "llm", "judge_source"} {
		delete(settings, key)
	}
	out, err := json.Marshal(settings)
	return string(out), err
}

// runtimeEnv is the MCP scan's environment under the embedded runtime: the
// skill scanner's allowlist plus the judge and AI Defense settings derived
// from config (the runtime reads no config of its own).
func (s *MCPScanner) runtimeEnv() []string {
	llm := s.LLM
	derived := map[string]string{
		"NO_COLOR":                         "1",
		"TERM":                             "dumb",
		"DEFENSECLAW_SCANNER_LLM_MODEL":    liteLLMModel(llm),
		"DEFENSECLAW_SCANNER_LLM_PROVIDER": strings.TrimSpace(llm.Provider),
		"DEFENSECLAW_SCANNER_LLM_API_KEY":  llm.ResolvedAPIKey(),
		"DEFENSECLAW_SCANNER_LLM_BASE_URL": strings.TrimSpace(llm.BaseURL),
		"DEFENSECLAW_SCANNER_LLM_REGION":   strings.TrimSpace(llm.Region),
		"DEFENSECLAW_SCANNER_AID_API_KEY":  s.CiscoAIDefense.ResolvedAPIKey(),
		"DEFENSECLAW_SCANNER_AID_ENDPOINT": strings.TrimSpace(s.CiscoAIDefense.Endpoint),
	}
	if llm.Bedrock != nil && strings.TrimSpace(llm.Bedrock.Region) != "" {
		derived["DEFENSECLAW_SCANNER_LLM_REGION"] = strings.TrimSpace(llm.Bedrock.Region)
	}
	if region := derived["DEFENSECLAW_SCANNER_LLM_REGION"]; region != "" {
		derived["AWS_REGION"] = region
	}
	env := make([]string, 0, 32)
	for _, kv := range os.Environ() {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		upper := strings.ToUpper(name)
		if v, set := derived[upper]; set && v != "" {
			continue
		}
		if skillScannerEnvPassthrough[upper] || hasAnyPrefix(upper, skillScannerEnvPassthroughPrefixes) {
			env = append(env, kv)
		}
	}
	for name, value := range derived {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	return env
}

// MCPRulePack is the guardrail rule pack an MCP scan lays over the server
// definition, as `defenseclaw mcp scan` does with rulepack.maybe_wrap: the
// effective pack directory and the guardrail.rules layers that change its
// rules (GAP-0296).
type MCPRulePack struct {
	Dir   string
	Rules []config.GuardrailRulesConfig
}

// MCPRulePackFor resolves the rule pack for connector the way the Python CLI
// does: the connector's effective pack, else the global one; guardrail.rules
// alone act on the default pack. A Secure Client host has none: Cisco AI
// Defense decides there and local regex detection is off.
func MCPRulePackFor(cfg *config.Config, connector string) MCPRulePack {
	if cfg == nil || cfg.SecureClientIntegration() {
		return MCPRulePack{}
	}
	layers := cfg.EffectiveRulesForConnector(connector)
	dir := cfg.EffectiveRulePackDirForConnector(connector)
	if dir == "" && len(layers) > 0 {
		dir = cfg.ResolveRulePackDir(config.RulePackRef{Name: "default"})
	}
	return MCPRulePack{Dir: dir, Rules: layers}
}

// runtimeArg is the pack as JSON with config.yaml's keys, which the
// runtime's mcp-scan turns into the CLI's rule-pack overlay.
func (p MCPRulePack) runtimeArg() (string, error) {
	rules := make([]map[string]any, 0, len(p.Rules))
	for _, layer := range p.Rules {
		encoded, err := yaml.Marshal(layer)
		if err != nil {
			return "", err
		}
		var block map[string]any
		if err := yaml.Unmarshal(encoded, &block); err != nil {
			return "", err
		}
		rules = append(rules, block)
	}
	out, err := json.Marshal(map[string]any{"dir": p.Dir, "rules": rules})
	return string(out), err
}
