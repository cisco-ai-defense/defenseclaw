// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// ErrScannerRuntimeUnavailable is the error of a scan on a standalone
// managed Windows host whose scanner runtime cannot be run, for example while
// Setup is still preparing it: Setup starts the gateway first, and its
// startup rescan scans every installed skill and plugin at once. The rescan
// loop retries such scans soon rather than an interval later (GAP-0975).
var ErrScannerRuntimeUnavailable = errors.New("the managed scanner runtime is not ready")

// requireScannerTargetPath checks a filesystem target before a scanner opens
// it or starts a child under the gateway service token.
var requireScannerTargetPath = func(path string) error {
	return managed.RequireWindowsGatewayPathOutsideUserProfiles(path)
}

// scannerNotFound is the error of a scanner binary that does not exist.
// hint is the generic remedy. A default scanner command on a host with a
// managed scanner runtime never gets here: scannerRuntimePreflight stops
// that scan first and says why the runtime was not used (GAP-0686).
func scannerNotFound(name, binary, hint string) error {
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
	base := os.Environ()
	derived := runtimeJudgeEnv(s.LLM, base)
	derived["NO_COLOR"] = "1"
	derived["TERM"] = "dumb"
	derived["DEFENSECLAW_SCANNER_AID_API_KEY"] = s.CiscoAIDefense.ResolvedAPIKey()
	derived["DEFENSECLAW_SCANNER_AID_ENDPOINT"] = strings.TrimSpace(s.CiscoAIDefense.Endpoint)
	return scannerRuntimeEnv(base, derived, nil)
}

// VersionProbeEnv is the environment of a `<scanner> --version` probe: the
// scan allowlist of the gateway environment and nothing derived from config,
// so an ambient AI_DEFENSE_API_KEY or provider key never reaches the probe.
func VersionProbeEnv() []string {
	return scannerRuntimeEnv(os.Environ(), map[string]string{"NO_COLOR": "1", "TERM": "dumb"}, nil)
}

// scannerRuntimeEnv is a scanner runtime child's environment: the variables
// of base on the scanner allowlist (skillScannerEnvPassthrough) or in keep,
// then the values the gateway derived from config. Nothing else from the
// service environment reaches the scan: not DEFENSECLAW_LLM_KEY, which the
// Python judge falls back to, and not a provider key or endpoint such as
// OPENAI_BASE_URL, which LiteLLM uses when config names none (GAP-1437). An
// AWS endpoint never passes, and a derived name replaces an inherited one,
// even with an empty value, which then leaves the variable unset.
func scannerRuntimeEnv(base []string, derived map[string]string, keep map[string]bool) []string {
	env := make([]string, 0, 32)
	temp := scannerRuntimeTemp()
	for _, kv := range base {
		name, _, ok := strings.Cut(kv, "=")
		if !ok || name == "" {
			continue
		}
		upper := strings.ToUpper(name)
		if _, set := derived[upper]; set || strings.HasPrefix(upper, "AWS_ENDPOINT_URL") {
			continue
		}
		if temp != "" && (upper == "TEMP" || upper == "TMP") {
			continue
		}
		if keep[upper] || skillScannerEnvPassthrough[upper] || hasAnyPrefix(upper, skillScannerEnvPassthroughPrefixes) {
			env = append(env, kv)
		}
	}
	for name, value := range derived {
		if value != "" {
			env = append(env, name+"="+value)
		}
	}
	if temp != "" {
		env = append(env, "TEMP="+temp, "TMP="+temp)
	}
	return env
}

// scannerRuntimeDataDir is the managed gateway's data folder (the service
// sets DEFENSECLAW_HOME), "" off Windows, where no scanner runtime runs.
// Tests replace it.
var scannerRuntimeDataDir = func() string {
	if runtime.GOOS != "windows" {
		return ""
	}
	return strings.TrimSpace(os.Getenv("DEFENSECLAW_HOME"))
}

// scannerRuntimeTemp is the TEMP and TMP of a scanner runtime child: a
// folder in the gateway's data folder (GAP-0114). The child keeps the
// gateway's write-restricted LocalSystem token, which can write none of the
// folders Python looks in for one (the service TEMP, the LocalSystem
// profile, the Windows folder, the System32 working folder), so every
// local MCP server scan failed before the server started, reported as a
// Windows npx wrapper startup failure. The data folder's access list is the
// gateway's own (SYSTEM, administrators, the gateway service), so a
// server's stderr kept there while the scan runs stays private. "" keeps
// the inherited values.
func scannerRuntimeTemp() string {
	home := scannerRuntimeDataDir()
	if home == "" || !filepath.IsAbs(home) {
		return ""
	}
	dir := filepath.Join(home, "scanner-tmp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintf(os.Stderr, "[scan] scanner runtime temporary folder %s: %v\n", dir, err)
		return ""
	}
	return dir
}

// runtimeJudgeEnv is the resolved scanner judge as the variables the
// embedded runtime's scan programs read: the runtime reads no config of its
// own, so the gateway hands it the judge it resolved from config. base is
// the environment the runtime starts from.
func runtimeJudgeEnv(llm config.LLMConfig, base []string) map[string]string {
	derived := map[string]string{
		"AWS_IGNORE_CONFIGURED_ENDPOINT_URLS": "true",
		"DEFENSECLAW_SCANNER_LLM_MODEL":       liteLLMModel(llm),
		"DEFENSECLAW_SCANNER_LLM_PROVIDER":    strings.TrimSpace(llm.Provider),
		"DEFENSECLAW_SCANNER_LLM_API_KEY":     llm.ResolvedAPIKey(),
		"DEFENSECLAW_SCANNER_LLM_BASE_URL":    strings.TrimSpace(llm.BaseURL),
		"DEFENSECLAW_SCANNER_LLM_REGION":      strings.TrimSpace(llm.Region),
	}
	if llm.Bedrock != nil && strings.TrimSpace(llm.Bedrock.Region) != "" {
		derived["DEFENSECLAW_SCANNER_LLM_REGION"] = strings.TrimSpace(llm.Bedrock.Region)
	}
	if region := derived["DEFENSECLAW_SCANNER_LLM_REGION"]; region != "" {
		derived["AWS_REGION"] = region
	}
	addBedrockAuthEnv(derived, llm, base)
	return derived
}

// addBedrockAuthEnv hands the runtime a Bedrock judge auth_mode and, for
// iam_credentials, the keys in base under the variable names llm.bedrock
// configures (access_key_env, secret_key_env, session_token_env), as the
// AWS variables LiteLLM signs with. The gateway judge reads the same
// names; the runtime got neither the mode nor a custom-named key, found no
// credentials and blocked the plugin (GAP-1460). The configured pair
// replaces an inherited one and drops an inherited session token unless
// session_token_env names one. Without both keys the runtime keeps the AWS
// credential chain, as the gateway judge does. No other name is read.
func addBedrockAuthEnv(derived map[string]string, llm config.LLMConfig, base []string) {
	if llm.Bedrock == nil {
		return
	}
	if prefix := llm.ProviderPrefix(); prefix != "bedrock" && prefix != "amazon-bedrock" {
		return
	}
	mode := strings.ToLower(strings.TrimSpace(llm.Bedrock.AuthMode))
	if mode == "" {
		mode = "api_key"
	}
	derived["DEFENSECLAW_SCANNER_LLM_BEDROCK_AUTH_MODE"] = mode
	if mode != "iam_credentials" {
		return
	}
	access := baseEnvValue(base, llm.Bedrock.AccessKeyEnv)
	secret := baseEnvValue(base, llm.Bedrock.SecretKeyEnv)
	if access == "" || secret == "" {
		return
	}
	derived["AWS_ACCESS_KEY_ID"] = access
	derived["AWS_SECRET_ACCESS_KEY"] = secret
	derived["AWS_SESSION_TOKEN"] = baseEnvValue(base, llm.Bedrock.SessionTokenEnv)
}

// baseEnvValue is the trimmed value of the variable name in base, or "".
// Windows compares names case-insensitively, as os.Getenv does there.
func baseEnvValue(base []string, name string) string {
	name = strings.TrimSpace(name)
	if name == "" {
		return ""
	}
	for _, kv := range base {
		key, value, ok := strings.Cut(kv, "=")
		if ok && (key == name || runtime.GOOS == "windows" && strings.EqualFold(key, name)) {
			return strings.TrimSpace(value)
		}
	}
	return ""
}

// pluginRuntimeConfigEnv are the DefenseClaw variables a plugin scan keeps
// from the service environment: the plugin-scan program loads the managed
// config for the rule-pack overlay, so it needs the config path, data
// directory and deployment pins the service sets. Each is a name declared
// in the env-var registry.
var pluginRuntimeConfigEnv = map[string]bool{
	managed.ConfigPathEnv:        true,
	"DEFENSECLAW_HOME":           true,
	managed.DeploymentModeEnv:    true,
	managed.EnterpriseProfileEnv: true,
}

// runtimeEnv is a plugin scan's environment under the embedded runtime: the
// scanner allowlist and the config location from base, plus the
// scanners.plugin judge the gateway resolved from config. Before, the
// runtime got no judge and ran the plugin scan rules-only although an
// administrator configured one (GAP-1408); then it got the whole service
// environment, so an inherited DEFENSECLAW_LLM_KEY stood in for a missing
// protected credential and OPENAI_BASE_URL moved the judge (GAP-1437).
func (s *PluginScanner) runtimeEnv(base []string) []string {
	return scannerRuntimeEnv(base, runtimeJudgeEnv(s.LLM, base), pluginRuntimeConfigEnv)
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
