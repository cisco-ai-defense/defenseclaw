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

// Types for the config_version 9 keys besides admission (admission.go):
// guardrail rule customisation, custom LLM providers, self-update and the
// scanner model. They mirror schemas/config/v8/defenseclaw-config.schema.json
// and the dataclasses in cli/defenseclaw/config.py.

// ConfigVersionV9 is the config_version of the single-source-of-truth
// layout. The v8 to v9 step is MigrateV9 (migrate_v9.go).
const ConfigVersionV9 = 9

// AssetFileRef is a file referenced by path and pinned by digest
// ("sha256:<64 hex>"). Both empty means unset.
type AssetFileRef struct {
	Path   string `mapstructure:"path"   yaml:"path,omitempty"   json:"path,omitempty"`
	Digest string `mapstructure:"digest" yaml:"digest,omitempty" json:"digest,omitempty"`
}

// IsZero reports whether neither the path nor the digest is set.
func (r AssetFileRef) IsZero() bool { return r.Path == "" && r.Digest == "" }

// CustomRulePack is one guardrail.custom_packs entry: a rule-pack directory
// and the RulePackSummary digest it must hash to.
type CustomRulePack struct {
	Path   string `mapstructure:"path"   yaml:"path"`
	Digest string `mapstructure:"digest" yaml:"digest"`
}

// GuardrailRulesConfig is guardrail[.connectors.C|.profiles.P[.connectors.C]].rules:
// the customisation layered on the selected rule pack, applied in memory in
// field order. Rule IDs are upper case (schema $defs.ruleId).
type GuardrailRulesConfig struct {
	// Protections are built-in use-case packs (policies/guardrail-use-cases).
	Protections []string `yaml:"protections,omitempty"`
	// Enable and Disable flip a rule's enabled state; an unknown ID is a
	// validation error.
	Enable  []string `yaml:"enable,omitempty"`
	Disable []string `yaml:"disable,omitempty"`
	// SeverityOverrides maps a rule ID to CRITICAL, HIGH, MEDIUM, LOW or INFO.
	SeverityOverrides map[string]string `yaml:"severity_overrides,omitempty"`
	// Suppressions are appended to the pack's finding suppressions; IDs are
	// unique across the pack and config.
	Suppressions []GuardrailRuleSuppression `yaml:"suppressions,omitempty"`
	// SensitiveTools merge into the pack's sensitive tools by name.
	SensitiveTools []GuardrailSensitiveTool `yaml:"sensitive_tools,omitempty"`
}

// IsZero reports whether no customisation is set.
func (r GuardrailRulesConfig) IsZero() bool {
	return len(r.Protections) == 0 && len(r.Enable) == 0 && len(r.Disable) == 0 &&
		len(r.SeverityOverrides) == 0 && len(r.Suppressions) == 0 && len(r.SensitiveTools) == 0
}

// GuardrailRuleSuppression has the shape of a suppressions.yaml
// finding_suppressions entry.
type GuardrailRuleSuppression struct {
	ID             string `yaml:"id"`
	FindingPattern string `yaml:"finding_pattern"`
	EntityPattern  string `yaml:"entity_pattern,omitempty"`
	Reason         string `yaml:"reason"`
}

// GuardrailSensitiveTool has the shape of a sensitive-tools.yaml tools[]
// entry; nil and zero fields keep the pack's value.
type GuardrailSensitiveTool struct {
	Name                string `yaml:"name"`
	ResultInspection    *bool  `yaml:"result_inspection,omitempty"`
	JudgeResult         *bool  `yaml:"judge_result,omitempty"`
	MinEntitiesForAlert int    `yaml:"min_entities_for_alert,omitempty"`
}

// LLMProvidersConfig is llm_providers: (config_version 9). It replaces
// custom-providers.json as the input; that file becomes derived output.
type LLMProvidersConfig struct {
	Custom      []LLMCustomProvider `yaml:"custom,omitempty"`
	OllamaPorts []int               `yaml:"ollama_ports,omitempty"`
}

// LLMCustomProvider mirrors configs.Provider, with a CA file reference in
// place of inline PEM.
type LLMCustomProvider struct {
	Name                 string                `yaml:"name"`
	Domains              []string              `yaml:"domains,omitempty"`
	ProfileID            string                `yaml:"profile_id,omitempty"`
	EnvKeys              []string              `yaml:"env_keys,omitempty"`
	BaseProviderType     string                `yaml:"base_provider_type,omitempty"`
	BaseURL              string                `yaml:"base_url,omitempty"`
	AllowedRequests      []string              `yaml:"allowed_requests,omitempty"`
	AvailableModels      []string              `yaml:"available_models,omitempty"`
	RequestPathOverrides map[string]string     `yaml:"request_path_overrides,omitempty"`
	TLS                  *LLMCustomProviderTLS `yaml:"tls,omitempty"`
	Bedrock              *BedrockKeyConfig     `yaml:"bedrock,omitempty"`
	Vertex               *VertexKeyConfig      `yaml:"vertex,omitempty"`
	Azure                *AzureKeyConfig       `yaml:"azure,omitempty"`
	ExtraHeaders         map[string]string     `yaml:"extra_headers,omitempty"`
}

// LLMCustomProviderTLS is a custom provider's TLS posture.
type LLMCustomProviderTLS struct {
	CACertFile         string `yaml:"ca_cert_file,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify,omitempty"`
}

// UpdateChannelStable is the only update channel in config_version 9.
const UpdateChannelStable = "stable"

// UpdateConfig is update: (config_version 9). Source only changes where
// release bytes are fetched; signatures are always verified against the
// compiled release identity.
type UpdateConfig struct {
	// Check enables the update notice; nil means true. It replaces the
	// unschematized top-level update_check key.
	Check *bool `mapstructure:"check" yaml:"check,omitempty"`
	// Channel is "stable" (or empty, meaning stable).
	Channel string `mapstructure:"channel" yaml:"channel,omitempty"`
	// Source is "" for the official GitHub releases, else an HTTPS mirror.
	Source string `mapstructure:"source" yaml:"source,omitempty"`
}

// CheckEnabled reports whether the update notice is on.
func (u UpdateConfig) CheckEnabled() bool { return u.Check == nil || *u.Check }

// Scanner judge sources (scanners.<scanner>.judge_source).
const (
	ScannerJudgeInherit  = "inherit"
	ScannerJudgeOverride = "override"
)

// SkillScannerAnalyzers holds the optional skill-scanner analyzers.
type SkillScannerAnalyzers struct {
	VirusTotal SkillScannerVirusTotal `mapstructure:"virustotal" yaml:"virustotal,omitempty"`
	AIDefense  ScannerAnalyzerToggle  `mapstructure:"aidefense"  yaml:"aidefense,omitempty"`
	OSV        ScannerAnalyzerToggle  `mapstructure:"osv"        yaml:"osv,omitempty"`
}

// SkillScannerVirusTotal is scanners.skill_scanner.analyzers.virustotal.
type SkillScannerVirusTotal struct {
	Enabled     bool   `mapstructure:"enabled"      yaml:"enabled,omitempty"`
	APIKeyEnv   string `mapstructure:"api_key_env"  yaml:"api_key_env,omitempty"`
	UploadFiles bool   `mapstructure:"upload_files" yaml:"upload_files,omitempty"`
}

// ScannerAnalyzerToggle is an analyzer with only an on/off switch.
type ScannerAnalyzerToggle struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
}

// SkillScannerTimeouts are in seconds; zero uses the defaults (300, 60).
type SkillScannerTimeouts struct {
	ScanS int `mapstructure:"scan_s" yaml:"scan_s,omitempty"`
	LLMS  int `mapstructure:"llm_s"  yaml:"llm_s,omitempty"`
}

// MCPScannerAPIConfig is scanners.mcp_scanner.api; empty values inherit
// cisco_ai_defense.endpoint and api_key_env.
type MCPScannerAPIConfig struct {
	Endpoint  string `mapstructure:"endpoint"    yaml:"endpoint,omitempty"`
	APIKeyEnv string `mapstructure:"api_key_env" yaml:"api_key_env,omitempty"`
}

// MCPScannerYARAConfig is scanners.mcp_scanner.yara.
type MCPScannerYARAConfig struct {
	// IncludeBundled defaults to true when nil.
	IncludeBundled *bool          `mapstructure:"include_bundled" yaml:"include_bundled,omitempty"`
	ExtraRules     []AssetFileRef `mapstructure:"extra_rules"     yaml:"extra_rules,omitempty"`
}

// MCPScannerTimeouts are in seconds; zero uses the defaults (60, 120, 30).
type MCPScannerTimeouts struct {
	StdioS  int `mapstructure:"stdio_s"  yaml:"stdio_s,omitempty"`
	RemoteS int `mapstructure:"remote_s" yaml:"remote_s,omitempty"`
	LLMS    int `mapstructure:"llm_s"    yaml:"llm_s,omitempty"`
}
