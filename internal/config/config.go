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
	"fmt"
	"log"
	"os"
	"path/filepath"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"
)

type ClawMode string

const (
	ClawOpenClaw ClawMode = "openclaw"
	// Future: ClawNemoClaw, ClawOpenCode, ClawClaudeCode
)

type ClawConfig struct {
	Mode       ClawMode `mapstructure:"mode"        yaml:"mode"`
	HomeDir    string   `mapstructure:"home_dir"    yaml:"home_dir"`
	ConfigFile string   `mapstructure:"config_file" yaml:"config_file"`
}

// CurrentConfigVersion is bumped when the config schema changes in a way
// that requires migration (new required fields, renamed keys, etc.).
const CurrentConfigVersion = 3

type Config struct {
	ConfigVersion     int                  `mapstructure:"config_version"        yaml:"config_version"`
	DefaultLLMAPIKeyEnv string             `mapstructure:"default_llm_api_key_env" yaml:"default_llm_api_key_env,omitempty"`
	DefaultLLMModel   string               `mapstructure:"default_llm_model"     yaml:"default_llm_model,omitempty"`
	DataDir           string               `mapstructure:"data_dir"              yaml:"data_dir"`
	AuditDB        string               `mapstructure:"audit_db"         yaml:"audit_db"`
	QuarantineDir  string               `mapstructure:"quarantine_dir"   yaml:"quarantine_dir"`
	PluginDir      string               `mapstructure:"plugin_dir"       yaml:"plugin_dir"`
	PolicyDir      string               `mapstructure:"policy_dir"       yaml:"policy_dir"`
	Environment    string               `mapstructure:"environment"      yaml:"environment"`
	Claw           ClawConfig           `mapstructure:"claw"             yaml:"claw"`
	InspectLLM     InspectLLMConfig     `mapstructure:"inspect_llm"      yaml:"inspect_llm"`
	CiscoAIDefense CiscoAIDefenseConfig `mapstructure:"cisco_ai_defense" yaml:"cisco_ai_defense"`
	Scanners       ScannersConfig       `mapstructure:"scanners"         yaml:"scanners"`
	OpenShell      OpenShellConfig      `mapstructure:"openshell"        yaml:"openshell"`
	Watch          WatchConfig          `mapstructure:"watch"            yaml:"watch"`
	Firewall       FirewallConfig       `mapstructure:"firewall"         yaml:"firewall"`
	Guardrail      GuardrailConfig      `mapstructure:"guardrail"        yaml:"guardrail"`
	Splunk         SplunkConfig         `mapstructure:"splunk"           yaml:"splunk"`
	Gateway        GatewayConfig        `mapstructure:"gateway"          yaml:"gateway"`
	SkillActions   SkillActionsConfig   `mapstructure:"skill_actions"    yaml:"skill_actions"`
	MCPActions     MCPActionsConfig     `mapstructure:"mcp_actions"      yaml:"mcp_actions"`
	PluginActions  PluginActionsConfig  `mapstructure:"plugin_actions"   yaml:"plugin_actions"`
	OTel           OTelConfig           `mapstructure:"otel"             yaml:"otel"`
	Webhooks       []WebhookConfig      `mapstructure:"webhooks"         yaml:"webhooks"`
	Budget         BudgetConfig         `mapstructure:"budget"           yaml:"budget"`
}

// BudgetConfig controls the token/cost budget enforcer that throttles LLM
// traffic to mitigate LLM-04 (Model DoS) and runaway spend. The per-subject
// limits and pricing table are defined in the OPA Rego data layer
// (policies/rego/data.json under "budget"), not here.
type BudgetConfig struct {
	// Enabled turns enforcement on. When false the enforcer is a no-op and
	// the proxy records token telemetry only.
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// Mode selects the enforcement posture:
	//   "enforce" — deny requests that would exceed budgets
	//   "monitor" — allow but log + emit audit/webhook events
	Mode string `mapstructure:"mode" yaml:"mode"`

	// SubjectHeader is the HTTP header the enforcer reads to identify the
	// caller (e.g. "X-DC-Subject"). When empty or header is missing the
	// enforcer falls back to DefaultSubject.
	SubjectHeader string `mapstructure:"subject_header" yaml:"subject_header"`

	// DefaultSubject is used when no subject header is provided. Keep as
	// "default" to share the default entry in policies/rego/data.json.
	DefaultSubject string `mapstructure:"default_subject" yaml:"default_subject"`

	// BlockMessage is the user-facing message returned when a request is
	// denied. An empty value selects a sensible default.
	BlockMessage string `mapstructure:"block_message" yaml:"block_message"`

	// LogAllowed emits an audit event for each allowed request. Disabled
	// by default because it can be noisy; enable only when investigating.
	LogAllowed bool `mapstructure:"log_allowed" yaml:"log_allowed"`
}

// IsEnforcing reports whether the budget enforcer should actively block
// requests. Monitor mode returns false so the proxy lets traffic through.
func (b *BudgetConfig) IsEnforcing() bool {
	return b.Enabled && b.Mode == "enforce"
}

// EffectiveSubjectHeader returns the configured header name or the sensible
// default. The gateway never trusts this header on its own — the enforcer
// pairs it with auth context.
func (b *BudgetConfig) EffectiveSubjectHeader() string {
	if b.SubjectHeader != "" {
		return b.SubjectHeader
	}
	return "X-DC-Subject"
}

// EffectiveDefaultSubject returns the fallback subject for unidentified
// callers. Keeping this aligned with data.budget.subjects.default ensures a
// sane enforcement floor.
func (b *BudgetConfig) EffectiveDefaultSubject() string {
	if b.DefaultSubject != "" {
		return b.DefaultSubject
	}
	return "default"
}

// ResolvedDefaultLLMAPIKey returns the shared LLM API key from the configured
// env var. Components (judge, scanners) fall back to this when they have no
// component-specific key configured.
func (c *Config) ResolvedDefaultLLMAPIKey() string {
	if c.DefaultLLMAPIKeyEnv != "" {
		if v := os.Getenv(c.DefaultLLMAPIKeyEnv); v != "" {
			return v
		}
	}
	return ""
}

// EffectiveInspectLLM returns InspectLLM with the shared default key applied
// as a fallback so callers don't need to wire the fallback themselves.
func (c *Config) EffectiveInspectLLM() InspectLLMConfig {
	llm := c.InspectLLM
	if llm.ResolvedAPIKey() == "" {
		if sharedKey := c.ResolvedDefaultLLMAPIKey(); sharedKey != "" && llm.APIKey == "" {
			llm.APIKey = sharedKey
		}
	}
	if llm.Model == "" && c.DefaultLLMModel != "" {
		llm.Model = c.DefaultLLMModel
	}
	return llm
}

type OTelConfig struct {
	Enabled  bool               `mapstructure:"enabled"  yaml:"enabled"`
	Protocol string             `mapstructure:"protocol" yaml:"protocol"`
	Endpoint string             `mapstructure:"endpoint" yaml:"endpoint"`
	Headers  map[string]string  `mapstructure:"headers"  yaml:"headers"`
	TLS      OTelTLSConfig      `mapstructure:"tls"      yaml:"tls"`
	Traces   OTelTracesConfig   `mapstructure:"traces"   yaml:"traces"`
	Logs     OTelLogsConfig     `mapstructure:"logs"     yaml:"logs"`
	Metrics  OTelMetricsConfig  `mapstructure:"metrics"  yaml:"metrics"`
	Batch    OTelBatchConfig    `mapstructure:"batch"    yaml:"batch"`
	Resource OTelResourceConfig `mapstructure:"resource" yaml:"resource"`
}

type OTelTLSConfig struct {
	Insecure bool   `mapstructure:"insecure" yaml:"insecure"`
	CACert   string `mapstructure:"ca_cert"  yaml:"ca_cert"`
}

type OTelTracesConfig struct {
	Enabled    bool   `mapstructure:"enabled"     yaml:"enabled"`
	Sampler    string `mapstructure:"sampler"      yaml:"sampler"`
	SamplerArg string `mapstructure:"sampler_arg"  yaml:"sampler_arg"`
	Endpoint   string `mapstructure:"endpoint"     yaml:"endpoint"`
	Protocol   string `mapstructure:"protocol"     yaml:"protocol"`
	URLPath    string `mapstructure:"url_path"     yaml:"url_path"`
}

type OTelLogsConfig struct {
	Enabled                bool   `mapstructure:"enabled"                  yaml:"enabled"`
	EmitIndividualFindings bool   `mapstructure:"emit_individual_findings" yaml:"emit_individual_findings"`
	Endpoint               string `mapstructure:"endpoint"                 yaml:"endpoint"`
	Protocol               string `mapstructure:"protocol"                 yaml:"protocol"`
	URLPath                string `mapstructure:"url_path"                 yaml:"url_path"`
}

type OTelMetricsConfig struct {
	Enabled         bool   `mapstructure:"enabled"            yaml:"enabled"`
	ExportIntervalS int    `mapstructure:"export_interval_s"  yaml:"export_interval_s"`
	Temporality     string `mapstructure:"temporality"         yaml:"temporality"`
	Endpoint        string `mapstructure:"endpoint"           yaml:"endpoint"`
	Protocol        string `mapstructure:"protocol"           yaml:"protocol"`
	URLPath         string `mapstructure:"url_path"           yaml:"url_path"`
}

type OTelBatchConfig struct {
	MaxExportBatchSize int `mapstructure:"max_export_batch_size" yaml:"max_export_batch_size"`
	ScheduledDelayMs   int `mapstructure:"scheduled_delay_ms"    yaml:"scheduled_delay_ms"`
	MaxQueueSize       int `mapstructure:"max_queue_size"         yaml:"max_queue_size"`
}

type OTelResourceConfig struct {
	Attributes map[string]string `mapstructure:"attributes" yaml:"attributes"`
}

type FirewallConfig struct {
	ConfigFile string `mapstructure:"config_file" yaml:"config_file"`
	RulesFile  string `mapstructure:"rules_file"  yaml:"rules_file"`
	AnchorName string `mapstructure:"anchor_name" yaml:"anchor_name"`
}

type SplunkConfig struct {
	HECEndpoint   string `mapstructure:"hec_endpoint"    yaml:"hec_endpoint"`
	HECToken      string `mapstructure:"hec_token"       yaml:"hec_token"`
	HECTokenEnv   string `mapstructure:"hec_token_env"   yaml:"hec_token_env"`
	Index         string `mapstructure:"index"            yaml:"index"`
	Source        string `mapstructure:"source"           yaml:"source"`
	SourceType    string `mapstructure:"sourcetype"       yaml:"sourcetype"`
	VerifyTLS     bool   `mapstructure:"verify_tls"       yaml:"verify_tls"`
	Enabled       bool   `mapstructure:"enabled"          yaml:"enabled"`
	BatchSize     int    `mapstructure:"batch_size"       yaml:"batch_size"`
	FlushInterval int    `mapstructure:"flush_interval_s" yaml:"flush_interval_s"`
}

// ResolvedHECToken returns the HEC token from the env var (if set) or the direct value.
func (c *SplunkConfig) ResolvedHECToken() string {
	if c.HECTokenEnv != "" {
		if v := os.Getenv(c.HECTokenEnv); v != "" {
			return v
		}
	}
	return c.HECToken
}

type WebhookConfig struct {
	URL             string   `mapstructure:"url"              yaml:"url"`
	Type            string   `mapstructure:"type"             yaml:"type"`
	SecretEnv       string   `mapstructure:"secret_env"       yaml:"secret_env"`
	RoomID          string   `mapstructure:"room_id"          yaml:"room_id"`
	MinSeverity     string   `mapstructure:"min_severity"     yaml:"min_severity"`
	Events          []string `mapstructure:"events"           yaml:"events"`
	TimeoutSeconds  int      `mapstructure:"timeout_seconds"  yaml:"timeout_seconds"`
	CooldownSeconds *int     `mapstructure:"cooldown_seconds" yaml:"cooldown_seconds,omitempty"`
	Enabled         bool     `mapstructure:"enabled"          yaml:"enabled"`
}

// ResolvedSecret returns the webhook secret/token from the env var.
func (c *WebhookConfig) ResolvedSecret() string {
	if c.SecretEnv != "" {
		return os.Getenv(c.SecretEnv)
	}
	return ""
}

type WatchConfig struct {
	DebounceMs          int  `mapstructure:"debounce_ms"            yaml:"debounce_ms"`
	AutoBlock           bool `mapstructure:"auto_block"             yaml:"auto_block"`
	AllowListBypassScan bool `mapstructure:"allow_list_bypass_scan" yaml:"allow_list_bypass_scan"`
	RescanEnabled       bool `mapstructure:"rescan_enabled"         yaml:"rescan_enabled"`
	RescanIntervalMin   int  `mapstructure:"rescan_interval_min"    yaml:"rescan_interval_min"`
}

type InspectLLMConfig struct {
	Provider   string `mapstructure:"provider"    yaml:"provider"`
	Model      string `mapstructure:"model"       yaml:"model"`
	APIKey     string `mapstructure:"api_key"     yaml:"api_key"`
	APIKeyEnv  string `mapstructure:"api_key_env" yaml:"api_key_env"`
	BaseURL    string `mapstructure:"base_url"    yaml:"base_url"`
	Timeout    int    `mapstructure:"timeout"     yaml:"timeout"`
	MaxRetries int    `mapstructure:"max_retries" yaml:"max_retries"`
}

// ResolvedAPIKey returns the API key from the env var (if set) or the direct value.
func (c *InspectLLMConfig) ResolvedAPIKey() string {
	if c.APIKeyEnv != "" {
		if v := os.Getenv(c.APIKeyEnv); v != "" {
			return v
		}
	}
	return c.APIKey
}

type SkillScannerConfig struct {
	Binary           string `mapstructure:"binary"                 yaml:"binary"`
	UseLLM           bool   `mapstructure:"use_llm"                yaml:"use_llm"`
	UseBehavioral    bool   `mapstructure:"use_behavioral"         yaml:"use_behavioral"`
	EnableMeta       bool   `mapstructure:"enable_meta"            yaml:"enable_meta"`
	UseTrigger       bool   `mapstructure:"use_trigger"            yaml:"use_trigger"`
	UseVirusTotal    bool   `mapstructure:"use_virustotal"         yaml:"use_virustotal"`
	UseAIDefense     bool   `mapstructure:"use_aidefense"          yaml:"use_aidefense"`
	LLMConsensus     int    `mapstructure:"llm_consensus_runs"     yaml:"llm_consensus_runs"`
	Policy           string `mapstructure:"policy"                 yaml:"policy"`
	Lenient          bool   `mapstructure:"lenient"                yaml:"lenient"`
	VirusTotalKey    string `mapstructure:"virustotal_api_key"     yaml:"virustotal_api_key"`
	VirusTotalKeyEnv string `mapstructure:"virustotal_api_key_env" yaml:"virustotal_api_key_env"`
}

// ResolvedVirusTotalKey returns the VirusTotal key from the env var (if set) or the direct value.
func (c *SkillScannerConfig) ResolvedVirusTotalKey() string {
	if c.VirusTotalKeyEnv != "" {
		if v := os.Getenv(c.VirusTotalKeyEnv); v != "" {
			return v
		}
	}
	return c.VirusTotalKey
}

type MCPScannerConfig struct {
	Binary           string `mapstructure:"binary"            yaml:"binary"`
	Analyzers        string `mapstructure:"analyzers"         yaml:"analyzers"`
	ScanPrompts      bool   `mapstructure:"scan_prompts"      yaml:"scan_prompts"`
	ScanResources    bool   `mapstructure:"scan_resources"    yaml:"scan_resources"`
	ScanInstructions bool   `mapstructure:"scan_instructions" yaml:"scan_instructions"`
}

type ScannersConfig struct {
	SkillScanner  SkillScannerConfig `mapstructure:"skill_scanner"  yaml:"skill_scanner"`
	MCPScanner    MCPScannerConfig   `mapstructure:"mcp_scanner"    yaml:"mcp_scanner"`
	PluginScanner string             `mapstructure:"plugin_scanner" yaml:"plugin_scanner"`
	CodeGuard     string             `mapstructure:"codeguard"       yaml:"codeguard"`
}

type OpenShellConfig struct {
	Binary         string `mapstructure:"binary"        yaml:"binary"`
	PolicyDir      string `mapstructure:"policy_dir"    yaml:"policy_dir"`
	Mode           string `mapstructure:"mode"           yaml:"mode,omitempty"`
	Version        string `mapstructure:"version"        yaml:"version,omitempty"`
	SandboxHome    string `mapstructure:"sandbox_home"   yaml:"sandbox_home,omitempty"`
	AutoPair       *bool  `mapstructure:"auto_pair"      yaml:"auto_pair,omitempty"`
	HostNetworking *bool  `mapstructure:"host_networking" yaml:"host_networking,omitempty"`
}

const DefaultOpenShellVersion = "0.6.2"
const DefaultSandboxHome = "/home/sandbox"

// IsStandalone returns true when openshell-sandbox is running in standalone
// Linux supervisor mode (Landlock + seccomp + network namespace, no Docker).
func (o *OpenShellConfig) IsStandalone() bool {
	return o.Mode == "standalone"
}

// EffectiveVersion returns the configured OpenShell version or the default.
func (o *OpenShellConfig) EffectiveVersion() string {
	if o.Version != "" {
		return o.Version
	}
	return DefaultOpenShellVersion
}

// EffectiveSandboxHome returns the configured sandbox home or the default.
func (o *OpenShellConfig) EffectiveSandboxHome() string {
	if o.SandboxHome != "" {
		return o.SandboxHome
	}
	return DefaultSandboxHome
}

// ShouldAutoPair returns whether device pre-pairing is enabled.
// Defaults to true when not explicitly set.
func (o *OpenShellConfig) ShouldAutoPair() bool {
	if o.AutoPair != nil {
		return *o.AutoPair
	}
	return true
}

// HostNetworkingEnabled returns whether DefenseClaw should manage host-side
// iptables rules for the sandbox (DNS forwarding, UI port forwarding,
// guardrail redirect, MASQUERADE). Defaults to true when not explicitly set.
func (o *OpenShellConfig) HostNetworkingEnabled() bool {
	if o.HostNetworking != nil {
		return *o.HostNetworking
	}
	return true
}

type GatewayWatcherSkillConfig struct {
	Enabled    bool     `mapstructure:"enabled"      yaml:"enabled"`
	TakeAction bool     `mapstructure:"take_action"   yaml:"take_action"`
	Dirs       []string `mapstructure:"dirs"           yaml:"dirs"`
}

type GatewayWatcherPluginConfig struct {
	Enabled    bool     `mapstructure:"enabled"      yaml:"enabled"`
	TakeAction bool     `mapstructure:"take_action"   yaml:"take_action"`
	Dirs       []string `mapstructure:"dirs"           yaml:"dirs"`
}

type GatewayWatcherMCPConfig struct {
	TakeAction bool `mapstructure:"take_action" yaml:"take_action"`
}

type GatewayWatcherConfig struct {
	Enabled bool                       `mapstructure:"enabled" yaml:"enabled"`
	Skill   GatewayWatcherSkillConfig  `mapstructure:"skill"   yaml:"skill"`
	Plugin  GatewayWatcherPluginConfig `mapstructure:"plugin"  yaml:"plugin"`
	MCP     GatewayWatcherMCPConfig    `mapstructure:"mcp"     yaml:"mcp"`
}

type CiscoAIDefenseConfig struct {
	Endpoint     string   `mapstructure:"endpoint"       yaml:"endpoint"`
	APIKey       string   `mapstructure:"api_key"        yaml:"api_key"`
	APIKeyEnv    string   `mapstructure:"api_key_env"    yaml:"api_key_env"`
	TimeoutMs    int      `mapstructure:"timeout_ms"     yaml:"timeout_ms"`
	EnabledRules []string `mapstructure:"enabled_rules"  yaml:"enabled_rules"`
}

// ResolvedAPIKey returns the API key from the env var (if set) or the direct value.
func (c *CiscoAIDefenseConfig) ResolvedAPIKey() string {
	if c.APIKeyEnv != "" {
		if v := os.Getenv(c.APIKeyEnv); v != "" {
			return v
		}
	}
	return c.APIKey
}

type GuardrailConfig struct {
	Enabled           bool        `mapstructure:"enabled"              yaml:"enabled"`
	Mode              string      `mapstructure:"mode"                 yaml:"mode"`
	ScannerMode       string      `mapstructure:"scanner_mode"         yaml:"scanner_mode"`
	Host              string      `mapstructure:"host"                 yaml:"host,omitempty"`
	Port              int         `mapstructure:"port"                 yaml:"port"`
	Model             string      `mapstructure:"model"                yaml:"model"`
	ModelName         string      `mapstructure:"model_name"           yaml:"model_name"`
	APIKeyEnv         string      `mapstructure:"api_key_env"          yaml:"api_key_env"`
	OriginalModel     string      `mapstructure:"original_model"       yaml:"original_model"`
	BlockMessage      string      `mapstructure:"block_message"        yaml:"block_message"`
	APIBase           string      `mapstructure:"api_base"             yaml:"api_base"`
	StreamBufferBytes int         `mapstructure:"stream_buffer_bytes"  yaml:"stream_buffer_bytes"`
	RulePackDir       string      `mapstructure:"rule_pack_dir"        yaml:"rule_pack_dir"`
	Judge             JudgeConfig `mapstructure:"judge"                yaml:"judge"`

	// Detection strategy: "regex_only" (default), "regex_judge", "judge_first".
	// Per-direction overrides take precedence over the global setting.
	DetectionStrategy           string `mapstructure:"detection_strategy"            yaml:"detection_strategy,omitempty"`
	DetectionStrategyPrompt     string `mapstructure:"detection_strategy_prompt"     yaml:"detection_strategy_prompt,omitempty"`
	DetectionStrategyCompletion string `mapstructure:"detection_strategy_completion" yaml:"detection_strategy_completion,omitempty"`
	DetectionStrategyToolCall   string `mapstructure:"detection_strategy_tool_call"  yaml:"detection_strategy_tool_call,omitempty"`
	JudgeSweep                  bool   `mapstructure:"judge_sweep"                  yaml:"judge_sweep,omitempty"`
}

// EffectiveStrategy returns the detection strategy for the given direction,
// falling back to the global DetectionStrategy (default: "regex_only").
func (g *GuardrailConfig) EffectiveStrategy(direction string) string {
	var override string
	switch direction {
	case "prompt":
		override = g.DetectionStrategyPrompt
	case "completion":
		override = g.DetectionStrategyCompletion
	case "tool_call":
		override = g.DetectionStrategyToolCall
	}
	if override != "" {
		return override
	}
	if g.DetectionStrategy != "" {
		return g.DetectionStrategy
	}
	return "regex_judge"
}

// JudgeConfig controls the LLM-as-a-Judge guardrail scanners that use
// an LLM to detect prompt injection and PII exfiltration.
type JudgeConfig struct {
	Enabled       bool    `mapstructure:"enabled"         yaml:"enabled"`
	Injection     bool    `mapstructure:"injection"       yaml:"injection"`
	PII           bool    `mapstructure:"pii"             yaml:"pii"`
	PIIPrompt     bool    `mapstructure:"pii_prompt"      yaml:"pii_prompt"`
	PIICompletion bool    `mapstructure:"pii_completion"  yaml:"pii_completion"`
	ToolInjection bool    `mapstructure:"tool_injection"  yaml:"tool_injection"`
	Model         string  `mapstructure:"model"           yaml:"model"`
	APIKeyEnv     string  `mapstructure:"api_key_env"     yaml:"api_key_env"`
	APIBase       string  `mapstructure:"api_base"        yaml:"api_base"`
	Timeout       float64 `mapstructure:"timeout"         yaml:"timeout"`

	Fallbacks           []string `mapstructure:"fallbacks"            yaml:"fallbacks,omitempty"`
	AdjudicationTimeout float64  `mapstructure:"adjudication_timeout" yaml:"adjudication_timeout,omitempty"`
}

// ResolvedJudgeAPIKey returns the judge API key from the env var.
func (c *JudgeConfig) ResolvedJudgeAPIKey() string {
	if c.APIKeyEnv != "" {
		if v := os.Getenv(c.APIKeyEnv); v != "" {
			return v
		}
	}
	return ""
}

// ResolvedJudgeAPIKeyWithFallback returns the judge key, falling back to the
// shared default LLM key when none is configured.
func (c *JudgeConfig) ResolvedJudgeAPIKeyWithFallback(sharedKey string) string {
	if k := c.ResolvedJudgeAPIKey(); k != "" {
		return k
	}
	return sharedKey
}

// EffectiveHost returns the hostname clients (e.g. OpenClaw) use to reach the
// guardrail proxy — same value written to openclaw.json baseUrl. Defaults to
// "127.0.0.1" when not configured so macOS IPv6-first resolution of
// "localhost" (→ ::1) does not silently bypass the IPv4-only proxy.
func (g *GuardrailConfig) EffectiveHost() string {
	if g.Host != "" {
		return g.Host
	}
	return "127.0.0.1"
}

type GatewayConfig struct {
	Host            string               `mapstructure:"host"              yaml:"host"`
	Port            int                  `mapstructure:"port"              yaml:"port"`
	Token           string               `mapstructure:"token"             yaml:"token,omitempty"`
	TokenEnv        string               `mapstructure:"token_env"         yaml:"token_env"`
	TLS             bool                 `mapstructure:"tls"               yaml:"tls"`
	TLSSkipVerify   bool                 `mapstructure:"tls_skip_verify"   yaml:"tls_skip_verify"`
	NoTLS           bool                 `mapstructure:"-"                 yaml:"-"`
	DeviceKeyFile   string               `mapstructure:"device_key_file"   yaml:"device_key_file"`
	AutoApprove     bool                 `mapstructure:"auto_approve_safe" yaml:"auto_approve_safe"`
	ReconnectMs     int                  `mapstructure:"reconnect_ms"      yaml:"reconnect_ms"`
	MaxReconnectMs  int                  `mapstructure:"max_reconnect_ms"  yaml:"max_reconnect_ms"`
	ApprovalTimeout int                  `mapstructure:"approval_timeout_s" yaml:"approval_timeout_s"`
	APIPort         int                  `mapstructure:"api_port"           yaml:"api_port"`
	APIBind         string               `mapstructure:"api_bind"           yaml:"api_bind"`
	Watcher         GatewayWatcherConfig `mapstructure:"watcher"            yaml:"watcher"`
	Watchdog        WatchdogConfig       `mapstructure:"watchdog"           yaml:"watchdog"`
	SandboxHome     string               `mapstructure:"-"                  yaml:"-"`
	ClawHome        string               `mapstructure:"-"                  yaml:"-"`
}

// WatchdogConfig controls the health watchdog that notifies users when the
// gateway is down and they lack protection.
type WatchdogConfig struct {
	Enabled  bool `mapstructure:"enabled"  yaml:"enabled"`
	Interval int  `mapstructure:"interval" yaml:"interval"` // seconds between polls, default 30
	Debounce int  `mapstructure:"debounce" yaml:"debounce"` // consecutive failures before alert, default 2
}

// defaultOpenClawGatewayTokenEnv matches gateway.auth.token when copied to ~/.defenseclaw/.env.
const defaultOpenClawGatewayTokenEnv = "OPENCLAW_GATEWAY_TOKEN"

// ResolvedToken returns the gateway token from the env var (if set) or the direct value.
// When token_env is empty (legacy configs), OPENCLAW_GATEWAY_TOKEN is still consulted so
// secrets loaded from ~/.defenseclaw/.env by the sidecar are visible.
func (g *GatewayConfig) ResolvedToken() string {
	if g.TokenEnv != "" {
		if v := os.Getenv(g.TokenEnv); v != "" {
			return v
		}
	} else if v := os.Getenv(defaultOpenClawGatewayTokenEnv); v != "" {
		return v
	}
	return g.Token
}

// RequiresTLS returns true when TLS should be used for the gateway connection.
// When gateway.tls is true, TLS is always required. Otherwise, non-loopback hosts
// require TLS to protect tokens in transit.
func (g *GatewayConfig) RequiresTLS() bool {
	if g.NoTLS {
		return false
	}
	if g.TLS {
		return true
	}
	switch g.Host {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return false
	default:
		return true
	}
}

// RequiresTLSWithMode is like RequiresTLS but treats openshell standalone mode as
// point-to-point (no TLS) unless gateway.tls forces it on.
func (g *GatewayConfig) RequiresTLSWithMode(openshell *OpenShellConfig) bool {
	if g.TLS {
		return true
	}
	if openshell != nil && openshell.IsStandalone() {
		return false
	}
	switch g.Host {
	case "", "127.0.0.1", "localhost", "::1", "[::1]":
		return false
	default:
		return true
	}
}

type RuntimeAction string

const (
	RuntimeDisable RuntimeAction = "disable"
	RuntimeEnable  RuntimeAction = "enable"
)

type FileAction string

const (
	FileActionNone       FileAction = "none"
	FileActionQuarantine FileAction = "quarantine"
)

type InstallAction string

const (
	InstallBlock InstallAction = "block"
	InstallAllow InstallAction = "allow"
	InstallNone  InstallAction = "none"
)

type SeverityAction struct {
	File    FileAction    `mapstructure:"file"    yaml:"file"`
	Runtime RuntimeAction `mapstructure:"runtime" yaml:"runtime"`
	Install InstallAction `mapstructure:"install" yaml:"install"`
}

type SkillActionsConfig struct {
	Critical SeverityAction `mapstructure:"critical" yaml:"critical"`
	High     SeverityAction `mapstructure:"high"     yaml:"high"`
	Medium   SeverityAction `mapstructure:"medium"   yaml:"medium"`
	Low      SeverityAction `mapstructure:"low"      yaml:"low"`
	Info     SeverityAction `mapstructure:"info"     yaml:"info"`
}

type MCPActionsConfig struct {
	Critical SeverityAction `mapstructure:"critical" yaml:"critical"`
	High     SeverityAction `mapstructure:"high"     yaml:"high"`
	Medium   SeverityAction `mapstructure:"medium"   yaml:"medium"`
	Low      SeverityAction `mapstructure:"low"      yaml:"low"`
	Info     SeverityAction `mapstructure:"info"     yaml:"info"`
}

type PluginActionsConfig struct {
	Critical SeverityAction `mapstructure:"critical" yaml:"critical"`
	High     SeverityAction `mapstructure:"high"     yaml:"high"`
	Medium   SeverityAction `mapstructure:"medium"   yaml:"medium"`
	Low      SeverityAction `mapstructure:"low"      yaml:"low"`
	Info     SeverityAction `mapstructure:"info"     yaml:"info"`
}

func Load() (*Config, error) {
	dataDir := DefaultDataPath()
	configFile := filepath.Join(dataDir, DefaultConfigName)

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	setDefaults(dataDir)

	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			if !os.IsNotExist(err) {
				return nil, fmt.Errorf("config: read %s: %w", configFile, err)
			}
		}
	}

	// Backward compat: legacy configs store mcp_scanner as a bare string.
	if v := viper.Get("scanners.mcp_scanner"); v != nil {
		if s, ok := v.(string); ok {
			viper.Set("scanners.mcp_scanner", map[string]interface{}{
				"binary": s,
			})
		}
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	migrateConfig(&cfg)

	if err := cfg.SkillActions.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.MCPActions.Validate(); err != nil {
		return nil, err
	}
	if err := cfg.PluginActions.Validate(); err != nil {
		return nil, err
	}
	if cfg.OpenShell.IsStandalone() {
		cfg.Gateway.SandboxHome = cfg.OpenShell.EffectiveSandboxHome()
	}

	if home, err := os.UserHomeDir(); err == nil {
		cfg.Gateway.ClawHome = home
	}

	warnPlaintextSecrets(&cfg)
	return &cfg, nil
}

// migrateConfig applies forward migrations when config_version is behind
// CurrentConfigVersion. Each migration step is idempotent.
func migrateConfig(cfg *Config) {
	if cfg.ConfigVersion >= CurrentConfigVersion {
		return
	}

	oldVersion := cfg.ConfigVersion

	// v0/v1 → v2: ensure detection_strategy defaults are populated
	if cfg.ConfigVersion < 2 {
		if cfg.Guardrail.DetectionStrategy == "" {
			cfg.Guardrail.DetectionStrategy = "regex_only"
		}
		if cfg.Guardrail.Mode == "" {
			cfg.Guardrail.Mode = "observe"
		}
		if cfg.Guardrail.RulePackDir == "" {
			cfg.Guardrail.RulePackDir = filepath.Join(cfg.DataDir, "policies", "guardrail", "default")
		}
		if cfg.Guardrail.StreamBufferBytes == 0 {
			cfg.Guardrail.StreamBufferBytes = 1024
		}
	}

	// v2 → v3: upgrade detection_strategy to regex_judge when judge is
	// enabled, add completion-specific strategy, wire shared LLM key
	if cfg.ConfigVersion < 3 {
		if cfg.Guardrail.Judge.Enabled && cfg.Guardrail.DetectionStrategy == "regex_only" {
			cfg.Guardrail.DetectionStrategy = "regex_judge"
		}
		if cfg.Guardrail.DetectionStrategyCompletion == "" {
			cfg.Guardrail.DetectionStrategyCompletion = "regex_only"
		}
	}

	cfg.ConfigVersion = CurrentConfigVersion
	log.Printf("[config] migrated config from version %d to %d", oldVersion, CurrentConfigVersion)
}

// warnPlaintextSecrets logs a deprecation warning for each secret stored as
// plain text in config.yaml instead of via an env-var indirection.
func warnPlaintextSecrets(cfg *Config) {
	warn := func(section, field, envDefault string) {
		log.Printf("WARNING: %s.%s contains a plain-text secret in config.yaml — "+
			"migrate it to ~/.defenseclaw/.env as %s and set %s.%s_env=%s instead",
			section, field, envDefault, section, field, envDefault)
	}
	if cfg.InspectLLM.APIKey != "" {
		warn("inspect_llm", "api_key", "LLM_API_KEY")
	}
	if cfg.CiscoAIDefense.APIKey != "" {
		warn("cisco_ai_defense", "api_key", "CISCO_AI_DEFENSE_API_KEY")
	}
	if cfg.Scanners.SkillScanner.VirusTotalKey != "" {
		warn("scanners.skill_scanner", "virustotal_api_key", "VIRUSTOTAL_API_KEY")
	}
	if cfg.Splunk.HECToken != "" {
		warn("splunk", "hec_token", "DEFENSECLAW_SPLUNK_HEC_TOKEN")
	}
}

func (c *Config) Save() error {
	configFile := filepath.Join(c.DataDir, DefaultConfigName)

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	return os.WriteFile(configFile, data, 0o600)
}

func setDefaults(dataDir string) {
	viper.SetDefault("data_dir", dataDir)
	viper.SetDefault("audit_db", filepath.Join(dataDir, DefaultAuditDBName))
	viper.SetDefault("quarantine_dir", filepath.Join(dataDir, "quarantine"))
	viper.SetDefault("plugin_dir", filepath.Join(dataDir, "plugins"))
	viper.SetDefault("policy_dir", filepath.Join(dataDir, "policies"))
	viper.SetDefault("environment", string(DetectEnvironment()))
	viper.SetDefault("claw.mode", string(ClawOpenClaw))
	viper.SetDefault("claw.home_dir", "~/.openclaw")
	viper.SetDefault("claw.config_file", "~/.openclaw/openclaw.json")

	viper.SetDefault("inspect_llm.provider", "")
	viper.SetDefault("inspect_llm.model", "")
	viper.SetDefault("inspect_llm.api_key", "")
	viper.SetDefault("inspect_llm.api_key_env", "")
	viper.SetDefault("inspect_llm.base_url", "")
	viper.SetDefault("inspect_llm.timeout", 30)
	viper.SetDefault("inspect_llm.max_retries", 3)

	viper.SetDefault("cisco_ai_defense.endpoint", "https://us.api.inspect.aidefense.security.cisco.com")
	viper.SetDefault("cisco_ai_defense.api_key", "")
	viper.SetDefault("cisco_ai_defense.api_key_env", "CISCO_AI_DEFENSE_API_KEY")
	viper.SetDefault("cisco_ai_defense.timeout_ms", 3000)
	viper.SetDefault("cisco_ai_defense.enabled_rules", []string{})

	viper.SetDefault("scanners.skill_scanner.binary", "skill-scanner")
	viper.SetDefault("scanners.skill_scanner.use_llm", false)
	viper.SetDefault("scanners.skill_scanner.use_behavioral", false)
	viper.SetDefault("scanners.skill_scanner.enable_meta", false)
	viper.SetDefault("scanners.skill_scanner.use_trigger", false)
	viper.SetDefault("scanners.skill_scanner.use_virustotal", false)
	viper.SetDefault("scanners.skill_scanner.use_aidefense", false)
	viper.SetDefault("scanners.skill_scanner.llm_consensus_runs", 0)
	viper.SetDefault("scanners.skill_scanner.policy", "permissive")
	viper.SetDefault("scanners.skill_scanner.lenient", true)
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key", "")
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key_env", "VIRUSTOTAL_API_KEY")
	viper.SetDefault("scanners.mcp_scanner.binary", "mcp-scanner")
	viper.SetDefault("scanners.mcp_scanner.analyzers", "yara")
	viper.SetDefault("scanners.mcp_scanner.scan_prompts", false)
	viper.SetDefault("scanners.mcp_scanner.scan_resources", false)
	viper.SetDefault("scanners.mcp_scanner.scan_instructions", false)
	viper.SetDefault("scanners.plugin_scanner", "defenseclaw")
	viper.SetDefault("scanners.codeguard", filepath.Join(dataDir, "codeguard-rules"))
	viper.SetDefault("openshell.binary", "openshell")
	viper.SetDefault("openshell.policy_dir", "/etc/openshell/policies")
	viper.SetDefault("openshell.version", DefaultOpenShellVersion)
	viper.SetDefault("openshell.host_networking", true)

	viper.SetDefault("watch.debounce_ms", 500)
	viper.SetDefault("watch.auto_block", true)
	viper.SetDefault("watch.allow_list_bypass_scan", true)
	viper.SetDefault("watch.rescan_enabled", true)
	viper.SetDefault("watch.rescan_interval_min", 60)

	viper.SetDefault("splunk.hec_endpoint", "https://localhost:8088/services/collector/event")
	viper.SetDefault("splunk.hec_token", "")
	viper.SetDefault("splunk.hec_token_env", "DEFENSECLAW_SPLUNK_HEC_TOKEN")
	viper.SetDefault("splunk.index", "defenseclaw")
	viper.SetDefault("splunk.source", "defenseclaw")
	viper.SetDefault("splunk.sourcetype", "_json")
	viper.SetDefault("splunk.verify_tls", false)
	viper.SetDefault("splunk.enabled", false)
	viper.SetDefault("splunk.batch_size", 50)
	viper.SetDefault("splunk.flush_interval_s", 5)

	viper.SetDefault("skill_actions.critical.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.critical.runtime", string(RuntimeDisable))
	viper.SetDefault("skill_actions.critical.install", string(InstallBlock))
	viper.SetDefault("skill_actions.high.file", string(FileActionQuarantine))
	viper.SetDefault("skill_actions.high.runtime", string(RuntimeDisable))
	viper.SetDefault("skill_actions.high.install", string(InstallBlock))
	viper.SetDefault("skill_actions.medium.file", string(FileActionNone))
	viper.SetDefault("skill_actions.medium.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.medium.install", string(InstallNone))
	viper.SetDefault("skill_actions.low.file", string(FileActionNone))
	viper.SetDefault("skill_actions.low.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.low.install", string(InstallNone))
	viper.SetDefault("skill_actions.info.file", string(FileActionNone))
	viper.SetDefault("skill_actions.info.runtime", string(RuntimeEnable))
	viper.SetDefault("skill_actions.info.install", string(InstallNone))

	viper.SetDefault("mcp_actions.critical.file", string(FileActionNone))
	viper.SetDefault("mcp_actions.critical.runtime", string(RuntimeEnable))
	viper.SetDefault("mcp_actions.critical.install", string(InstallBlock))
	viper.SetDefault("mcp_actions.high.file", string(FileActionNone))
	viper.SetDefault("mcp_actions.high.runtime", string(RuntimeEnable))
	viper.SetDefault("mcp_actions.high.install", string(InstallBlock))
	viper.SetDefault("mcp_actions.medium.file", string(FileActionNone))
	viper.SetDefault("mcp_actions.medium.runtime", string(RuntimeEnable))
	viper.SetDefault("mcp_actions.medium.install", string(InstallNone))
	viper.SetDefault("mcp_actions.low.file", string(FileActionNone))
	viper.SetDefault("mcp_actions.low.runtime", string(RuntimeEnable))
	viper.SetDefault("mcp_actions.low.install", string(InstallNone))
	viper.SetDefault("mcp_actions.info.file", string(FileActionNone))
	viper.SetDefault("mcp_actions.info.runtime", string(RuntimeEnable))
	viper.SetDefault("mcp_actions.info.install", string(InstallNone))

	viper.SetDefault("plugin_actions.critical.file", string(FileActionNone))
	viper.SetDefault("plugin_actions.critical.runtime", string(RuntimeEnable))
	viper.SetDefault("plugin_actions.critical.install", string(InstallNone))
	viper.SetDefault("plugin_actions.high.file", string(FileActionNone))
	viper.SetDefault("plugin_actions.high.runtime", string(RuntimeEnable))
	viper.SetDefault("plugin_actions.high.install", string(InstallNone))
	viper.SetDefault("plugin_actions.medium.file", string(FileActionNone))
	viper.SetDefault("plugin_actions.medium.runtime", string(RuntimeEnable))
	viper.SetDefault("plugin_actions.medium.install", string(InstallNone))
	viper.SetDefault("plugin_actions.low.file", string(FileActionNone))
	viper.SetDefault("plugin_actions.low.runtime", string(RuntimeEnable))
	viper.SetDefault("plugin_actions.low.install", string(InstallNone))
	viper.SetDefault("plugin_actions.info.file", string(FileActionNone))
	viper.SetDefault("plugin_actions.info.runtime", string(RuntimeEnable))
	viper.SetDefault("plugin_actions.info.install", string(InstallNone))

	viper.SetDefault("guardrail.enabled", false)
	viper.SetDefault("guardrail.mode", "observe")
	viper.SetDefault("guardrail.scanner_mode", "both")
	viper.SetDefault("guardrail.host", "")
	viper.SetDefault("guardrail.port", 4000)
	viper.SetDefault("guardrail.stream_buffer_bytes", 1024)
	viper.SetDefault("guardrail.block_message", "")
	viper.SetDefault("guardrail.rule_pack_dir", filepath.Join(dataDir, "policies", "guardrail", "default"))
	viper.SetDefault("guardrail.judge.enabled", false)
	viper.SetDefault("guardrail.judge.injection", true)
	viper.SetDefault("guardrail.judge.pii", true)
	viper.SetDefault("guardrail.judge.pii_prompt", true)
	viper.SetDefault("guardrail.judge.pii_completion", true)
	viper.SetDefault("guardrail.judge.tool_injection", true)
	viper.SetDefault("guardrail.judge.timeout", 30.0)
	viper.SetDefault("guardrail.judge.adjudication_timeout", 5.0)
	viper.SetDefault("guardrail.detection_strategy", "regex_judge")
	viper.SetDefault("guardrail.detection_strategy_completion", "regex_only")

	viper.SetDefault("budget.enabled", false)
	viper.SetDefault("budget.mode", "monitor")
	viper.SetDefault("budget.subject_header", "X-DC-Subject")
	viper.SetDefault("budget.default_subject", "default")
	viper.SetDefault("budget.block_message", "")
	viper.SetDefault("budget.log_allowed", false)

	viper.SetDefault("gateway.host", "127.0.0.1")
	viper.SetDefault("gateway.port", 18789)
	viper.SetDefault("gateway.token_env", "OPENCLAW_GATEWAY_TOKEN")
	viper.SetDefault("gateway.device_key_file", filepath.Join(dataDir, "device.key"))
	viper.SetDefault("gateway.auto_approve_safe", false)
	viper.SetDefault("gateway.reconnect_ms", 800)
	viper.SetDefault("gateway.max_reconnect_ms", 15000)
	viper.SetDefault("gateway.approval_timeout_s", 30)
	viper.SetDefault("gateway.api_port", 18970)
	viper.SetDefault("gateway.watcher.enabled", true)
	viper.SetDefault("gateway.watcher.skill.enabled", true)
	viper.SetDefault("gateway.watcher.skill.take_action", true)
	viper.SetDefault("gateway.watcher.skill.dirs", []string{})
	viper.SetDefault("gateway.watcher.plugin.enabled", true)
	viper.SetDefault("gateway.watcher.plugin.take_action", true)
	viper.SetDefault("gateway.watcher.plugin.dirs", []string{})
	viper.SetDefault("gateway.watcher.mcp.take_action", true)

	viper.SetDefault("gateway.watchdog.enabled", true)
	viper.SetDefault("gateway.watchdog.interval", 30)
	viper.SetDefault("gateway.watchdog.debounce", 2)

	viper.SetDefault("otel.enabled", false)
	viper.SetDefault("otel.protocol", "grpc")
	viper.SetDefault("otel.endpoint", "")
	viper.SetDefault("otel.tls.insecure", false)
	viper.SetDefault("otel.tls.ca_cert", "")
	viper.SetDefault("otel.traces.enabled", true)
	viper.SetDefault("otel.traces.sampler", "always_on")
	viper.SetDefault("otel.traces.sampler_arg", "1.0")
	viper.SetDefault("otel.traces.endpoint", "")
	viper.SetDefault("otel.traces.protocol", "")
	viper.SetDefault("otel.traces.url_path", "")
	viper.SetDefault("otel.logs.enabled", true)
	viper.SetDefault("otel.logs.emit_individual_findings", false)
	viper.SetDefault("otel.logs.endpoint", "")
	viper.SetDefault("otel.logs.protocol", "")
	viper.SetDefault("otel.logs.url_path", "")
	viper.SetDefault("otel.metrics.enabled", true)
	viper.SetDefault("otel.metrics.export_interval_s", 60)
	viper.SetDefault("otel.metrics.temporality", "delta")
	viper.SetDefault("otel.metrics.endpoint", "")
	viper.SetDefault("otel.metrics.protocol", "")
	viper.SetDefault("otel.metrics.url_path", "")
	viper.SetDefault("otel.batch.max_export_batch_size", 512)
	viper.SetDefault("otel.batch.scheduled_delay_ms", 5000)
	viper.SetDefault("otel.batch.max_queue_size", 2048)

	_ = viper.BindEnv("otel.enabled", "DEFENSECLAW_OTEL_ENABLED")
	_ = viper.BindEnv("otel.endpoint", "DEFENSECLAW_OTEL_ENDPOINT")
	_ = viper.BindEnv("otel.protocol", "DEFENSECLAW_OTEL_PROTOCOL")
	_ = viper.BindEnv("otel.tls.insecure", "DEFENSECLAW_OTEL_TLS_INSECURE")
	_ = viper.BindEnv("otel.traces.endpoint", "DEFENSECLAW_OTEL_TRACES_ENDPOINT")
	_ = viper.BindEnv("otel.traces.protocol", "DEFENSECLAW_OTEL_TRACES_PROTOCOL")
	_ = viper.BindEnv("otel.traces.url_path", "DEFENSECLAW_OTEL_TRACES_URL_PATH")
	_ = viper.BindEnv("otel.metrics.endpoint", "DEFENSECLAW_OTEL_METRICS_ENDPOINT")
	_ = viper.BindEnv("otel.metrics.protocol", "DEFENSECLAW_OTEL_METRICS_PROTOCOL")
	_ = viper.BindEnv("otel.metrics.url_path", "DEFENSECLAW_OTEL_METRICS_URL_PATH")
	_ = viper.BindEnv("otel.logs.endpoint", "DEFENSECLAW_OTEL_LOGS_ENDPOINT")
	_ = viper.BindEnv("otel.logs.protocol", "DEFENSECLAW_OTEL_LOGS_PROTOCOL")
	_ = viper.BindEnv("otel.logs.url_path", "DEFENSECLAW_OTEL_LOGS_URL_PATH")
}
