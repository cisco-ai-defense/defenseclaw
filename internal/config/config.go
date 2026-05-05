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
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/version"
)

// ReportConfigLoadError is wired by telemetry.NewProvider to emit OTel on Load failures.
// Nil in binaries/tests that do not install the hook.
var ReportConfigLoadError func(ctx context.Context, reason string)

var privacyDisableRedactionWarnOnce sync.Once

// DefenseClawLLMKeyEnv is the canonical environment variable holding the
// unified LLM API key that powers every LLM-using component in DefenseClaw
// (guardrail upstream, LLM judge, MCP scanner, skill scanner, plugin scanner).
// A user only needs to set this one env var to configure LLM access across
// the whole product. Per-component overrides are still available via the
// nested "llm:" blocks under "scanners.*", "guardrail", and
// "guardrail.judge". Local providers (ollama, vllm) don't need a key —
// an empty resolved value is allowed downstream.
const DefenseClawLLMKeyEnv = "DEFENSECLAW_LLM_KEY"

// DefenseClawLLMModelEnv is the env var holding the default
// "provider/model" string when llm.model is empty in config.yaml.
const DefenseClawLLMModelEnv = "DEFENSECLAW_LLM_MODEL"

// defaultLLMTimeoutSeconds is the HTTP timeout for LLM calls when unset.
const defaultLLMTimeoutSeconds = 30

// defaultLLMMaxRetries is the retry count for LLM calls when unset.
const defaultLLMMaxRetries = 2

type ClawMode string

const (
	ClawOpenClaw ClawMode = "openclaw"
	// Other recognised connector names (kept in sync with
	// Connector.Name() in internal/gateway/connector and with the
	// `defenseclaw.claw.mode` enum in schemas/otel/resource.schema.json):
	// "zeptoclaw", "claudecode", "codex", "hermes", "cursor",
	// "windsurf", "geminicli", "copilot". Constants for those modes
	// are intentionally not introduced here yet — they're used as
	// raw strings by Config.activeConnector() (see internal/config/
	// claw.go) which dispatches to per-connector readers. Promoting
	// them to typed constants is part of S1.2 and tracked in the
	// claw-agnostic refactor plan.
)

type ClawConfig struct {
	Mode       ClawMode `mapstructure:"mode"        yaml:"mode"`
	HomeDir    string   `mapstructure:"home_dir"    yaml:"home_dir"`
	ConfigFile string   `mapstructure:"config_file" yaml:"config_file"`
}

// AgentConfig [v7] pins the logical agent identity for this
// sidecar deployment. The three-tier identity model distinguishes:
//
//   - AgentID (this field): logical, stable across restarts &
//     instances. Operators set this in config.yaml; it is what
//     aggregates like /v1/agentwatch/agents, /v1/events, /summary,
//     and /risk-summary key off. Blank means "no agent identity
//     pinned" — downstream consumers must tolerate that.
//   - AgentInstanceID: per-session, assigned by the gateway's
//     agent registry at session start; never configured.
//   - SidecarInstanceID: per-process, minted at sidecar boot; never
//     configured.
//
// Keeping this at the top level (not nested under `claw:`) means it
// survives future multi-agent-framework expansions without schema
// churn.
type AgentConfig struct {
	// ID is the stable logical agent identifier. If empty, the
	// sidecar runs without a pinned agent identity — all events
	// still carry AgentInstanceID & SidecarInstanceID so they
	// correlate within a session, but cross-session aggregation
	// by agent is not possible.
	//
	// Convention: lower-kebab-case, globally unique within a
	// tenant (e.g. "code-review-bot", "triage-agent-prod").
	ID string `mapstructure:"id" yaml:"id,omitempty"`

	// Name is a human-readable display name surfaced in the TUI,
	// webhook notifications, and event.agent_name. Blank falls
	// back to ID. Never used for aggregation.
	Name string `mapstructure:"name" yaml:"name,omitempty"`
}

// CurrentConfigVersion is bumped when the config schema changes in a way
// that requires migration (new required fields, renamed keys, etc.).
//
// v4: replaces the legacy `splunk:` block with a generic `audit_sinks:`
// list; decouples OTel from any vendor-specific auto-injection. There is
// no in-process migration shim — the v3→v4 step requires operator action,
// and Load() emits a hard error when a legacy `splunk:` block is found.
//
// v5: introduces the unified `llm:` block at the top level plus optional
// per-component `llm:` overrides under scanners.*, guardrail, and
// guardrail.judge. The legacy `default_llm_api_key_env`,
// `default_llm_model`, `inspect_llm`, `guardrail.model`,
// `guardrail.api_key_env`, `guardrail.api_base`, `guardrail.judge.model`,
// `guardrail.judge.api_key_env`, and `guardrail.judge.api_base` fields
// are migrated in-process by migrateConfig: their values are copied
// into the matching LLMConfig slots, then the legacy fields are left
// alone so hand-edited configs keep round-tripping. `defenseclaw setup
// migrate-llm` writes the canonical v5 shape back to disk.
const CurrentConfigVersion = 5

type Config struct {
	ConfigVersion int `mapstructure:"config_version"        yaml:"config_version"`

	// LLM is the top-level unified LLM configuration. Every LLM-using
	// component (guardrail, judge, mcp scanner, skill scanner, plugin
	// scanner) resolves its effective LLM settings by layering its
	// own per-component `llm:` override on top of this block. The
	// resolver is Config.ResolveLLM(path).
	//
	// For most deployments the operator sets exactly two things:
	//   llm.api_key_env: DEFENSECLAW_LLM_KEY
	//   llm.model:       openai/gpt-4o  (Bifrost + LiteLLM style)
	// and every scanner inherits them.
	LLM LLMConfig `mapstructure:"llm" yaml:"llm,omitempty"`

	// DefaultLLMAPIKeyEnv / DefaultLLMModel are DEPRECATED (legacy v<5
	// fields). Load() migrates populated values into c.LLM, but new
	// code should read c.LLM / c.ResolveLLM(...) instead. The YAML
	// tag is kept with omitempty so round-tripped configs don't
	// resurface these after migration.
	DefaultLLMAPIKeyEnv string `mapstructure:"default_llm_api_key_env" yaml:"default_llm_api_key_env,omitempty"`
	DefaultLLMModel     string `mapstructure:"default_llm_model"     yaml:"default_llm_model,omitempty"`

	DataDir         string                     `mapstructure:"data_dir"              yaml:"data_dir"`
	AuditDB         string                     `mapstructure:"audit_db"         yaml:"audit_db"`
	QuarantineDir   string                     `mapstructure:"quarantine_dir"   yaml:"quarantine_dir"`
	PluginDir       string                     `mapstructure:"plugin_dir"       yaml:"plugin_dir"`
	PolicyDir       string                     `mapstructure:"policy_dir"       yaml:"policy_dir"`
	Environment     string                     `mapstructure:"environment"      yaml:"environment"`
	TenantID        string                     `mapstructure:"tenant_id"        yaml:"tenant_id,omitempty"`
	WorkspaceID     string                     `mapstructure:"workspace_id"     yaml:"workspace_id,omitempty"`
	DeploymentMode  string                     `mapstructure:"deployment_mode"  yaml:"deployment_mode,omitempty"`
	DiscoverySource string                     `mapstructure:"discovery_source" yaml:"discovery_source,omitempty"`
	Claw            ClawConfig                 `mapstructure:"claw"             yaml:"claw"`
	Agent           AgentConfig                `mapstructure:"agent"            yaml:"agent,omitempty"`
	InspectLLM      InspectLLMConfig           `mapstructure:"inspect_llm"      yaml:"inspect_llm,omitempty"`
	CiscoAIDefense  CiscoAIDefenseConfig       `mapstructure:"cisco_ai_defense" yaml:"cisco_ai_defense"`
	Scanners        ScannersConfig             `mapstructure:"scanners"         yaml:"scanners"`
	OpenShell       OpenShellConfig            `mapstructure:"openshell"        yaml:"openshell"`
	Watch           WatchConfig                `mapstructure:"watch"            yaml:"watch"`
	Firewall        FirewallConfig             `mapstructure:"firewall"         yaml:"firewall"`
	Guardrail       GuardrailConfig            `mapstructure:"guardrail"        yaml:"guardrail"`
	Gateway         GatewayConfig              `mapstructure:"gateway"          yaml:"gateway"`
	SkillActions    SkillActionsConfig         `mapstructure:"skill_actions"    yaml:"skill_actions"`
	MCPActions      MCPActionsConfig           `mapstructure:"mcp_actions"      yaml:"mcp_actions"`
	PluginActions   PluginActionsConfig        `mapstructure:"plugin_actions"   yaml:"plugin_actions"`
	AssetPolicy     AssetPolicyConfig          `mapstructure:"asset_policy"     yaml:"asset_policy"`
	OTel            OTelConfig                 `mapstructure:"otel"             yaml:"otel"`
	ClaudeCode      AgentHookConfig            `mapstructure:"claude_code"      yaml:"claude_code,omitempty"`
	Codex           AgentHookConfig            `mapstructure:"codex"            yaml:"codex,omitempty"`
	ConnectorHooks  map[string]AgentHookConfig `mapstructure:"connector_hooks"  yaml:"connector_hooks,omitempty"`
	// AuditSinks is the v4 replacement for the legacy `splunk:` block.
	// It supports an arbitrary number of named sinks of any registered
	// kind (splunk_hec, otlp_logs, http_jsonl). Legacy `splunk:` keys are
	// detected at Load() and emit a hard migration error.
	AuditSinks  []AuditSink       `mapstructure:"audit_sinks"      yaml:"audit_sinks,omitempty"`
	Webhooks    []WebhookConfig   `mapstructure:"webhooks"         yaml:"webhooks"`
	Privacy     PrivacyConfig     `mapstructure:"privacy"          yaml:"privacy,omitempty"`
	AIDiscovery AIDiscoveryConfig `mapstructure:"ai_discovery"    yaml:"ai_discovery,omitempty"`
}

// PrivacyConfig groups privacy/redaction toggles. Today it carries
// only the redaction kill-switch; future fields (per-sink redaction
// scope, custom redactor profiles) land here so operators have a
// single section to audit.
//
// Scope: this is a deliberate, persistent operator decision.
// Defaults match the existing redacting-by-default behavior so a
// fresh install or a config without a `privacy:` block keeps the
// historical contract documented in OBSERVABILITY.md.
type PrivacyConfig struct {
	// DisableRedaction, when true, instructs the sidecar to bypass
	// every ForSink* redaction helper at startup — including
	// persistent sinks (SQLite audit, OTel log exporters, Splunk
	// HEC, webhooks). Equivalent to setting
	// DEFENSECLAW_DISABLE_REDACTION=1 but persisted in config so
	// the choice survives restarts and TUI invocations without
	// per-shell env-var ceremony.
	//
	// WARNING: this violates the unconditional-redaction contract
	// documented in OBSERVABILITY.md. Only enable on single-tenant
	// installs where every downstream sink already lives inside
	// the same trust boundary (e.g. lab / prompt-engineering use).
	// The CLI emits a loud warning on flip-on, and config loaders emit
	// a once-per-process warning when they observe the setting so the
	// runtime state stays auditable without spamming reload loops.
	DisableRedaction bool `mapstructure:"disable_redaction" yaml:"disable_redaction,omitempty"`
}

// AIDiscoveryConfig controls continuous, sidecar-native visibility for
// supported connectors and broader "shadow AI" usage signals. Outbound
// telemetry is sanitized by the inventory service; this config only controls
// which local metadata sources are inspected.
type AIDiscoveryConfig struct {
	Enabled                 bool     `mapstructure:"enabled"                   yaml:"enabled"`
	Mode                    string   `mapstructure:"mode"                      yaml:"mode"` // passive | enhanced
	ScanIntervalMin         int      `mapstructure:"scan_interval_min"         yaml:"scan_interval_min"`
	ProcessIntervalSec      int      `mapstructure:"process_interval_s"        yaml:"process_interval_s"`
	ScanRoots               []string `mapstructure:"scan_roots"                yaml:"scan_roots,omitempty"`
	IncludeShellHistory     bool     `mapstructure:"include_shell_history"     yaml:"include_shell_history"`
	IncludePackageManifests bool     `mapstructure:"include_package_manifests" yaml:"include_package_manifests"`
	IncludeEnvVarNames      bool     `mapstructure:"include_env_var_names"     yaml:"include_env_var_names"`
	IncludeNetworkDomains   bool     `mapstructure:"include_network_domains"   yaml:"include_network_domains"`
	MaxFilesPerScan         int      `mapstructure:"max_files_per_scan"        yaml:"max_files_per_scan"`
	MaxFileBytes            int      `mapstructure:"max_file_bytes"            yaml:"max_file_bytes"`
	EmitOTel                bool     `mapstructure:"emit_otel"                 yaml:"emit_otel"`
	StoreRawLocalPaths      bool     `mapstructure:"store_raw_local_paths"     yaml:"store_raw_local_paths"`
}

// LLMConfig is the unified LLM configuration block used at the top level
// and as a per-component override under "scanners.*", "guardrail", and
// "guardrail.judge". A LoadedConfig.ResolveLLM(path) call merges the
// top-level defaults with the per-component override and returns the
// resolved settings for that call site.
//
// Model string conventions:
//
//   - The required format is "provider/model-id", e.g.
//     "openai/gpt-4o", "anthropic/claude-3-5-sonnet-20241022",
//     "ollama/llama3.1", "vllm/mistral-7b-instruct",
//     "azure/<deployment-name>", "gemini/gemini-2.0-flash",
//     "bedrock/anthropic.claude-3-5-sonnet-20240620-v1:0".
//   - This prefix is shared by the Go gateway (Bifrost routes by the
//     "provider/" prefix) AND by the Python scanners (LiteLLM accepts
//     the same "provider/model" shape). Passing a bare model id
//     without a provider prefix is allowed but will emit a warning
//     at resolution time and may behave differently between Bifrost
//     and LiteLLM.
//   - Recognized prefixes: openai, anthropic, azure, gemini, vertex_ai,
//     bedrock, groq, mistral, cohere, ollama, vllm, deepseek, xai,
//     fireworks_ai, perplexity, huggingface, replicate, openrouter,
//     together_ai, cerebras. Anything else emits an unknown-prefix
//     warning so typos surface immediately.
//
// APIKey vs APIKeyEnv:
//
//   - Prefer APIKeyEnv (the name of an env var) so secrets stay out of
//     config.yaml. An empty APIKeyEnv defaults to DEFENSECLAW_LLM_KEY,
//     the canonical env var for the whole product.
//   - APIKey is honored as a last resort for tests and single-machine
//     installs, but a warnPlaintextSecrets pass at Load() will log a
//     deprecation line every time it is non-empty.
//
// BaseURL:
//
//   - Optional. When empty, providers use their library default
//     (api.openai.com, api.anthropic.com, etc.). Set this to point at
//     a local gateway (http://127.0.0.1:11434 for Ollama,
//     http://127.0.0.1:8000/v1 for a local vLLM server) or a
//     corporate proxy.
type LLMConfig struct {
	// Model is the "provider/model" identifier. See the package doc
	// above for the recognized prefixes and conventions.
	Model string `mapstructure:"model"       yaml:"model,omitempty"`
	// Provider is optional and only read when Model has no "provider/"
	// prefix. Prefer encoding the provider in Model directly.
	Provider string `mapstructure:"provider"    yaml:"provider,omitempty"`
	// APIKey is an inline secret. Prefer APIKeyEnv.
	APIKey string `mapstructure:"api_key"     yaml:"api_key,omitempty"`
	// APIKeyEnv is the name of the environment variable to read the
	// API key from. Empty defaults to DEFENSECLAW_LLM_KEY.
	APIKeyEnv string `mapstructure:"api_key_env" yaml:"api_key_env,omitempty"`
	// BaseURL points at a non-default endpoint (local Ollama, corporate
	// proxy, Azure endpoint). Empty means "use the provider default".
	BaseURL string `mapstructure:"base_url"    yaml:"base_url,omitempty"`
	// Timeout is the per-request HTTP timeout in seconds. 0 picks a
	// sensible default (defaultLLMTimeoutSeconds).
	Timeout int `mapstructure:"timeout"     yaml:"timeout,omitempty"`
	// MaxRetries bounds upstream retry attempts. 0 picks a sensible
	// default (defaultLLMMaxRetries).
	MaxRetries int `mapstructure:"max_retries" yaml:"max_retries,omitempty"`
}

// ResolvedAPIKey returns the API key from the env var first, then the
// inline value. Resolution order:
//
//  1. If APIKeyEnv is explicitly set, read from that env var and return
//     it if non-empty.
//  2. Otherwise, if APIKey is explicitly set inline, return it — users
//     who hard-code a key in config.yaml expect it to win over the
//     unified-key fallback.
//  3. Finally, fall back to the canonical DEFENSECLAW_LLM_KEY env var
//     so operators can set exactly one env var and have every
//     LLM-using component inherit it.
//
// Mirrors cli/defenseclaw/config.py::LLMConfig.resolved_api_key — the
// Python parity test (cli/tests/test_llm_env.py::ParityTests) asserts
// these stay in lock-step.
func (l LLMConfig) ResolvedAPIKey() string {
	if l.APIKeyEnv != "" {
		if v := strings.TrimSpace(os.Getenv(l.APIKeyEnv)); v != "" {
			return v
		}
	}
	if l.APIKey != "" {
		return l.APIKey
	}
	return strings.TrimSpace(os.Getenv(DefenseClawLLMKeyEnv))
}

// EffectiveTimeout returns Timeout or the default when unset.
func (l LLMConfig) EffectiveTimeout() int {
	if l.Timeout > 0 {
		return l.Timeout
	}
	return defaultLLMTimeoutSeconds
}

// EffectiveMaxRetries returns MaxRetries or the default when unset.
func (l LLMConfig) EffectiveMaxRetries() int {
	if l.MaxRetries > 0 {
		return l.MaxRetries
	}
	return defaultLLMMaxRetries
}

// ProviderPrefix extracts the "provider" part of Model ("openai/gpt-4o"
// → "openai"). Returns "" when Model is empty or lacks a slash.
func (l LLMConfig) ProviderPrefix() string {
	if l.Provider != "" {
		return strings.ToLower(strings.TrimSpace(l.Provider))
	}
	if idx := strings.Index(l.Model, "/"); idx > 0 {
		return strings.ToLower(l.Model[:idx])
	}
	return ""
}

// IsLocalProvider returns true when the resolved provider prefix points
// at an on-box runtime that doesn't require an API key (ollama, vllm,
// lm_studio). Local providers let the wizard skip the key prompt and
// let `defenseclaw doctor` skip the "missing key" warning.
func (l LLMConfig) IsLocalProvider() bool {
	switch l.ProviderPrefix() {
	case "ollama", "vllm", "lm_studio", "lmstudio", "local":
		return true
	}
	if l.BaseURL != "" {
		host := strings.ToLower(l.BaseURL)
		if strings.Contains(host, "127.0.0.1") ||
			strings.Contains(host, "localhost") ||
			strings.Contains(host, "[::1]") ||
			strings.HasPrefix(host, "unix:") {
			return true
		}
	}
	return false
}

// recognizedLLMProviders lists the "provider/" prefixes the gateway and
// LiteLLM both understand. Unknown prefixes emit a one-shot warning.
var recognizedLLMProviders = map[string]struct{}{
	"openai":       {},
	"anthropic":    {},
	"azure":        {},
	"gemini":       {},
	"vertex_ai":    {},
	"bedrock":      {},
	"groq":         {},
	"mistral":      {},
	"cohere":       {},
	"ollama":       {},
	"vllm":         {},
	"deepseek":     {},
	"xai":          {},
	"fireworks_ai": {},
	"perplexity":   {},
	"huggingface":  {},
	"replicate":    {},
	"openrouter":   {},
	"together_ai":  {},
	"cerebras":     {},
	"lm_studio":    {},
	"lmstudio":     {},
	"local":        {},
}

// warnedPrefixes keeps one-shot-per-process warning state.
var warnedPrefixes = map[string]struct{}{}

func maybeWarnUnknownProvider(prefix, componentPath string) {
	if prefix == "" {
		return
	}
	if _, ok := recognizedLLMProviders[prefix]; ok {
		return
	}
	key := componentPath + "\x00" + prefix
	if _, seen := warnedPrefixes[key]; seen {
		return
	}
	warnedPrefixes[key] = struct{}{}
	log.Printf("WARNING: config: unknown LLM provider prefix %q for %s — "+
		"expected one of openai/anthropic/azure/gemini/vertex_ai/bedrock/"+
		"groq/mistral/cohere/ollama/vllm/deepseek/xai/fireworks_ai/"+
		"perplexity/huggingface/replicate/openrouter/together_ai/cerebras/"+
		"lm_studio/local. Gateway (Bifrost) and scanners (LiteLLM) may "+
		"disagree on how to route this model",
		prefix, componentPath)
}

// ResolveLLM returns the effective LLMConfig for the given component
// path. The path selects which per-component override block to layer on
// top of c.LLM. Supported paths:
//
//   - ""                       — returns c.LLM as-is
//   - "scanners.mcp"           — scanners.mcp_scanner.llm
//   - "scanners.skill"         — scanners.skill_scanner.llm
//   - "scanners.plugin"        — scanners.plugin_scanner_llm (reserved)
//   - "guardrail"              — guardrail.llm
//   - "guardrail.judge"        — guardrail.judge.llm
//
// Merge rules: every non-empty scalar on the override wins. An unset
// Model on the override inherits from the top level, so an operator can
// set a single llm.model once and every scanner picks it up. The
// returned LLMConfig always has a resolved Model: if still empty, the
// DEFENSECLAW_LLM_MODEL env var is consulted.
//
// This method is the single source of truth for LLM resolution across
// the whole Go codebase — callers must NEVER read c.InspectLLM or the
// legacy top-level default_llm_* fields directly.
func (c *Config) ResolveLLM(path string) LLMConfig {
	out := c.LLM
	var override LLMConfig
	switch path {
	case "":
		// no-op
	case "scanners.mcp":
		override = c.Scanners.MCPScanner.LLM
	case "scanners.skill":
		override = c.Scanners.SkillScanner.LLM
	case "scanners.plugin":
		override = c.Scanners.PluginScannerLLM
	case "guardrail":
		override = c.Guardrail.LLM
	case "guardrail.judge":
		override = c.Guardrail.Judge.LLM
	default:
		log.Printf("WARNING: config: ResolveLLM called with unknown path %q", path)
	}

	if override.Model != "" {
		out.Model = override.Model
	}
	if override.Provider != "" {
		out.Provider = override.Provider
	}
	if override.APIKey != "" {
		out.APIKey = override.APIKey
	}
	if override.APIKeyEnv != "" {
		out.APIKeyEnv = override.APIKeyEnv
	}
	if override.BaseURL != "" {
		out.BaseURL = override.BaseURL
	}
	if override.Timeout > 0 {
		out.Timeout = override.Timeout
	}
	if override.MaxRetries > 0 {
		out.MaxRetries = override.MaxRetries
	}

	if out.Model == "" {
		if env := strings.TrimSpace(os.Getenv(DefenseClawLLMModelEnv)); env != "" {
			out.Model = env
		}
	}

	// Legacy fallback: honor DefaultLLMModel when top-level model is
	// still empty after env consultation. This keeps pre-v5 configs
	// working until operators run `defenseclaw setup migrate-llm`.
	if out.Model == "" && c.DefaultLLMModel != "" {
		out.Model = c.DefaultLLMModel
	}
	if out.APIKeyEnv == "" && c.DefaultLLMAPIKeyEnv != "" {
		out.APIKeyEnv = c.DefaultLLMAPIKeyEnv
	}

	maybeWarnUnknownProvider(out.ProviderPrefix(), path)
	return out
}

// ResolvedDefaultLLMAPIKey returns the shared LLM API key from the
// configured env var. DEPRECATED: prefer Config.ResolveLLM(path) which
// handles the top-level + per-component override merge for each
// component in one call.
func (c *Config) ResolvedDefaultLLMAPIKey() string {
	return c.ResolveLLM("").ResolvedAPIKey()
}

// EffectiveInspectLLM returns InspectLLM-shaped settings by delegating to
// ResolveLLM. DEPRECATED: prefer c.ResolveLLM("scanners.skill") /
// c.ResolveLLM("scanners.mcp") directly.
func (c *Config) EffectiveInspectLLM() InspectLLMConfig {
	base := c.ResolveLLM("")
	out := c.InspectLLM
	if out.Model == "" {
		out.Model = base.Model
	}
	if out.Provider == "" {
		out.Provider = base.Provider
	}
	if out.APIKey == "" {
		out.APIKey = base.APIKey
	}
	if out.APIKeyEnv == "" {
		out.APIKeyEnv = base.APIKeyEnv
	}
	if out.BaseURL == "" {
		out.BaseURL = base.BaseURL
	}
	if out.Timeout == 0 {
		out.Timeout = base.EffectiveTimeout()
	}
	if out.MaxRetries == 0 {
		out.MaxRetries = base.EffectiveMaxRetries()
	}
	return out
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

// WebhookConfig is one entry in the top-level “webhooks[]“ list. These
// are notifier webhooks (chat/incident), NOT audit sinks — audit
// forwarding lives in “audit_sinks[]“. See docs/OBSERVABILITY.md §7.
//
// CooldownSeconds is a tri-state on purpose (see webhook.go
// “webhookDefaultCooldown = 300s“):
//
//   - nil (YAML key absent / null): "use the dispatcher default"
//     (“webhookDefaultCooldown“, currently 300s). This is what
//     “setup webhook add“ writes when the operator omits --cooldown.
//   - *v == 0: explicit "dispatch every event" (debounce disabled).
//     Stored so round-tripping the YAML doesn't silently re-introduce
//     the 300s default.
//   - *v > 0: minimum seconds between dispatches per
//     (webhook, event_category) pair. Enforced by the gateway
//     WebhookDispatcher.
//
// The Python writer (cli/defenseclaw/webhooks/writer.py) preserves the
// same nil-vs-zero distinction end-to-end.
//
// Name is the CLI-visible identifier (“defenseclaw setup webhook
// enable <name>“ etc.). The runtime dispatcher itself identifies
// webhooks by URL, but Name is round-tripped through Load/Save so
// saving the config via Config.Save() or the TUI doesn't silently
// strip the operator's chosen name. “omitempty“ keeps legacy files
// that never set “name:“ identical after load-save.
type WebhookConfig struct {
	Name            string   `mapstructure:"name"             yaml:"name,omitempty"`
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

// AgentHookConfig is the per-connector hook policy block (e.g.
// claude_code.fail_mode, codex.fail_mode). It is independent from
// the gateway-side hook script fail-mode controlled by
// GuardrailConfig.HookFailMode.
//
// IMPORTANT — disambiguation, both fields are named "fail_mode":
//
//   - GuardrailConfig.HookFailMode (yaml: guardrail.hook_fail_mode)
//     is the SHELL-side fail-mode baked into the generated hook
//     templates (codex-hook.sh, claude-code-hook.sh, inspect-*).
//     It governs what those scripts do when the gateway returns a
//     RESPONSE-LAYER failure (4xx, malformed JSON, missing
//     `action` field). Its default is "open" because silently
//     bricking the agent on a transient response error is worse
//     than allowing one tool call. Transport-layer failures
//     (gateway unreachable / 5xx) are handled separately and
//     ALWAYS allow unless DEFENSECLAW_STRICT_AVAILABILITY=1.
//
//   - AgentHookConfig.FailMode (yaml: <connector>.fail_mode below)
//     is a per-connector POLICY-LAYER hint that downstream
//     connector glue can read to pick a policy posture. It is
//     NOT consumed by the generated hook scripts. The legacy
//     default "closed" is preserved here for backward
//     compatibility with installs that wrote it before
//     hook_fail_mode existed.
//
// Operators who want to change the runtime behavior of the
// generated hooks should edit guardrail.hook_fail_mode (or run
// `defenseclaw guardrail fail-mode`), NOT this field.
type AgentHookConfig struct {
	Enabled                      bool     `mapstructure:"enabled"                         yaml:"enabled"`
	Mode                         string   `mapstructure:"mode"                            yaml:"mode,omitempty"`
	FailMode                     string   `mapstructure:"fail_mode"                       yaml:"fail_mode,omitempty"`
	ScanOnSessionStart           bool     `mapstructure:"scan_on_session_start"           yaml:"scan_on_session_start,omitempty"`
	ScanOnStop                   bool     `mapstructure:"scan_on_stop"                    yaml:"scan_on_stop,omitempty"`
	ScanPaths                    []string `mapstructure:"scan_paths"                      yaml:"scan_paths,omitempty"`
	ComponentScanIntervalMinutes int      `mapstructure:"component_scan_interval_minutes" yaml:"component_scan_interval_minutes,omitempty"`
}

// EffectiveFailMode returns the per-connector POLICY-LAYER fail
// mode for AgentHookConfig, defaulting to "closed" for backward
// compatibility. NOTE: this is NOT what governs the generated
// hook scripts; see GuardrailConfig.EffectiveHookFailMode for
// that. Both fields are named "fail_mode" in YAML — the namespace
// (top-level connector vs guardrail.hook_fail_mode) is what tells
// them apart.
func (c AgentHookConfig) EffectiveFailMode() string {
	if c.FailMode == "open" {
		return "open"
	}
	return "closed"
}

// ConnectorHookConfig returns the AgentHookConfig for a named connector.
// It checks ConnectorHooks first, then falls back to the legacy
// ClaudeCode/Codex top-level fields for backward compatibility.
func (c *Config) ConnectorHookConfig(name string) AgentHookConfig {
	if c.ConnectorHooks != nil {
		if h, ok := c.ConnectorHooks[name]; ok {
			return h
		}
	}
	switch name {
	case "claudecode", "claude_code":
		return c.ClaudeCode
	case "codex":
		return c.Codex
	case "gemini-cli", "gemini_cli", "gemini":
		if c.ConnectorHooks != nil {
			if h, ok := c.ConnectorHooks["geminicli"]; ok {
				return h
			}
		}
	}
	return AgentHookConfig{}
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
	Binary        string `mapstructure:"binary"                 yaml:"binary"`
	UseLLM        bool   `mapstructure:"use_llm"                yaml:"use_llm"`
	UseBehavioral bool   `mapstructure:"use_behavioral"         yaml:"use_behavioral"`
	EnableMeta    bool   `mapstructure:"enable_meta"            yaml:"enable_meta"`
	UseTrigger    bool   `mapstructure:"use_trigger"            yaml:"use_trigger"`
	UseVirusTotal bool   `mapstructure:"use_virustotal"         yaml:"use_virustotal"`
	UseAIDefense  bool   `mapstructure:"use_aidefense"          yaml:"use_aidefense"`
	LLMConsensus  int    `mapstructure:"llm_consensus_runs"     yaml:"llm_consensus_runs"`
	Policy        string `mapstructure:"policy"                 yaml:"policy"`
	Lenient       bool   `mapstructure:"lenient"                yaml:"lenient"`
	// LLM overrides the top-level llm: block for the skill scanner.
	// Every field is optional: unset fields inherit from Config.LLM
	// via Config.ResolveLLM("scanners.skill").
	LLM              LLMConfig `mapstructure:"llm"                    yaml:"llm,omitempty"`
	VirusTotalKey    string    `mapstructure:"virustotal_api_key"     yaml:"virustotal_api_key"`
	VirusTotalKeyEnv string    `mapstructure:"virustotal_api_key_env" yaml:"virustotal_api_key_env"`
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
	// LLM overrides the top-level llm: block for the MCP scanner.
	LLM LLMConfig `mapstructure:"llm"               yaml:"llm,omitempty"`
}

type ScannersConfig struct {
	SkillScanner  SkillScannerConfig `mapstructure:"skill_scanner"  yaml:"skill_scanner"`
	MCPScanner    MCPScannerConfig   `mapstructure:"mcp_scanner"    yaml:"mcp_scanner"`
	PluginScanner string             `mapstructure:"plugin_scanner" yaml:"plugin_scanner"`
	// PluginScannerLLM overrides the top-level llm: block for the
	// plugin scanner, which goes through LiteLLM directly (not the
	// Bifrost gateway) to avoid burning guardrail tokens on
	// 3rd-party plugin analysis. Lives under scanners.plugin_llm in
	// YAML so it doesn't collide with the string-typed
	// plugin_scanner field above.
	PluginScannerLLM LLMConfig `mapstructure:"plugin_llm"     yaml:"plugin_llm,omitempty"`
	CodeGuard        string    `mapstructure:"codeguard"       yaml:"codeguard"`
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

type HILTConfig struct {
	Enabled     bool   `mapstructure:"enabled"      yaml:"enabled"`
	MinSeverity string `mapstructure:"min_severity" yaml:"min_severity"`
}

type GuardrailConfig struct {
	Enabled     bool   `mapstructure:"enabled"              yaml:"enabled"`
	Mode        string `mapstructure:"mode"                 yaml:"mode"`
	ScannerMode string `mapstructure:"scanner_mode"         yaml:"scanner_mode"`
	Host        string `mapstructure:"host"                 yaml:"host,omitempty"`
	Port        int    `mapstructure:"port"                 yaml:"port"`

	// Connector selects the active agent framework adapter. Written by
	// `defenseclaw setup` and read by the sidecar at boot. When empty,
	// defaults to "openclaw" for backward compatibility.
	Connector string `mapstructure:"connector"            yaml:"connector,omitempty"`

	// AllowEmptyProviders bypasses the boot-time ProviderProbe refusal
	// (plan A4 / S0.12). The default behavior is to fail-closed when the
	// active connector reports zero usable upstream providers — this
	// catches half-installed deployments where the gateway would accept
	// traffic with no LLM to forward to. Test harnesses that intentionally
	// run with stub upstreams opt in by setting this to true.
	AllowEmptyProviders bool `mapstructure:"allow_empty_providers" yaml:"allow_empty_providers,omitempty"`

	// LLM overrides the top-level llm: block for the guardrail upstream
	// (the model that DefenseClaw proxies client traffic to). Prefer
	// Config.ResolveLLM("guardrail") over reading LLM / legacy Model
	// directly.
	LLM LLMConfig `mapstructure:"llm"                  yaml:"llm,omitempty"`

	// Model / ModelName / APIKeyEnv / APIBase are DEPRECATED (v<5
	// fields). Load() copies populated values into LLM. New readers
	// MUST go through ResolveLLM("guardrail").
	Model     string `mapstructure:"model"                yaml:"model,omitempty"`
	ModelName string `mapstructure:"model_name"           yaml:"model_name,omitempty"`
	APIKeyEnv string `mapstructure:"api_key_env"          yaml:"api_key_env,omitempty"`
	APIBase   string `mapstructure:"api_base"             yaml:"api_base,omitempty"`

	// OriginalModel is NOT a secret-bearing field. It records the
	// upstream model name the client will see rewritten onto outgoing
	// requests (Bifrost model-routing). It is orthogonal to the
	// LLM block.
	OriginalModel     string      `mapstructure:"original_model"       yaml:"original_model,omitempty"`
	BlockMessage      string      `mapstructure:"block_message"        yaml:"block_message"`
	StreamBufferBytes int         `mapstructure:"stream_buffer_bytes"  yaml:"stream_buffer_bytes"`
	RulePackDir       string      `mapstructure:"rule_pack_dir"        yaml:"rule_pack_dir"`
	Judge             JudgeConfig `mapstructure:"judge"                yaml:"judge"`
	HILT              HILTConfig  `mapstructure:"hilt"                 yaml:"hilt"`

	// Detection strategy: "regex_only" (default), "regex_judge", "judge_first".
	// Per-direction overrides take precedence over the global setting.
	DetectionStrategy           string `mapstructure:"detection_strategy"            yaml:"detection_strategy,omitempty"`
	DetectionStrategyPrompt     string `mapstructure:"detection_strategy_prompt"     yaml:"detection_strategy_prompt,omitempty"`
	DetectionStrategyCompletion string `mapstructure:"detection_strategy_completion" yaml:"detection_strategy_completion,omitempty"`
	DetectionStrategyToolCall   string `mapstructure:"detection_strategy_tool_call"  yaml:"detection_strategy_tool_call,omitempty"`
	JudgeSweep                  bool   `mapstructure:"judge_sweep"                  yaml:"judge_sweep,omitempty"`

	// RetainJudgeBodies controls whether raw LLM-judge responses are
	// persisted to the local SQLite audit store for later forensics.
	// The default is ON (see viper.SetDefault in defaultsFor) so every
	// operator gets judge-response history out of the box. The raw body
	// only ever lands on the local disk; the sink-forwarded copy (Splunk,
	// OTLP) is redacted by emitJudge before it leaves the process.
	//
	// Operators who prefer not to store judge bodies can opt out via
	// `guardrail.retain_judge_bodies: false` in config.yaml or the
	// DEFENSECLAW_PERSIST_JUDGE=0 environment override. Redaction is
	// the safety mechanism for downstream sinks; retention is a
	// local-only decision.
	RetainJudgeBodies bool `mapstructure:"retain_judge_bodies" yaml:"retain_judge_bodies,omitempty"`

	// AllowUnknownLLMDomains, when true, permits passthrough to hosts
	// that are NOT listed in providers.json — provided the request
	// body still classifies as an LLM shape (messages/contents/input/
	// prompt). The default is false; unknown hosts are rejected so the
	// proxy never fails open. The request is still inspected, audited,
	// and emitted as an EventEgress with branch="shape".
	AllowUnknownLLMDomains bool `mapstructure:"allow_unknown_llm_domains" yaml:"allow_unknown_llm_domains,omitempty"`

	// CodexEnforcementEnabled gates the proxy-redirect / blocking
	// path for the Codex connector. When false (the default),
	// codex talks DIRECTLY to its native upstream
	// (api.openai.com/v1/responses for OPENAI_API_KEY mode,
	// chatgpt.com/backend-api/codex/responses for chatgpt mode);
	// the DefenseClaw proxy is NOT in the data path and no
	// reserved-id strip / openai_base_url rewrite is performed.
	// Observability still runs end-to-end via three independent
	// channels: hooks (UserPromptSubmit / PreToolUse / PostToolUse /
	// Stop) post to /api/v1/codex/hook, the [otel] block in
	// config.toml exports OTLP-HTTP to /v1/logs and /v1/metrics,
	// and the notify bridge POSTs agent-turn-complete to
	// /api/v1/codex/notify.
	//
	// When true, the existing guardrail enforcement code in
	// patchCodexConfig() runs (openai_base_url rewrite, reserved-id
	// strip, model_providers rewrite, subprocess sandbox) and the
	// proxy port binds. Designed to be flipped on later by an
	// operator who wants the proxy in path; the enforcement code
	// stays intact behind this flag rather than being removed, so
	// re-enabling is a single-line config change with no rebuild.
	CodexEnforcementEnabled bool `mapstructure:"codex_enforcement_enabled" yaml:"codex_enforcement_enabled,omitempty"`

	// ClaudeCodeEnforcementEnabled is the parallel flag for the
	// Claude Code connector. When false (the default), claude code
	// talks DIRECTLY to api.anthropic.com; no
	// ANTHROPIC_BASE_URL/claudecode_env.sh override is written and
	// the proxy port does NOT bind. Observability runs via hooks
	// (settings.json hook entries) and Claude Code's native OTel
	// stack — including OTEL_LOG_RAW_API_BODIES=file: which writes
	// the full Anthropic Messages API request/response JSON to disk
	// alongside a body_ref pointer in each event, the closest thing
	// to proxy-level body capture without sitting in the data path.
	//
	// When true, writeEnvOverride and SetupSubprocessEnforcement
	// run as before. Designed for the same flip-on-later workflow
	// as CodexEnforcementEnabled.
	ClaudeCodeEnforcementEnabled bool `mapstructure:"claudecode_enforcement_enabled" yaml:"claudecode_enforcement_enabled,omitempty"`

	// HookFailMode is the operator-chosen response-layer fail mode
	// for every generated hook script (codex-hook, claude-code-hook,
	// inspect-*). Two values are supported:
	//
	//   - "open" (default, recommended): when the gateway answers
	//     with a 4xx, malformed JSON, or a missing action field, the
	//     hook ALLOWS the tool/prompt with a stderr warning and an
	//     entry in $DEFENSECLAW_HOME/logs/hook-failures.jsonl. The
	//     rationale: a misbehaving gateway that bricks every agent
	//     interaction is strictly worse UX than a brief observability
	//     gap, and the operator can detect the problem from the log.
	//
	//   - "closed": the same response-layer failures BLOCK the tool/
	//     prompt (exit 2). Choose when you'd rather take the agent
	//     offline than miss a policy decision (e.g., regulated
	//     workflows where every prompt MUST be inspected).
	//
	// This field governs ONLY response-layer failures. Transport-
	// layer failures (gateway unreachable / 5xx) are handled
	// separately by each hook's fail_unreachable helper and ALWAYS
	// allow unless the operator opts into strict availability via
	// DEFENSECLAW_STRICT_AVAILABILITY=1 — regardless of this field's
	// value. See internal/gateway/connector/hooks/_hardening.sh for
	// the rationale.
	//
	// `defenseclaw setup guardrail` prompts for this when the install
	// is fresh or when the operator changes guardrail.mode (observe
	// ↔ action). It can also be flipped standalone via
	// `defenseclaw guardrail fail-mode <open|closed>` or via
	// `defenseclaw init --fail-mode <open|closed>` /
	// `defenseclaw quickstart --fail-mode <open|closed>`.
	//
	// IMPORTANT — disambiguation: this is NOT the same field as
	// AgentHookConfig.FailMode (e.g. claude_code.fail_mode,
	// codex.fail_mode). That sibling field is a per-connector
	// POLICY-LAYER hint defaulting to "closed" for backward
	// compatibility, and it is NOT consumed by the generated hook
	// scripts. Operators who want to change runtime hook behavior
	// must edit THIS field (guardrail.hook_fail_mode), not the
	// per-connector one. See AgentHookConfig docs for the full
	// rationale.
	HookFailMode string `mapstructure:"hook_fail_mode" yaml:"hook_fail_mode,omitempty"`
}

// EffectiveHookFailMode returns the operator-chosen hook fail mode,
// defaulting to "open" when unset or set to anything other than the
// canonical "closed" sentinel. Centralized here so the sidecar and
// any future config-edit surfaces never disagree on the default.
func (g *GuardrailConfig) EffectiveHookFailMode() string {
	if g == nil {
		return "open"
	}
	if g.HookFailMode == "closed" {
		return "closed"
	}
	return "open"
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
	Enabled       bool `mapstructure:"enabled"         yaml:"enabled"`
	Injection     bool `mapstructure:"injection"       yaml:"injection"`
	PII           bool `mapstructure:"pii"             yaml:"pii"`
	PIIPrompt     bool `mapstructure:"pii_prompt"      yaml:"pii_prompt"`
	PIICompletion bool `mapstructure:"pii_completion"  yaml:"pii_completion"`
	ToolInjection bool `mapstructure:"tool_injection"  yaml:"tool_injection"`
	// Exfil enables the data-exfiltration judge that explicitly asks the
	// LLM whether the prompt is trying to read or exfiltrate sensitive
	// files, credentials, secrets, or system data. Distinct from the
	// injection judge (which asks "is this prompt overriding my
	// instructions?") and the PII judge (which only fires on substring
	// PII). The exfil judge catches polite-tone /etc/passwd-shaped
	// prompts where neither category alone would block.
	Exfil   bool    `mapstructure:"exfil"           yaml:"exfil"`
	Timeout float64 `mapstructure:"timeout"         yaml:"timeout"`

	// LLM overrides the top-level llm: block for the LLM judge. Prefer
	// Config.ResolveLLM("guardrail.judge") over reading LLM / legacy
	// Model directly.
	LLM LLMConfig `mapstructure:"llm"             yaml:"llm,omitempty"`

	// Model / APIKeyEnv / APIBase are DEPRECATED (v<5 fields). Load()
	// copies populated values into LLM. New readers MUST go through
	// ResolveLLM("guardrail.judge").
	Model     string `mapstructure:"model"           yaml:"model,omitempty"`
	APIKeyEnv string `mapstructure:"api_key_env"     yaml:"api_key_env,omitempty"`
	APIBase   string `mapstructure:"api_base"        yaml:"api_base,omitempty"`

	Fallbacks           []string `mapstructure:"fallbacks"            yaml:"fallbacks,omitempty"`
	AdjudicationTimeout float64  `mapstructure:"adjudication_timeout" yaml:"adjudication_timeout,omitempty"`
}

// ResolvedJudgeAPIKey returns the judge API key from the env var.
// DEPRECATED: prefer Config.ResolveLLM("guardrail.judge").ResolvedAPIKey().
func (c *JudgeConfig) ResolvedJudgeAPIKey() string {
	if c.LLM.APIKeyEnv != "" || c.LLM.APIKey != "" {
		return c.LLM.ResolvedAPIKey()
	}
	if c.APIKeyEnv != "" {
		if v := os.Getenv(c.APIKeyEnv); v != "" {
			return v
		}
	}
	return ""
}

// ResolvedJudgeAPIKeyWithFallback returns the judge key, falling back to the
// shared default LLM key when none is configured.
// DEPRECATED: prefer Config.ResolveLLM("guardrail.judge").ResolvedAPIKey().
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
	Host            string `mapstructure:"host"              yaml:"host"`
	Port            int    `mapstructure:"port"              yaml:"port"`
	Token           string `mapstructure:"token"             yaml:"token,omitempty"`
	TokenEnv        string `mapstructure:"token_env"         yaml:"token_env"`
	TLS             bool   `mapstructure:"tls"               yaml:"tls"`
	TLSSkipVerify   bool   `mapstructure:"tls_skip_verify"   yaml:"tls_skip_verify"`
	NoTLS           bool   `mapstructure:"-"                 yaml:"-"`
	DeviceKeyFile   string `mapstructure:"device_key_file"   yaml:"device_key_file"`
	AutoApprove     bool   `mapstructure:"auto_approve_safe" yaml:"auto_approve_safe"`
	ReconnectMs     int    `mapstructure:"reconnect_ms"      yaml:"reconnect_ms"`
	MaxReconnectMs  int    `mapstructure:"max_reconnect_ms"  yaml:"max_reconnect_ms"`
	ApprovalTimeout int    `mapstructure:"approval_timeout_s" yaml:"approval_timeout_s"`
	APIPort         int    `mapstructure:"api_port"           yaml:"api_port"`
	APIBind         string `mapstructure:"api_bind"           yaml:"api_bind"`
	// FleetMode forces or disables the OpenClaw upstream WebSocket
	// dial loop, overriding the connector + host derivation in
	// gatewayShouldConnectForConfiguredConnector. Three values:
	//
	//   "" / "auto"   — derive from connector + host. openclaw/zeptoclaw
	//                   always dial; codex/claudecode dial only if
	//                   gateway.host is non-loopback.
	//   "enabled"     — always dial regardless of connector/host. Use
	//                   when running a local OpenClaw daemon on
	//                   127.0.0.1 alongside a codex/claudecode connector
	//                   (the only case the auto heuristic gets wrong).
	//   "disabled"    — never dial regardless of connector/host. Lets
	//                   operators run an OpenClaw connector in a
	//                   pure-local mode, or silence the loop while
	//                   debugging.
	//
	// Default is "" (treated as "auto"). Validated case-insensitively
	// in gatewayShouldConnectForConfiguredConnector — unknown values
	// fall through to "auto" so a typo doesn't accidentally disable
	// fleet integration on production.
	FleetMode   string               `mapstructure:"fleet_mode"        yaml:"fleet_mode,omitempty"`
	Watcher     GatewayWatcherConfig `mapstructure:"watcher"            yaml:"watcher"`
	Watchdog    WatchdogConfig       `mapstructure:"watchdog"           yaml:"watchdog"`
	SandboxHome string               `mapstructure:"-"                  yaml:"-"`
	ClawHome    string               `mapstructure:"-"                  yaml:"-"`
}

// WatchdogConfig controls the health watchdog that notifies users when the
// gateway is down and they lack protection.
type WatchdogConfig struct {
	Enabled  bool `mapstructure:"enabled"  yaml:"enabled"`
	Interval int  `mapstructure:"interval" yaml:"interval"` // seconds between polls, default 30
	Debounce int  `mapstructure:"debounce" yaml:"debounce"` // consecutive failures before alert, default 2
}

// defaultGatewayTokenEnv is the canonical env var for the gateway auth token.
const defaultGatewayTokenEnv = "DEFENSECLAW_GATEWAY_TOKEN"

// legacyGatewayTokenEnv is the old env var name, still consulted for
// backward compatibility with existing .env files.
const legacyGatewayTokenEnv = "OPENCLAW_GATEWAY_TOKEN"

// ResolvedToken returns the gateway token from the env var (if set) or the direct value.
// When token_env is empty (default config), checks DEFENSECLAW_GATEWAY_TOKEN first, then
// falls back to OPENCLAW_GATEWAY_TOKEN for backward compatibility. When token_env is set
// to a custom var, only that var is consulted — it does not fall through to the global
// env vars, preserving operator intent.
func (g *GatewayConfig) ResolvedToken() string {
	if g.TokenEnv != "" {
		if v := os.Getenv(g.TokenEnv); v != "" {
			return v
		}
	} else {
		if v := os.Getenv(defaultGatewayTokenEnv); v != "" {
			return v
		}
		if v := os.Getenv(legacyGatewayTokenEnv); v != "" {
			return v
		}
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
	// viper holds a process-global keystore. Without resetting it, a
	// previous Load() (e.g. from another binary path or test case)
	// leaves stale keys behind — including a legacy `splunk.*` block
	// that detectLegacySplunk() would then flag forever. Reset gives
	// us a clean slate per Load(); setDefaults() re-installs defaults
	// and BindEnv() bindings immediately after.
	viper.Reset()

	dataDir := DefaultDataPath()
	configFile := filepath.Join(dataDir, DefaultConfigName)

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	setDefaults(dataDir)

	// Pre-extract otel.resource.attributes from the raw YAML. OTel
	// semconv keys are dotted (service.name, defenseclaw.preset, …)
	// and Viper interprets "." as a path separator, which silently
	// nests them into map[string]map[string]… and then fails to
	// unmarshal back into map[string]string. We parse that block with
	// yaml.v3 (literal keys), then strip it from the bytes we feed to
	// Viper so Viper never sees the problematic shape, and reinstate
	// it on the decoded Config afterwards.
	otelAttrs, cleanedBytes, err := extractOTelResourceAttributes(configFile)
	if err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "otel_attrs_parse")
		}
		return nil, fmt.Errorf("config: parse otel.resource.attributes: %w", err)
	}

	if cleanedBytes != nil {
		if err := viper.ReadConfig(bytes.NewReader(cleanedBytes)); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "read_config")
			}
			return nil, fmt.Errorf("config: read %s: %w", configFile, err)
		}
	} else if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			if !os.IsNotExist(err) {
				if ReportConfigLoadError != nil {
					ReportConfigLoadError(context.Background(), "read_config")
				}
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
	if !viper.IsSet("guardrail.hilt") && viper.IsSet("guardrail.hitl") {
		viper.Set("guardrail.hilt", viper.Get("guardrail.hitl"))
	}

	// v3 → v4 hard migration: the `splunk:` block was removed in favor
	// of audit_sinks. Detect any populated legacy keys and refuse to
	// start so operators don't silently lose Splunk forwarding.
	if legacy := detectLegacySplunk(); legacy != "" {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "legacy_splunk")
		}
		return nil, fmt.Errorf("config: legacy `splunk:` block found in %s (key %s). "+
			"DefenseClaw v4 replaced it with `audit_sinks:`. "+
			"Run `defenseclaw setup observability migrate-splunk --apply` "+
			"or see docs/OBSERVABILITY.md for the new schema",
			configFile, legacy)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "unmarshal")
		}
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}

	// Reinstate the dot-preserving OTel resource attributes that we
	// stripped before handing bytes to Viper.
	if otelAttrs != nil {
		cfg.OTel.Resource.Attributes = otelAttrs
	}

	migrateConfig(&cfg)
	warnDisableRedactionConfig(&cfg)

	for i := range cfg.AuditSinks {
		if err := cfg.AuditSinks[i].Validate(); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "audit_sink_invalid")
			}
			return nil, fmt.Errorf("config: audit_sinks[%d]: %w", i, err)
		}
	}

	if err := cfg.SkillActions.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "skill_actions_invalid")
		}
		return nil, err
	}
	if err := cfg.MCPActions.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "mcp_actions_invalid")
		}
		return nil, err
	}
	if err := cfg.PluginActions.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "plugin_actions_invalid")
		}
		return nil, err
	}
	if cfg.OpenShell.IsStandalone() {
		cfg.Gateway.SandboxHome = cfg.OpenShell.EffectiveSandboxHome()
	}

	if home, err := os.UserHomeDir(); err == nil {
		cfg.Gateway.ClawHome = home
	}

	warnPlaintextSecrets(&cfg)

	// v7 provenance: seed the content_hash from the on-disk config
	// bytes at load time so events emitted between sidecar boot and
	// the first Save() already carry a meaningful fingerprint.
	// Without this, dashboards would see `content_hash=""` for every
	// event until someone explicitly saves the config through the
	// CLI/TUI, which hides genuine drift across restarts. Prefer
	// the original (dot-preserving) bytes read by
	// extractOTelResourceAttributes; fall back to a re-marshal when
	// the file did not exist (first boot / default config) so the
	// hash is still stable across identical in-memory configs.
	seedProvenanceOnLoad(configFile, &cfg)

	return &cfg, nil
}

func warnDisableRedactionConfig(cfg *Config) {
	if cfg == nil || !cfg.Privacy.DisableRedaction {
		return
	}
	privacyDisableRedactionWarnOnce.Do(func() {
		fmt.Fprintln(os.Stderr,
			"warning: privacy.disable_redaction=true — ALL sinks (audit DB, "+
				"OTel logs, webhooks, Splunk HEC) will receive UNREDACTED "+
				"prompts, judge bodies, and verdict reasons. Disable in "+
				"shared/multi-tenant deployments via "+
				"`defenseclaw config set privacy.disable_redaction false`.")
	})
}

// seedProvenanceOnLoad stamps the process-wide content hash from the
// config we just loaded. Separated from Load() so the branching stays
// readable and so tests can bypass it by not calling Load(). A hash
// failure is non-fatal — we just leave the prior value in place, which
// is the correct behavior for transient read races (editor saving
// in-place under us) where the next successful Load() will re-seed.
func seedProvenanceOnLoad(configFile string, cfg *Config) {
	if data, err := os.ReadFile(configFile); err == nil && len(data) > 0 {
		version.SetContentHash(data)
		return
	}
	// File not found or empty — fall back to a canonical re-marshal
	// of the in-memory Config so first-boot events still carry a
	// non-empty, deterministic fingerprint of the default config.
	if data, err := yaml.Marshal(cfg); err == nil && len(data) > 0 {
		version.SetContentHash(data)
	}
}

// extractOTelResourceAttributes reads the config file with yaml.v3
// (which preserves dotted map keys verbatim), pulls the
// otel.resource.attributes block out as a flat map[string]string, and
// returns the remaining YAML bytes with that block removed. The caller
// feeds the cleaned bytes to Viper (whose "." key separator would
// otherwise nest "service.name" into map[service][name] and break the
// mapstructure unmarshal into map[string]string) and re-attaches the
// returned attributes to the decoded Config afterwards.
//
// Returns:
//   - (attrs, cleanedBytes, nil) when the file exists and the block was
//     present (attrs may be empty if `attributes: {}` was set).
//   - (nil, cleanedBytes, nil) when the file exists but has no
//     otel.resource.attributes; caller should still use the cleaned
//     bytes (which are just the original bytes in that case) for
//     deterministic behavior.
//   - (nil, nil, nil) when the config file does not exist — caller
//     should fall back to viper.ReadInConfig's normal not-found path.
//   - (nil, nil, err) when the YAML is malformed or an attribute has a
//     non-scalar value.
func extractOTelResourceAttributes(configFile string) (map[string]string, []byte, error) {
	data, err := os.ReadFile(configFile)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil, nil
		}
		return nil, nil, fmt.Errorf("read %s: %w", configFile, err)
	}

	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, nil, fmt.Errorf("yaml unmarshal: %w", err)
	}

	doc := firstDocumentNode(&root)
	if doc == nil || doc.Kind != yaml.MappingNode {
		// Empty or non-mapping YAML (e.g. only comments). Nothing to
		// strip; pass original bytes back so Viper behavior is
		// unchanged.
		return nil, data, nil
	}

	otelNode := mappingChild(doc, "otel")
	if otelNode == nil || otelNode.Kind != yaml.MappingNode {
		return nil, data, nil
	}
	resourceNode := mappingChild(otelNode, "resource")
	if resourceNode == nil || resourceNode.Kind != yaml.MappingNode {
		return nil, data, nil
	}
	attrsNode := mappingChild(resourceNode, "attributes")
	if attrsNode == nil {
		return nil, data, nil
	}
	// Support explicit null (`attributes: ~`) by treating it as absent.
	if attrsNode.Kind == yaml.ScalarNode && attrsNode.Tag == "!!null" {
		removeMappingChild(resourceNode, "attributes")
		cleaned, marshalErr := yaml.Marshal(&root)
		if marshalErr != nil {
			return nil, nil, fmt.Errorf("yaml re-marshal: %w", marshalErr)
		}
		return map[string]string{}, cleaned, nil
	}
	if attrsNode.Kind != yaml.MappingNode {
		return nil, nil, fmt.Errorf("otel.resource.attributes must be a mapping, got %v", yamlKindName(attrsNode.Kind))
	}

	attrs := make(map[string]string, len(attrsNode.Content)/2)
	for i := 0; i+1 < len(attrsNode.Content); i += 2 {
		keyNode := attrsNode.Content[i]
		valNode := attrsNode.Content[i+1]
		if keyNode.Kind != yaml.ScalarNode {
			return nil, nil, fmt.Errorf("otel.resource.attributes: non-scalar key at line %d", keyNode.Line)
		}
		key := keyNode.Value
		switch valNode.Kind {
		case yaml.ScalarNode:
			if valNode.Tag == "!!null" {
				// Skip: operator explicitly cleared this attribute.
				continue
			}
			attrs[key] = valNode.Value
		default:
			return nil, nil, fmt.Errorf("otel.resource.attributes[%q]: expected scalar, got %v", key, yamlKindName(valNode.Kind))
		}
	}

	// Strip otel.resource.attributes from the tree before feeding to
	// Viper. We keep the surrounding otel.resource scaffolding so
	// anything else under `resource:` (future fields) still loads
	// normally.
	removeMappingChild(resourceNode, "attributes")

	cleaned, err := yaml.Marshal(&root)
	if err != nil {
		return nil, nil, fmt.Errorf("yaml re-marshal: %w", err)
	}
	return attrs, cleaned, nil
}

// firstDocumentNode unwraps a DocumentNode root produced by
// yaml.Unmarshal into *yaml.Node. Returns nil if the document is empty.
func firstDocumentNode(n *yaml.Node) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode {
		if len(n.Content) == 0 {
			return nil
		}
		return n.Content[0]
	}
	return n
}

// mappingChild returns the value node for `key` inside a mapping node,
// or nil if the key is absent or the parent isn't a mapping.
func mappingChild(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}

// removeMappingChild deletes the (key, value) pair for `key` from a
// mapping node in place. No-op if `key` is absent.
func removeMappingChild(m *yaml.Node, key string) {
	if m == nil || m.Kind != yaml.MappingNode {
		return
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		k := m.Content[i]
		if k.Kind == yaml.ScalarNode && k.Value == key {
			m.Content = append(m.Content[:i], m.Content[i+2:]...)
			return
		}
	}
}

func yamlKindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "document"
	case yaml.SequenceNode:
		return "sequence"
	case yaml.MappingNode:
		return "mapping"
	case yaml.ScalarNode:
		return "scalar"
	case yaml.AliasNode:
		return "alias"
	default:
		return fmt.Sprintf("unknown(%d)", k)
	}
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

	// v3 → v4: there is no in-process upgrade. The legacy `splunk:` block
	// is detected in Load() before unmarshal and produces a hard error,
	// so reaching this branch with v<4 simply means the file was created
	// without a splunk block at all — safe to bump the version stamp.
	// No in-process field changes are required here.

	// v4 → v5: copy legacy LLM fields into the unified LLMConfig blocks
	// so ResolveLLM(...) returns the same answers as the pre-v5
	// ResolvedDefaultLLMAPIKey / EffectiveInspectLLM /
	// ResolvedJudgeAPIKey functions. Migration is one-way and
	// idempotent: if the v5 llm: block is already populated we
	// leave it alone, otherwise we populate it from the legacy
	// fields. We deliberately do NOT clear the legacy fields here
	// so hand-edited YAML keeps round-tripping; `defenseclaw setup
	// migrate-llm` is the tool that actually rewrites the file.
	if cfg.ConfigVersion < 5 {
		migrateLLMConfigFields(cfg)
	}

	cfg.ConfigVersion = CurrentConfigVersion
	// Intentionally silent: migrateConfig() runs on every Load() because
	// we don't rewrite the YAML file (that would be a surprising
	// write-on-read side effect). Logging on every load was just noise
	// — every CLI invocation, every TUI launch, every sidecar restart.
	// The migration is idempotent; suppressing the line keeps the TUI's
	// initial render clean and stops `defenseclaw-gateway status` from
	// printing a banner above the actual status output.
	_ = oldVersion
}

// migrateLLMConfigFields performs the v4→v5 migration: legacy fields
// (default_llm_api_key_env, default_llm_model, inspect_llm.*,
// guardrail.model, guardrail.api_key_env, guardrail.api_base,
// guardrail.judge.model, guardrail.judge.api_key_env,
// guardrail.judge.api_base) are copied into the unified LLMConfig
// slots on the top level and per-component overrides.
//
// Idempotent: re-running does nothing when the v5 slots are already
// populated.
func migrateLLMConfigFields(cfg *Config) {
	// Top-level: inspect_llm + default_llm_* → cfg.LLM.
	if cfg.LLM.APIKeyEnv == "" {
		if cfg.DefaultLLMAPIKeyEnv != "" {
			cfg.LLM.APIKeyEnv = cfg.DefaultLLMAPIKeyEnv
		} else if cfg.InspectLLM.APIKeyEnv != "" {
			cfg.LLM.APIKeyEnv = cfg.InspectLLM.APIKeyEnv
		}
	}
	if cfg.LLM.APIKey == "" && cfg.InspectLLM.APIKey != "" {
		cfg.LLM.APIKey = cfg.InspectLLM.APIKey
	}
	if cfg.LLM.Model == "" {
		switch {
		case cfg.DefaultLLMModel != "":
			cfg.LLM.Model = cfg.DefaultLLMModel
		case cfg.InspectLLM.Model != "":
			cfg.LLM.Model = cfg.InspectLLM.Model
		}
	}
	if cfg.LLM.Provider == "" && cfg.InspectLLM.Provider != "" {
		cfg.LLM.Provider = cfg.InspectLLM.Provider
	}
	if cfg.LLM.BaseURL == "" && cfg.InspectLLM.BaseURL != "" {
		cfg.LLM.BaseURL = cfg.InspectLLM.BaseURL
	}
	if cfg.LLM.Timeout == 0 && cfg.InspectLLM.Timeout > 0 {
		cfg.LLM.Timeout = cfg.InspectLLM.Timeout
	}
	if cfg.LLM.MaxRetries == 0 && cfg.InspectLLM.MaxRetries > 0 {
		cfg.LLM.MaxRetries = cfg.InspectLLM.MaxRetries
	}

	// Guardrail upstream.
	if cfg.Guardrail.LLM.Model == "" && cfg.Guardrail.Model != "" {
		cfg.Guardrail.LLM.Model = cfg.Guardrail.Model
	}
	if cfg.Guardrail.LLM.APIKeyEnv == "" && cfg.Guardrail.APIKeyEnv != "" {
		cfg.Guardrail.LLM.APIKeyEnv = cfg.Guardrail.APIKeyEnv
	}
	if cfg.Guardrail.LLM.BaseURL == "" && cfg.Guardrail.APIBase != "" {
		cfg.Guardrail.LLM.BaseURL = cfg.Guardrail.APIBase
	}

	// Judge.
	if cfg.Guardrail.Judge.LLM.Model == "" && cfg.Guardrail.Judge.Model != "" {
		cfg.Guardrail.Judge.LLM.Model = cfg.Guardrail.Judge.Model
	}
	if cfg.Guardrail.Judge.LLM.APIKeyEnv == "" && cfg.Guardrail.Judge.APIKeyEnv != "" {
		cfg.Guardrail.Judge.LLM.APIKeyEnv = cfg.Guardrail.Judge.APIKeyEnv
	}
	if cfg.Guardrail.Judge.LLM.BaseURL == "" && cfg.Guardrail.Judge.APIBase != "" {
		cfg.Guardrail.Judge.LLM.BaseURL = cfg.Guardrail.Judge.APIBase
	}
}

// detectLegacySplunk returns the first populated splunk.* key found in the
// already-loaded viper state, or "" when none are present. Callers use a
// non-empty result to fail fast with a migration error rather than
// silently dropping the legacy block.
//
// We probe a small set of meaningful keys instead of `viper.IsSet("splunk")`
// because viper treats default values as "set" and all `splunk.*` defaults
// were removed; the only way a key shows up here now is if the operator's
// config file (or env var) populated it.
func detectLegacySplunk() string {
	keys := []string{
		"splunk.hec_endpoint",
		"splunk.hec_token",
		"splunk.hec_token_env",
		"splunk.enabled",
		"splunk.index",
		"splunk.source",
		"splunk.sourcetype",
	}
	for _, k := range keys {
		if viper.IsSet(k) {
			return k
		}
	}
	return ""
}

// warnPlaintextSecrets logs a deprecation warning for each secret stored as
// plain text in config.yaml instead of via an env-var indirection.
func warnPlaintextSecrets(cfg *Config) {
	warn := func(section, field, envDefault string) {
		log.Printf("WARNING: %s.%s contains a plain-text secret in config.yaml — "+
			"migrate it to ~/.defenseclaw/.env as %s and set %s.%s_env=%s instead",
			section, field, envDefault, section, field, envDefault)
	}
	if cfg.LLM.APIKey != "" {
		warn("llm", "api_key", DefenseClawLLMKeyEnv)
	}
	if cfg.InspectLLM.APIKey != "" {
		warn("inspect_llm", "api_key", DefenseClawLLMKeyEnv)
	}
	if cfg.CiscoAIDefense.APIKey != "" {
		warn("cisco_ai_defense", "api_key", "CISCO_AI_DEFENSE_API_KEY")
	}
	if cfg.Scanners.SkillScanner.VirusTotalKey != "" {
		warn("scanners.skill_scanner", "virustotal_api_key", "VIRUSTOTAL_API_KEY")
	}
	for _, s := range cfg.AuditSinks {
		if s.SplunkHEC != nil && s.SplunkHEC.Token != "" {
			log.Printf("WARNING: audit_sinks[%q].splunk_hec.token is set inline — "+
				"prefer token_env to keep secrets out of config.yaml", s.Name)
		}
		if s.HTTPJSONL != nil && s.HTTPJSONL.BearerToken != "" {
			log.Printf("WARNING: audit_sinks[%q].http_jsonl.bearer_token is set inline — "+
				"prefer bearer_env to keep secrets out of config.yaml", s.Name)
		}
	}
}

func (c *Config) Save() error {
	configFile := filepath.Join(c.DataDir, DefaultConfigName)

	data, err := yaml.Marshal(c)
	if err != nil {
		return fmt.Errorf("config: marshal: %w", err)
	}

	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		return err
	}

	// v7 provenance: every successful config save updates the
	// content_hash (so downstream events carry a fingerprint of
	// exactly which config shape produced them) and bumps the
	// monotonic generation counter (so dashboards can detect churn
	// without diffing hashes). A failed Save() never reaches this
	// line — a stale generation would fire spurious "config
	// changed" alerts. Hash the marshaled YAML bytes directly; they
	// are already deterministic per (Config struct, yaml.Marshal
	// impl) and any Load() reading the same file will compute the
	// same fingerprint, which is the property needed for content
	// hash stability across save↔load round-trips.
	version.SetContentHash(data)
	version.BumpGeneration()

	return nil
}

func setDefaults(dataDir string) {
	viper.SetDefault("data_dir", dataDir)
	viper.SetDefault("audit_db", filepath.Join(dataDir, DefaultAuditDBName))
	viper.SetDefault("quarantine_dir", filepath.Join(dataDir, "quarantine"))
	viper.SetDefault("plugin_dir", filepath.Join(dataDir, "plugins"))
	viper.SetDefault("policy_dir", filepath.Join(dataDir, "policies"))
	viper.SetDefault("environment", string(DetectEnvironment()))
	viper.SetDefault("tenant_id", "")
	viper.SetDefault("workspace_id", "")
	viper.SetDefault("deployment_mode", "")
	viper.SetDefault("discovery_source", "")
	viper.SetDefault("claw.mode", string(ClawOpenClaw))
	viper.SetDefault("claw.home_dir", "~/.openclaw")
	viper.SetDefault("claw.config_file", "~/.openclaw/openclaw.json")

	// Unified v5 LLM block. DEFENSECLAW_LLM_KEY / DEFENSECLAW_LLM_MODEL
	// are the canonical env vars — both are bound below so operators can
	// set them in ~/.defenseclaw/.env without touching config.yaml.
	viper.SetDefault("llm.provider", "")
	viper.SetDefault("llm.model", "")
	viper.SetDefault("llm.api_key", "")
	viper.SetDefault("llm.api_key_env", DefenseClawLLMKeyEnv)
	viper.SetDefault("llm.base_url", "")
	viper.SetDefault("llm.timeout", defaultLLMTimeoutSeconds)
	viper.SetDefault("llm.max_retries", defaultLLMMaxRetries)
	_ = viper.BindEnv("llm.api_key_env", DefenseClawLLMKeyEnv)
	_ = viper.BindEnv("llm.model", DefenseClawLLMModelEnv)

	// Legacy inspect_llm defaults preserved for back-compat with
	// pre-v5 hand-edited configs. New writers should emit `llm:`.
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

	viper.SetDefault("audit_sinks", []AuditSink{})

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

	viper.SetDefault("asset_policy.enabled", false)
	viper.SetDefault("asset_policy.mode", AssetPolicyModeObserve)
	for _, target := range []string{"mcp", "skill", "plugin"} {
		viper.SetDefault("asset_policy."+target+".default", "allow")
		viper.SetDefault("asset_policy."+target+".registry_required", false)
		viper.SetDefault("asset_policy."+target+".registry", []AssetPolicyRule{})
		viper.SetDefault("asset_policy."+target+".allowed", []AssetPolicyRule{})
		viper.SetDefault("asset_policy."+target+".denied", []AssetPolicyRule{})
	}
	viper.SetDefault("asset_policy.mcp.runtime_detection.enabled", true)
	viper.SetDefault("asset_policy.mcp.runtime_detection.terminal_commands", true)
	viper.SetDefault("asset_policy.mcp.runtime_detection.unknown_terminal_mcp", AssetPolicyModeObserve)

	viper.SetDefault("ai_discovery.enabled", false)
	viper.SetDefault("ai_discovery.mode", "enhanced")
	viper.SetDefault("ai_discovery.scan_interval_min", 5)
	viper.SetDefault("ai_discovery.process_interval_s", 60)
	viper.SetDefault("ai_discovery.scan_roots", []string{"~"})
	viper.SetDefault("ai_discovery.include_shell_history", true)
	viper.SetDefault("ai_discovery.include_package_manifests", true)
	viper.SetDefault("ai_discovery.include_env_var_names", true)
	viper.SetDefault("ai_discovery.include_network_domains", true)
	viper.SetDefault("ai_discovery.max_files_per_scan", 1000)
	viper.SetDefault("ai_discovery.max_file_bytes", 512*1024)
	viper.SetDefault("ai_discovery.emit_otel", true)
	viper.SetDefault("ai_discovery.store_raw_local_paths", false)

	viper.SetDefault("guardrail.enabled", false)
	viper.SetDefault("guardrail.mode", "observe")
	// "open" is the user-friendly default — see
	// GuardrailConfig.HookFailMode for the rationale. Operators who
	// want strict response-layer enforcement run `defenseclaw setup
	// guardrail` (which prompts) or `defenseclaw guardrail fail-mode
	// closed`.
	viper.SetDefault("guardrail.hook_fail_mode", "open")
	viper.SetDefault("guardrail.scanner_mode", "both")
	viper.SetDefault("guardrail.connector", "")
	viper.SetDefault("guardrail.host", "")
	viper.SetDefault("guardrail.port", 4000)
	viper.SetDefault("guardrail.stream_buffer_bytes", 1024)
	viper.SetDefault("guardrail.block_message", "")
	viper.SetDefault("guardrail.rule_pack_dir", filepath.Join(dataDir, "policies", "guardrail", "default"))
	viper.SetDefault("guardrail.hilt.enabled", false)
	viper.SetDefault("guardrail.hilt.min_severity", "HIGH")
	viper.SetDefault("guardrail.judge.enabled", false)
	viper.SetDefault("guardrail.judge.injection", true)
	viper.SetDefault("guardrail.judge.pii", true)
	viper.SetDefault("guardrail.judge.pii_prompt", true)
	viper.SetDefault("guardrail.judge.pii_completion", true)
	viper.SetDefault("guardrail.judge.tool_injection", true)
	// guardrail.judge.exfil registers the data-exfiltration judge default
	// here so existing config.yaml files without an `exfil:` key still get
	// the judge wired on next reload. Mirrors the Go-side JudgeConfig.Exfil
	// default in defaults.go and the Python JudgeConfig.exfil default in
	// cli/defenseclaw/config.py — three sources of truth must agree, so
	// any of them being missed surfaces as kind=exfil rows never appearing
	// in the audit JSONL during live tests.
	viper.SetDefault("guardrail.judge.exfil", true)
	viper.SetDefault("guardrail.judge.timeout", 30.0)
	viper.SetDefault("guardrail.judge.adjudication_timeout", 5.0)
	viper.SetDefault("guardrail.detection_strategy", "regex_judge")
	viper.SetDefault("guardrail.detection_strategy_completion", "regex_only")
	// judge_sweep runs the full LLM judge on content the regex
	// triager classified as no-signal. Flipped from false to true
	// in the multi-provider-adapters PR after internal red-team
	// runs found pure-regex triage missed enough whitespace-
	// evasion ("/ etc / passwd") and typo-evasion ("passswd")
	// variants that default-off was the dominant false-negative
	// source. Operators who care about latency over recall can
	// still opt out with `guardrail.judge_sweep: false` — viper
	// honors explicit false values because BindEnv/SetDefault
	// resolves in precedence order (explicit > env > default).
	viper.SetDefault("guardrail.judge_sweep", true)
	// Phase 3: retention defaults ON so every operator gets local
	// judge-response forensics without explicit opt-in. The raw body
	// is redacted by emitJudge before it leaves the process (Splunk /
	// OTel see the masked payload); the un-redacted copy lives only
	// in ~/.defenseclaw/audit.db, which is already covered by the
	// same filesystem ACLs as the rest of the data directory. Operators
	// with strict storage or privacy constraints can still opt out with
	// `guardrail.retain_judge_bodies: false` or DEFENSECLAW_PERSIST_JUDGE=0.
	viper.SetDefault("guardrail.retain_judge_bodies", true)

	viper.SetDefault("gateway.host", "127.0.0.1")
	viper.SetDefault("gateway.port", 18789)
	viper.SetDefault("gateway.token_env", "DEFENSECLAW_GATEWAY_TOKEN")
	// fleet_mode defaults to "auto" so existing installs (which never
	// set this field) keep getting the connector + host derivation
	// in gatewayShouldConnectForConfiguredConnector. See the field
	// doc on GatewayConfig.FleetMode for the override semantics.
	viper.SetDefault("gateway.fleet_mode", "auto")
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
	viper.SetDefault("otel.protocol", "")
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
