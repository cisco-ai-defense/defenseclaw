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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/spf13/viper"
	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/version"
)

// ReportConfigLoadError is wired by the unified v8 runtime to emit a generated
// platform-health signal when legacy/recovery config decoding fails.
// Nil in binaries/tests that do not install the hook.
var ReportConfigLoadError func(ctx context.Context, reason string)

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
	// "devin", "copilot", "openhands", "antigravity". Constants for those modes
	// are intentionally not introduced here yet — they're used as
	// raw strings by Config.activeConnector() (see internal/config/
	// claw.go) which dispatches to per-connector readers. Promoting
	// them to typed constants is part of S1.2 and tracked in the
	// claw-agnostic refactor plan.
)

type ClawConfig struct {
	Mode                 ClawMode `mapstructure:"mode"                       yaml:"mode"`
	HomeDir              string   `mapstructure:"home_dir"                   yaml:"home_dir"`
	ConfigFile           string   `mapstructure:"config_file"                yaml:"config_file"`
	WorkspaceDir         string   `mapstructure:"workspace_dir"              yaml:"workspace_dir,omitempty"`
	OpenClawHomeOriginal string   `mapstructure:"openclaw_home_original"     yaml:"openclaw_home_original,omitempty"`
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

// ACPConfig controls the local stdio ACP guard. It contains no executable
// commands or secrets: agent entry points are selected from the compiled ACP
// catalog (or supplied explicitly to defenseclaw-acp), and credentials stay in
// permission-restricted token files.
type ACPConfig struct {
	Enabled        bool                  `mapstructure:"enabled" yaml:"enabled,omitempty"`
	Mode           string                `mapstructure:"mode" yaml:"mode,omitempty"`
	DefaultProfile string                `mapstructure:"default_profile" yaml:"default_profile,omitempty"`
	Clients        map[string]ACPBinding `mapstructure:"clients" yaml:"clients,omitempty"`
	Agents         map[string]ACPBinding `mapstructure:"agents" yaml:"agents,omitempty"`
	// Bindings carries per-pair policy keyed "<client>/<agent>", the same
	// identifier `defenseclaw acp status` already prints. Clients and Agents
	// each hold exactly one profile, and evaluation used to require both of
	// those pins to equal the profile being evaluated, which made the profile
	// global across the whole client x agent matrix: giving a second agent its
	// own profile took it offline in every client pinned to a different one,
	// in both directions. That also made `--activate` all-or-nothing, since
	// promoting one pair promoted every pair sharing the profile, defeating
	// the observe-then-activate rollout the CLI is built around.
	//
	// A present entry decides the profile for that pair alone. Absent, the
	// Clients/Agents pins continue to decide it exactly as before, so an
	// existing config behaves identically.
	Bindings map[string]ACPBinding `mapstructure:"bindings" yaml:"bindings,omitempty"`
	Profiles map[string]ACPProfile `mapstructure:"profiles" yaml:"profiles,omitempty"`
}

// ACPBindingKey is the canonical "<client>/<agent>" key for ACPConfig.Bindings.
func ACPBindingKey(client, agent string) string {
	return strings.ToLower(strings.TrimSpace(client)) + "/" + strings.ToLower(strings.TrimSpace(agent))
}

// ACPBindingFor returns the per-pair binding for one client/agent pair.
func (c ACPConfig) ACPBindingFor(client, agent string) (ACPBinding, bool) {
	if len(c.Bindings) == 0 {
		return ACPBinding{}, false
	}
	binding, ok := c.Bindings[ACPBindingKey(client, agent)]
	return binding, ok
}

// ACPProfileForPair resolves the profile name that governs one pair.
//
// Most specific wins: an explicit per-pair binding, then the agent pin, then
// the client pin, then default_profile. The caller still validates that the
// resolved name exists and admits the pair.
func (c ACPConfig) ACPProfileForPair(client, agent string) string {
	if binding, ok := c.ACPBindingFor(client, agent); ok {
		if profile := strings.TrimSpace(binding.Profile); profile != "" {
			return profile
		}
	}
	if binding, ok := c.Agents[agent]; ok {
		if profile := strings.TrimSpace(binding.Profile); profile != "" {
			return profile
		}
	}
	if binding, ok := c.Clients[client]; ok {
		if profile := strings.TrimSpace(binding.Profile); profile != "" {
			return profile
		}
	}
	return strings.TrimSpace(c.DefaultProfile)
}

type ACPBinding struct {
	Enabled bool   `mapstructure:"enabled" yaml:"enabled,omitempty"`
	Profile string `mapstructure:"profile" yaml:"profile,omitempty"`
}

type ACPProfile struct {
	Mode           string   `mapstructure:"mode" yaml:"mode,omitempty" json:"mode,omitempty"`
	FailMode       string   `mapstructure:"fail_mode" yaml:"fail_mode,omitempty" json:"fail_mode,omitempty"`
	AllowedClients []string `mapstructure:"allowed_clients" yaml:"allowed_clients,omitempty" json:"allowed_clients,omitempty"`
	AllowedAgents  []string `mapstructure:"allowed_agents" yaml:"allowed_agents,omitempty" json:"allowed_agents,omitempty"`
	DeniedMethods  []string `mapstructure:"denied_methods" yaml:"denied_methods,omitempty" json:"denied_methods,omitempty"`
}

type Config struct {
	ConfigVersion  int    `mapstructure:"config_version"        yaml:"config_version"`
	ConfigFilePath string `mapstructure:"-" yaml:"-"`
	// declaredEnterpriseProfile is enterprise.profile as the config source
	// declared it, before the service pin or the per-OS default filled it
	// in. Set only by the loader; not serialized.
	declaredEnterpriseProfile string
	// rulePackDirDeclared records that the config source sets
	// guardrail.rule_pack_dir, so the standalone implicit rule pack default
	// never rewrites an explicit value. Set only by the loader.
	rulePackDirDeclared bool
	// legacyConnectorRouteSelectors names the observability route selectors
	// that list a retired connector ID, for the migration notice.
	legacyConnectorRouteSelectors []string
	// LegacyConnectorNotices records connector IDs this load moved to their
	// replacement (see internal/legacyconnector). The gateway logs them once
	// per boot and finishes the host-side cleanup. Never serialized.
	LegacyConnectorNotices []string `mapstructure:"-" yaml:"-"`

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

	// LLMProviders declares custom LLM providers (config_version 9). It is
	// the input custom-providers.json is derived from. Decoded from the
	// source bytes, not viper, so map keys keep their case.
	LLMProviders LLMProvidersConfig `mapstructure:"-" yaml:"llm_providers,omitempty"`

	DataDir string `mapstructure:"data_dir"              yaml:"data_dir"`
	AuditDB string `mapstructure:"audit_db"         yaml:"audit_db"`
	// JudgeBodiesDB is the standalone SQLite file that holds
	// retained LLM-judge bodies (judge_responses table). Splitting
	// it out from audit.db isolates the highest-volume write path
	// (judge bodies, up to MaxJudgeRawBytes = 64 KiB each) from
	// the comparatively narrow audit_events / activity_events
	// writes, so the two write-lock domains do not contend.
	//
	// Defaults to ~/.defenseclaw/judge_bodies.db; operators can
	// point this at a separate disk in high-throughput
	// deployments. The legacy judge_responses rows in audit.db
	// remain readable; new rows only ever land here.
	JudgeBodiesDB   string               `mapstructure:"judge_bodies_db"  yaml:"judge_bodies_db,omitempty"`
	QuarantineDir   string               `mapstructure:"quarantine_dir"   yaml:"quarantine_dir"`
	PluginDir       string               `mapstructure:"plugin_dir"       yaml:"plugin_dir"`
	PolicyDir       string               `mapstructure:"policy_dir"       yaml:"policy_dir"`
	Environment     string               `mapstructure:"environment"      yaml:"environment"`
	TenantID        string               `mapstructure:"tenant_id"        yaml:"tenant_id,omitempty"`
	WorkspaceID     string               `mapstructure:"workspace_id"     yaml:"workspace_id,omitempty"`
	DeploymentMode  string               `mapstructure:"deployment_mode"  yaml:"deployment_mode,omitempty"`
	DiscoverySource string               `mapstructure:"discovery_source" yaml:"discovery_source,omitempty"`
	Claw            ClawConfig           `mapstructure:"claw"             yaml:"claw"`
	Agent           AgentConfig          `mapstructure:"agent"            yaml:"agent,omitempty"`
	ACP             ACPConfig            `mapstructure:"acp"              yaml:"acp,omitempty"`
	InspectLLM      InspectLLMConfig     `mapstructure:"inspect_llm"      yaml:"inspect_llm,omitempty"`
	CiscoAIDefense  CiscoAIDefenseConfig `mapstructure:"cisco_ai_defense" yaml:"cisco_ai_defense"`
	Scanners        ScannersConfig       `mapstructure:"scanners"         yaml:"scanners"`
	OpenShell       OpenShellConfig      `mapstructure:"openshell"        yaml:"openshell"`
	Watch           WatchConfig          `mapstructure:"watch"            yaml:"watch"`
	Firewall        FirewallConfig       `mapstructure:"firewall"         yaml:"firewall"`
	Guardrail       GuardrailConfig      `mapstructure:"guardrail"        yaml:"guardrail"`
	Gateway         GatewayConfig        `mapstructure:"gateway"          yaml:"gateway"`
	CloudAuth       CloudAuthConfig      `mapstructure:"cloud_auth"       yaml:"cloud_auth,omitempty"`
	// Admission is the install-time admission policy (config_version 9).
	// It replaces policies/rego/data.json and the *_actions keys below.
	// Decoded from the source bytes, not viper, because an action is either
	// a shorthand string or an install/file/runtime triple.
	Admission AdmissionConfig `mapstructure:"-" yaml:"admission,omitempty"`
	// SkillActions, MCPActions and PluginActions are v8 keys: migration
	// input for admission, rejected in a config_version 9 source.
	SkillActions   SkillActionsConfig         `mapstructure:"skill_actions"    yaml:"skill_actions"`
	MCPActions     MCPActionsConfig           `mapstructure:"mcp_actions"      yaml:"mcp_actions"`
	PluginActions  PluginActionsConfig        `mapstructure:"plugin_actions"   yaml:"plugin_actions"`
	AssetPolicy    AssetPolicyConfig          `mapstructure:"asset_policy"     yaml:"asset_policy"`
	Registries     RegistriesConfig           `mapstructure:"registries"       yaml:"registries,omitempty"`
	ClaudeCode     AgentHookConfig            `mapstructure:"claude_code"      yaml:"claude_code,omitempty"`
	Codex          AgentHookConfig            `mapstructure:"codex"            yaml:"codex,omitempty"`
	ConnectorHooks map[string]AgentHookConfig `mapstructure:"connector_hooks"  yaml:"connector_hooks,omitempty"`
	Webhooks []WebhookConfig `mapstructure:"webhooks"         yaml:"webhooks"`
	// Observability decodes the notification-only per-connector webhook
	// overrides used by webhook setup. The canonical v8 telemetry graph is
	// parsed and compiled independently and owns all export routing.
	Observability         ObservabilityConfig         `mapstructure:"observability"    yaml:"observability,omitempty"`
	Privacy               PrivacyConfig               `mapstructure:"privacy"          yaml:"privacy,omitempty"`
	AIDiscovery           AIDiscoveryConfig           `mapstructure:"ai_discovery"     yaml:"ai_discovery,omitempty"`
	ApplicationProtection ApplicationProtectionConfig `mapstructure:"application_protection" yaml:"application_protection,omitempty"`
	Notifications         NotificationsConfig         `mapstructure:"notifications"    yaml:"notifications,omitempty"`
	// Managed configures the local UDS gRPC server consumed by AVC
	// (Cisco Secure Client). Only active when ManagedIPCEnabled()
	// returns true — see managed.go.
	Managed ManagedIPCConfig `mapstructure:"managed" yaml:"managed,omitempty"`
	// Enterprise selects the managed_enterprise profile (Secure Client or
	// standalone) and tunes the standalone profile. See enterprise.go.
	Enterprise EnterpriseConfig `mapstructure:"enterprise" yaml:"enterprise,omitempty"`
	Routing    RoutingConfig    `mapstructure:"routing"          yaml:"routing,omitempty"`
	// Update holds the self-update settings (config_version 9).
	Update UpdateConfig `mapstructure:"update" yaml:"update,omitempty"`
}

// RoutingConfig mirrors routing.RoutingConfig for config.yaml parsing.
// Kept in config package to avoid circular imports; the gateway adapter
// converts to routing.RoutingConfig at boot.
type RoutingConfig struct {
	Enabled   bool                  `mapstructure:"enabled"       yaml:"enabled"`
	Version   string                `mapstructure:"version"       yaml:"version,omitempty"`
	Port      int                   `mapstructure:"port"          yaml:"port,omitempty"`
	Algorithm string                `mapstructure:"algorithm"     yaml:"algorithm,omitempty"`
	Remote    RoutingRemoteConfig   `mapstructure:"remote"        yaml:"remote,omitempty"`
	Models    []RoutingModelBackend `mapstructure:"models"        yaml:"models,omitempty"`
	Signals   RoutingSignalConfig   `mapstructure:"signals"       yaml:"signals,omitempty"`
	Decisions []RoutingDecisionRule `mapstructure:"decisions"     yaml:"decisions,omitempty"`
}

type RoutingModelBackend struct {
	Name         string   `mapstructure:"name"              yaml:"name"`
	Provider     string   `mapstructure:"provider"          yaml:"provider"`
	Model        string   `mapstructure:"model"             yaml:"model"`
	BaseURL      string   `mapstructure:"base_url"          yaml:"base_url,omitempty"`
	APIKeyEnv    string   `mapstructure:"api_key_env"       yaml:"api_key_env,omitempty"`
	Capabilities []string `mapstructure:"capabilities"      yaml:"capabilities,omitempty"`
}

type RoutingSignalConfig struct {
	Keywords []RoutingKeywordSignal `mapstructure:"keywords" yaml:"keywords,omitempty"`
}

type RoutingKeywordSignal struct {
	Name     string   `mapstructure:"name"     yaml:"name"`
	Keywords []string `mapstructure:"keywords" yaml:"keywords"`
	Operator string   `mapstructure:"operator" yaml:"operator,omitempty"`
}

type RoutingDecisionRule struct {
	Name       string             `mapstructure:"name"       yaml:"name"`
	Priority   int                `mapstructure:"priority"   yaml:"priority"`
	Conditions []RoutingCondition `mapstructure:"conditions" yaml:"conditions,omitempty"`
	Operator   string             `mapstructure:"operator"   yaml:"operator,omitempty"`
	ModelRefs  []string           `mapstructure:"model_refs" yaml:"model_refs"`
	Algorithm  string             `mapstructure:"algorithm"  yaml:"algorithm,omitempty"`
}

type RoutingCondition struct {
	Type string `mapstructure:"type" yaml:"type"`
	Name string `mapstructure:"name" yaml:"name"`
}

type RoutingRemoteConfig struct {
	Endpoint  string `mapstructure:"endpoint"   yaml:"endpoint,omitempty"`
	TimeoutMs int    `mapstructure:"timeout_ms" yaml:"timeout_ms,omitempty"`
}

// PrivacyConfig groups privacy/redaction toggles. Today it carries
// only the redaction kill-switch; future fields (per-sink redaction
// scope, custom redactor profiles) land here so operators have a
// single section to audit.
//
// PrivacyConfig is the reserved, empty privacy: section. Redaction is
// controlled by observability.redaction_profiles; the v7 disable_redaction
// switch is rejected by the v8 entrypoint (yaml_v8.go) and only the 0.x
// migration reads it.
type PrivacyConfig struct{}

// AIDiscoveryConfig controls continuous, sidecar-native visibility for
// supported connectors and broader "shadow AI" usage signals. Outbound
// telemetry is sanitized by the inventory service. Local inspection is the
// default; LookupModelProvenanceOnline is a separate, explicit opt-in that
// sends recovered public model repository IDs to the fixed Hugging Face API.
type AIDiscoveryConfig struct {
	Enabled            bool     `mapstructure:"enabled"                   yaml:"enabled"`
	Mode               string   `mapstructure:"mode"                      yaml:"mode"` // passive | enhanced
	ScanIntervalMin    int      `mapstructure:"scan_interval_min"         yaml:"scan_interval_min"`
	ProcessIntervalSec int      `mapstructure:"process_interval_s"        yaml:"process_interval_s"`
	ScanRoots          []string `mapstructure:"scan_roots"                yaml:"scan_roots,omitempty"`
	// HomeDirs is the list of user home directories the detectors that
	// walk per-user dotfiles (editor extensions, MCP configs, shell
	// history, installed applications) should inspect. Empty means
	// "the daemon's own $HOME only" — which under launchd/root resolves
	// to /var/root and misses every actual local user. In
	// managed_enterprise the packaging layer's hook-enumerator populates
	// this list from the same eligible-users enumeration that renders
	// targets.yaml, so per-user detectors and per-user hook wiring stay
	// in lockstep.
	HomeDirs                 []string `mapstructure:"home_dirs"                 yaml:"home_dirs,omitempty"`
	SignaturePacks           []string `mapstructure:"signature_packs"           yaml:"signature_packs,omitempty"`
	AllowWorkspaceSignatures bool     `mapstructure:"allow_workspace_signatures" yaml:"allow_workspace_signatures"`
	DisabledSignatureIDs     []string `mapstructure:"disabled_signature_ids"    yaml:"disabled_signature_ids,omitempty"`
	IncludeShellHistory      bool     `mapstructure:"include_shell_history"     yaml:"include_shell_history"`
	IncludePackageManifests  bool     `mapstructure:"include_package_manifests" yaml:"include_package_manifests"`
	IncludeEnvVarNames       bool     `mapstructure:"include_env_var_names"     yaml:"include_env_var_names"`
	IncludeNetworkDomains    bool     `mapstructure:"include_network_domains"   yaml:"include_network_domains"`
	// IncludeUserEmail adds the signed-in email address DefenseClaw can read
	// from a connector's own account file to identity telemetry: the per-user
	// inventory rows and the hook lifecycle records. Off by default. The uid
	// or SID it would accompany identifies an account on one endpoint, while
	// the address identifies a person across every system they use and is
	// emitted as plaintext, so collecting it is a deliberate privacy decision
	// for the deployment rather than a consequence of enabling discovery.
	IncludeUserEmail            bool     `mapstructure:"include_user_email"        yaml:"include_user_email"`
	LookupModelProvenanceOnline bool     `mapstructure:"lookup_model_provenance_online" yaml:"lookup_model_provenance_online"`
	MaxFilesPerScan             int      `mapstructure:"max_files_per_scan"        yaml:"max_files_per_scan"`
	MaxFileBytes                int      `mapstructure:"max_file_bytes"            yaml:"max_file_bytes"`
	StoreRawLocalPaths          bool     `mapstructure:"store_raw_local_paths"     yaml:"store_raw_local_paths"`
	ConfidencePolicyPath        string   `mapstructure:"confidence_policy_path"    yaml:"confidence_policy_path,omitempty"`
	RequireTrustedBinaryPaths   bool     `mapstructure:"require_trusted_binary_paths" yaml:"require_trusted_binary_paths"`
	TrustedBinaryPrefixes       []string `mapstructure:"trusted_binary_prefixes" yaml:"trusted_binary_prefixes,omitempty"`

	// Runtime controls the runtime planes -- the half of AI discovery that
	// observes what actually ran, next to this block's inventory of what is
	// present. Disabled by default; see AIRuntimeConfig.
	Runtime AIRuntimeConfig `mapstructure:"runtime" yaml:"runtime,omitempty"`

	// IncludeUserPrincipal adds the end-user directory principal (UPN) and
	// the session's Kerberos principal to every record that carries
	// identity: hook decisions, guardrail evaluations, tool activity, the
	// agent, model, tool and guardrail spans, and the inventory records.
	// Off by default for the same reason as IncludeUserEmail: the principal
	// identifies a person across systems.
	IncludeUserPrincipal bool `mapstructure:"include_user_principal" yaml:"include_user_principal,omitempty"`
	// IDEInventory scopes the IDE extension and plugin inventory:
	// IDEInventoryAll (the default, also when empty), IDEInventoryAIOnly
	// or IDEInventoryOff. Resolve through EffectiveIDEInventory.
	IDEInventory string `mapstructure:"ide_inventory" yaml:"ide_inventory,omitempty"`

	// SignaturePackDigests pins pack files by path ("sha256:<hex>"): a
	// pinned pack loads only when it matches, and on a managed standalone
	// device an unpinned pack does not load. ConfidencePolicyDigest pins
	// ConfidencePolicyPath the same way.
	// The keys are file paths with dots, which Viper would split into nested
	// maps, so the loader reads this map from the YAML itself
	// (restoreSignaturePackDigests).
	SignaturePackDigests   map[string]string `mapstructure:"-"                        yaml:"signature_pack_digests,omitempty"`
	ConfidencePolicyDigest string            `mapstructure:"confidence_policy_digest" yaml:"confidence_policy_digest,omitempty"`
}

// IDE inventory scopes for AIDiscoveryConfig.IDEInventory.
const (
	IDEInventoryAll    = "all"
	IDEInventoryAIOnly = "ai_only"
	IDEInventoryOff    = "off"
)

// EffectiveIDEInventory returns the IDE inventory scope, treating an empty
// value as IDEInventoryAll.
func (a AIDiscoveryConfig) EffectiveIDEInventory() string {
	switch scope := strings.TrimSpace(strings.ToLower(a.IDEInventory)); scope {
	case IDEInventoryAIOnly, IDEInventoryOff:
		return scope
	default:
		return IDEInventoryAll
	}
}

// AIRuntimeConfig controls the AI Discovery runtime planes.
//
// Where the surrounding AIDiscoveryConfig inventories what is installed, these
// planes observe behaviour: sustained inference compute, per-process egress to
// a provider, and -- where the platform and privilege allow it -- the sequence
// of host actions an agent takes. The two are joined in process, so a signal
// can report whether an inventoried component was ever actually used and
// whether observed behaviour has any inventoried explanation.
//
// This surface reads more than the inventory scanner does, and the extra reads
// are individually gated:
//
//   - Process argv is read, which the inventory detector deliberately does not
//     collect. It is what makes an agent framework inside a bare python3
//     visible. Argv is classified as content and passes through the same v8
//     field-class projection as everything else, so each destination's
//     redaction profile governs whether it leaves the host.
//   - DNSCapture opens a packet capture to name egress peers exactly rather
//     than inferring them from an address. It needs elevated privilege and is
//     off by default.
//   - EnableHostPlane turns on kernel process, file, and identity events. Every
//     host-plane signal is gated on an AI agent appearing in the process
//     lineage, which is the primary false-positive control: a developer running
//     sudo produces nothing, the same sudo under an agent produces a signal.
//
// Environment variable values are never read on any of these paths, matching
// the inventory detector's names-only rule.
type AIRuntimeConfig struct {
	Enabled bool `mapstructure:"enabled" yaml:"enabled"`

	// PollIntervalSec is how often the planes are sampled. Plane A works on
	// the CPU delta between two polls, so this also sets the window that
	// distinguishes sustained inference from a momentary spike.
	PollIntervalSec int `mapstructure:"poll_interval_s" yaml:"poll_interval_s,omitempty"`

	// MinRiskToReport is the score a finding must reach to be emitted.
	// Defaults to the medium band.
	MinRiskToReport int `mapstructure:"min_risk_to_report" yaml:"min_risk_to_report,omitempty"`

	// Planes selects which of "a", "b", "c" run. Empty means A and B, which
	// need no privilege beyond what the gateway already has.
	Planes []string `mapstructure:"planes" yaml:"planes,omitempty"`

	// EnableHostPlane is the explicit opt-in for Plane C.
	EnableHostPlane bool `mapstructure:"enable_host_plane" yaml:"enable_host_plane"`

	// DNSCapture enables passive DNS observation so an egress peer is named
	// from the answer the process actually received rather than inferred.
	DNSCapture bool `mapstructure:"dns_capture" yaml:"dns_capture"`

	// ChainWindowMin bounds how long a kill chain may take. A chain is a chain
	// within a window rather than over the lifetime of a long-running agent.
	ChainWindowMin int `mapstructure:"chain_window_min" yaml:"chain_window_min,omitempty"`

	// SanctionedEndpoints are gateway hostnames through which AI use is
	// approved. Reaching one is recorded as inventory rather than alarm; going
	// around one that exists is scored as a bypass.
	SanctionedEndpoints []string `mapstructure:"sanctioned_endpoints" yaml:"sanctioned_endpoints,omitempty"`

	// Correlate joins runtime observations against the inventory snapshot.
	// Defaults on. Disabling it removes the read entirely; it does not make
	// findings score as though the inventory disagreed.
	Correlate *bool `mapstructure:"correlate" yaml:"correlate,omitempty"`

	// Acquisition selects where the privileged reads come from:
	//
	//   auto     read directly when this process can, ask the helper when a
	//            managed deployment has de-privileged the gateway
	//   direct   always read directly
	//   helper   always ask the helper, and report blindness if it is absent
	//
	// Empty means auto. The distinction matters because the two failure
	// modes read differently to an operator: "direct" on a sandboxed gateway
	// is a plane that sees nothing, and "helper" with no helper running is a
	// plane that says so.
	Acquisition string `mapstructure:"acquisition" yaml:"acquisition,omitempty"`

	// HelperSocket overrides where the helper listens. Empty means the
	// deployment default.
	HelperSocket string `mapstructure:"helper_socket" yaml:"helper_socket,omitempty"`
}

// Acquisition modes.
const (
	AcquisitionAuto   = "auto"
	AcquisitionDirect = "direct"
	AcquisitionHelper = "helper"
)

// EffectiveAcquisition resolves the acquisition mode, applying the default.
func (c AIRuntimeConfig) EffectiveAcquisition() string {
	switch c.Acquisition {
	case AcquisitionDirect, AcquisitionHelper:
		return c.Acquisition
	default:
		return AcquisitionAuto
	}
}

// Defaults for the runtime planes, applied when a field is left at zero.
const (
	DefaultRuntimePollIntervalSec = 30
	DefaultRuntimeMinRiskToReport = 30
	DefaultRuntimeChainWindowMin  = 60
)

// EffectivePollInterval resolves the poll interval, applying the default.
func (c AIRuntimeConfig) EffectivePollInterval() time.Duration {
	if c.PollIntervalSec <= 0 {
		return DefaultRuntimePollIntervalSec * time.Second
	}
	return time.Duration(c.PollIntervalSec) * time.Second
}

// EffectiveMinRisk resolves the reporting floor, applying the default.
func (c AIRuntimeConfig) EffectiveMinRisk() int {
	if c.MinRiskToReport <= 0 {
		return DefaultRuntimeMinRiskToReport
	}
	return c.MinRiskToReport
}

// EffectiveChainWindow resolves the chain window, applying the default.
func (c AIRuntimeConfig) EffectiveChainWindow() time.Duration {
	if c.ChainWindowMin <= 0 {
		return DefaultRuntimeChainWindowMin * time.Minute
	}
	return time.Duration(c.ChainWindowMin) * time.Minute
}

// CorrelationEnabled resolves the correlate opt-out, which defaults on.
func (c AIRuntimeConfig) CorrelationEnabled() bool {
	return c.Correlate == nil || *c.Correlate
}

// EffectivePlanes resolves which planes run.
//
// An empty selection means A and B. Plane C is never implied: it reads kernel
// process, file, and identity events and must be asked for explicitly, both
// here and through EnableHostPlane.
func (c AIRuntimeConfig) EffectivePlanes() []string {
	if len(c.Planes) == 0 {
		if c.EnableHostPlane {
			return []string{"a", "b", "c"}
		}
		return []string{"a", "b"}
	}
	selected := make([]string, 0, 3)
	for _, plane := range []string{"a", "b", "c"} {
		for _, candidate := range c.Planes {
			if strings.EqualFold(strings.TrimSpace(candidate), plane) {
				if plane == "c" && !c.EnableHostPlane {
					// Selecting plane c without the host-plane opt-in is a
					// configuration mistake worth ignoring loudly rather than
					// silently honouring: the opt-in is where the privilege
					// and privacy decision is recorded.
					break
				}
				selected = append(selected, plane)
				break
			}
		}
	}
	return selected
}

// HostPlaneRequestedWithoutOptIn reports the one configuration where plane c
// is asked for in two places and granted in neither: listed in Planes, with
// EnableHostPlane left false.
//
// It exists so the health surface can name the setting the operator actually
// has to change. Collapsing this into "not selected in
// ai_discovery.runtime.planes" sends someone to a list that already contains
// "c", which is the same failure the permissions command's [unknown] state is
// written to avoid.
func (c AIRuntimeConfig) HostPlaneRequestedWithoutOptIn() bool {
	if c.EnableHostPlane {
		return false
	}
	for _, candidate := range c.Planes {
		if strings.EqualFold(strings.TrimSpace(candidate), "c") {
			return true
		}
	}
	return false
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
	// InstanceName points at a named entry in
	// ~/.defenseclaw/custom-providers.json. When set, the gateway
	// resolves base_url / TLS / base_provider_type from the overlay
	// rather than from this struct. Mirrors the Python-side
	// LLMConfig.instance_name field.
	InstanceName string `mapstructure:"instance_name" yaml:"instance_name,omitempty"`

	// ForwardCustomHeaders controls whether the guardrail gateway
	// forwards inbound HTTP headers (minus an always-denied blocklist of
	// proxy-hop, auth, hop-by-hop, cookie, and framework-internal headers)
	// from the agent on to the upstream LLM provider on both the
	// /v1/chat/completions and passthrough paths (Responses API,
	// /v1/messages, etc.).
	//
	// Pointer-typed so an absent YAML field round-trips as nil, which is
	// interpreted as the safe default (enabled). Operators opt out
	// explicitly with `forward_custom_headers: false`. Use
	// ForwardCustomHeadersEnabled() to read the effective value.
	ForwardCustomHeaders *bool `mapstructure:"forward_custom_headers" yaml:"forward_custom_headers,omitempty"`

	// Region is a free-form region/location hint surfaced on the role
	// (e.g. "us-east-1" for Bedrock, "us-central1" for Vertex). The
	// per-provider sub-blocks (Bedrock.Region, Vertex.Region) take
	// precedence when both are set. Mirrors Python LLMConfig.region.
	Region string `mapstructure:"region" yaml:"region,omitempty"`

	// TLS holds optional per-role TLS overrides. Pointer-typed so an
	// absent block round-trips through YAML unchanged.
	TLS *TLSConfig `mapstructure:"tls" yaml:"tls,omitempty"`

	// Bedrock holds optional per-role Bedrock posture. Pointer-typed
	// so omitempty drops the block on marshal. The gateway dispatcher
	// merges this with the overlay sub-block (role wins, overlay
	// fills blanks) before populating Bifrost's BedrockKeyConfig.
	Bedrock *BedrockKeyConfig `mapstructure:"bedrock" yaml:"bedrock,omitempty"`

	// Vertex holds optional per-role Vertex AI posture. Same merge
	// semantics as Bedrock.
	Vertex *VertexKeyConfig `mapstructure:"vertex"  yaml:"vertex,omitempty"`

	// Azure holds optional per-role Azure OpenAI posture. Same merge
	// semantics as Bedrock.
	Azure *AzureKeyConfig `mapstructure:"azure"   yaml:"azure,omitempty"`

	// ExtraHeaders are additional HTTP headers sent on every request to
	// this provider (e.g. {"llm-model": "gpt-5-5"} for Circuit routing).
	// Forwarded to Bifrost's NetworkConfig.ExtraHeaders.
	ExtraHeaders map[string]string `mapstructure:"extra_headers" yaml:"extra_headers,omitempty"`
}

// TLSConfig captures per-instance TLS overrides on a role-level
// LLMConfig (the same shape lives in custom-providers.json under
// providers[].tls). Operators reach for this when an internal LLM
// endpoint terminates TLS with a self-signed cert chain.
type TLSConfig struct {
	// CACertFile is a path to a PEM-encoded CA bundle on disk. Used
	// when the role wants to pin trust outside of the overlay.
	CACertFile string `mapstructure:"ca_cert_file" yaml:"ca_cert_file,omitempty"`
	// CACertPEM is the inline PEM bundle (typically loaded from the
	// overlay; the gateway never writes this on a role config).
	CACertPEM string `mapstructure:"ca_cert_pem" yaml:"ca_cert_pem,omitempty"`
	// InsecureSkipVerify disables certificate validation. Lab-only.
	InsecureSkipVerify bool `mapstructure:"insecure_skip_verify" yaml:"insecure_skip_verify,omitempty"`
}

// BedrockKeyConfig mirrors the Python LLMConfig.bedrock dataclass and
// the overlay's providers[].bedrock JSON shape. The dispatcher uses
// this struct to populate Bifrost's per-key BedrockKeyConfig.
//
// AuthMode values:
//   - "api_key" (default): gateway-injected; Bifrost reads the API key.
//   - "iam_credentials": access-key / secret-key (+ optional session
//     token) provided via env vars named below.
//   - "profile": named AWS shared-config profile; applied process-wide
//     via AWS_PROFILE before Bifrost loads the default cred chain.
//   - "instance_role": Bifrost falls through to the default cred chain
//     (EC2 / ECS / EKS IRSA).
type BedrockKeyConfig struct {
	Region            string            `mapstructure:"region"             yaml:"region,omitempty"             json:"region,omitempty"`
	AuthMode          string            `mapstructure:"auth_mode"          yaml:"auth_mode,omitempty"          json:"auth_mode,omitempty"`
	AccessKeyEnv      string            `mapstructure:"access_key_env"     yaml:"access_key_env,omitempty"     json:"access_key_env,omitempty"`
	SecretKeyEnv      string            `mapstructure:"secret_key_env"     yaml:"secret_key_env,omitempty"     json:"secret_key_env,omitempty"`
	SessionTokenEnv   string            `mapstructure:"session_token_env"  yaml:"session_token_env,omitempty"  json:"session_token_env,omitempty"`
	ProfileName       string            `mapstructure:"profile_name"       yaml:"profile_name,omitempty"       json:"profile_name,omitempty"`
	InferenceProfile  string            `mapstructure:"inference_profile"  yaml:"inference_profile,omitempty"  json:"inference_profile,omitempty"`
	DeploymentAliases map[string]string `mapstructure:"deployment_aliases" yaml:"deployment_aliases,omitempty" json:"deployment_aliases,omitempty"`
}

// VertexKeyConfig mirrors the Python LLMConfig.vertex dataclass. The
// dispatcher uses this to populate Bifrost's per-key VertexKeyConfig.
//
// AuthMode values: "service_account" (env var holds JSON), "adc"
// (default cred chain), "workload_identity" (k8s WIF).
type VertexKeyConfig struct {
	ProjectID             string `mapstructure:"project_id"               yaml:"project_id,omitempty"               json:"project_id,omitempty"`
	Region                string `mapstructure:"region"                   yaml:"region,omitempty"                   json:"region,omitempty"`
	AuthMode              string `mapstructure:"auth_mode"                yaml:"auth_mode,omitempty"                json:"auth_mode,omitempty"`
	ServiceAccountJSONEnv string `mapstructure:"service_account_json_env" yaml:"service_account_json_env,omitempty" json:"service_account_json_env,omitempty"`
}

// AzureKeyConfig mirrors the Python LLMConfig.azure dataclass. The
// dispatcher uses this to populate Bifrost's per-key AzureKeyConfig.
//
// AuthMode values: "api_key" (gateway-injected from env),
// "managed_identity" (AAD on the host).
type AzureKeyConfig struct {
	Endpoint          string            `mapstructure:"endpoint"           yaml:"endpoint,omitempty"           json:"endpoint,omitempty"`
	APIVersion        string            `mapstructure:"api_version"        yaml:"api_version,omitempty"        json:"api_version,omitempty"`
	AuthMode          string            `mapstructure:"auth_mode"          yaml:"auth_mode,omitempty"          json:"auth_mode,omitempty"`
	DeploymentAliases map[string]string `mapstructure:"deployment_aliases" yaml:"deployment_aliases,omitempty" json:"deployment_aliases,omitempty"`
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
		if v, ok := GetKey(l.APIKeyEnv); ok && strings.TrimSpace(v) != "" {
			return strings.TrimSpace(v)
		}
		if v := strings.TrimSpace(os.Getenv(l.APIKeyEnv)); v != "" {
			return v
		}
	}
	if l.APIKey != "" {
		return l.APIKey
	}
	if v, ok := GetKey(DefenseClawLLMKeyEnv); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
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

// ForwardCustomHeadersEnabled reports whether the gateway forwards
// inbound HTTP headers from the agent through to the upstream LLM
// provider. The feature is enabled by default; nil (unset YAML) is
// treated as true so existing configs keep working. Operators can
// opt out with `llm.forward_custom_headers: false`.
func (l LLMConfig) ForwardCustomHeadersEnabled() bool {
	if l.ForwardCustomHeaders == nil {
		return true
	}
	return *l.ForwardCustomHeaders
}

// recognizedLLMProviders lists the "provider/" prefixes the gateway and
// LiteLLM both understand. Unknown prefixes emit a one-shot warning.
//
// Keep in lockstep with _RECOGNIZED_LLM_PROVIDERS in
// cli/defenseclaw/config.py. The "gemini-openai" entry in particular
// is a Bifrost routing key for Google's OpenAI-compatible Gemini
// endpoint — the gateway routes it through Bifrost's Gemini handler
// (see internal/gateway/provider_bifrost.go), while the Python
// LiteLLM bridge maps it to the same GOOGLE_API_KEY env var via
// cli/defenseclaw/scanner/_llm_env.py.
var recognizedLLMProviders = map[string]struct{}{
	"openai":        {},
	"anthropic":     {},
	"azure":         {},
	"gemini":        {},
	"gemini-openai": {},
	"vertex_ai":     {},
	"bedrock":       {},
	"groq":          {},
	"mistral":       {},
	"cohere":        {},
	"ollama":        {},
	"vllm":          {},
	"deepseek":      {},
	"xai":           {},
	"fireworks_ai":  {},
	"perplexity":    {},
	"huggingface":   {},
	"replicate":     {},
	"openrouter":    {},
	"together_ai":   {},
	"cerebras":      {},
	"lm_studio":     {},
	"lmstudio":      {},
	"local":         {},
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
	// InstanceName is the ONLY signal that binds a role to a
	// custom-providers.json overlay entry (NewProviderForLLMConfig
	// matches the overlay by instance name, never by model prefix).
	// Dropping it here meant a role-level binding like
	// guardrail.judge.llm.instance_name silently fell back to the
	// inferred provider family — live judge content went to the
	// public provider endpoint instead of the operator's custom one.
	if override.InstanceName != "" {
		out.InstanceName = override.InstanceName
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

type FirewallConfig struct {
	ConfigFile string `mapstructure:"config_file" yaml:"config_file"`
	RulesFile  string `mapstructure:"rules_file"  yaml:"rules_file"`
	AnchorName string `mapstructure:"anchor_name" yaml:"anchor_name"`
}

// WebhookConfig is one entry in the top-level “webhooks[]“ list. These are
// notifier webhooks (chat/incident), not telemetry destinations. Canonical v8
// forwarding lives in observability.destinations/routes.
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
// saving the config through the config writer or the TUI doesn't silently
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
//     It governs what those scripts do when delivery, authentication,
//     or the gateway response fails (connection/timeout/5xx, missing
//     token, 4xx, malformed JSON, or no `action` field). "open"
//     allows and logs; "closed" blocks where the connector exposes a
//     block response. DEFENSECLAW_STRICT_AVAILABILITY=1 additionally
//     forces transport and missing-token failures closed.
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
	}
	return AgentHookConfig{}
}

type WatchConfig struct {
	DebounceMs int  `mapstructure:"debounce_ms"            yaml:"debounce_ms"`
	AutoBlock  bool `mapstructure:"auto_block"             yaml:"auto_block"`
	// watch.allow_list_bypass_scan is only v8 migration input (read from the
	// YAML document) for admission.<type>.allow_list_bypass_scan.
	RescanEnabled     bool `mapstructure:"rescan_enabled"         yaml:"rescan_enabled"`
	RescanIntervalMin int  `mapstructure:"rescan_interval_min"    yaml:"rescan_interval_min"`
	// RescanContentGated skips the scanner during a periodic re-scan when a
	// target's content hash and scanner fingerprint are both unchanged since
	// the stored baseline. This avoids re-running the (expensive) scanner and
	// writing a fresh scan_results row every cycle for targets that did not
	// change. Set to false to restore the legacy "scan every target every
	// cycle" behavior.
	RescanContentGated bool `mapstructure:"rescan_content_gated"   yaml:"rescan_content_gated"`
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
	// Binary, UseVirusTotal, UseAIDefense, VirusTotalKey and
	// VirusTotalKeyEnv are v8 keys: migration input, rejected in a
	// config_version 9 source (see Analyzers).
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

	// PolicyFile pins a custom scan policy by digest; required when Policy
	// is "custom" (config_version 9).
	PolicyFile AssetFileRef `mapstructure:"policy_file" yaml:"policy_file,omitempty"`
	// JudgeSource is "inherit" (top-level llm:) or "override" (LLM above).
	JudgeSource string `mapstructure:"judge_source" yaml:"judge_source,omitempty"`
	// FailOnSeverity is the blocking gate DefenseClaw applies to the JSON
	// findings; it is never passed to the scanner. ReviewQueueMin starts
	// the [ReviewQueueMin, FailOnSeverity) review (warn) band.
	FailOnSeverity string `mapstructure:"fail_on_severity" yaml:"fail_on_severity,omitempty"`
	ReviewQueueMin string `mapstructure:"review_queue_min" yaml:"review_queue_min,omitempty"`
	// Analyzers holds the optional analyzers, all off by default.
	Analyzers SkillScannerAnalyzers `mapstructure:"analyzers" yaml:"analyzers,omitempty"`
	Timeouts  SkillScannerTimeouts  `mapstructure:"timeouts"  yaml:"timeouts,omitempty"`
}

// ResolvedVirusTotalKey returns the VirusTotal key from its env var (the
// keys store first, then the process), or the v8 inline value.
func (c *SkillScannerConfig) ResolvedVirusTotalKey() string {
	name := c.VirusTotalKeyEnvName()
	if v, ok := GetKey(name); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return c.VirusTotalKey
}

type MCPScannerConfig struct {
	// Binary is a v8 key: migration input, rejected in config_version 9.
	Binary string `mapstructure:"binary"            yaml:"binary"`
	// Analyzers lists the analyzers to run; empty lets the scanner choose.
	// A v8 source holds a comma-separated string, which the loader splits.
	Analyzers        []string `mapstructure:"analyzers"         yaml:"analyzers"`
	ScanPrompts      bool     `mapstructure:"scan_prompts"      yaml:"scan_prompts"`
	ScanResources    bool     `mapstructure:"scan_resources"    yaml:"scan_resources"`
	ScanInstructions bool     `mapstructure:"scan_instructions" yaml:"scan_instructions"`
	// LLM overrides the top-level llm: block for the MCP scanner.
	LLM LLMConfig `mapstructure:"llm"               yaml:"llm,omitempty"`

	// JudgeSource is "inherit" (top-level llm:) or "override" (LLM above).
	JudgeSource string               `mapstructure:"judge_source" yaml:"judge_source,omitempty"`
	API         MCPScannerAPIConfig  `mapstructure:"api"          yaml:"api,omitempty"`
	YARA        MCPScannerYARAConfig `mapstructure:"yara"         yaml:"yara,omitempty"`
	Timeouts    MCPScannerTimeouts   `mapstructure:"timeouts"     yaml:"timeouts,omitempty"`
}

// AnalyzersArg renders EffectiveAnalyzers as the scanner's comma-separated
// --analyzers value ("" is auto).
func (c MCPScannerConfig) AnalyzersArg() string {
	return strings.Join(c.EffectiveAnalyzers(), ",")
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

	// ScanHookSurface controls whether the hook lane (PreToolUse +
	// PostToolUse + UserPromptSubmit on hook-only connectors like
	// Codex / Claude Code / Cursor / Devin / Hermes / Copilot)
	// forwards payloads to Cisco AI Defense.
	//
	// Pre-existing AID integration only fires on the proxy lane
	// (chat prompts + completions) for OpenClaw / ZeptoClaw, so
	// without this flag tool calls and tool results on hook-only
	// connectors never reach AID.
	//
	// When the API key is unset this flag is a no-op (the AID lane
	// is silently skipped). Default is true so an operator who
	// configures the AID key gets coverage on every surface; flip
	// to false to scope AID to the proxy lane only (e.g. when
	// pricing per-call matters and the operator already gets
	// per-tool coverage from the bundled regex rule pack).
	ScanHookSurface *bool `mapstructure:"scan_hook_surface" yaml:"scan_hook_surface,omitempty"`
}

// HookSurfaceEnabled reports whether the AID lane should fire on the
// hook-side surfaces. Defaults to true (opt-out) so an operator who
// sets `cisco_ai_defense.api_key_env` gets coverage on every surface
// without having to flip a second flag. Returns false when the
// pointer is explicitly set to false.
func (c *CiscoAIDefenseConfig) HookSurfaceEnabled() bool {
	if c == nil || c.ScanHookSurface == nil {
		return true
	}
	return *c.ScanHookSurface
}

// ResolvedAPIKey returns the API key from the key store, env var, or inline value.
func (c *CiscoAIDefenseConfig) ResolvedAPIKey() string {
	if c.APIKeyEnv != "" {
		if v, ok := GetKey(c.APIKeyEnv); ok && v != "" {
			return v
		}
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
	OriginalModel     string `mapstructure:"original_model"       yaml:"original_model,omitempty"`
	BlockMessage      string `mapstructure:"block_message"        yaml:"block_message"`
	StreamBufferBytes int    `mapstructure:"stream_buffer_bytes"  yaml:"stream_buffer_bytes"`
	// RulePackDir is a v8 key: migration input for RulePack/CustomPacks,
	// rejected in a config_version 9 source.
	RulePackDir string `mapstructure:"rule_pack_dir"        yaml:"rule_pack_dir"`
	// RulePack names a built-in pack (default, strict, permissive) or a
	// CustomPacks key; empty uses the default pack (config_version 9).
	RulePack string `mapstructure:"rule_pack" yaml:"rule_pack,omitempty"`
	// CustomPacks maps a pack name to its directory and pinned digest.
	CustomPacks map[string]CustomRulePack `mapstructure:"custom_packs" yaml:"custom_packs,omitempty"`
	// Rules customises RulePack in memory (protections, enable/disable,
	// severity overrides, suppressions, sensitive tools). Restored from
	// the source bytes so rule IDs keep their case.
	Rules GuardrailRulesConfig `mapstructure:"-" yaml:"rules,omitempty"`
	// CiscoTrustLevel is full, advisory or none; empty means full. It was
	// data.json guardrail.cisco_trust_level.
	CiscoTrustLevel string      `mapstructure:"cisco_trust_level" yaml:"cisco_trust_level,omitempty"`
	Judge           JudgeConfig `mapstructure:"judge"                yaml:"judge"`
	HILT            HILTConfig  `mapstructure:"hilt"                 yaml:"hilt"`

	// BlockAt and AlertAt replace the block and alert levels the rule
	// pack's profile implies (strict / default / permissive) when the
	// gateway maps a finding's severity to an action: BlockAt is the
	// lowest severity that blocks, AlertAt the lowest that alerts.
	// Values are CRITICAL, HIGH, MEDIUM or LOW in any case; empty (the
	// default) keeps the pack's level. A guardrail.connectors entry's own
	// value wins over these. They never reach OPA, so the named policy's
	// thresholds for LLM traffic through the guardrail proxy are
	// unaffected. Resolve through EffectiveBlockAt / EffectiveAlertAt,
	// never by reading the fields. Hook decisions read the start-time
	// config, so guardrailNeedsRestart restarts on a change to either.
	BlockAt string `mapstructure:"block_at" yaml:"block_at,omitempty"`
	AlertAt string `mapstructure:"alert_at" yaml:"alert_at,omitempty"`

	// Detection strategy: "regex_only", "regex_judge" (default), "judge_first".
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
	// `guardrail.retain_judge_bodies: false` in config.yaml. Redaction is
	// the safety mechanism for downstream sinks; retention is a
	// local-only decision.
	RetainJudgeBodies bool `mapstructure:"retain_judge_bodies" yaml:"retain_judge_bodies,omitempty"`

	// JudgePersistQueueDepth caps the buffered channel that
	// decouples judge persistence from the proxy hot path. Each
	// slot holds one pending INSERT into judge_responses; the
	// dedicated worker drains the queue and amortizes fsync cost
	// by batching up to 32 rows per transaction.
	//
	// Tuning notes:
	//   - 1024 (default) is sized to absorb a ~10-second burst at
	//     100 RPS of tool-call inspections without dropping rows
	//     while bounding worst-case memory to ~64 MiB (each row
	//     is capped at MaxJudgeRawBytes = 64 KiB).
	//   - Setting this to 0 falls back to the default at boot.
	//
	// Drops show up as defenseclaw.judge.persist.drops with
	// reason="queue_full"; a sustained non-zero rate is the cue
	// to bump this knob (or investigate SQLite write throughput).
	JudgePersistQueueDepth int `mapstructure:"judge_persist_queue_depth" yaml:"judge_persist_queue_depth,omitempty"`

	// AllowUnknownLLMDomains, when true, permits passthrough to hosts
	// that are NOT listed in providers.json — provided the request
	// body still classifies as an LLM shape (messages/contents/input/
	// prompt). The default is false; unknown hosts are rejected so the
	// proxy never fails open. The request is still inspected, audited,
	// and emitted as an EventEgress with branch="shape".
	AllowUnknownLLMDomains bool `mapstructure:"allow_unknown_llm_domains" yaml:"allow_unknown_llm_domains,omitempty"`

	// LLMRole is "", judge_only or judge_and_agent. Python setup owns it;
	// the Go field lets the canonical validator round-trip the key.
	LLMRole string `mapstructure:"llm_role" yaml:"llm_role,omitempty"`

	// AllowPrivateUpstreams is a list of specific IP addresses that are
	// exempt from the SSRF private-address block for LLM upstream forwarding.
	// Loopback, link-local, and cloud-metadata IPs are never exempted.
	AllowPrivateUpstreams []string `mapstructure:"allow_private_upstreams" yaml:"allow_private_upstreams,omitempty"`

	// HookFailMode is the operator-chosen failure behavior for every generated
	// hook script (codex-hook, claude-code-hook, inspect-*). It covers
	// transport, missing-token/authentication, and invalid-response failures.
	// Two values are supported:
	//
	//   - "open": connection failures, timeouts, 5xx/4xx responses,
	//     missing authentication, malformed JSON, or no action ALLOW
	//     the event with a stderr warning and an entry in
	//     $DEFENSECLAW_HOME/logs/hook-failures.jsonl.
	//
	//   - "closed" (fresh-install default): the same failures BLOCK where
	//     the connector/event exposes a blocking response. Migrated legacy
	//     configs can retain an explicit "open".
	//
	// DEFENSECLAW_STRICT_AVAILABILITY=1 additionally forces transport and
	// missing-token failures closed. See
	// internal/gateway/connector/hooks/_hardening.sh for the runtime contract.
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

	// HookSelfHeal enables the connector hook self-heal guard
	// (internal/gateway/hook_config_guard.go). When true (the default),
	// the sidecar watches the active connector's agent config file
	// (e.g. ~/.cursor/hooks.json, ~/.claude/settings.json,
	// ~/.codex/config.toml) and immediately re-installs the DefenseClaw
	// hook block if a user deletes or strips it while the gateway is
	// running. Set to false to allow operators to remove hooks by hand
	// without the gateway restoring them; enforcement then lapses until
	// the next setup/restart, which is the pre-self-heal behavior.
	HookSelfHeal bool `mapstructure:"hook_self_heal" yaml:"hook_self_heal,omitempty"`

	// HookSelfHealDebounceMs coalesces a burst of filesystem events into
	// a single presence check before deciding whether to re-install.
	// <= 0 falls back to the built-in default (500ms).
	HookSelfHealDebounceMs int `mapstructure:"hook_self_heal_debounce_ms" yaml:"hook_self_heal_debounce_ms,omitempty"`

	// Connectors holds per-connector guardrail overrides keyed by
	// connector name. Scope is HOOK-BASED connectors only (codex,
	// claudecode, antigravity, ...); the proxy connectors (openclaw,
	// zeptoclaw) are never listed here. An empty or absent map
	// preserves the legacy single-connector behavior driven by the
	// singular Connector field.
	//
	// Each entry inherits any unset field from the global
	// GuardrailConfig — resolution goes through the Effective*(connector)
	// methods, never by reading map entries directly. This struct does
	// NOT validate connector identity against the registry (config is a
	// leaf package); the "must implement HookEndpoint" guard lives in the
	// gateway boot loop where the registry is available.
	Connectors map[string]PerConnectorGuardrailConfig `mapstructure:"connectors" yaml:"connectors,omitempty"`

	// Profiles, ProfileAssignments and DefaultProfile configure
	// identity-based guardrail profiles (see guardrail_profiles.go). All
	// three are empty by default, which keeps the behaviour above, and
	// ValidateGuardrailProfiles rejects them under the Secure Client
	// integration.
	Profiles           map[string]GuardrailProfile `mapstructure:"profiles"            yaml:"profiles,omitempty"`
	ProfileAssignments []ProfileAssignment         `mapstructure:"profile_assignments" yaml:"profile_assignments,omitempty"`
	DefaultProfile     string                      `mapstructure:"default_profile"     yaml:"default_profile,omitempty"`

	// profileConnectors is set only on a configuration DerivedForProfile
	// returns: the profile's own connectors map, keyed by normalized
	// connector name. policyOverride layers it over Connectors so a profile
	// can tune one connector without making it a member of
	// guardrail.connectors. It is unexported, so it never reaches YAML,
	// JSON or a cloned configuration.
	profileConnectors map[string]PerConnectorGuardrailConfig
	// profileRules is the profile's own guardrail.profiles.<p>.rules on a
	// derived configuration; EffectiveRulesForConnector layers it over the
	// global and connector rules. Unexported like profileConnectors.
	profileRules *GuardrailRulesConfig
}

// PerConnectorGuardrailConfig carries the subset of guardrail policy
// that an operator may override on a single hook-based connector. Every
// field is optional: an unset (zero-value) field inherits the global
// GuardrailConfig value via the Effective*(connector) resolvers. The
// HILT block is a pointer so a nil block means "inherit the global HILT"
// while a present-but-empty block means "explicitly override".
type PerConnectorGuardrailConfig struct {
	Mode         string      `mapstructure:"mode"           yaml:"mode,omitempty"`
	HILT         *HILTConfig `mapstructure:"hilt"           yaml:"hilt,omitempty"`
	HookFailMode string      `mapstructure:"hook_fail_mode" yaml:"hook_fail_mode,omitempty"`
	BlockMessage string      `mapstructure:"block_message"  yaml:"block_message,omitempty"`
	// RulePackDir is a v8 key, rejected in config_version 9 (use RulePack).
	RulePackDir string `mapstructure:"rule_pack_dir"  yaml:"rule_pack_dir,omitempty"`
	// RulePack and Rules override the global pack and its customisation
	// for this connector; empty / nil inherit.
	RulePack string                `mapstructure:"rule_pack" yaml:"rule_pack,omitempty"`
	Rules    *GuardrailRulesConfig `mapstructure:"-"         yaml:"rules,omitempty"`

	// BlockAt / AlertAt set this connector's block and alert levels,
	// winning over guardrail.block_at / alert_at and over the levels of
	// the connector's rule pack (see GuardrailConfig.BlockAt for values
	// and meaning). This struct also types the application_protection
	// guardrail overlays, which do not support these two keys:
	// ApplicationProtectionConfig.Validate rejects them there.
	BlockAt string `mapstructure:"block_at" yaml:"block_at,omitempty"`
	AlertAt string `mapstructure:"alert_at" yaml:"alert_at,omitempty"`

	// Enabled is the per-connector on/off switch toggled by
	// `defenseclaw guardrail disable --connector X` (and its enable
	// counterpart). It is a pointer so that an unset (nil) field means
	// "inherit the default (enabled)" — the overwhelming majority case,
	// which keeps the connector active exactly as before. A non-nil
	// false means the operator explicitly disabled this connector: the
	// boot loop drops it from the active set so the existing
	// set-difference teardown removes its hooks (parity with the global
	// `guardrail disable`, scoped to one connector), and the hook gates
	// short-circuit it to allow-without-scan as defense-in-depth.
	// Resolved via EffectiveEnabled(connector); never read directly.
	// Unlike a full `setup remove`, the connector's other policy fields
	// (mode/hilt/rule_pack_dir) are retained so re-enable restores it
	// with no re-prompt.
	Enabled *bool `mapstructure:"enabled" yaml:"enabled,omitempty"`
}

// normalizeConnectorKey canonicalizes a connector name for
// guardrail.connectors map lookups: trim, lowercase, and fold the known
// hyphen/underscore aliases onto their canonical registry name. It is
// the leaf-package counterpart of the Python connector_paths.normalize
// alias table and must be kept in sync with it. Unlike that helper this
// one returns "" for an empty/whitespace input rather than defaulting to
// "openclaw": callers (connectorOverride / HasConnector) guard the empty
// case separately so an unset connector falls through to the global
// value instead of accidentally matching the openclaw override.
func normalizeConnectorKey(name string) string {
	n := strings.ToLower(strings.TrimSpace(name))
	switch n {
	case "open-hands", "open_hands":
		return "openhands"
	case "claude-code", "claude_code":
		return "claudecode"
	default:
		return n
	}
}

// connectorOverride returns the per-connector override block for the
// named connector, if one is configured. It is the single internal
// lookup point shared by every Effective*(connector) resolver: an empty
// connector name, a nil receiver, or an empty map all yield (zero,
// false) so callers uniformly fall through to the global value.
//
// Lookup is connector-name-insensitive: an exact key hit is the fast
// path, otherwise keys are compared after normalizeConnectorKey so that
// a request for the registry-canonical name (e.g. "openhands") resolves
// an override written with different case or a hyphen/underscore alias
// (e.g. "OpenHands", "open-hands"). This matches HasConnector and keeps
// every Effective*() resolver consistent with the boot loop, which keys
// connectors by their canonical registry name.
func (g *GuardrailConfig) connectorOverride(connector string) (PerConnectorGuardrailConfig, bool) {
	if g == nil || connector == "" || len(g.Connectors) == 0 {
		return PerConnectorGuardrailConfig{}, false
	}
	if pc, ok := g.Connectors[connector]; ok {
		return pc, true
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return PerConnectorGuardrailConfig{}, false
	}
	for name, pc := range g.Connectors {
		if normalizeConnectorKey(name) == want {
			return pc, true
		}
	}
	return PerConnectorGuardrailConfig{}, false
}

// HasConnector reports whether the named connector is a member of the
// multi-connector guardrail.connectors set (connector-name-insensitive).
// In a multi-connector install every configured connector is active and
// therefore opted into hook evaluation, so the gateway treats set
// membership as a sufficient enablement signal. Returns false for a nil
// receiver or an empty map, so single-connector installs (which never
// populate guardrail.connectors) are unaffected. Pure lookup.
func (g *GuardrailConfig) HasConnector(connector string) bool {
	_, ok := g.connectorOverride(connector)
	return ok
}

// EffectiveMode returns the guardrail mode for the named connector:
// per-connector override (when non-empty) > global Mode > "observe".
// Pure lookup — never errors, never mutates, never touches I/O.
func (g *GuardrailConfig) EffectiveMode(connector string) string {
	if g == nil {
		return "observe"
	}
	if pc, ok := g.policyOverride(connector); ok {
		if m := strings.TrimSpace(pc.Mode); m != "" {
			return m
		}
	}
	if m := strings.TrimSpace(g.Mode); m != "" {
		return m
	}
	return "observe"
}

// EffectiveEnabled reports whether the named connector should be brought
// up and enforced. The default is true: a nil receiver, an empty
// connector name, no override entry, or an entry with an unset (nil)
// Enabled pointer all resolve to true, so single-connector installs and
// every connector that was never explicitly disabled keep running
// exactly as before. Only an explicit `enabled: false` in the
// per-connector override returns false — that is the signal the boot
// loop uses to drop the connector from the active set (triggering the
// existing set-difference teardown) and the hook gates use to
// short-circuit it to allow-without-scan. Pure lookup — never errors,
// never mutates, never touches I/O.
func (g *GuardrailConfig) EffectiveEnabled(connector string) bool {
	if g == nil {
		return true
	}
	if pc, ok := g.connectorOverride(connector); ok && pc.Enabled != nil {
		return *pc.Enabled
	}
	return true
}

// EffectiveHILT returns the HILT config for the named connector. A
// per-connector hilt block (when present) fully replaces the global
// block; otherwise the global HILT is returned. Pure lookup.
func (g *GuardrailConfig) EffectiveHILT(connector string) HILTConfig {
	if g == nil {
		return HILTConfig{}
	}
	if pc, ok := g.policyOverride(connector); ok && pc.HILT != nil {
		return *pc.HILT
	}
	return g.HILT
}

// EffectiveBlockMessage returns the per-connector block message when
// set, else the global BlockMessage (which may be empty — the gateway
// substitutes its built-in default downstream). Pure lookup.
func (g *GuardrailConfig) EffectiveBlockMessage(connector string) string {
	if g == nil {
		return ""
	}
	if pc, ok := g.policyOverride(connector); ok {
		if pc.BlockMessage != "" {
			return pc.BlockMessage
		}
	}
	return g.BlockMessage
}

// EffectiveRulePackDir returns the per-connector rule-pack directory
// when set, else the global RulePackDir. Pure lookup — path existence
// is validated elsewhere (rule-pack load), not here.
func (g *GuardrailConfig) EffectiveRulePackDir(connector string) string {
	if g == nil {
		return ""
	}
	if pc, ok := g.policyOverride(connector); ok {
		if strings.TrimSpace(pc.RulePackDir) != "" {
			return pc.RulePackDir
		}
	}
	return g.RulePackDir
}

// EffectiveBlockAt returns the lowest severity that blocks for the named
// connector: its guardrail.connectors block_at when set, else the global
// guardrail.block_at, as a canonical uppercase level (CRITICAL, HIGH,
// MEDIUM, LOW). "" means neither is set, so the connector's rule pack
// profile decides. A value Validate would reject counts as unset, so a
// config that skipped Validate can never produce an out-of-range level.
// Pure lookup — never errors, never mutates, never touches I/O.
func (g *GuardrailConfig) EffectiveBlockAt(connector string) string {
	if g == nil {
		return ""
	}
	if pc, ok := g.policyOverride(connector); ok {
		if level := canonicalGuardrailLevel(pc.BlockAt); level != "" {
			return level
		}
	}
	return canonicalGuardrailLevel(g.BlockAt)
}

// EffectiveAlertAt is EffectiveBlockAt for the lowest severity that
// alerts (per-connector alert_at, else global alert_at, else ""). It does
// not clamp the alert level to the block level: the gateway does that
// after resolving both against the connector's rule pack. Pure lookup.
func (g *GuardrailConfig) EffectiveAlertAt(connector string) string {
	if g == nil {
		return ""
	}
	if pc, ok := g.policyOverride(connector); ok {
		if level := canonicalGuardrailLevel(pc.AlertAt); level != "" {
			return level
		}
	}
	return canonicalGuardrailLevel(g.AlertAt)
}

// canonicalGuardrailLevel trims and uppercases a block_at / alert_at value
// and returns it when it is CRITICAL, HIGH, MEDIUM or LOW, else "".
func canonicalGuardrailLevel(value string) string {
	level := strings.ToUpper(strings.TrimSpace(value))
	switch level {
	case "CRITICAL", "HIGH", "MEDIUM", "LOW":
		return level
	default:
		return ""
	}
}

// validateGuardrailLevel accepts "" (inherit) and the four levels in any
// case. field names the key in the error, e.g. "guardrail.block_at".
func validateGuardrailLevel(field, value string) error {
	if strings.TrimSpace(value) == "" || canonicalGuardrailLevel(value) != "" {
		return nil
	}
	return fmt.Errorf("%s: must be one of CRITICAL, HIGH, MEDIUM, LOW (got %q)", field, value)
}

// Validate checks per-connector guardrail VALUE invariants only — the
// NEW guardrail.connectors map. For each override it inspects enum
// values (mode, hook_fail_mode, hilt.min_severity, block_at, alert_at)
// and rejects empty connector names. It deliberately does NOT
// re-validate the older global guardrail fields: those predate
// multi-connector support and were never gated by Load(), so validating
// them here could reject configs that load fine today. The exception is
// the global block_at / alert_at pair: it is new, so no existing config
// can carry a bad value, and it is checked like its per-connector
// counterpart. It never imports the connector registry — the "entries
// must be hook connectors" guard lives in the gateway boot loop, where
// the registry is in hand. Wired into Load().
func (g *GuardrailConfig) Validate() error {
	if g == nil {
		return nil
	}
	if err := validateGuardrailLevel("guardrail.block_at", g.BlockAt); err != nil {
		return err
	}
	if err := validateGuardrailLevel("guardrail.alert_at", g.AlertAt); err != nil {
		return err
	}
	// Per-connector overrides, in sorted order for deterministic errors.
	names := make([]string, 0, len(g.Connectors))
	for name := range g.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	// Reject two distinct keys that canonicalize to the same connector
	// (e.g. "OpenHands" + "openhands", or "open-hands" + "openhands").
	// connectorOverride() resolves keys through normalizeConnectorKey, so a
	// duplicate would make per-connector lookups (mode, fail mode, HILT) and
	// the active-connector roster depend on Go map iteration order — a
	// nondeterministic, security-relevant ambiguity in action mode. Fail loud
	// at config load instead.
	seen := make(map[string]string, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("guardrail.connectors: empty connector name is not allowed")
		}
		if norm := normalizeConnectorKey(name); norm != "" {
			if prev, dup := seen[norm]; dup {
				return fmt.Errorf("guardrail.connectors: %q and %q refer to the same connector %q; keep only one", prev, name, norm)
			}
			seen[norm] = name
		}
	}
	for _, name := range names {
		pc := g.Connectors[name]
		if err := validateGuardrailMode(pc.Mode); err != nil {
			return fmt.Errorf("guardrail.connectors[%q]: %w", name, err)
		}
		if err := validateGuardrailHookFailMode(pc.HookFailMode); err != nil {
			return fmt.Errorf("guardrail.connectors[%q]: %w", name, err)
		}
		if pc.HILT != nil {
			if err := validateGuardrailMinSeverity(pc.HILT.MinSeverity); err != nil {
				return fmt.Errorf("guardrail.connectors[%q]: %w", name, err)
			}
		}
		if err := validateGuardrailLevel("block_at", pc.BlockAt); err != nil {
			return fmt.Errorf("guardrail.connectors[%q]: %w", name, err)
		}
		if err := validateGuardrailLevel("alert_at", pc.AlertAt); err != nil {
			return fmt.Errorf("guardrail.connectors[%q]: %w", name, err)
		}
	}
	if err := validateAllowPrivateUpstreams(g.AllowPrivateUpstreams); err != nil {
		return err
	}
	return nil
}

// validateGuardrailMode accepts the empty string (inherit/default) and
// the canonical guardrail modes. Anything else is a named error.
func validateGuardrailMode(mode string) error {
	switch strings.TrimSpace(mode) {
	case "", "observe", "action":
		return nil
	default:
		return fmt.Errorf("invalid guardrail mode %q (want \"observe\" or \"action\")", mode)
	}
}

// validateGuardrailHookFailMode accepts the empty string (inherit/
// default) plus the two canonical hook fail-mode sentinels.
func validateGuardrailHookFailMode(mode string) error {
	switch strings.TrimSpace(strings.ToLower(mode)) {
	case "", "open", "closed":
		return nil
	default:
		return fmt.Errorf("invalid hook_fail_mode %q (want \"open\" or \"closed\")", mode)
	}
}

// validateGuardrailMinSeverity accepts the empty string (inherit/
// default) plus the canonical severity ladder.
func validateGuardrailMinSeverity(sev string) error {
	switch strings.TrimSpace(strings.ToUpper(sev)) {
	case "", "LOW", "MEDIUM", "HIGH", "CRITICAL":
		return nil
	default:
		return fmt.Errorf("invalid hilt.min_severity %q (want LOW, MEDIUM, HIGH, or CRITICAL)", sev)
	}
}

// validateAllowPrivateUpstreams checks that each entry is a valid IP
// address (not CIDR, not loopback/link-local/metadata).
func validateAllowPrivateUpstreams(ips []string) error {
	for _, raw := range ips {
		s := strings.TrimSpace(raw)
		if s == "" {
			continue
		}
		if strings.Contains(s, "/") {
			return fmt.Errorf("guardrail.allow_private_upstreams: %q is a CIDR — specify individual IPs only (e.g. %q)", s, strings.SplitN(s, "/", 2)[0])
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return fmt.Errorf("guardrail.allow_private_upstreams: %q is not a valid IP address", s)
		}
		if netguard.IsCloudMetadataIP(ip) {
			return fmt.Errorf("guardrail.allow_private_upstreams: cloud metadata address %q is not allowed", s)
		}
		if ip.IsLoopback() {
			return fmt.Errorf("guardrail.allow_private_upstreams: loopback address %q is not allowed (Ollama uses a dedicated bypass)", s)
		}
		if ip.IsMulticast() || ip.IsUnspecified() {
			return fmt.Errorf("guardrail.allow_private_upstreams: %q is not a valid upstream address", s)
		}
		if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
			return fmt.Errorf("guardrail.allow_private_upstreams: link-local address %q is not allowed", s)
		}
	}
	return nil
}

// EffectiveHookFailMode returns the operator-chosen hook fail mode,
// defaulting to "closed" when unset (CodeGuard rule
// codeguard-0-authorization-access-control: deny by default). The
// canonical "open" sentinel is the only way to get the legacy
// fail-open behavior; any other value (typo, blank, malformed
// migration row) collapses to "closed" so the agent never silently
// fails open at the hook failure boundary. Centralized here so the
// sidecar and any future config-edit surfaces never disagree on the
// default.
//
// Backwards compatibility: existing operators on v3 are protected by
// the _migrate_0_4_0_seed_hook_fail_mode migration in
// cli/defenseclaw/migrations.py, which writes “hook_fail_mode: open“
// into config.yaml on first upgrade. New installs and explicit-empty
// values get the safer default.
func (g *GuardrailConfig) EffectiveHookFailMode() string {
	if g == nil {
		return "closed"
	}
	if g.HookFailMode == "open" {
		return "open"
	}
	return "closed"
}

// EffectiveHookFailModeFor returns the hook fail mode for the named
// connector. An explicit connector override wins even in observe mode: it is
// an operator-selected response-integrity posture, not a policy verdict.
// Observe-only connectors without an override retain the historical fail-open
// behavior; action mode falls through to the global value. Pass "" to resolve
// the global connector mode/value. Pure lookup — never errors, never mutates.
func (g *GuardrailConfig) EffectiveHookFailModeFor(connector string) string {
	if g == nil {
		return "closed"
	}
	if pc, ok := g.connectorOverride(connector); ok {
		if strings.TrimSpace(pc.HookFailMode) != "" {
			// Mirror the global EffectiveHookFailMode() normalization
			// (avarice F-0681): the canonical "open" sentinel is the only
			// way to opt into legacy fail-open; any other per-connector
			// value (typo, blank, malformed row) collapses to "closed" so
			// the multi-connector boot path never silently fails open.
			if strings.EqualFold(strings.TrimSpace(pc.HookFailMode), "open") {
				return "open"
			}
			return "closed"
		}
	}
	if !strings.EqualFold(strings.TrimSpace(g.EffectiveMode(connector)), "action") {
		return "open"
	}
	return g.EffectiveHookFailMode()
}

// EffectiveStrategy returns the detection strategy for the given direction,
// falling back to the global DetectionStrategy (default: "regex_judge").
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

	// HookConnectors gates the hook-lane judge per connector. Hook-based
	// connectors (hermes / opencode / claudecode / …) deliver content to
	// inspectMessageContent, which historically ran regex + Cisco AID
	// only; connectors listed here additionally forward that content to
	// the LLM judge — and therefore to a custom provider when
	// guardrail.judge.llm points at one. Empty list keeps the hook-lane
	// judge off (the proxy lane is unaffected); the "*" entry enables
	// every connector.
	HookConnectors []string `mapstructure:"hook_connectors" yaml:"hook_connectors,omitempty"`

	// Trace logs judge prompts and responses for debugging. It replaces
	// DEFENSECLAW_JUDGE_TRACE and is refused in managed mode.
	Trace bool `mapstructure:"trace" yaml:"trace,omitempty"`

	// HookTimeout caps the hook-lane judge round-trip in seconds.
	// Distinct from Timeout (proxy lane, default 30s) because hook
	// scripts abandon the gateway call at curl --max-time 10; the
	// gateway applies a 5s default when unset.
	HookTimeout float64 `mapstructure:"hook_timeout" yaml:"hook_timeout,omitempty"`

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

// HookConnectorEnabled reports whether the hook-lane judge is enabled
// for the named connector. Requires the judge itself to be enabled;
// matching against HookConnectors is case-insensitive and the "*"
// entry matches every connector. Empty list (the default) keeps the
// hook lane off so existing deployments see no behavior change.
func (c *JudgeConfig) HookConnectorEnabled(name string) bool {
	if c == nil || !c.Enabled {
		return false
	}
	name = strings.TrimSpace(name)
	if name == "" {
		return false
	}
	for _, entry := range c.HookConnectors {
		entry = strings.TrimSpace(entry)
		if entry == "*" || strings.EqualFold(entry, name) {
			return true
		}
	}
	return false
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
	//                   dial; codex/claudecode dial only if
	//                   gateway.host is non-loopback. An openclaw
	//                   connector implied only by claw.mode, on a
	//                   loopback host, does not dial when OpenClaw is
	//                   not installed (no openclaw.json, no binary).
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
	FleetMode    string                    `mapstructure:"fleet_mode"        yaml:"fleet_mode,omitempty"`
	ConfigReload GatewayConfigReloadConfig `mapstructure:"config_reload"     yaml:"config_reload,omitempty"`
	Watcher      GatewayWatcherConfig      `mapstructure:"watcher"           yaml:"watcher"`
	Watchdog     WatchdogConfig            `mapstructure:"watchdog"          yaml:"watchdog"`
	SandboxHome  string                    `mapstructure:"-"                 yaml:"-"`
	ClawHome     string                    `mapstructure:"-"                 yaml:"-"`
}

type GatewayConfigReloadConfig struct {
	// Mode controls what the running gateway does after config.yaml changes.
	// "hot" validates and reconciles in process. "restart" validates the new
	// file, records the reload, then shuts down so an external supervisor can
	// start a fresh process with the full config.
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
}

// CloudAuthMode values select the credential source used when the future
// defenseclaw cloud client authenticates outbound requests.
const (
	CloudAuthModeCMID = "cmid"
)

// CloudAuthConfig selects how defenseclaw authenticates to the defenseclaw
// cloud. The empty Mode disables cloud auth; today the only supported value
// is "cmid", which sources credentials from the managed cloud auth provider
// registered via internal/managed/cloudreg.
type CloudAuthConfig struct {
	Mode    string `mapstructure:"mode"     yaml:"mode,omitempty"`
	LibPath string `mapstructure:"lib_path" yaml:"lib_path,omitempty"`
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

// ResolvedToken returns the gateway token, walking the precedence
// ladder. The order mirrors GatewayConfig.resolved_token in
// cli/defenseclaw/config.py so the Python CLI and the Go gateway
// can never disagree on which token is "live".
//
// Resolution:
//
//  1. g.TokenEnv (operator-supplied override) — if set AND the
//     named env var is populated, return it.
//  2. defaultGatewayTokenEnv (DEFENSECLAW_GATEWAY_TOKEN) — the
//     canonical name EnsureGatewayToken writes on first boot.
//  3. legacyGatewayTokenEnv (OPENCLAW_GATEWAY_TOKEN) — back-compat
//     shim for installs that bootstrapped before the rename.
//  4. g.Token literal — last resort because plaintext secrets in
//     config.yaml are discouraged.
//
// Why fall through past g.TokenEnv when it's set-but-empty:
// pre-fix this function had `if/else` semantics — when TokenEnv
// was set the canonical+legacy checks were SKIPPED entirely.
// That broke the symmetric Python flow: with the pre-defenseclaw
// default token_env=OPENCLAW_GATEWAY_TOKEN in config.yaml AND
// only DEFENSECLAW_GATEWAY_TOKEN in the dotenv (the post-firstboot
// state), Python found the token via fall-through while Go
// silently returned g.Token (empty) for every non-sidecar-boot
// caller (judge LLM init, etc.). The sidecar boot path masked
// the bug via EnsureGatewayToken's own fallback, so it only
// surfaced in obscure code paths until investigation.
func (g *GatewayConfig) ResolvedToken() string {
	if g.TokenEnv != "" {
		if v := os.Getenv(g.TokenEnv); v != "" {
			return v
		}
	}
	if v := os.Getenv(defaultGatewayTokenEnv); v != "" {
		return v
	}
	if v := os.Getenv(legacyGatewayTokenEnv); v != "" {
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

// APIBindHost returns the address the gateway REST API listens on: an explicit
// gateway.api_bind, else the legacy standalone shim's host, else loopback.
// Every listener, hook/plugin address, and health probe derives the API host
// from here so they cannot disagree.
func APIBindHost(cfg *Config) string {
	if cfg == nil {
		return "127.0.0.1"
	}
	if cfg.Gateway.APIBind != "" {
		return cfg.Gateway.APIBind
	}
	if host, ok := LegacyStandaloneAPIHost(cfg); ok {
		return host
	}
	return "127.0.0.1"
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

// LoadFromFile reads one config file (the default config path when empty) and
// decodes it with the strict runtime loader, the one path every consumer
// shares with the gateway. A source older than config_version 8 is refused
// with a single error that names the repair, `defenseclaw migrate`; nothing
// here converts or half-loads it. The managed-enterprise trust check runs
// before the file is read.
func LoadFromFile(configFile string) (*Config, error) {
	return loadFromFile(configFile, true, true)
}

// LoadManagedFileForLifecycleRecovery loads a managed config like
// LoadFromFile, without publishing provenance and without requiring the
// standalone policy inputs (policy_dir, rule-pack dirs) to be readable by
// the gateway service. The Windows managed-hook lifecycle snapshot and
// teardown read only listener settings from it, and they run during the
// rollback of an install whose new config the services could not load:
// refusing that config there failed the rollback too, and left every
// service stopped (GAP-1291). The gateway and every activation keep the
// strict loaders.
func LoadManagedFileForLifecycleRecovery(configFile string) (*Config, error) {
	return loadFromFile(configFile, false, false)
}

func loadFromFile(configFile string, publishProvenance, checkPolicyInputs bool) (*Config, error) {
	if strings.TrimSpace(configFile) == "" {
		configFile = ConfigPath()
	}
	configFile = filepath.Clean(configFile)
	if pinned := normalizeDeploymentMode(os.Getenv(managed.DeploymentModeEnv)); managed.IsManagedEnterprise(pinned) {
		if err := managed.ValidateTrustedConfigPath(configFile); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_config_untrusted")
			}
			return nil, fmt.Errorf("config: managed_enterprise config trust check failed: %w", err)
		}
	}
	raw, err := readRuntimeSourceFile(configFile)
	if err != nil {
		return nil, err
	}
	document, err := ParseV8YAML(configFile, raw)
	if err != nil {
		return nil, err
	}
	candidate, err := loadConfigSourceChecked(configFile, raw, publishProvenance, true, checkPolicyInputs)
	if err != nil {
		return nil, err
	}
	applyRuntimeV8DataDirDefaults(candidate, document, candidate.DataDir)
	return candidate, nil
}

// LoadRuntimeV8FromBytes decodes the non-observability portions of an exact
// schema-v8 source for the target gateway runtime. The caller remains
// responsible for compiling the canonical ObservabilityV8 plan from the same
// immutable bytes before activation.
func LoadRuntimeV8FromBytes(configFile string, raw []byte) (*Config, error) {
	document, err := ParseV8YAML(configFile, raw)
	if err != nil {
		return nil, err
	}
	candidate, err := loadConfigSource(configFile, append([]byte(nil), raw...), true, true)
	if err != nil {
		return nil, err
	}
	applyRuntimeV8DataDirDefaults(candidate, document, candidate.DataDir)
	return candidate, nil
}

// LoadRuntimeV8CandidateFromBytes is the reload counterpart of
// LoadRuntimeV8FromBytes. It keeps process-wide provenance unchanged until the
// source-aware reload transaction has committed.
func LoadRuntimeV8CandidateFromBytes(configFile string, raw []byte) (*Config, error) {
	return loadRuntimeV8CandidateFromBytes(configFile, raw, true)
}

// LoadRuntimeV8InspectionCandidateFromBytes decodes the same immutable target
// candidate without publishing provenance or requiring the staged copy to have
// the live managed-enterprise path identity. The caller must independently
// bind and validate its isolated source and data roots before invoking this
// read-only helper. Live activation and reload must use the strict loaders.
func LoadRuntimeV8InspectionCandidateFromBytes(configFile string, raw []byte) (*Config, error) {
	return loadRuntimeV8CandidateFromBytes(configFile, raw, false)
}

func loadRuntimeV8CandidateFromBytes(configFile string, raw []byte, enforceManagedTrust bool) (*Config, error) {
	document, err := ParseV8YAML(configFile, raw)
	if err != nil {
		return nil, err
	}
	candidate, err := loadConfigSource(configFile, append([]byte(nil), raw...), false, enforceManagedTrust)
	if err != nil {
		return nil, err
	}
	applyRuntimeV8DataDirDefaults(candidate, document, candidate.DataDir)
	return candidate, nil
}

// ResolveObservabilityV8ManagedAIDOptionsForInspection decodes only the
// release-owned managed-destination inputs from one exact schema-v8 source.
// It applies the same defaults and environment bindings as runtime decoding,
// but never publishes provenance and returns no activatable Config. Managed
// path trust is intentionally an activation concern: read-only plan/status
// inspection compiles a private exact-byte snapshot whose temporary path is
// not the authoritative service config path.
func ResolveObservabilityV8ManagedAIDOptionsForInspection(
	configFile string,
	raw []byte,
) (ObservabilityV8ManagedAIDOptions, error) {
	candidate, err := loadConfigSource(configFile, append([]byte(nil), raw...), false, false)
	if err != nil {
		return ObservabilityV8ManagedAIDOptions{}, err
	}
	return ObservabilityV8ManagedAIDOptions{
		DeploymentMode:    candidate.DeploymentMode,
		Profile:           candidate.EnterpriseProfile(),
		Endpoint:          candidate.CiscoAIDefense.Endpoint,
		SourceContentHash: ObservabilityV8SourceContentHash(raw),
	}, nil
}

// ApplyRuntimeV8DataDirDefaultsFromBytes re-bases omitted path fields and an
// explicit relative device-key spelling on the canonical compiler-selected
// data directory. It is used after compilation when data_dir was defaulted
// externally (for example by a reload transaction). Explicit absolute paths
// are preserved.
func ApplyRuntimeV8DataDirDefaultsFromBytes(candidate *Config, source string, raw []byte, dataDir string) error {
	document, err := ParseV8YAML(source, raw)
	if err != nil {
		return err
	}
	applyRuntimeV8DataDirDefaults(candidate, document, dataDir)
	return nil
}

func applyRuntimeV8DataDirDefaults(candidate *Config, document *V8YAMLDocument, dataDir string) {
	if candidate == nil || document == nil || strings.TrimSpace(dataDir) == "" {
		return
	}
	root := v8DocumentRoot(document.Document)
	has := func(path ...string) bool {
		current := root
		for _, segment := range path {
			current = v8YAMLMapValue(current, segment)
			if current == nil {
				return false
			}
		}
		return true
	}
	if !has("quarantine_dir") {
		candidate.QuarantineDir = filepath.Join(dataDir, "quarantine")
	}
	if !has("plugin_dir") {
		candidate.PluginDir = filepath.Join(dataDir, "plugins")
	}
	if !has("policy_dir") {
		candidate.PolicyDir = filepath.Join(dataDir, "policies")
		if candidate.StandaloneEnterprise() {
			if layout, ok := standaloneUnixLayoutForConfig(candidate.ConfigFilePath); ok {
				// The gateway service can write data_dir, and the gateway
				// loads its Rego policies from policy_dir. On the Linux and
				// macOS layout an omitted policy_dir is the root-owned
				// vendor policy folder, as in the lifecycle's built-in
				// config, never a folder inside data_dir.
				candidate.PolicyDir = layout.VendorPolicyDir
			}
			standalonePolicyDirDefault(candidate, dataDir, runtime.GOOS)
		}
	}
	if !has("scanners", "codeguard") {
		candidate.Scanners.CodeGuard = filepath.Join(dataDir, "codeguard-rules")
	}
	if !has("ai_discovery", "confidence_policy_path") {
		candidate.AIDiscovery.ConfidencePolicyPath = filepath.Join(dataDir, "confidence.yaml")
	}
	if !has("firewall", "config_file") {
		candidate.Firewall.ConfigFile = filepath.Join(dataDir, "firewall.yaml")
	}
	if !has("firewall", "rules_file") {
		candidate.Firewall.RulesFile = filepath.Join(dataDir, "firewall.pf.conf")
	}
	if !has("guardrail", "rule_pack_dir") {
		candidate.Guardrail.RulePackDir = filepath.Join(dataDir, "policies", "guardrail", "default")
		if candidate.StandaloneEnterprise() {
			standaloneRulePackDefault(candidate, dataDir, runtime.GOOS)
		}
	}
	if !has("openshell", "pack_dir") {
		candidate.OpenShell.PackDir = filepath.Join(dataDir, "policies", DefaultOpenShellPackDirName)
	}
	if !has("gateway", "device_key_file") {
		candidate.Gateway.DeviceKeyFile = filepath.Join(dataDir, "device.key")
	} else if gateway := v8YAMLMapValue(root, "gateway"); gateway != nil {
		if keyFile := v8YAMLMapValue(gateway, "device_key_file"); keyFile != nil {
			if resolved, ok := ResolveRelativeGatewayDeviceKeyFile(keyFile.Value, dataDir); ok {
				candidate.Gateway.DeviceKeyFile = resolved
			}
		}
	}
}

func loadConfigSource(configFile string, sourceBytes []byte, publishProvenance, enforceManagedTrust bool) (*Config, error) {
	return loadConfigSourceChecked(configFile, sourceBytes, publishProvenance, enforceManagedTrust, true)
}

func loadConfigSourceChecked(
	configFile string,
	sourceBytes []byte,
	publishProvenance bool,
	enforceManagedTrust bool,
	checkPolicyInputs bool,
) (*Config, error) {
	// viper holds a process-global keystore. Without resetting it, a
	// previous load (e.g. from another binary path or test case) leaves
	// stale keys behind. Reset gives us a clean slate per load;
	// setDefaults() re-installs defaults and BindEnv() bindings
	// immediately after.
	viper.Reset()

	if strings.TrimSpace(configFile) == "" {
		configFile = ConfigPath()
	}
	configFile = filepath.Clean(configFile)
	dataDir := filepath.Dir(configFile)
	if configuredPath := strings.TrimSpace(os.Getenv(managed.ConfigPathEnv)); configuredPath != "" &&
		filepath.Clean(configuredPath) == configFile {
		dataDir = DefaultDataPath()
	}
	// A managed standalone config at the Linux or macOS layout path that
	// leaves data_dir unset uses the layout's data directory, the one the
	// services and the lifecycle require, instead of the config's folder.
	if layoutDataDir, ok := standaloneLayoutDataDirForSource(configFile, sourceBytes); ok {
		dataDir = layoutDataDir
	}
	pinnedDeploymentMode := normalizeDeploymentMode(os.Getenv(managed.DeploymentModeEnv))
	if err := validateDeploymentMode(pinnedDeploymentMode); err != nil {
		return nil, fmt.Errorf("config: %s: %w", managed.DeploymentModeEnv, err)
	}
	if enforceManagedTrust && managed.IsManagedEnterprise(pinnedDeploymentMode) {
		if err := managed.ValidateTrustedConfigPath(configFile); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_config_untrusted")
			}
			return nil, fmt.Errorf("config: managed_enterprise config trust check failed: %w", err)
		}
	}

	viper.SetConfigFile(configFile)
	viper.SetConfigType("yaml")

	setDefaults(dataDir)

	if err := viper.ReadConfig(bytes.NewReader(sourceBytes)); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "read_config")
		}
		return nil, fmt.Errorf("config: read %s: %w", configFile, err)
	}

	var cfg Config
	if err := viper.Unmarshal(&cfg); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "unmarshal")
		}
		return nil, fmt.Errorf("config: unmarshal: %w", err)
	}
	if err := restoreRuntimeV8GuardrailConnectors(&cfg, sourceBytes); err != nil {
		return nil, err
	}
	if err := restoreSignaturePackDigests(&cfg, sourceBytes, configFile); err != nil {
		return nil, err
	}
	cfg.ConfigFilePath = configFile
	cfg.rulePackDirDeclared = viper.InConfig("guardrail.rule_pack_dir")
	cfg.legacyConnectorRouteSelectors = legacyConnectorRouteSelectorPaths(viper.Get("observability.destinations"))
	// Move retired connector IDs to their replacement before any connector
	// key is normalized or checked for duplicates.
	migrateLegacyConnectorIDs(&cfg)

	if err := checkRuntimeConfigVersion(cfg.ConfigVersion); err != nil {
		return nil, err
	}
	cfg.DeploymentMode = normalizeDeploymentMode(cfg.DeploymentMode)
	if pinnedDeploymentMode != "" {
		if cfg.DeploymentMode != "" && cfg.DeploymentMode != pinnedDeploymentMode {
			return nil, fmt.Errorf("config: deployment_mode=%q conflicts with immutable %s=%q", cfg.DeploymentMode, managed.DeploymentModeEnv, pinnedDeploymentMode)
		}
		cfg.DeploymentMode = pinnedDeploymentMode
	}

	if err := validateDeploymentMode(cfg.DeploymentMode); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "deployment_mode_invalid")
		}
		return nil, err
	}
	if err := resolveEnterpriseConfig(&cfg, runtime.GOOS, os.Getenv(managed.EnterpriseProfileEnv)); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "enterprise_config_invalid")
		}
		return nil, err
	}
	if enforceManagedTrust && managed.IsManagedEnterprise(cfg.DeploymentMode) {
		if !managed.IsManagedEnterprise(pinnedDeploymentMode) {
			if err := managed.ValidateTrustedConfigPath(configFile); err != nil {
				if ReportConfigLoadError != nil {
					ReportConfigLoadError(context.Background(), "managed_config_untrusted")
				}
				return nil, fmt.Errorf("config: managed_enterprise config trust check failed: %w", err)
			}
		}
		if err := managed.ValidateTrustedServiceRuntimeDir(
			cfg.DataDir,
			"managed data_dir",
			os.Getenv(managed.WindowsServiceAccountEnv),
		); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_data_dir_untrusted")
			}
			return nil, fmt.Errorf("config: managed_enterprise data_dir trust check failed: %w", err)
		}
		if err := validateManagedEnterpriseListenerBindings(&cfg); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_listener_non_loopback")
			}
			return nil, err
		}
		if checkPolicyInputs {
			if err := validateManagedStandalonePolicyInputs(&cfg); err != nil {
				if ReportConfigLoadError != nil {
					ReportConfigLoadError(context.Background(), "managed_policy_input_untrusted")
				}
				return nil, err
			}
		}
		if err := validateManagedEnterpriseWindowsPeerAuthKnobs(&cfg); err != nil {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "managed_ipc_peer_auth_unsupported_on_windows")
			}
			return nil, err
		}
	}

	cfg.Gateway.ConfigReload.Mode = normalizeGatewayConfigReloadMode(cfg.Gateway.ConfigReload.Mode)
	if err := validateGatewayConfigReloadMode(cfg.Gateway.ConfigReload.Mode); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "gateway_config_reload_invalid")
		}
		return nil, err
	}

	// Per-connector observability (D5b): reject empty / alias-duplicate
	// connector names so a hand-edited observability.connectors[...] block
	// fails loud at startup rather than silently mis-routing a connector's
	// webhooks. Webhooks are validated at dispatcher build time (URL/SSRF
	// checks), matching the top-level webhooks: handling.
	if err := cfg.Observability.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "observability_invalid")
		}
		return nil, fmt.Errorf("config: observability: %w", err)
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
	if err := cfg.ACP.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "acp_invalid")
		}
		return nil, fmt.Errorf("config: acp: %w", err)
	}

	if err := cfg.Guardrail.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "guardrail_invalid")
		}
		return nil, fmt.Errorf("config: guardrail: %w", err)
	}
	if err := cfg.ValidateGuardrailProfiles(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "guardrail_invalid")
		}
		return nil, fmt.Errorf("config: guardrail: %w", err)
	}
	if err := cfg.Scanners.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "scanners_invalid")
		}
		return nil, err
	}
	if err := cfg.Routing.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "routing_invalid")
		}
		return nil, fmt.Errorf("config: routing: %w", err)
	}
	if err := cfg.ApplicationProtection.Validate(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "application_protection_invalid")
		}
		return nil, fmt.Errorf("config: application_protection: %w", err)
	}
	if err := cfg.ValidateOpenShell(); err != nil {
		if ReportConfigLoadError != nil {
			ReportConfigLoadError(context.Background(), "openshell_invalid")
		}
		return nil, fmt.Errorf("config: openshell: %w", err)
	}

	// Validate registry source kind/content shapes. The Python CLI
	// is the authoritative writer for ``registries.sources`` (it
	// drives ``defenseclaw registry add/edit``), but any operator
	// hand-edit of config.yaml lands in the Go gateway too and a
	// typo'd ``kind: htttp_yaml`` should fail loud at startup
	// rather than be silently accepted and bypass admission. We
	// keep the check additive: empty kind/content is tolerated for
	// upgrade-in-place from older configs.
	for i := range cfg.Registries.Sources {
		src := &cfg.Registries.Sources[i]
		if src.Kind != "" && !IsKnownRegistryKind(src.Kind) {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "registry_kind_invalid")
			}
			return nil, fmt.Errorf(
				"config: registries.sources[%d] (id=%q): unknown kind %q "+
					"(want one of %v)",
				i, src.ID, src.Kind, KnownRegistryKinds,
			)
		}
		if src.Content != "" && !IsKnownRegistryContent(src.Content) {
			if ReportConfigLoadError != nil {
				ReportConfigLoadError(context.Background(), "registry_content_invalid")
			}
			return nil, fmt.Errorf(
				"config: registries.sources[%d] (id=%q): unknown content %q "+
					"(want one of %v)",
				i, src.ID, src.Content, KnownRegistryContentTypes,
			)
		}
	}

	cfg.Gateway.SandboxHome = LegacySandboxHome(&cfg)

	if home, err := os.UserHomeDir(); err == nil {
		cfg.Gateway.ClawHome = home
	}

	warnPlaintextSecrets(&cfg)

	// Provenance: seed the content_hash from the exact source bytes at load
	// time so events emitted between sidecar boot and the first Save()
	// already carry a meaningful fingerprint. Without this, dashboards would
	// see `content_hash=""` for every event until someone explicitly saves
	// the config through the CLI/TUI, which hides genuine drift across
	// restarts. An empty source falls back to a re-marshal of the in-memory
	// config so the hash is still stable across identical configs.
	if publishProvenance {
		seedProvenanceOnLoad(&cfg, sourceBytes)
	}

	return &cfg, nil
}

// restoreRuntimeV8GuardrailConnectors closes Viper decode gaps by decoding
// some sections from the same immutable target-runtime bytes before
// migration/defaulting and validation continue:
//   - guardrail.connectors: entries whose policy value is an empty mapping
//     (for example, codex: {}) are roster members, but Viper omits them;
//   - guardrail.rules (global, profile and profile connector): Viper
//     lower-cases map keys, and severity_overrides is keyed by rule ID;
//   - admission: an action is a shorthand string or a triple, which the
//     mapstructure decode cannot express;
//   - llm_providers: header and alias map keys keep their case.
func restoreRuntimeV8GuardrailConnectors(cfg *Config, raw []byte) error {
	type profileConnectorRules struct {
		Rules *GuardrailRulesConfig `yaml:"rules"`
	}
	type profileRules struct {
		Rules      *GuardrailRulesConfig            `yaml:"rules"`
		Connectors map[string]profileConnectorRules `yaml:"connectors"`
	}
	var source struct {
		Admission    AdmissionConfig    `yaml:"admission"`
		LLMProviders LLMProvidersConfig `yaml:"llm_providers"`
		Guardrail    struct {
			Connectors map[string]PerConnectorGuardrailConfig `yaml:"connectors"`
			Rules      GuardrailRulesConfig                   `yaml:"rules"`
			Profiles   map[string]profileRules                `yaml:"profiles"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(raw, &source); err != nil {
		return fmt.Errorf("config: decode schema-v8 guardrail.connectors: %w", err)
	}
	cfg.Guardrail.Connectors = source.Guardrail.Connectors
	cfg.Guardrail.Rules = source.Guardrail.Rules
	cfg.Admission = source.Admission
	cfg.LLMProviders = source.LLMProviders
	for name, restored := range source.Guardrail.Profiles {
		profile, ok := cfg.Guardrail.Profiles[name]
		if !ok {
			continue
		}
		profile.Rules = restored.Rules
		for connector, entry := range restored.Connectors {
			if override, ok := profile.Connectors[connector]; ok {
				override.Rules = entry.Rules
				profile.Connectors[connector] = override
			}
		}
		cfg.Guardrail.Profiles[name] = profile
	}
	return nil
}

// restoreSignaturePackDigests reads ai_discovery.signature_pack_digests, keyed
// by pack file path, from the YAML (the source bytes, else the file): Viper
// splits a key at every dot, so a path never survived its decode (GAP-0066).
func restoreSignaturePackDigests(cfg *Config, raw []byte, configFile string) error {
	if raw == nil {
		var err error
		if raw, err = os.ReadFile(configFile); err != nil { // #nosec G304 -- the config file being loaded.
			return nil
		}
	}
	var source struct {
		AIDiscovery struct {
			SignaturePackDigests map[string]string `yaml:"signature_pack_digests"`
		} `yaml:"ai_discovery"`
	}
	if err := yaml.Unmarshal(raw, &source); err != nil {
		return fmt.Errorf("config: decode ai_discovery.signature_pack_digests: %w", err)
	}
	cfg.AIDiscovery.SignaturePackDigests = source.AIDiscovery.SignaturePackDigests
	return nil
}

// validateManagedEnterpriseListenerBindings keeps every inbound enterprise
// surface on loopback. The managed hook transport is intentionally pinned to
// canonical numeric IPv4, so the API listener must be exactly 127.0.0.1 rather
// than another loopback spelling or address. This is enterprise-only:
// unmanaged/BYOD deployments retain their existing remote-bind behavior.
func validateManagedEnterpriseListenerBindings(cfg *Config) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}

	apiBind := cfg.Gateway.APIBind
	if apiBind == "" {
		// Persist the effective managed bind into the in-memory config so
		// standalone topology cannot later derive the API listener from an
		// independent IPv6 guardrail host.
		cfg.Gateway.APIBind = "127.0.0.1"
		apiBind = cfg.Gateway.APIBind
	}
	if apiBind != "127.0.0.1" {
		return fmt.Errorf(
			"config: managed_enterprise gateway API must bind to exact canonical 127.0.0.1, got %q",
			apiBind,
		)
	}

	if cfg.Guardrail.Enabled {
		proxyBind := strings.TrimSpace(cfg.Guardrail.EffectiveHost())
		if !isLoopbackListenerHost(proxyBind) {
			return fmt.Errorf(
				"config: managed_enterprise guardrail proxy must bind to loopback, got %q",
				proxyBind,
			)
		}
	}
	return nil
}

// validateManagedEnterpriseWindowsPeerAuthKnobs refuses to load a
// managed_enterprise config on Windows that carries non-empty
// AllowedTeamIDs / AllowedSigningIDs / AllowedBundleIDs. Those allowlists
// only take effect on macOS / linux, where LOCAL_PEERCRED-style peer
// credentials give the AF_UNIX IPC surface a real accept-time codesign
// check. On Windows the AF_UNIX kernel implementation exposes no peer
// credential API, so the values are silently discarded by
// newCodesignValidatingListener (peerauth_windows.go, deferred_windows
// posture). Accepting them from config and dropping them at start-time
// is a config-honesty gap: an operator setting an allowlist expecting
// hardening ends up with an AF_UNIX socket whose only access boundary
// is the file DACL. Refusing to load makes that gap loud instead of
// silent; the deferred Windows peer-auth mechanism belongs to parity
// plan §4.4 and is not something operators can enable from config.
//
// Non-managed builds keep operator config verbatim per the existing
// unmanaged/BYOD contract (unmanaged doesn't ship the IPC surface at
// all outside dev rigs), so this validator is scoped to
// managed_enterprise on Windows.
func validateManagedEnterpriseWindowsPeerAuthKnobs(cfg *Config) error {
	if cfg == nil || !managed.IsManagedEnterprise(cfg.DeploymentMode) {
		return nil
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	var offending []string
	if len(cfg.Managed.AllowedTeamIDs) != 0 {
		offending = append(offending, "managed.allowed_team_ids")
	}
	if len(cfg.Managed.AllowedSigningIDs) != 0 {
		offending = append(offending, "managed.allowed_signing_ids")
	}
	if len(cfg.Managed.AllowedBundleIDs) != 0 {
		offending = append(offending, "managed.allowed_bundle_ids")
	}
	if len(offending) == 0 {
		return nil
	}
	return fmt.Errorf(
		"config: %s cannot be set on Windows in the initial-cut managed IPC "+
			"peer-auth posture (spec 004): the AF_UNIX socket has no peer-"+
			"credential API on Windows, so any allowlist here would be silently "+
			"discarded. Remove these keys from config.yaml; the socket DACL is "+
			"the enforcement boundary until parity plan §4.4 lands the Windows "+
			"peer-auth mechanism.",
		strings.Join(offending, ", "),
	)
}

func isLoopbackListenerHost(host string) bool {
	host = strings.TrimSpace(host)
	if strings.EqualFold(host, "localhost") {
		return true
	}
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// seedProvenanceOnLoad stamps the process-wide content hash from the exact
// source bytes just loaded. A hash failure is non-fatal: the prior value stays
// in place, which is the correct behavior for transient read races (an editor
// saving in place under us) where the next successful load re-seeds.
func seedProvenanceOnLoad(cfg *Config, sourceBytes []byte) {
	if len(sourceBytes) > 0 {
		version.SetContentHash(sourceBytes)
		return
	}
	// Empty source: fall back to a canonical re-marshal of the in-memory
	// Config so first-boot events still carry a non-empty, deterministic
	// fingerprint of the default config.
	if data, err := yaml.Marshal(cfg); err == nil && len(data) > 0 {
		version.SetContentHash(data)
	}
}

// checkRuntimeConfigVersion admits config_version 8 through
// MaxSupportedConfigVersion. An older source (a released 0.8.x layout) is
// never decoded here: `defenseclaw migrate` rewrites it once, and this
// runtime refuses it with that single instruction. A newer one belongs to a
// newer DefenseClaw and is never guessed at.
func checkRuntimeConfigVersion(version int) error {
	switch {
	case version < ObservabilityV8ConfigVersion:
		return fmt.Errorf("config: config_version %d is older than %d; run `defenseclaw migrate`",
			version, ObservabilityV8ConfigVersion)
	case version > MaxSupportedConfigVersion:
		return fmt.Errorf("config: config was written by a newer DefenseClaw (config_version %d); "+
			"upgrade DefenseClaw or restore ~/.defenseclaw/previous", version)
	}
	return nil
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
}

func validateDeploymentMode(mode string) error {
	mode = normalizeDeploymentMode(mode)
	if mode == "" {
		return nil
	}
	if _, ok := validDeploymentModes[mode]; ok {
		return nil
	}
	return fmt.Errorf("config: deployment_mode=%q is invalid (allowed: managed_enterprise, unmanaged_byod, ci_cd, sandboxed, server, saas)", mode)
}

func validateGatewayConfigReloadMode(mode string) error {
	switch normalizeGatewayConfigReloadMode(mode) {
	case "", "hot", "restart":
		return nil
	}
	return fmt.Errorf("config: gateway.config_reload.mode=%q is invalid (allowed: hot, restart)", mode)
}

func normalizeGatewayConfigReloadMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "hot"
	}
	return mode
}

func normalizeDeploymentMode(mode string) string {
	switch strings.TrimSpace(mode) {
	case "managed":
		return string(DeploymentModeManagedEnterprise)
	case "standalone":
		return string(DeploymentModeUnmanagedBYOD)
	case "ci":
		return string(DeploymentModeCICD)
	case "edge":
		return string(DeploymentModeServer)
	default:
		return strings.TrimSpace(mode)
	}
}

func setDefaults(dataDir string) {
	viper.SetDefault("data_dir", dataDir)
	viper.SetDefault("audit_db", filepath.Join(dataDir, DefaultAuditDBName))
	viper.SetDefault("judge_bodies_db", filepath.Join(dataDir, DefaultJudgeBodiesDBName))
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
	viper.SetDefault("scanners.skill_scanner.use_llm", true)
	viper.SetDefault("scanners.skill_scanner.use_behavioral", false)
	viper.SetDefault("scanners.skill_scanner.enable_meta", false)
	viper.SetDefault("scanners.skill_scanner.use_trigger", false)
	viper.SetDefault("scanners.skill_scanner.use_virustotal", false)
	viper.SetDefault("scanners.skill_scanner.use_aidefense", false)
	viper.SetDefault("scanners.skill_scanner.llm_consensus_runs", 0)
	viper.SetDefault("scanners.skill_scanner.policy", DefaultSkillScannerPolicy)
	viper.SetDefault("scanners.skill_scanner.lenient", true)
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key", "")
	viper.SetDefault("scanners.skill_scanner.virustotal_api_key_env", "VIRUSTOTAL_API_KEY")
	viper.SetDefault("scanners.mcp_scanner.binary", "mcp-scanner")
	viper.SetDefault("scanners.mcp_scanner.analyzers", "auto")
	viper.SetDefault("scanners.mcp_scanner.scan_prompts", false)
	viper.SetDefault("scanners.mcp_scanner.scan_resources", false)
	viper.SetDefault("scanners.mcp_scanner.scan_instructions", false)
	viper.SetDefault("scanners.plugin_scanner", "defenseclaw")
	viper.SetDefault("scanners.codeguard", filepath.Join(dataDir, "codeguard-rules"))
	// Pack-governed openshell keys (profile, yolo, workdir.mode, upload caps,
	// egress lists, mcp.import) deliberately have no loader default so an
	// unset key inherits the selected sandbox policy pack.
	viper.SetDefault("openshell.binary", DefaultOpenShellBinary)
	viper.SetDefault("openshell.pack_dir", filepath.Join(dataDir, "policies", DefaultOpenShellPackDirName))
	viper.SetDefault("openshell.workdir.git_depth", DefaultOpenShellGitDepth)
	viper.SetDefault("openshell.workdir.on_exit", DefaultOpenShellOnExit)
	viper.SetDefault("openshell.workdir.undo_ignored.max_mb", DefaultOpenShellUndoIgnoredMaxMB)
	viper.SetDefault("openshell.workdir.undo_ignored.dirs", DefaultOpenShellUndoIgnoredDirs)
	viper.SetDefault("openshell.approvals.debounce_ms", DefaultOpenShellApprovalDebounceMs)
	viper.SetDefault("openshell.token_delivery", DefaultOpenShellTokenDelivery)
	viper.SetDefault("openshell.llm", DefaultOpenShellLLM)

	viper.SetDefault("watch.debounce_ms", 500)
	viper.SetDefault("watch.auto_block", true)
	viper.SetDefault("watch.rescan_enabled", true)
	viper.SetDefault("watch.rescan_interval_min", 60)
	viper.SetDefault("watch.rescan_content_gated", true)

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
	viper.SetDefault("ai_discovery.home_dirs", []string{})
	viper.SetDefault("ai_discovery.signature_packs", []string{})
	viper.SetDefault("ai_discovery.allow_workspace_signatures", false)
	viper.SetDefault("ai_discovery.disabled_signature_ids", []string{})
	viper.SetDefault("ai_discovery.include_shell_history", true)
	viper.SetDefault("ai_discovery.include_package_manifests", true)
	viper.SetDefault("ai_discovery.include_env_var_names", true)
	viper.SetDefault("ai_discovery.include_network_domains", true)
	viper.SetDefault("ai_discovery.lookup_model_provenance_online", false)
	viper.SetDefault("ai_discovery.max_files_per_scan", 1000)
	viper.SetDefault("ai_discovery.max_file_bytes", 512*1024)
	viper.SetDefault("ai_discovery.store_raw_local_paths", false)
	viper.SetDefault("ai_discovery.confidence_policy_path", filepath.Join(dataDir, "confidence.yaml"))
	viper.SetDefault("ai_discovery.require_trusted_binary_paths", false)
	viper.SetDefault("ai_discovery.trusted_binary_prefixes", []string{})

	viper.SetDefault("application_protection.enabled", false)
	viper.SetDefault("application_protection.min_confidence", DefaultApplicationProtectionMinConfidence)
	viper.SetDefault("application_protection.remove_when_gone", false)
	viper.SetDefault("application_protection.gone_after_min", DefaultApplicationProtectionGoneAfterMin)
	viper.SetDefault("application_protection.include_connectors", []string{})
	viper.SetDefault("application_protection.exclude_connectors", []string{})
	viper.SetDefault("application_protection.guardrail.mode", "observe")
	viper.SetDefault("application_protection.asset_policy.mode", AssetPolicyModeObserve)
	viper.SetDefault("application_protection.connectors", map[string]any{})

	viper.SetDefault("guardrail.enabled", false)
	viper.SetDefault("guardrail.mode", "observe")
	// "closed" is the safer default — transport, authentication, and
	// invalid-response failures BLOCK supported events rather than silently
	// allowing them. Pre-existing operators are protected
	// by _migrate_0_4_0_seed_hook_fail_mode (migrations.py) which
	// writes ``hook_fail_mode: open`` to existing config.yaml so prior
	// behavior is preserved on upgrade. Operators who explicitly want
	// fail-open run `defenseclaw guardrail fail-mode open` (or set
	// guardrail.hook_fail_mode: open in YAML).
	viper.SetDefault("guardrail.hook_fail_mode", "closed")
	// Self-heal connector hook configs by default: if a user deletes
	// the DefenseClaw hook block while the gateway is running, the
	// hook config guard re-installs it. Operators can opt out with
	// `guardrail.hook_self_heal: false`.
	viper.SetDefault("guardrail.hook_self_heal", true)
	viper.SetDefault("guardrail.hook_self_heal_debounce_ms", 500)
	viper.SetDefault("guardrail.scanner_mode", "both")
	viper.SetDefault("guardrail.connector", "")
	viper.SetDefault("guardrail.connectors", map[string]any{})
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
	// `guardrail.retain_judge_bodies: false`.
	viper.SetDefault("guardrail.retain_judge_bodies", true)
	// Buffered async persistence queue: 1024 entries is the sweet
	// spot between memory ceiling and BUSY absorption under burst
	// load. See GuardrailConfig.JudgePersistQueueDepth for the
	// tuning rationale.
	viper.SetDefault("guardrail.judge_persist_queue_depth", 1024)

	viper.SetDefault("gateway.host", "127.0.0.1")
	viper.SetDefault("gateway.port", 18789)
	viper.SetDefault("gateway.token_env", "DEFENSECLAW_GATEWAY_TOKEN")
	// fleet_mode defaults to "auto" so existing installs (which never
	// set this field) keep getting the connector + host derivation
	// in gatewayShouldConnectForConfiguredConnector. See the field
	// doc on GatewayConfig.FleetMode for the override semantics.
	viper.SetDefault("gateway.fleet_mode", "auto")
	viper.SetDefault("gateway.config_reload.mode", "hot")
	viper.SetDefault("gateway.device_key_file", filepath.Join(dataDir, "device.key"))
	viper.SetDefault("gateway.auto_approve_safe", false)
	viper.SetDefault("gateway.reconnect_ms", 800)
	viper.SetDefault("gateway.max_reconnect_ms", 15000)
	viper.SetDefault("gateway.approval_timeout_s", 30)
	viper.SetDefault("gateway.api_port", DefaultGatewayAPIPort)
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

	// User-session OS notifications. Master switch defaults to true on macOS
	// and native Windows and false elsewhere — see DefaultNotificationsEnabled
	// in notifications.go for the rationale. block_enforced and
	// hitl_approval default ON so the user sees real blocks and
	// real chat-side asks; block_would_block defaults OFF so the
	// observe-mode "would have blocked / would have asked" toasts
	// stay quiet by default and are an explicit opt-in for operators
	// tuning policy. Keep this in lockstep with
	// cli/defenseclaw/config.py.
	viper.SetDefault("notifications.enabled", DefaultNotificationsEnabled)
	viper.SetDefault("notifications.block_enforced", true)
	viper.SetDefault("notifications.block_would_block", false)
	viper.SetDefault("notifications.hitl_approval", true)
	viper.SetDefault("notifications.sources.hook", true)
	viper.SetDefault("notifications.sources.guardrail", true)
	viper.SetDefault("notifications.sources.asset_policy", true)
	viper.SetDefault("notifications.dedup_window", NotificationsDefaultDedupWindow)
	viper.SetDefault("notifications.max_per_minute", NotificationsDefaultMaxPerMinute)
}
