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

// Package connector defines the adapter layer between agent frameworks and
// DefenseClaw's guardrail proxy. Each connector owns all security surfaces
// for its agent: LLM traffic routing, tool call inspection, agent hook events,
// component scanning, CodeGuard file scanning, and subprocess enforcement.
package connector

import (
	"context"
	"net/http"
)

// ToolInspectionMode describes how a connector monitors tool calls.
type ToolInspectionMode string

const (
	ToolModePreExecution ToolInspectionMode = "pre-execution"
	ToolModeResponseScan ToolInspectionMode = "response-scan"
	ToolModeBoth         ToolInspectionMode = "both"
	ToolModeNone         ToolInspectionMode = "none"
)

// SubprocessPolicy declares how the connector restricts subprocess execution.
type SubprocessPolicy string

const (
	SubprocessSandbox SubprocessPolicy = "sandbox"
	SubprocessShims   SubprocessPolicy = "shims"
	SubprocessNone    SubprocessPolicy = "none"
)

// ConnectorSignals holds the raw, unresolved signals extracted by a connector
// from the inbound HTTP request. The proxy core resolves these into a concrete
// provider using the existing inferProviderFromURL / splitModel / inferProvider
// chain. From ConnectorSignals onwards, the pipeline is fully agent-agnostic.
type ConnectorSignals struct {
	RawAPIKey       string
	RawModel        string
	RawUpstream     string
	RawBody         []byte
	Stream          bool
	PassthroughMode bool
	ConnectorName   string
	StripHeaders    []string
	ExtraHeaders    map[string]string
}

// SetupOpts is passed to Setup/Teardown during `defenseclaw setup`.
type SetupOpts struct {
	DataDir     string // ~/.defenseclaw/
	ProxyAddr   string // 127.0.0.1:4000 (guardrail proxy — LLM traffic)
	APIAddr     string // 127.0.0.1:18970 (API server — inspection endpoints)
	APIToken    string // gateway bearer token; baked into hook curl -H
	Interactive bool
	// WorkspaceDir is the project/workspace root for connectors whose
	// hook configuration is intentionally repository-scoped (for
	// example Copilot CLI's .github/hooks/*.json files). When empty,
	// connectors fall back to the process working directory.
	WorkspaceDir string

	// HookFailMode is the operator-chosen response-layer fail mode
	// baked into every hook script we write. Values: "open" (default,
	// allow on response-layer failures) or "closed" (block on
	// response-layer failures). The sidecar populates this from
	// cfg.Guardrail.EffectiveHookFailMode(); empty string is treated as
	// the default ("open"). Transport-layer failures (gateway unreachable /
	// 5xx) are governed separately by DEFENSECLAW_STRICT_AVAILABILITY in
	// the hook scripts themselves and are NOT controlled by this field.
	HookFailMode string

	// HILTEnabled tells connectors with native approval surfaces to wire
	// their host approval delivery path. For OpenClaw this enables plugin
	// approval forwarding so approval prompts can reach chat-origin
	// sessions instead of living only in the native approval queue.
	HILTEnabled bool

	// InstallCodeGuard enables explicit, opt-in native Project CodeGuard
	// bootstrapping for connectors that have their own extension mechanism.
	// The sidecar default is false; CLI startup/init/setup must not flip it
	// implicitly. Server-side CodeGuard scanning remains independent from
	// native skill/rule/plugin installation.
	InstallCodeGuard bool

	// AgentVersion is the raw local agent CLI version observed by trusted
	// discovery (`<agent> --version`). HookProfile resolution treats this as
	// audit/debug input, normalizes it locally, and maps it to a deterministic
	// HookContract. Empty means "not probed"; it never implies latest.
	AgentVersion string

	// HookContractID optionally pins setup/profile resolution to a specific
	// known contract. A non-empty value that does not match the resolved
	// contract marks the profile incompatible instead of silently using a
	// different hook surface.
	HookContractID string

	// CodexEnforcement signals that the operator turned on hard
	// enforcement for the codex connector (see avarice F-0681).
	// When true, an empty HookFailMode upgrades to "closed" instead
	// of using the legacy "open" default — without overriding an
	// explicit operator-supplied value.
	CodexEnforcement bool

	// ClaudeCodeEnforcement is the parallel flag for claudecode.
	ClaudeCodeEnforcement bool
}

// Connector is the contract every agent framework adapter implements.
type Connector interface {
	Name() string
	Description() string
	ToolInspectionMode() ToolInspectionMode
	SubprocessPolicy() SubprocessPolicy

	Setup(ctx context.Context, opts SetupOpts) error
	Teardown(ctx context.Context, opts SetupOpts) error

	Authenticate(r *http.Request) bool
	Route(r *http.Request, body []byte) (*ConnectorSignals, error)

	// SetCredentials injects the gateway token and master key at sidecar
	// boot. Every connector must implement this so that a missing
	// implementation causes a compile-time error rather than a silent
	// runtime auth bypass via the old type-assertion path.
	SetCredentials(gatewayToken, masterKey string)

	// VerifyClean checks that the connector's teardown left no stale
	// artifacts (hooks, env files, config patches, shims). Returns nil
	// when the agent framework's configuration is free of DefenseClaw
	// state; returns a descriptive error listing residual artifacts.
	// Called after Teardown and before a new connector's Setup to
	// guarantee a clean handoff.
	VerifyClean(opts SetupOpts) error
}

// HookEndpoint — optional, connectors that receive lifecycle events
// from agents declare which API path they need. The gateway registers
// the route dynamically at boot instead of hardcoding paths in api.go.
type HookEndpoint interface {
	HookAPIPath() string
}

// HookCapability describes the actual lifecycle hook controls a connector
// can exercise. This is intentionally surface-specific: native human approval
// is not inferred from a connector name, and "confirm" decisions must consult
// AskEvents before being rendered as an agent-native ask.
type HookCapability struct {
	CanBlock           bool     `json:"can_block"`
	CanAskNative       bool     `json:"can_ask_native"`
	AskEvents          []string `json:"ask_events,omitempty"`
	BlockEvents        []string `json:"block_events,omitempty"`
	SupportsFailClosed bool     `json:"supports_fail_closed"`
	Scope              string   `json:"scope"`
	ConfigPath         string   `json:"config_path,omitempty"`
}

// SurfaceCapability describes an installable/readable connector surface other
// than hook verdict delivery. These surfaces are deliberately modeled
// separately from enforcement/HILT so setup can install MCP servers, skills,
// rules, plugins, or agents without implying the connector can block or ask.
type SurfaceCapability struct {
	Supported       bool     `json:"supported"`
	Scope           string   `json:"scope,omitempty"`
	ConfigPaths     []string `json:"config_paths,omitempty"`
	ReadPaths       []string `json:"read_paths,omitempty"`
	WritePaths      []string `json:"write_paths,omitempty"`
	InstallTargets  []string `json:"install_targets,omitempty"`
	DiscoveryOnly   bool     `json:"discovery_only,omitempty"`
	RequiresOptIn   bool     `json:"requires_opt_in,omitempty"`
	SupportsBackup  bool     `json:"supports_backup,omitempty"`
	SupportsRestore bool     `json:"supports_restore,omitempty"`
	Notes           []string `json:"notes,omitempty"`
}

// SurfaceLocations is the resolved, on-this-machine path manifest for a
// connector surface. It is derived from SurfaceCapability and SetupOpts so
// diagnostics can distinguish static capability ("OpenHands supports skills")
// from the concrete path being watched in this workspace.
type SurfaceLocations struct {
	Supported      bool     `json:"supported"`
	Scope          string   `json:"scope,omitempty"`
	ConfigPaths    []string `json:"config_paths,omitempty"`
	ReadPaths      []string `json:"read_paths,omitempty"`
	WritePaths     []string `json:"write_paths,omitempty"`
	InstallTargets []string `json:"install_targets,omitempty"`
	DiscoveryOnly  bool     `json:"discovery_only,omitempty"`
	RequiresOptIn  bool     `json:"requires_opt_in,omitempty"`
	Notes          []string `json:"notes,omitempty"`
}

// ConnectorLocations is the resolved connector path contract captured into
// hook_contract_lock.json and exposed by connector metadata. Static hook
// contracts say what protocol DefenseClaw supports; this manifest says where
// DefenseClaw installed hooks and where it will discover MCP servers, skills,
// plugins, rules, and agents for the selected workspace.
type ConnectorLocations struct {
	WorkspaceDir         string                      `json:"workspace_dir,omitempty"`
	HookConfigPaths      []string                    `json:"hook_config_paths,omitempty"`
	HookScriptPaths      []string                    `json:"hook_script_paths,omitempty"`
	TelemetryConfigPaths []string                    `json:"telemetry_config_paths,omitempty"`
	Surfaces             map[string]SurfaceLocations `json:"surfaces,omitempty"`
}

// CodeGuardCapability models native Project CodeGuard asset installation for
// a connector. Server-side CodeGuard scanning remains independent from this:
// these flags only describe optional skill/rule/plugin assets placed into the
// agent's own configuration directories.
type CodeGuardCapability struct {
	Supported      bool     `json:"supported"`
	InstallTargets []string `json:"install_targets,omitempty"`
	OptInOnly      bool     `json:"opt_in_only"`
	AutoInstall    bool     `json:"auto_install"`
	Idempotent     bool     `json:"idempotent"`
	ConflictSafe   bool     `json:"conflict_safe"`
	Notes          []string `json:"notes,omitempty"`
}

// TelemetryCapability advertises native and hook-generated telemetry channels
// for a connector. Native OTLP means the vendor CLI can emit OTLP directly to
// DefenseClaw; hook telemetry is synthesized by DefenseClaw hook handlers.
type TelemetryCapability struct {
	NativeOTLP       bool             `json:"native_otlp"`
	NativeSignals    []string         `json:"native_signals,omitempty"`
	HookSignals      []string         `json:"hook_signals,omitempty"`
	ConfigPaths      []string         `json:"config_paths,omitempty"`
	Env              []EnvRequirement `json:"env,omitempty"`
	AuthMode         string           `json:"auth_mode,omitempty"`
	EndpointTemplate string           `json:"endpoint_template,omitempty"`
	SourceModes      []string         `json:"source_modes,omitempty"`
	Notes            []string         `json:"notes,omitempty"`
}

// ConnectorCapabilities is the first-class capability matrix used by setup,
// doctor, API metadata, and future installer flows. HookCapabilityProvider
// remains as a compatibility shim for the verdict mapper.
type ConnectorCapabilities struct {
	// LLMTrafficMode states whether DefenseClaw sits in the agent's LLM
	// data path ("proxy") or only attaches to lifecycle hooks
	// ("hooks-only"). It is the single honest signal for what a custom
	// provider actually does when bound to this connector: on a proxy
	// connector a custom provider can be the agent's enforced upstream
	// model; on a hooks-only connector it can only be DefenseClaw's
	// judge/aux model — the agent's own model traffic is never seen.
	LLMTrafficMode string              `json:"llm_traffic_mode"`
	Hooks          HookCapability      `json:"hooks"`
	MCP            SurfaceCapability   `json:"mcp"`
	Skills         SurfaceCapability   `json:"skills"`
	Rules          SurfaceCapability   `json:"rules"`
	Plugins        SurfaceCapability   `json:"plugins"`
	Agents         SurfaceCapability   `json:"agents"`
	CodeGuard      CodeGuardCapability `json:"codeguard"`
	Telemetry      TelemetryCapability `json:"telemetry"`
}

// LLMTrafficModeProxy / LLMTrafficModeHooksOnly are the two values of
// ConnectorCapabilities.LLMTrafficMode.
const (
	LLMTrafficModeProxy     = "proxy"
	LLMTrafficModeHooksOnly = "hooks-only"
)

// LLMTrafficModeForConnector returns the traffic mode for a connector
// name: "proxy" for the proxy/chat connectors (OpenClaw, ZeptoClaw)
// that interpose on the LLM data path, "hooks-only" for every hook
// connector. This is the authoritative classifier the API and CLI use
// to describe custom-provider enforcement per connector.
func LLMTrafficModeForConnector(name string) string {
	if IsProxyConnector(normalizeConnectorName(name)) {
		return LLMTrafficModeProxy
	}
	return LLMTrafficModeHooksOnly
}

// ConnectorCapabilityProvider — optional, connectors that can describe their
// installable/readable local surfaces implement this richer matrix.
type ConnectorCapabilityProvider interface {
	Capabilities(opts SetupOpts) ConnectorCapabilities
}

// HookCapabilityProvider — optional, connectors that install native agent
// hooks expose their exact action/approval surface here. The gateway decision
// mapper uses this matrix to avoid treating unsupported "confirm" verdicts as
// native HITL.
type HookCapabilityProvider interface {
	HookCapabilities(opts SetupOpts) HookCapability
}

// HookProfile is the declarative description a connector returns to
// the unified hook collector. handleAgentHook is the sole entry point
// for every connector hook route; connector-specific differences live
// behind HookProfile callbacks and the gateway-side profile-runtime
// registry. The HookProfile fields drive route registration
// (HookAPIPath), trace-propagation (SupportsTraceparent), native OTLP
// shape (NativeOTLP), versioned hook contracts, and the declarative
// Decode / MapVerdict / Respond callbacks the connector-side tooling
// can read without depending on gateway-private request types.
//
// Fields:
//
//   - Name: the connector's short name (matches Connector.Name()).
//   - Capabilities: existing HookCapability (CanBlock, CanAskNative, AskEvents).
//   - SupportsTraceparent: true when the connector's hook scripts forward
//     W3C traceparent / tracestate headers from DEFENSECLAW_TRACEPARENT. The
//     gateway uses this to decide whether to expect a propagated trace
//     context vs. mint a fresh root span. v6-managed hooks set this true.
//   - NativeOTLP: optional descriptor for the connector's native OTLP
//     emission. nil when the connector does not emit native OTLP (cursor,
//     windsurf, hermes today). Non-nil for codex (TOML), claudecode (env),
//     geminicli (JSON + path-token), copilot (env).
//   - Decode: optional decoder that translates a connector-specific raw
//     payload into the shared HookProfileRequest shape. codex and
//     claudecode set this so their bespoke per-connector evaluators
//     can run from the unified handler with no extra HTTP surface.
//     nil = caller uses the generic normalizeAgentHookRequest path.
//   - MapVerdict: optional verdict mapper for connectors whose mode →
//     action translation deviates from the generic mapHookAction (codex
//     never enforces alert; claudecode's "can enforce" gate covers
//     non-blockable events with rawAction=block + wouldBlock=true). nil =
//     caller uses mapHookAction directly.
//   - Respond: optional response shaper that produces the connector-
//     specific top-level output map plus its JSON field name
//     ("hook_output", "codex_output", "claude_code_output"). nil =
//     caller uses hookOutputFor and the "hook_output" field.
type HookProfile struct {
	Name                    string
	Capabilities            HookCapability
	SupportsTraceparent     bool
	NativeOTLP              *NativeOTLPSpec
	ContractID              string
	HookScriptVersion       string
	HookConfigPathTemplates []string
	ResponseFieldName       string
	SupportedEvents         []string
	AIDSurfaces             []string
	AgentVersion            string
	NormalizedAgentVersion  string
	CompatibilityStatus     string
	CompatibilityReason     string

	// ContentEnvelopeKey names the single nested payload object this
	// connector hides inspectable content in (hermes nests prompt /
	// result text under "extra"). When set, the generic decoder —
	// after every top-level content lookup misses — opens exactly
	// this one declared sub-object and re-runs the expected
	// content-key search inside it. Empty for flat-payload
	// connectors, which therefore never take that path. Deliberately
	// a single declared key, not a recursive scan: tool inputs /
	// results carry attacker-influenced nested JSON, so the only
	// sub-object ever opened is the one declared in the audited
	// contract.
	ContentEnvelopeKey string

	// Profile-driven dispatch callbacks. All optional — the
	// unified dispatch helper consults these fields when present
	// (codex / claudecode set them today); generic connectors leave
	// them nil and the unified handler falls through to the inlined
	// generic evaluator.
	Decode     func(payload map[string]interface{}) HookProfileRequest
	MapVerdict func(in HookVerdictInput) HookVerdictOutput
	Respond    func(in HookRespondInput) HookRespondOutput
}

// HookProfileRequest is the shared representation of a decoded hook
// request used by the unified collector. Connector-specific payload
// fields (codex's tool_response, claudecode's permission_mode,
// command_args, etc.) live in Payload so connector-aware evaluators
// can recover them without forcing the unified handler to know about
// every vendor schema.
//
// Decode implementations MUST populate at least HookEventName and
// Payload; other fields are populated when the corresponding payload
// keys are present. The unified collector treats empty fields as
// "not provided" and falls back to generic-extraction helpers.
type HookProfileRequest struct {
	ConnectorName string
	HookEventName string
	SessionID     string
	TurnID        string
	AgentID       string
	AgentName     string
	AgentType     string
	CWD           string
	ToolName      string
	Content       string
	Direction     string
	Model         string
	Payload       map[string]interface{}
}

// HookVerdictInput is the mode-mapping context fed to a profile's
// MapVerdict. RawAction is the normalized upstream verdict
// ("allow", "block", "alert", "confirm"), Event is the hook event
// name, Mode is the connector-resolved guardrail mode
// ("observe" or "action"), and Caps is the connector's hook
// capability matrix. MapVerdict returns the final action plus a
// would_block flag.
type HookVerdictInput struct {
	RawAction string
	Event     string
	Mode      string
	Caps      HookCapability
}

// HookVerdictOutput is MapVerdict's return value. Action is the
// final agent-visible decision ("allow", "block", "alert",
// "confirm"); WouldBlock is true when the mapping demoted a block
// because the connector cannot enforce on this event/mode.
type HookVerdictOutput struct {
	Action     string
	WouldBlock bool
}

// HookRespondInput carries the rendered verdict and surrounding
// context a profile's Respond uses to build the connector-specific
// top-level output map. Tool / event / mode are duplicated from the
// request so Respond does not need to keep a pointer to the original
// HookProfileRequest.
type HookRespondInput struct {
	Req               HookProfileRequest
	Action            string
	RawAction         string
	Reason            string
	AdditionalContext string
	Caps              HookCapability
}

// HookRespondOutput is Respond's return value. FieldName is the JSON
// field name of the output map in the final response body
// ("hook_output", "codex_output", "claude_code_output"). Output is
// the map itself; a nil map means "omit the field entirely" (matches
// the existing omitempty behavior on agentHookResponse.HookOutput).
type HookRespondOutput struct {
	FieldName string
	Output    map[string]interface{}
}

// HookProfileProvider — optional, connectors that participate in the
// unified hook collector declare their profile here. Connectors that do
// not implement this interface continue to flow through the legacy
// per-connector handlers and the HookCapabilityProvider path; the unified
// collector falls back to a zero-value profile for them.
type HookProfileProvider interface {
	HookProfile(opts SetupOpts) HookProfile
}

// AllowedHostsProvider — optional. Connectors that depend on
// connector-specific upstream hostnames (e.g. ZeptoClaw → openrouter.ai
// when the user has BYOK'd against OpenRouter; Codex → its update
// channel) implement this so the firewall default-deny config can
// fold them into the allow-list at boot. Without it,
// firewall.DefaultFirewallConfig only knows the OpenClaw / OpenAI /
// Anthropic baseline and a ZeptoClaw user gets every chat blocked
// at L4. The list returned here is treated as additive over the
// firewall's static defaults — connectors should not return their
// only required host (api.openai.com, api.anthropic.com) since
// those are already in the static list. See S3.3 / F26.
//
// Hostnames must be plain DNS names (no scheme, no path, no
// wildcards). The firewall layer does its own validation; returning
// an invalid host is logged and that host is dropped.
type AllowedHostsProvider interface {
	AllowedHosts() []string
}

// ComponentScanner — optional, connectors that support scanning
// agent-specific skills, plugins, MCP servers implement this.
type ComponentScanner interface {
	ComponentTargets(cwd string) map[string][]string
	SupportsComponentScanning() bool
}

// StopScanner — optional, connectors that scan git-changed files
// at session stop implement this.
type StopScanner interface {
	SupportsStopScan() bool
}

// AgentPaths describes the on-disk filesystem footprint that a
// connector touches at Setup/Teardown time. It is informational
// metadata used by the CLI / `defenseclaw doctor` / install.sh to:
//
//   - preview what files Setup will modify before the operator runs it
//   - audit what Teardown is responsible for removing
//   - surface a friendlier "you need write access to <list>" error
//     than letting Setup fail mid-write
//
// All paths are absolute. Empty slices are valid (a connector may have
// no patched files, e.g. a pure proxy connector with no on-disk
// integration).
type AgentPaths struct {
	// PatchedFiles are agent-owned files DefenseClaw modifies in
	// place during Setup and restores during Teardown (e.g.
	// ~/.codex/config.toml, ~/.zeptoclaw/config.json,
	// ~/.claude/settings.json, ~/.openclaw/openclaw.json).
	PatchedFiles []string

	// BackupFiles are DefenseClaw-owned files written under
	// opts.DataDir at Setup so Teardown can restore PatchedFiles.
	// Clobbering these strands the user — they should be excluded
	// from any cleanup that isn't a full Teardown.
	BackupFiles []string

	// HookScripts are executable scripts written under
	// <opts.DataDir>/hooks/ at Setup that the agent invokes at
	// runtime (PreToolUse, PostToolUse, etc.). Path semantics match
	// PatchedFiles.
	HookScripts []string

	// CreatedDirs are directories the connector creates and owns
	// (e.g. ~/.openclaw/extensions/defenseclaw/). Distinct from
	// PatchedFiles because the entire directory is owned by
	// DefenseClaw, not just edited.
	CreatedDirs []string
}

// AgentPathProvider — optional, connectors that touch on-disk agent
// configuration expose the paths they will patch / back up / write
// here. This is metadata only: implementing it does not change
// Setup/Teardown behavior, it just makes the connector inspectable
// before / after those phases run. Unimplemented = "unknown
// footprint" (the CLI falls back to a generic warning).
type AgentPathProvider interface {
	AgentPaths(opts SetupOpts) AgentPaths
}

// EnvScope describes where an environment variable needs to be set
// for the connector's routing to take effect. DefenseClaw never
// writes to user shell rc files; this enum is documentation for the
// operator surfaced by `defenseclaw doctor`.
type EnvScope string

const (
	// EnvScopeProcess — variable must be set in the agent's process
	// env at launch time. The connector typically achieves this by
	// patching an agent-specific config file that the agent reads at
	// startup (e.g. config.toml for codex), so the operator usually
	// does not need to do anything.
	EnvScopeProcess EnvScope = "process"
	// EnvScopeShell — variable must be set in the user's shell rc.
	// DefenseClaw will not write the rc file; the operator must do
	// it manually. Surfaced as a doctor warning when unset.
	EnvScopeShell EnvScope = "shell"
	// EnvScopeNone — no env var required (native binary configured
	// entirely via on-disk config files).
	EnvScopeNone EnvScope = "none"
)

// EnvRequirement describes a single env var the connector relies on
// for the agent → proxy hop to work. It is informational metadata
// surfaced by the CLI; a connector that needs no env vars implements
// EnvRequirementsProvider returning an empty slice.
type EnvRequirement struct {
	// Name of the env var, e.g. "ANTHROPIC_BASE_URL".
	Name string
	// Scope describes where the var needs to be set.
	Scope EnvScope
	// Required is true when the connector cannot route the agent
	// through the proxy without this var. False = ergonomic
	// (e.g. helps debugging) but not required for routing.
	Required bool
	// Description explains why the var matters and how the
	// connector uses it. Surfaced verbatim by `defenseclaw doctor`.
	Description string
}

// EnvRequirementsProvider — optional, connectors that depend on env
// vars (or document the absence of any) implement this so the CLI
// can surface clear preflight diagnostics.
type EnvRequirementsProvider interface {
	RequiredEnv() []EnvRequirement
}

// HookScriptProvider — optional, connectors that own one or more
// hook scripts at runtime expose their absolute on-disk paths here.
// This is a thin convenience wrapper over AgentPaths.HookScripts so a
// connector can advertise hook scripts without committing to the
// rest of the AgentPaths shape.
type HookScriptProvider interface {
	HookScripts(opts SetupOpts) []string
}

// HookScriptOwner — plan C2 / S2.5: optional, connectors that own a
// per-vendor hook template implement this to advertise the BASENAMES
// (not absolute paths) of the scripts they need written into hookDir.
// Used by WriteHookScriptsForConnector to collect the union of
// generic + per-connector scripts without consulting a package-level
// map. A connector that does not own any vendor hook (openclaw,
// zeptoclaw) should NOT implement this interface — the empty case
// flows through the no-extra-scripts branch.
//
// The returned slice MUST contain only base filenames, no path
// separators; the embed FS at hooks/<name> is the single source of
// truth for the file body. Returning a name that doesn't exist in
// the embed FS produces an explicit error at write time so a typo
// never silently no-ops.
type HookScriptOwner interface {
	HookScriptNames(opts SetupOpts) []string
}

// ProviderProbe — optional, connectors that can self-diagnose whether
// at least one usable upstream provider is configured implement this.
// The sidecar boot path calls HasUsableProviders() right after Setup
// and refuses to start (returns an error from Run) when count == 0,
// preventing the gateway from accepting traffic with no LLM upstream
// to forward to (S0.12 / plan A4).
//
// Implementations must be cheap (no network I/O, no blocking).
// Returning a non-nil error short-circuits the count check and is
// logged as the boot-time refusal reason.
//
// The cfg.Guardrail.AllowEmptyProviders flag bypasses the refusal —
// CI test harnesses that intentionally run with stub upstreams opt
// in via that flag.
type ProviderProbe interface {
	HasUsableProviders() (count int, err error)
}
