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

	// CodexEnforcement and ClaudeCodeEnforcement gate the
	// proxy-redirect / blocking path for the Codex and Claude Code
	// connectors respectively. The Sidecar populates these from
	// cfg.Guardrail.CodexEnforcementEnabled and
	// cfg.Guardrail.ClaudeCodeEnforcementEnabled. When false (the
	// default), the connector's Setup() installs hooks + native
	// OTel exporters but skips the proxy-redirect path
	// (openai_base_url rewrite, ANTHROPIC_BASE_URL env override,
	// reserved-id strip, subprocess sandbox). Observability still
	// runs end-to-end via three independent channels per connector;
	// see GuardrailConfig.CodexEnforcementEnabled in
	// internal/config/config.go for the rationale.
	//
	// Per-connector flags (rather than a single InstallMode enum)
	// because OpenClaw and ZeptoClaw run in full guardrail mode
	// regardless and have no observability-only path; mixing the
	// gates into one tri-state was producing an unused enforcement
	// branch for those connectors.
	CodexEnforcement      bool
	ClaudeCodeEnforcement bool

	// HILTEnabled tells connectors with native approval surfaces to wire
	// their host approval delivery path. For OpenClaw this enables plugin
	// approval forwarding so approval prompts can reach chat-origin
	// sessions instead of living only in the native approval queue.
	HILTEnabled bool

	// InstallCodeGuard enables one-time, native Project CodeGuard
	// bootstrapping for connectors that have their own extension
	// mechanism. Codex gets the upstream `software-security` skill
	// under ~/.codex/skills; Claude Code gets the upstream
	// codeguard-security plugin through `claude plugin`. These native
	// integrations are intentionally not torn down when the operator
	// changes connectors: they are user-visible security tooling, not
	// DefenseClaw hook/proxy state.
	InstallCodeGuard bool
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
