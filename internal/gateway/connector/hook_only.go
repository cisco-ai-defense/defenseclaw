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

package connector

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"gopkg.in/yaml.v3"
)

var (
	HermesConfigPathOverride      string
	CursorHooksPathOverride       string
	WindsurfHooksPathOverride     string
	GeminiSettingsPathOverride    string
	CopilotHooksPathOverride      string
	CopilotWorkspaceDirOverride   string
	OpenHandsHooksPathOverride    string
	OpenHandsWorkspaceDirOverride string
	AntigravityHooksPathOverride  string
	OpenCodePluginPathOverride    string
)

type hookOnlyConnector struct {
	name        string
	description string
	apiPath     string
	scriptName  string
	configPath  func(SetupOpts) string
	capability  func(SetupOpts) HookCapability

	// pluginArtifact connectors are governed by a host-agent plugin FILE
	// that DefenseClaw writes (and the agent auto-loads) rather than a
	// bundled shell hook + a config-file patch. opencode is the first:
	// it loads JS/TS plugins from ~/.config/opencode/plugins/ and a
	// plugin's tool.execute.before throws to block. For these connectors
	// configPath resolves to the plugin file's destination and
	// pluginArtifactAsset names the embedded template under hooks/.
	// Setup/Teardown/VerifyClean branch on this flag; everything else
	// (HookProfile, Capabilities, Authenticate, Route) is shared.
	pluginArtifact      bool
	pluginArtifactAsset string

	gatewayToken string
	masterKey    string
	loopbackWarn sync.Once
}

// NewOpenCodeConnector governs opencode (https://opencode.ai). Unlike the
// shell-hook connectors, opencode has no command-hook config surface: it
// auto-loads JavaScript/TypeScript plugins from
// ~/.config/opencode/plugins/ at startup. DefenseClaw ships a
// dependency-free bridge plugin (opencode-plugin.js) whose
// tool.execute.before POSTs each tool call to /api/v1/opencode/hook and
// throws new Error(reason) when the gateway returns a block decision —
// which aborts the tool the same way opencode's own .env-protection
// example does. The thrown error is authoritative, so opencode genuinely
// supports fail-closed: on an unreachable gateway the bridge throws when
// FAIL_MODE=closed.
func NewOpenCodeConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:                "opencode",
		description:         "auto-loaded JS bridge plugin (~/.config/opencode/plugins) with tool.execute.before blocking",
		apiPath:             "/api/v1/opencode/hook",
		scriptName:          "opencode-plugin.js",
		configPath:          opencodePluginPath,
		pluginArtifact:      true,
		pluginArtifactAsset: "opencode-plugin.js",
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"tool.execute.before"},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         opencodePluginPath(opts),
			}
		},
	}
}

func NewHermesConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "hermes",
		description: "config.yaml hooks with MCP, skills, plugins, and hook telemetry",
		apiPath:     "/api/v1/hermes/hook",
		scriptName:  "hermes-hook.sh",
		configPath:  hermesConfigPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"pre_tool_call"},
				SupportsFailClosed: false,
				Scope:              "user",
				ConfigPath:         hermesConfigPath(opts),
			}
		},
	}
}

func NewCursorConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "cursor",
		description: "hooks.json command hooks with MCP, skills, and rules surfaces",
		apiPath:     "/api/v1/cursor/hook",
		scriptName:  "cursor-hook.sh",
		configPath:  cursorHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents: []string{
					"beforeShellExecution",
					"beforeMCPExecution",
				},
				BlockEvents: []string{
					"preToolUse",
					"beforeShellExecution",
					"beforeMCPExecution",
					"beforeReadFile",
					"beforeTabFileRead",
					"beforeSubmitPrompt",
					"stop",
				},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         cursorHooksPath(opts),
			}
		},
	}
}

func NewWindsurfConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "windsurf",
		description: "Cascade hooks with documented MCP/rules discovery",
		apiPath:     "/api/v1/windsurf/hook",
		scriptName:  "windsurf-hook.sh",
		configPath:  windsurfHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"},
				SupportsFailClosed: false,
				Scope:              "user",
				ConfigPath:         windsurfHooksPath(opts),
			}
		},
	}
}

func NewGeminiCLIConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "geminicli",
		description: "settings.json hooks with native OTLP, MCP, skills, extensions, and agents",
		apiPath:     "/api/v1/geminicli/hook",
		scriptName:  "geminicli-hook.sh",
		configPath:  geminiSettingsPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:     true,
				CanAskNative: false,
				BlockEvents: []string{
					"BeforeAgent",
					"BeforeModel",
					"BeforeTool",
					"AfterTool",
					"AfterAgent",
				},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         geminiSettingsPath(opts),
			}
		},
	}
}

func NewCopilotConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "copilot",
		description: "user-global Copilot CLI hooks, with optional workspace .github/hooks override",
		apiPath:     "/api/v1/copilot/hook",
		scriptName:  "copilot-hook.sh",
		configPath:  copilotHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents:    []string{"preToolUse"},
				BlockEvents: []string{
					"preToolUse",
					"permissionRequest",
					"agentStop",
					"subagentStop",
					"postToolUseFailure",
				},
				SupportsFailClosed: false,
				Scope:              "user,workspace",
				ConfigPath:         copilotHooksPath(opts),
			}
		},
	}
}

func NewOpenHandsConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "openhands",
		description: "user-global OpenHands hooks, with optional repo-local .openhands/hooks.json override",
		apiPath:     "/api/v1/openhands/hook",
		scriptName:  "openhands-hook.sh",
		configPath:  openhandsHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:     true,
				CanAskNative: false,
				BlockEvents: []string{
					"pre_tool_use",
					"user_prompt_submit",
					"stop",
				},
				SupportsFailClosed: true,
				Scope:              "user,workspace",
				ConfigPath:         openhandsHooksPath(opts),
			}
		},
	}
}

// NewAntigravityConnector wires Google's Antigravity (`agy`) CLI through
// the unified hook collector. agy reads PreToolUse hooks from
// ~/.gemini/config/hooks.json in a Claude-Code-compatible nested
// schema (see patchAntigravityHooks) and supports a documented "ask"
// decision that bypasses --dangerously-skip-permissions, which is the
// strongest user-prompt primitive any connector currently exposes.
//
// Scope is intentionally "user" only: Antigravity merges every
// discovered hooks.json (global, project, legacy) so writing into
// more than one path causes duplicate firing. Setup writes only the
// single global file (see antigravityHooksPath).
func NewAntigravityConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "antigravity",
		description: "Antigravity (agy) PreToolUse hooks with native ask/deny decisions",
		apiPath:     "/api/v1/antigravity/hook",
		scriptName:  "antigravity-hook.sh",
		configPath:  antigravityHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       true,
				AskEvents:          []string{"PreToolUse"},
				BlockEvents:        []string{"PreToolUse"},
				SupportsFailClosed: false,
				Scope:              "user",
				ConfigPath:         antigravityHooksPath(opts),
			}
		},
	}
}

func (c *hookOnlyConnector) Name() string                           { return c.name }
func (c *hookOnlyConnector) Description() string                    { return c.description }
func (c *hookOnlyConnector) HookAPIPath() string                    { return c.apiPath }
func (c *hookOnlyConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *hookOnlyConnector) SubprocessPolicy() SubprocessPolicy     { return SubprocessNone }
func (c *hookOnlyConnector) HookScriptNames(SetupOpts) []string     { return []string{c.scriptName} }
func (c *hookOnlyConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return c.Capabilities(opts).Hooks
}

// HookProfile implements HookProfileProvider for the 6 generic
// hook-only connectors. Today only geminicli emits native OTLP (via
// the JSON-block telemetry section in settings.json with a scoped
// path-token); copilot returns an env-block spec that mirrors the
// NativeOTLP capability advertised to doctor/setup; cursor, windsurf,
// hermes, and openhands return spec=nil because their CLIs do not
// expose a native OTel exporter. When a future cursor release adds
// native OTLP support, that connector can flip its branch here to
// return a non-nil spec without changing the dispatcher.
//
// SupportsTraceparent is true for the entire generic family: every
// shipped hook script (cursor-hook.sh, windsurf-hook.sh,
// hermes-hook.sh, geminicli-hook.sh, copilot-hook.sh,
// openhands-hook.sh — see internal/gateway/connector/hooks/) sources
// _hardening.sh and
// invokes defenseclaw_extract_trace_context to forward the W3C
// traceparent / tracestate headers from DEFENSECLAW_TRACEPARENT
// (or TRACEPARENT / OTEL_TRACEPARENT). The pre-v6 era was when
// only codex / claudecode forwarded the header; v6 generalised the
// helper so the profile MUST advertise this capability or the
// gateway expects a fresh root span where the script is actually
// shipping a remote parent — collapsing trace continuity in
// dashboards.
func (c *hookOnlyConnector) HookProfile(opts SetupOpts) HookProfile {
	profile := HookProfile{
		Name:                c.name,
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		MapVerdict:          hookOnlyProfileMapVerdict,
		Respond:             hookOnlyProfileRespond,
	}
	if c.name == "geminicli" {
		profile.NativeOTLP = geminiCLINativeOTLPSpec(opts)
	}
	if c.name == "copilot" {
		profile.NativeOTLP = copilotNativeOTLPSpec(opts)
	}
	if c.name == "antigravity" {
		// Antigravity is the only generic hook-only connector whose
		// upstream wire shape is NOT flat hook_event_name +
		// tool_name / tool_input. agy v1 nests the tool descriptor
		// under `toolCall` (Claude-Code derived), so the unified
		// handler's generic normalizer can't extract the event name
		// or tool name and rejects every PreToolUse with HTTP 400
		// ("hook event name is required"). The connector-side
		// decoder maps agy's payload onto the canonical
		// HookProfileRequest fields. See antigravity_hook_profile.go
		// for the wire-shape contract this decoder honours and the
		// empirical agy-version notes.
		profile.Decode = antigravityProfileDecode
	}
	// NOTE: hermes needs no Decode override. Its nested `extra` content
	// is recovered by the generic decoder's ContentEnvelopeKey fallback
	// (declared on the hermes hook contract), and its wire replies are
	// shaped by the hermes case in hookOnlyProfileRespond.
	return ApplyHookContract(profile, opts)
}

func copilotNativeOTLPSpec(opts SetupOpts) *NativeOTLPSpec {
	headers := map[string]string{
		"x-defenseclaw-source": "copilot",
		"x-defenseclaw-client": "copilot-otel/1.0",
	}
	if opts.APIToken != "" {
		headers["x-defenseclaw-token"] = opts.APIToken
	}
	return &NativeOTLPSpec{
		Kind:               NativeOTLPEnvBlock,
		Endpoint:           "http://" + strings.TrimSpace(opts.APIAddr),
		Protocol:           "http/json",
		Headers:            headers,
		ServiceName:        "copilot",
		ResourceAttributes: map[string]string{"service.name": "copilot", "defenseclaw.connector": "copilot"},
		ExtraEnv:           map[string]string{"COPILOT_OTEL_ENABLED": "true"},
	}
}

// geminiCLINativeOTLPSpec returns the JSON-block spec for Gemini CLI
// native OTLP. The spec carries an unresolved PathToken/PathScope —
// the installer is expected to call EnsureOTLPPathToken on disk and
// inject the token before rendering. This matches the way
// patchGeminiTelemetry handles the mint today; the spec only carries
// the descriptive shape.
//
// patchGeminiTelemetry calls spec.JSONBlock() to produce the
// telemetry object embedded in settings.json.
func geminiCLINativeOTLPSpec(opts SetupOpts) *NativeOTLPSpec {
	spec := &NativeOTLPSpec{
		Kind:           NativeOTLPJSONBlock,
		Endpoint:       "http://" + strings.TrimSpace(opts.APIAddr),
		Protocol:       "http",
		PathScope:      OTLPScopeGeminiCLI,
		LogUserPrompts: redaction.DisableAll(),
	}
	// Best-effort: mint or load the scoped token here so the spec
	// can render its endpoint deterministically. patchGeminiTelemetry
	// runs the same EnsureOTLPPathToken call before serializing the
	// block; this duplicates the cheap lookup so callers that only
	// want the descriptive spec (parity tests, doctor reports) see
	// the resolved URL.
	if opts.DataDir != "" {
		if tok, err := EnsureOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err == nil && tok != "" {
			spec.PathToken = tok
		}
	}
	return spec
}

func (c *hookOnlyConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	caps := ConnectorCapabilities{
		LLMTrafficMode: LLMTrafficModeForConnector(c.name),
		Hooks:          c.capability(opts),
		CodeGuard: CodeGuardCapability{
			Supported:    false,
			OptInOnly:    true,
			AutoInstall:  false,
			Idempotent:   true,
			ConflictSafe: true,
			Notes: []string{
				"Native Project CodeGuard assets are installed only by an explicit codeguard install command.",
				"Server-side CodeGuard scanning in hooks remains independent from native skill/rule installation.",
			},
		},
		Telemetry: TelemetryCapability{
			HookSignals: []string{"logs", "metrics", "traces"},
			AuthMode:    "header-token",
			SourceModes: []string{"hook"},
			Notes:       []string{"Hook-generated telemetry is emitted by DefenseClaw for every hook invocation."},
		},
	}

	switch c.name {
	case "hermes":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     []string{hermesConfigPath(opts)},
			WritePaths:      []string{hermesConfigPath(opts)},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"MCP servers are merged into the resolved Hermes config.yaml (HERMES_HOME or the platform default)."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			ReadPaths:      []string{filepath.Join(hermespath.HomeDir(), "skills")},
			WritePaths:     []string{filepath.Join(hermespath.HomeDir(), "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Rules = unsupportedSurface("Hermes rules are not a separate documented local surface.")
		caps.Agents = unsupportedSurface("Hermes subagent/agent asset locations are not installed by DefenseClaw v1.")
	case "cursor":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     []string{workspacePath(opts, ".cursor", "mcp.json"), homePath(".cursor", "mcp.json")},
			WritePaths:      []string{workspacePath(opts, ".cursor", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      cursorSkillPaths(opts),
			WritePaths:     []string{workspacePath(opts, ".cursor", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{workspacePath(opts, ".cursor", "rules"), workspacePath(opts, "AGENTS.md")},
			WritePaths:     []string{workspacePath(opts, ".cursor", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = unsupportedSurface("Cursor subagent installation is not a documented local surface for this connector.")
	case "windsurf":
		caps.MCP = SurfaceCapability{
			Supported:     true,
			Scope:         "user",
			ConfigPaths:   windsurfMCPPaths(),
			ReadPaths:     windsurfMCPPaths(),
			DiscoveryOnly: true,
			RequiresOptIn: true,
			Notes:         []string{"DefenseClaw discovers existing Windsurf MCP paths only; it does not create undocumented config files."},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace",
			ReadPaths:     existingWindsurfRulePaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Windsurf rule writes are deferred unless a documented or pre-existing path is present."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"rule"}
		caps.CodeGuard.Notes = append(caps.CodeGuard.Notes, "Windsurf CodeGuard rule installation is available only when a documented/pre-existing rules path exists.")
		caps.Skills = unsupportedSurface("Windsurf skills are not exposed as a documented local install surface.")
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = unsupportedSurface("Windsurf agent/subagent asset installation is not supported.")
	case "geminicli":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     []string{geminiSettingsPath(opts)},
			WritePaths:      []string{geminiSettingsPath(opts)},
			SupportsBackup:  true,
			SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{homePath(".gemini", "skills"), workspacePath(opts, ".gemini", "skills"), workspacePath(opts, ".agents", "skills")},
			WritePaths:     []string{homePath(".gemini", "skills"), workspacePath(opts, ".gemini", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{homePath(".gemini", "agents"), workspacePath(opts, ".gemini", "agents")},
			WritePaths:     []string{homePath(".gemini", "agents"), workspacePath(opts, ".gemini", "agents")},
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{homePath(".gemini", "skills"), workspacePath(opts, ".agents", "skills")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes:          []string{"Gemini rule-style guidance is represented through skills/agents, not a guessed standalone rules file."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Telemetry = TelemetryCapability{
			NativeOTLP:       true,
			NativeSignals:    []string{"logs", "metrics", "traces"},
			HookSignals:      []string{"logs", "metrics", "traces"},
			ConfigPaths:      []string{geminiSettingsPath(opts)},
			AuthMode:         "path-token-loopback",
			EndpointTemplate: "http://" + opts.APIAddr + "/otlp/geminicli/<token>",
			SourceModes:      []string{"native", "hook"},
			Notes:            []string{"Gemini CLI telemetry is configured in settings.json with a path token because custom OTLP headers are not documented."},
		}
	case "copilot":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     []string{homePath(".copilot", "mcp-config.json"), workspacePath(opts, ".github", "mcp.json"), workspacePath(opts, ".mcp.json")},
			WritePaths:      []string{homePath(".copilot", "mcp-config.json"), workspacePath(opts, ".github", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{homePath(".copilot", "skills"), workspacePath(opts, ".github", "skills"), workspacePath(opts, ".agents", "skills")},
			WritePaths:     []string{homePath(".copilot", "skills"), workspacePath(opts, ".github", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{workspacePath(opts, ".github", "instructions")},
			WritePaths:     []string{workspacePath(opts, ".github", "instructions")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
		}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{homePath(".copilot", "agents"), workspacePath(opts, ".github", "agents")},
			WritePaths:     []string{homePath(".copilot", "agents"), workspacePath(opts, ".github", "agents")},
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Telemetry = TelemetryCapability{
			NativeOTLP:    true,
			NativeSignals: []string{"traces", "metrics"},
			HookSignals:   []string{"logs", "metrics", "traces"},
			Env: []EnvRequirement{
				{Name: "COPILOT_OTEL_ENABLED", Scope: EnvScopeProcess, Required: false, Description: "Set to true in the Copilot CLI process environment to enable native OpenTelemetry."},
				{Name: "OTEL_EXPORTER_OTLP_ENDPOINT", Scope: EnvScopeProcess, Required: false, Description: "Point Copilot native OTLP at the DefenseClaw gateway /v1 endpoints."},
				{Name: "OTEL_EXPORTER_OTLP_HEADERS", Scope: EnvScopeProcess, Required: false, Description: "Carry x-defenseclaw-token and x-defenseclaw-source headers for native OTLP authentication."},
			},
			AuthMode:         "header-token",
			EndpointTemplate: "http://" + opts.APIAddr,
			SourceModes:      []string{"native", "hook"},
			Notes:            []string{"DefenseClaw reports the required environment variables but does not mutate shell rc files."},
		}
	case "antigravity":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     antigravityMCPPaths(opts),
			ReadPaths:       antigravityMCPPaths(opts),
			WritePaths:      antigravityMCPPaths(opts),
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"Antigravity MCP uses ~/.gemini/config/mcp_config.json and <workspace>/.agents/mcp_config.json. DefenseClaw writes remote servers with serverUrl and reads url as a compatibility alias."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      antigravitySkillReadPaths(opts),
			WritePaths:     antigravitySkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"AgentSkills folder form is supported for read/write. CLI direct markdown skills under ~/.gemini/antigravity-cli/skills are discovery-only until Google reconciles the skill shape conflict."},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     antigravityRuleReadPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Antigravity rules are discovery-only; DefenseClaw does not write rules until activation metadata and file naming are documented."},
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     antigravityPluginPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Antigravity plugins are scan/discovery-only; DefenseClaw does not install or disable agy plugins in PR #365."},
		}
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "plugin",
			ReadPaths:     antigravityPluginPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"No standalone Antigravity agent path is documented. Plugin-contained agents under <plugin>/agents are discovered through Antigravity plugin roots only."},
		}
		caps.CodeGuard.Supported = false
	case "openhands":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     []string{homePath(".openhands", "mcp.json")},
			ReadPaths:       []string{homePath(".openhands", "mcp.json")},
			WritePaths:      []string{homePath(".openhands", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"OpenHands MCP servers are managed through the OpenHands CLI or ~/.openhands/mcp.json."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      openhandsSkillPaths(opts),
			WritePaths:     []string{filepath.Join(openhandsWorkspaceRoot(opts), ".agents", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"OpenHands recommends AgentSkills under .agents/skills; .openhands/skills, .openhands/microagents, installed skills, and the public skills cache are discovered for parity with the OpenHands loader. Global setup resolves user paths under HOME unless a workspace is pinned."},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "user,workspace",
			ReadPaths:     []string{filepath.Join(openhandsWorkspaceRoot(opts), "AGENTS.md")},
			DiscoveryOnly: true,
			Notes:         []string{"OpenHands permanent repository context is AGENTS.md; DefenseClaw discovers it but does not overwrite it."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = unsupportedSurface("OpenHands agent-specific microagents are deprecated; install AgentSkills under .agents/skills instead.")
	default:
		caps.MCP = unsupportedSurface("")
		caps.Skills = unsupportedSurface("")
		caps.Rules = unsupportedSurface("")
		caps.Plugins = unsupportedSurface("")
		caps.Agents = unsupportedSurface("")
	}
	return caps
}

func (c *hookOnlyConnector) Setup(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	if c.pluginArtifact {
		return c.setupPluginArtifact(opts)
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("%s hook script: %w", c.name, err)
	}
	if err := c.patchConfig(opts, c.hookCommand(opts)); err != nil {
		return fmt.Errorf("%s hook config: %w", c.name, err)
	}
	return nil
}

// setupPluginArtifact renders the embedded bridge-plugin template
// (APIAddr / APIToken / FailMode substituted) and writes it to the host
// agent's auto-load plugin directory at 0o600 (it carries the gateway
// token, so it is owner-only and never executable). The destination is
// captured in the managed-file backup so Teardown can heal it: if the
// plugin file is unchanged since setup it is removed (we created it);
// if the operator hand-edited it, the backup restore leaves it alone.
func (c *hookOnlyConnector) setupPluginArtifact(opts SetupOpts) error {
	tmpl, err := hookFS.ReadFile("hooks/" + c.pluginArtifactAsset)
	if err != nil {
		return fmt.Errorf("%s read plugin template %s: %w", c.name, c.pluginArtifactAsset, err)
	}
	failMode := normalizeHookFailMode(opts.HookFailMode)
	if failMode == "closed" && !c.capability(opts).SupportsFailClosed {
		failMode = "open"
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:  opts.APIAddr,
		APIToken: opts.APIToken,
		FailMode: failMode,
	})
	if err != nil {
		return fmt.Errorf("%s render plugin template: %w", c.name, err)
	}
	path := c.configPath(opts)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("%s create plugin dir: %w", c.name, err)
	}
	if err := captureManagedFileBackup(opts.DataDir, c.name, "config", path); err != nil {
		return fmt.Errorf("%s capture plugin backup: %w", c.name, err)
	}
	if err := atomicWriteFile(path, []byte(rendered), 0o600); err != nil {
		return fmt.Errorf("%s write plugin: %w", c.name, err)
	}
	return updateManagedFileBackupPostHash(opts.DataDir, c.name, "config", path)
}

// hookCommand returns the command an agent runs for this connector's hook. On
// Unix it is the bundled .sh path; on Windows it is the native DefenseClaw
// `hook` subcommand invocation. The same value is used at setup, teardown, and
// VerifyClean so the JSON/YAML hook removers (which match on the exact command
// string) recognize the entries DefenseClaw inserted.
func (c *hookOnlyConnector) hookCommand(opts SetupOpts) string {
	return hookInvocationCommand(c.name, filepath.Join(opts.DataDir, "hooks", c.scriptName))
}

// Teardown restores the host agent's config (or removes our entries
// when restoration is unsafe) AND replaces the hook script with a
// disabled tombstone.
//
// The tombstone step is unconditional and runs even when the config
// restore path returns early. The reason is symmetric with codex /
// claudecode: host agents that have been running since before teardown
// (cursor desktop, copilot IDE session, hermes daemon) cache the
// absolute hook path at startup and will keep invoking it for the life
// of the process. Without the tombstone they hit either:
//
//   - exit-127 ("command not found") if the file was deleted, or
//   - a strict-availability fail-closed block when
//     DEFENSECLAW_STRICT_AVAILABILITY=1 and the gateway is gone.
//
// Errors from the config and tombstone steps are joined so a tombstone
// failure does not mask a config-restore failure (or vice versa).
func (c *hookOnlyConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	if c.pluginArtifact {
		return c.teardownPluginArtifact(opts)
	}
	var errs []string

	path := managedFileBackupTargetPath(opts.DataDir, c.name, "config", c.configPath(opts))
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", path)
	switch {
	case err != nil:
		errs = append(errs, fmt.Sprintf("restore config backup: %v", err))
	case !restored:
		if err := c.removeConfigEntries(path, c.hookCommand(opts)); err != nil {
			errs = append(errs, fmt.Sprintf("remove hook entries: %v", err))
		} else {
			discardManagedFileBackup(opts.DataDir, c.name, "config")
		}
	}

	if err := writeDisabledHookTombstone(opts, c.scriptName, c.name); err != nil {
		errs = append(errs, fmt.Sprintf("disabled hook tombstone: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s teardown: %s", c.name, strings.Join(errs, "; "))
	}
	return nil
}

// teardownPluginArtifact heals the host agent's plugin directory. The
// managed-file backup removes the plugin when it is unchanged since
// setup (we created it, so "restore to pristine-missing" = delete) and
// otherwise leaves an operator-edited file in place. No tombstone is
// written: unlike a shell hook (whose absolute path a long-running host
// process caches and re-execs), an opencode plugin is re-read from the
// plugins directory on each startup, so simply removing the file stops
// it loading.
func (c *hookOnlyConnector) teardownPluginArtifact(opts SetupOpts) error {
	path := managedFileBackupTargetPath(opts.DataDir, c.name, "config", c.configPath(opts))
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", path)
	if err != nil {
		return fmt.Errorf("%s restore plugin backup: %w", c.name, err)
	}
	if !restored {
		// The plugin was hand-edited after setup; leave it for the
		// operator rather than clobbering their changes. Doctor surfaces
		// the lingering managed plugin.
		return nil
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
	return nil
}

func (c *hookOnlyConnector) VerifyClean(opts SetupOpts) error {
	path := managedFileBackupTargetPath(opts.DataDir, c.name, "config", c.configPath(opts))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if c.pluginArtifact {
		// The bridge plugin is a standalone managed file; a clean
		// teardown removes it entirely. Any residual DefenseClaw marker
		// means the heal did not complete.
		if bytes.Contains(data, []byte("DefenseClaw")) || bytes.Contains(data, []byte(c.apiPath)) {
			return fmt.Errorf("%s teardown incomplete: managed plugin still present at %s", c.name, path)
		}
		return nil
	}
	needle := c.hookCommand(opts)
	if bytes.Contains(data, []byte(needle)) || bytes.Contains(data, []byte(c.scriptName)) {
		return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
	}
	return nil
}

func (c *hookOnlyConnector) Authenticate(r *http.Request) bool {
	return authenticateHookBridgeRequest(r, c.gatewayToken, c.masterKey, c.name,
		"hook-only connectors run as local shell hooks; setup injects Authorization when possible, but loopback remains accepted for legacy hook installs",
		&c.loopbackWarn)
}

func (c *hookOnlyConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{
		RawBody:         body,
		RawModel:        ParseModelFromBody(body),
		Stream:          ParseStreamFromBody(body),
		PassthroughMode: !isChatPath(r.URL.Path),
		ConnectorName:   c.name,
	}, nil
}

func (c *hookOnlyConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *hookOnlyConnector) AgentPaths(opts SetupOpts) AgentPaths {
	caps := c.Capabilities(opts)
	patched := uniqueNonEmptyStrings(append([]string{c.configPath(opts)}, caps.Telemetry.ConfigPaths...))
	return AgentPaths{
		PatchedFiles: patched,
		BackupFiles:  []string{managedFileBackupPath(opts.DataDir, c.name, "config")},
		HookScripts:  hookScriptPathsForConnector(opts, c),
	}
}

func (c *hookOnlyConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

func (c *hookOnlyConnector) RequiredEnv() []EnvRequirement {
	if c.name == "copilot" {
		return append([]EnvRequirement{{
			Scope:       EnvScopeNone,
			Description: "Hooks and managed workspace config do not require shell environment variables; native Copilot OTLP uses optional process env vars.",
		}}, c.Capabilities(SetupOpts{APIAddr: "127.0.0.1:18970"}).Telemetry.Env...)
	}
	return []EnvRequirement{{
		Scope:       EnvScopeNone,
		Description: "No environment variables are required; this connector installs native hook configuration only.",
	}}
}

func (c *hookOnlyConnector) SupportsComponentScanning() bool {
	return true
}

func (c *hookOnlyConnector) ComponentTargets(cwd string) map[string][]string {
	opts := SetupOpts{WorkspaceDir: cwd}
	caps := c.Capabilities(opts)
	targets := map[string][]string{}
	addSurfaceTargets(targets, "mcp", caps.MCP)
	addSurfaceTargets(targets, "skill", caps.Skills)
	addSurfaceTargets(targets, "rule", caps.Rules)
	addSurfaceTargets(targets, "plugin", caps.Plugins)
	addSurfaceTargets(targets, "agent", caps.Agents)
	return targets
}

func (c *hookOnlyConnector) HasUsableProviders() (int, error) {
	return 1, nil
}

func (c *hookOnlyConnector) patchConfig(opts SetupOpts, hookScript string) error {
	if c.name == "copilot" {
		root := workspaceRoot(opts)
		if root != "" && !workspaceRootOutsideDataDir(root, opts.DataDir) {
			return fmt.Errorf("copilot setup workspace must be outside DefenseClaw data dir; pass --workspace with the target repository or omit it for global ~/.copilot hooks")
		}
	}
	path := c.configPath(opts)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s setup could not resolve a hook config path", c.name)
	}
	if err := captureManagedFileBackup(opts.DataDir, c.name, "config", path); err != nil {
		return err
	}

	var err error
	switch c.name {
	case "hermes":
		err = patchHermesHooks(path, hookScript)
	case "cursor":
		err = patchCursorHooks(path, hookScript, c.effectiveFailClosed(opts))
	case "windsurf":
		err = patchWindsurfHooks(path, hookScript)
	case "geminicli":
		if err = patchGeminiHooks(path, hookScript); err == nil {
			err = patchGeminiTelemetry(path, opts)
		}
	case "copilot":
		err = patchCopilotHooks(path, hookScript)
	case "openhands":
		err = patchOpenHandsHooks(path, hookScript)
	case "antigravity":
		err = patchAntigravityHooks(path, hookScript)
	default:
		err = fmt.Errorf("unknown hook connector %q", c.name)
	}
	if err != nil {
		return err
	}
	return updateManagedFileBackupPostHash(opts.DataDir, c.name, "config", path)
}

func (c *hookOnlyConnector) removeConfigEntries(path, hookScript string) error {
	switch c.name {
	case "hermes":
		return removeHermesHooks(path, hookScript)
	case "geminicli":
		return removeGeminiConfigEntries(path, hookScript)
	case "cursor", "windsurf", "copilot", "openhands", "antigravity":
		return removeJSONHookReferences(path, hookScript)
	default:
		return nil
	}
}

func (c *hookOnlyConnector) effectiveFailClosed(opts SetupOpts) bool {
	cap := c.HookCapabilities(opts)
	return cap.SupportsFailClosed && strings.TrimSpace(opts.HookFailMode) == "closed"
}

func hermesConfigPath(SetupOpts) string {
	if HermesConfigPathOverride != "" {
		return HermesConfigPathOverride
	}
	return hermespath.ConfigPath()
}

// opencodePluginPath resolves the destination of DefenseClaw's bridge
// plugin in opencode's global auto-load directory. opencode loads any
// JS/TS file under ~/.config/opencode/plugins/ at startup, so writing
// the file is the entire install — no opencode.json edit is required.
func opencodePluginPath(SetupOpts) string {
	if OpenCodePluginPathOverride != "" {
		return OpenCodePluginPathOverride
	}
	return homePath(".config", "opencode", "plugins", "defenseclaw.js")
}

func cursorHooksPath(SetupOpts) string {
	if CursorHooksPathOverride != "" {
		return CursorHooksPathOverride
	}
	return homePath(".cursor", "hooks.json")
}

func windsurfHooksPath(SetupOpts) string {
	if WindsurfHooksPathOverride != "" {
		return WindsurfHooksPathOverride
	}
	return homePath(".codeium", "windsurf", "hooks.json")
}

func geminiSettingsPath(SetupOpts) string {
	if GeminiSettingsPathOverride != "" {
		return GeminiSettingsPathOverride
	}
	return homePath(".gemini", "settings.json")
}

func copilotHooksPath(opts SetupOpts) string {
	if CopilotHooksPathOverride != "" {
		return CopilotHooksPathOverride
	}
	if root := workspaceRoot(opts); root != "" {
		return filepath.Join(root, ".github", "hooks", "defenseclaw.json")
	}
	return homePath(".copilot", "hooks", "defenseclaw.json")
}

func openhandsHooksPath(opts SetupOpts) string {
	if OpenHandsHooksPathOverride != "" {
		return OpenHandsHooksPathOverride
	}
	return filepath.Join(openhandsWorkspaceRoot(opts), ".openhands", "hooks.json")
}

// antigravityHooksPath returns the global Antigravity hook config path.
//
// Antigravity (`agy`) reads hooks from ~/.gemini/config/hooks.json.
// The Antigravity contract also documents workspace hooks at
// <workspace>/.agents/hooks.json and plugin-contained hooks at
// <plugin>/hooks.json, but DefenseClaw writes only the global config
// file. Current PR evidence says agy merges global and workspace hook
// files, so writing the same DefenseClaw hook to more than one path
// would duplicate-fire policy evaluations. Workspace and plugin hook
// files remain discovery-only surfaces.
func antigravityHooksPath(SetupOpts) string {
	if AntigravityHooksPathOverride != "" {
		return AntigravityHooksPathOverride
	}
	return homePath(".gemini", "config", "hooks.json")
}

func openhandsWorkspaceRoot(opts SetupOpts) string {
	root := selectedWorkspaceRoot(OpenHandsWorkspaceDirOverride, opts.WorkspaceDir)
	if root == "" || !workspaceRootOutsideDataDir(root, opts.DataDir) {
		if home := strings.TrimSpace(homePath()); home != "" {
			return home
		}
	}
	return root
}

func workspaceRoot(opts SetupOpts) string {
	return selectedWorkspaceRoot(CopilotWorkspaceDirOverride, opts.WorkspaceDir)
}

func selectedWorkspaceRoot(override, workspaceDir string) string {
	root := strings.TrimSpace(override)
	if root == "" {
		root = strings.TrimSpace(workspaceDir)
	}
	return root
}

func workspacePath(opts SetupOpts, parts ...string) string {
	root := workspaceRoot(opts)
	if strings.TrimSpace(root) == "" {
		return ""
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...)
}

func workspaceRootOutsideDataDir(root, dataDir string) bool {
	root = strings.TrimSpace(root)
	if root == "" {
		return false
	}
	dataDir = strings.TrimSpace(dataDir)
	if dataDir == "" {
		return true
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return true
	}
	dataAbs, err := filepath.Abs(dataDir)
	if err != nil {
		return true
	}
	rootAbs = filepath.Clean(rootAbs)
	dataAbs = filepath.Clean(dataAbs)
	if realRoot, err := filepath.EvalSymlinks(rootAbs); err == nil {
		rootAbs = filepath.Clean(realRoot)
	}
	if realData, err := filepath.EvalSymlinks(dataAbs); err == nil {
		dataAbs = filepath.Clean(realData)
	}
	rel, err := filepath.Rel(dataAbs, rootAbs)
	if err != nil {
		return true
	}
	return rel != "." && (rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)))
}

func homePath(parts ...string) string {
	home := strings.TrimSpace(userHomeDir())
	if home == "" {
		if h, err := os.UserHomeDir(); err == nil {
			home = strings.TrimSpace(h)
		}
	}
	all := append([]string{home}, parts...)
	return filepath.Join(all...)
}

func unsupportedSurface(note string) SurfaceCapability {
	cap := SurfaceCapability{Supported: false}
	if strings.TrimSpace(note) != "" {
		cap.Notes = []string{note}
	}
	return cap
}

// pluginsAreOpenClawOnly is the canonical "Plugins is an OpenClaw-only
// capability" surface. Hook-only connectors (hermes, cursor, windsurf,
// geminicli, copilot, openhands) advertise it so the TUI Plugins panel and the
// `defenseclaw plugin list` CLI both have a single, consistent message
// to surface to operators rather than silently doing nothing — or
// worse, doing something that LOOKS connector-aware but ignores the
// connector's actual extension model. The note is short on purpose:
// the renderer typically shows it under a "DefenseClaw plugins are
// OpenClaw-only" banner.
func pluginsAreOpenClawOnly() SurfaceCapability {
	return SurfaceCapability{
		Supported: false,
		Notes:     []string{"DefenseClaw plugins are an OpenClaw-only concept; this connector ships no plugin install surface."},
	}
}

func cursorSkillPaths(opts SetupOpts) []string {
	return []string{
		homePath(".cursor", "skills"),
		homePath(".agents", "skills"),
		workspacePath(opts, ".cursor", "skills"),
		workspacePath(opts, ".agents", "skills"),
	}
}

func openhandsSkillPaths(opts SetupOpts) []string {
	paths := []string{}
	if root := selectedWorkspaceRoot(OpenHandsWorkspaceDirOverride, opts.WorkspaceDir); root != "" && workspaceRootOutsideDataDir(root, opts.DataDir) {
		paths = append(paths,
			filepath.Join(root, ".agents", "skills"),
			filepath.Join(root, ".openhands", "skills"),
			filepath.Join(root, ".openhands", "microagents"),
		)
	}
	paths = append(paths,
		homePath(".agents", "skills"),
		homePath(".openhands", "skills"),
		homePath(".openhands", "microagents"),
		homePath(".openhands", "skills", "installed"),
		homePath(".openhands", "cache", "skills", "public-skills", "skills"),
	)
	return uniqueNonEmptyStrings(paths)
}

func antigravityMCPPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".gemini", "config", "mcp_config.json"),
		antigravityWorkspacePath(opts, ".agents", "mcp_config.json"),
	})
}

func antigravitySkillReadPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings(append(antigravitySkillWritePaths(opts),
		homePath(".gemini", "antigravity-cli", "skills"),
		antigravityWorkspacePath(opts, ".agent", "skills"),
	))
}

func antigravitySkillWritePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".gemini", "config", "skills"),
		antigravityWorkspacePath(opts, ".agents", "skills"),
	})
}

func antigravityRuleReadPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".gemini", "GEMINI.md"),
		antigravityWorkspacePath(opts, ".agents", "rules"),
	})
}

func antigravityPluginPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".gemini", "config", "plugins"),
		homePath(".gemini", "antigravity-cli", "plugins"),
		antigravityWorkspacePath(opts, ".agents", "plugins"),
		antigravityWorkspacePath(opts, "_agents", "plugins"),
	})
}

func antigravityWorkspacePath(opts SetupOpts, parts ...string) string {
	root := strings.TrimSpace(opts.WorkspaceDir)
	if root == "" {
		return ""
	}
	all := append([]string{root}, parts...)
	return filepath.Join(all...)
}

func windsurfMCPPaths() []string {
	return []string{
		homePath(".codeium", "windsurf", "mcp_config.json"),
		homePath(".codeium", "windsurf", "mcp.json"),
	}
}

func existingWindsurfRulePaths(opts SetupOpts) []string {
	root := workspaceRoot(opts)
	if strings.TrimSpace(root) == "" {
		return nil
	}
	candidates := []string{
		filepath.Join(root, ".windsurf", "rules"),
		filepath.Join(root, ".codeium", "windsurf", "rules"),
	}
	out := make([]string, 0, len(candidates))
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func uniqueNonEmptyStrings(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func addSurfaceTargets(targets map[string][]string, key string, cap SurfaceCapability) {
	if !cap.Supported {
		return
	}
	targets[key] = uniqueNonEmptyStrings(append(append([]string{}, cap.ReadPaths...), cap.ConfigPaths...))
}

func patchHermesHooks(path, hookScript string) error {
	cfg, err := readYAMLObject(path)
	if err != nil {
		return err
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		cfg["hooks"] = hooks
	}
	// Hermes prompts for per-(event, command) consent the first time it
	// sees a shell hook and persists the decision to
	// ~/.hermes/shell-hooks-allowlist.json. On non-TTY runs (the gateway
	// daemon, cron, CI) there is no prompt, so an un-accepted hook is
	// silently skipped and never fires. hooks_auto_accept is the
	// documented escape hatch that lets all of DefenseClaw's lifecycle
	// hooks register without an interactive prompt. We only set it when
	// the operator has not made an explicit choice, so a deliberate
	// `hooks_auto_accept: false` is preserved (and surfaced by doctor).
	// The managed-file backup captures and heals this key on teardown.
	if _, ok := cfg["hooks_auto_accept"]; !ok {
		cfg["hooks_auto_accept"] = true
	}
	for _, spec := range []struct {
		event   string
		matcher string
	}{
		{"pre_tool_call", ".*"},
		{"post_tool_call", ".*"},
		{"pre_llm_call", ""},
		{"post_llm_call", ""},
		{"on_session_start", ""},
		{"on_session_end", ""},
		{"on_session_finalize", ""},
		{"on_session_reset", ""},
		{"subagent_start", ""},
		{"subagent_stop", ""},
	} {
		entry := map[string]interface{}{
			"command": shellWord(hookScript),
			"timeout": 30,
		}
		if spec.matcher != "" {
			entry["matcher"] = spec.matcher
		}
		hooks[spec.event] = appendUniqueFlatHook(hooks[spec.event], hookScript, entry)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func removeHermesHooks(path, hookScript string) error {
	cfg, err := readYAMLObject(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
		for event, raw := range hooks {
			hooks[event] = removeOwnedFlatHooks(raw, hookScript)
		}
		pruneEmptyMapArrays(hooks)
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func patchCursorHooks(path, hookScript string, failClosed bool) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	cfg["version"] = 1
	for _, event := range []string{
		"sessionStart",
		"sessionEnd",
		"preToolUse",
		"postToolUse",
		"postToolUseFailure",
		"subagentStart",
		"subagentStop",
		"beforeShellExecution",
		"beforeMCPExecution",
		"afterShellExecution",
		"afterMCPExecution",
		"beforeReadFile",
		"beforeTabFileRead",
		"afterFileEdit",
		"afterTabFileEdit",
		"beforeSubmitPrompt",
		"afterAgentResponse",
		"afterAgentThought",
		"stop",
		"preCompact",
		"workspaceOpen",
	} {
		entry := map[string]interface{}{
			"type":       "command",
			"command":    shellWord(hookScript),
			"timeout":    30000,
			"failClosed": failClosed,
		}
		hooks[event] = appendUniqueFlatHook(hooks[event], hookScript, entry)
	}
	return writeJSONObject(path, cfg)
}

func patchWindsurfHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	for _, event := range []string{
		"pre_read_code",
		"post_read_code",
		"pre_write_code",
		"post_write_code",
		"pre_run_command",
		"post_run_command",
		"pre_mcp_tool_use",
		"post_mcp_tool_use",
		"pre_user_prompt",
		"post_cascade_response",
		"post_cascade_response_with_transcript",
		"post_setup_worktree",
	} {
		entry := map[string]interface{}{
			"command":     shellWord(hookScript),
			"show_output": true,
		}
		hooks[event] = appendUniqueFlatHook(hooks[event], hookScript, entry)
	}
	return writeJSONObject(path, cfg)
}

func patchGeminiHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	for _, event := range []string{
		"SessionStart",
		"SessionEnd",
		"BeforeAgent",
		"AfterAgent",
		"BeforeModel",
		"AfterModel",
		"BeforeToolSelection",
		"BeforeTool",
		"AfterTool",
		"PreCompress",
		"Notification",
	} {
		group := map[string]interface{}{
			"matcher": "*",
			"hooks": []interface{}{
				map[string]interface{}{
					"name":        "defenseclaw",
					"type":        "command",
					"command":     shellWord(hookScript),
					"timeout":     30000,
					"description": "DefenseClaw hook inspection",
				},
			},
		}
		hooks[event] = appendUniqueGeminiHookGroup(hooks[event], hookScript, group)
	}
	return writeJSONObject(path, cfg)
}

// patchGeminiTelemetry rewrites Gemini's settings.json to point its OTLP
// exporter at the local DefenseClaw gateway. Gemini's exporter cannot
// set arbitrary HTTP headers, so we authenticate via a path-token
// segment that the gateway's tokenAuth middleware accepts only for
// loopback callers (see parseOTLPPathToken + tokenAuth in api.go).
//
// SECURITY: the token embedded in the URL is now a per-connector scoped
// OTLP path-token, NOT the master gateway bearer.
//
//   - The scoped token is minted by EnsureOTLPPathToken() and stored
//     in ${data_dir}/hooks/.otlp-geminicli.token at 0o600.
//   - tokenAuth accepts it ONLY on /otlp/<source>/<token>/v1/<signal>
//     paths and ONLY for loopback callers, so a process that reads
//     ~/.gemini/settings.json cannot replay it against /api/v1/* or
//     against any other connector's OTLP namespace.
//   - sanitizeRouteForTelemetry continues to strip the token segment
//     from any OTel metric / span attribute the gateway exports.
//   - apiCSRFProtect continues to require an OTLP Content-Type for
//     path-token POSTs so a browser CSRF cannot smuggle a non-OTLP
//     payload.
//
// Setup fails loud if the scoped token cannot be minted. We never write
// the master gateway bearer into settings.json: that file is connector-
// readable configuration, and leaking it must not grant /api/v1/*
// authority or cross-namespace OTLP access.
func patchGeminiTelemetry(path string, opts SetupOpts) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	pathToken := ""
	if opts.DataDir != "" {
		if tok, mintErr := EnsureOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); mintErr == nil {
			pathToken = tok
		} else {
			return fmt.Errorf("mint scoped Gemini CLI OTLP token: %w", mintErr)
		}
	}
	if pathToken == "" {
		return fmt.Errorf("mint scoped Gemini CLI OTLP token: data dir is required")
	}
	telemetry := ensureJSONObject(cfg, "telemetry")

	// Spec-driven: drive the telemetry block from the connector's
	// NativeOTLPSpec via spec.JSONBlock(). The spec emits the same
	// shape Gemini CLI's settings.json schema requires
	// (https://geminicli.com/docs/reference/configuration/):
	// enabled/target/useCollector/otlpEndpoint/otlpProtocol/logPrompts.
	//
	// We always override spec.PathToken with the canonical token
	// just resolved above, so the disk-write path is the single
	// source of truth for which token is embedded (the spec's
	// best-effort lookup may have raced with another sidecar mint).
	//
	// Legacy keys "managedBy" and "protocol" are unrecognized by
	// the current Gemini schema and would crash `gemini` startup
	// if a stale settings.json is upgraded in place, so we delete
	// them unconditionally — that is also how
	// removeManagedGeminiTelemetry detects DefenseClaw-managed
	// blocks for teardown (it keys on the path-scoped endpoint URL
	// containing "/otlp/geminicli/").
	spec := geminiCLINativeOTLPSpec(opts)
	if spec == nil {
		return fmt.Errorf("geminicli: nil NativeOTLPSpec")
	}
	spec.PathToken = pathToken
	block, err := spec.JSONBlock()
	if err != nil {
		return fmt.Errorf("geminicli: render OTLP block: %w", err)
	}
	for k, v := range block {
		telemetry[k] = v
	}
	delete(telemetry, "managedBy")
	delete(telemetry, "protocol")
	return writeJSONObject(path, cfg)
}

func patchCopilotHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	cfg["version"] = 1
	for _, event := range []string{
		"sessionStart",
		"sessionEnd",
		"userPromptSubmitted",
		"preToolUse",
		"postToolUse",
		"postToolUseFailure",
		"permissionRequest",
		"agentStop",
		"subagentStart",
		"subagentStop",
		"errorOccurred",
		"preCompact",
		"notification",
	} {
		entry := map[string]interface{}{
			"type":       "command",
			"timeoutSec": 30,
		}
		if runtime.GOOS == "windows" {
			// Copilot selects the command field by host OS. A `bash`-only
			// entry is ignored on Windows even when its value names a native
			// executable. PowerShell requires the call operator before a quoted
			// executable path, otherwise the path is parsed as a string literal.
			entry["powershell"] = "& " + hookScript
		} else {
			entry["bash"] = shellWord(hookScript)
		}
		hooks[event] = appendUniqueFlatHook(hooks[event], hookScript, entry)
	}
	return writeJSONObject(path, cfg)
}

func patchOpenHandsHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	for _, spec := range []struct {
		event   string
		matcher string
	}{
		{"pre_tool_use", "*"},
		{"post_tool_use", "*"},
		{"user_prompt_submit", "*"},
		{"stop", "*"},
		{"session_start", "*"},
		{"session_end", "*"},
	} {
		group := map[string]interface{}{
			"matcher": spec.matcher,
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": shellWord(hookScript),
					"timeout": 60,
				},
			},
		}
		cfg[spec.event] = appendUniqueGeminiHookGroup(cfg[spec.event], hookScript, group)
	}
	return writeJSONObject(path, cfg)
}

// antigravityLifecycleEvents is the canonical Antigravity 2.0 hook
// lifecycle event list per the published spec:
//
//	PreInvocation  — before the agent calls the LLM
//	PreToolUse     — before a tool executes
//	PostToolUse    — after a tool completes
//	PostInvocation — after the LLM call + tool calls finish
//	Stop           — when the agent loop is about to terminate
//
// Order is the spec's documented lifecycle order so the on-disk
// hooks.json is human-readable in chronological sequence — useful
// when operators are debugging which hooks fired in what order
// against the gateway log.
//
// All five events are registered together to deliver Antigravity
// 2.0 spec parity. Per the spec the events are official, stable
// names; agy v1.0.x may not yet emit every event at runtime
// (PreToolUse is empirically verified; the others are gated on
// upstream agy implementation parity with the published spec),
// but registering all five in hooks.json is still correct: when
// agy starts emitting a previously-quiet event, DefenseClaw
// handles it with zero redeploy. The forward-compat decoder /
// respond branches in antigravity_hook_profile.go and
// hook_only_profile.go are the runtime side of this guarantee.
//
// Tracking gap: if empirical testing reveals agy v1.0.x rejects
// hooks.json on unknown event keys (rather than silently ignoring
// them), narrow this list to the verified-emitting subset and
// keep the code branches in place for a future agy version. As of
// the spec publication, agy is documented to share its hooks.json
// schema with Claude Code, which tolerates unknown event keys.
var antigravityLifecycleEvents = []string{
	"PreInvocation",
	"PreToolUse",
	"PostToolUse",
	"PostInvocation",
	"Stop",
}

// patchAntigravityHooks writes Antigravity's hooks.json in the
// Claude-Code-compatible nested schema agy v1.0.x actually evaluates:
//
//	{
//	  "defenseclaw-antigravity-preinvocation":  { "PreInvocation":  [...] },
//	  "defenseclaw-antigravity-pretooluse":     { "PreToolUse":     [...] },
//	  "defenseclaw-antigravity-posttooluse":    { "PostToolUse":    [...] },
//	  "defenseclaw-antigravity-postinvocation": { "PostInvocation": [...] },
//	  "defenseclaw-antigravity-stop":           { "Stop":           [...] }
//	}
//
// where each per-event value follows agy's Claude-Code-derived
// shape:
//
//	{
//	  "<EventName>": [
//	    {
//	      "matcher": "*",
//	      "hooks": [
//	        { "type": "command", "command": "/abs/path/antigravity-hook.sh" }
//	      ]
//	    }
//	  ]
//	}
//
// Each outer key ("defenseclaw-antigravity-<event>") is a stable,
// DefenseClaw-owned identifier that scopes ownership for re-setup
// idempotence and for teardown — operators / other tools writing
// to the same hooks.json file under their own keys are not
// disturbed.
//
// This shape was determined empirically for PreToolUse:
//   - During the v0.5.0 smoke test, an earlier flat schema
//     ({event, matcher, command, description}) was ignored entirely
//     by agy — no tracer fires, no agy log lines, nothing.
//   - Replacing the file with a Claude-Code-nested schema at
//     ~/.gemini/config/hooks.json caused agy to invoke the
//     configured command on every tool call, with the canonical
//     PreToolUse payload {toolCall: {name, args}, conversationId,
//     stepIdx, transcriptPath, ...} (decoded by
//     antigravityProfileDecode in antigravity_hook_profile.go).
//
// PreInvocation, PostToolUse, PostInvocation, and Stop reuse the
// same nested schema per the Antigravity 2.0 spec, which inherits
// the hooks.json structure from Claude Code wholesale. agy's
// parser is documented to tolerate unknown event keys (it merges
// every discovered hooks.json file and dispatches by event name);
// if empirical testing reveals it rejects unknown events instead,
// scope antigravityLifecycleEvents to the verified-emitting
// subset.
//
// The "command" field is written WITHOUT shellWord() quoting. agy v1.0.x
// tokenizes the command itself and passes quote characters through to direct
// exec, so shell quoting becomes literal path bytes and the hook silently
// no-fires (verified empirically via the v0.5.0 Antigravity smoke test). On
// Unix hookScript is the bare absolute .sh path. On Windows it is the PATH-
// resolved `defenseclaw-gateway.exe hook --connector antigravity` command;
// using the stable executable name avoids an unquotable absolute install path
// containing spaces while retaining the native Go hook path.
func patchAntigravityHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	for _, event := range antigravityLifecycleEvents {
		key := "defenseclaw-antigravity-" + strings.ToLower(event)
		cfg[key] = map[string]interface{}{
			event: []interface{}{
				map[string]interface{}{
					"matcher": "*",
					"hooks": []interface{}{
						map[string]interface{}{
							"type":    "command",
							"command": hookScript,
						},
					},
				},
			},
		}
	}
	return writeJSONObject(path, cfg)
}

func readYAMLObject(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	var out map[string]interface{}
	if err := yaml.Unmarshal(data, &out); err != nil {
		return nil, fmt.Errorf("parse YAML %s: %w", path, err)
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out, nil
}

func readJSONObject(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	var out map[string]interface{}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse JSON %s: %w", path, err)
	}
	if out == nil {
		out = map[string]interface{}{}
	}
	return out, nil
}

func writeJSONObject(path string, cfg map[string]interface{}) error {
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

func ensureJSONObject(obj map[string]interface{}, key string) map[string]interface{} {
	child, _ := obj[key].(map[string]interface{})
	if child == nil {
		child = map[string]interface{}{}
		obj[key] = child
	}
	return child
}

func appendUniqueFlatHook(raw interface{}, hookScript string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	for _, item := range list {
		if containsHookScript(item, hookScript) {
			return list
		}
	}
	return append(list, entry)
}

func appendUniqueGeminiHookGroup(raw interface{}, hookScript string, group map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	for _, item := range list {
		if containsHookScript(item, hookScript) {
			return list
		}
	}
	return append(list, group)
}

func removeJSONHookReferences(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	pruned, _ := removeHookScriptReferences(cfg, hookScript).(map[string]interface{})
	if pruned == nil {
		pruned = map[string]interface{}{}
	}
	return writeJSONObject(path, pruned)
}

func removeGeminiConfigEntries(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	pruned, _ := removeHookScriptReferences(cfg, hookScript).(map[string]interface{})
	if pruned == nil {
		pruned = map[string]interface{}{}
	}
	removeManagedGeminiTelemetry(pruned)
	return writeJSONObject(path, pruned)
}

func removeManagedGeminiTelemetry(cfg map[string]interface{}) {
	telemetry, ok := cfg["telemetry"].(map[string]interface{})
	if !ok {
		return
	}
	// Detect both current and legacy DefenseClaw-managed telemetry:
	//   - current: endpoint contains "/otlp/geminicli/<token>"
	//   - legacy:  managedBy == "defenseclaw" (pre-schema-fix installs)
	// Either signal is unique enough to attribute ownership safely.
	managedBy, _ := telemetry["managedBy"].(string)
	endpoint, _ := telemetry["otlpEndpoint"].(string)
	if !strings.EqualFold(strings.TrimSpace(managedBy), "defenseclaw") && !strings.Contains(endpoint, "/otlp/geminicli/") {
		return
	}
	// Delete both the current schema keys and the legacy keys
	// ("protocol", "managedBy") so an upgrade from an older
	// defenseclaw install also leaves a clean settings.json.
	for _, key := range []string{
		"enabled",
		"target",
		"otlpEndpoint",
		"otlpProtocol",
		"useCollector",
		"logPrompts",
		// legacy keys, harmless if absent
		"protocol",
		"managedBy",
	} {
		delete(telemetry, key)
	}
	if len(telemetry) == 0 {
		delete(cfg, "telemetry")
	}
}

func removeHookScriptReferences(raw interface{}, hookScript string) interface{} {
	switch v := raw.(type) {
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			if containsHookScript(item, hookScript) {
				continue
			}
			out = append(out, removeHookScriptReferences(item, hookScript))
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, value := range v {
			out[key] = removeHookScriptReferences(value, hookScript)
		}
		pruneEmptyMapArrays(out)
		return out
	default:
		return raw
	}
}

func removeOwnedFlatHooks(raw interface{}, hookScript string) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list))
	for _, item := range list {
		if containsHookScript(item, hookScript) {
			continue
		}
		out = append(out, item)
	}
	return out
}

func pruneEmptyMapArrays(obj map[string]interface{}) {
	for key, value := range obj {
		switch v := value.(type) {
		case []interface{}:
			if len(v) == 0 {
				delete(obj, key)
			}
		case map[string]interface{}:
			pruneEmptyMapArrays(v)
			if len(v) == 0 {
				delete(obj, key)
			}
		}
	}
}

func containsHookScript(raw interface{}, hookScript string) bool {
	switch v := raw.(type) {
	case string:
		return strings.Contains(v, hookScript) || strings.Contains(v, filepath.Base(hookScript))
	case []interface{}:
		for _, item := range v {
			if containsHookScript(item, hookScript) {
				return true
			}
		}
	case map[string]interface{}:
		for _, item := range v {
			if containsHookScript(item, hookScript) {
				return true
			}
		}
	}
	return false
}

func shellWord(s string) string {
	if s == "" {
		return "''"
	}
	// Native Go hook commands (Windows) are already a complete, correctly
	// quoted command line (`"<exe>" hook --connector <name>`). bash-style
	// single-quoting would corrupt the executable path and break invocation,
	// so pass these through unchanged. Unix .sh paths still get quoted.
	if isNativeHookCommand(s) {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
