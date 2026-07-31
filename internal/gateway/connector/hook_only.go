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
					"subagentStart",
					"beforeShellExecution",
					"beforeMCPExecution",
					"beforeReadFile",
					"beforeTabFileRead",
					"beforeSubmitPrompt",
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
		description: "Devin Desktop Cascade hooks with MCP, skills, rules, and instructions",
		apiPath:     "/api/v1/windsurf/hook",
		scriptName:  "windsurf-hook.sh",
		configPath:  windsurfHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         windsurfHooksPath(opts),
			}
		},
	}
}

func NewGeminiCLIConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "geminicli",
		description: "enterprise/Cloud/paid-key settings.json hooks with native OTLP, MCP, skills, extensions, and agents",
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
			blockEvents := []string{
				"preToolUse",
				"permissionRequest",
				"agentStop",
				"subagentStop",
			}
			// Preserve the accepted PR #655 Windows/v1 capability surface.
			if runtime.GOOS == "windows" || versionInRange(NormalizeAgentVersion("copilot", opts.AgentVersion), "1.0.18", "1.0.76") {
				blockEvents = append(blockEvents, "postToolUseFailure")
			}
			return HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents:    []string{"preToolUse"},
				BlockEvents: []string{
					"preToolUse",
					"permissionRequest",
					"agentStop",
					"subagentStop",
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

// NewAntigravityConnector wires Google's Antigravity (`agy`) CLI through the
// unified hook collector. agy reads global hooks from
// ~/.gemini/config/hooks.json. PreToolUse and PostToolUse use matcher groups;
// PreInvocation, PostInvocation, and Stop use direct command-handler lists.
// PreToolUse supports documented allow/deny/ask/force_ask decisions.
//
// Scope is intentionally "user" only. Antigravity also discovers
// <workspace>/.agents/hooks.json, but Setup owns only the global file so the
// registration is deterministic and is not duplicated per workspace.
func NewAntigravityConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "antigravity",
		description: "Antigravity (agy) lifecycle hooks with synchronous PreToolUse ask/deny decisions",
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

func (c *hookOnlyConnector) Name() string        { return c.name }
func (c *hookOnlyConnector) Description() string { return c.description }
func (c *hookOnlyConnector) HookAPIPath() string { return c.apiPath }
func (c *hookOnlyConnector) ToolInspectionMode() ToolInspectionMode {
	if c.name == "antigravity" {
		// Antigravity's PostToolUse input contains only lifecycle metadata
		// (stepIdx and optional error), not tool-result content. DefenseClaw
		// therefore claims inspection only at the documented PreToolUse gate.
		return ToolModePreExecution
	}
	return ToolModeBoth
}
func (c *hookOnlyConnector) SubprocessPolicy() SubprocessPolicy { return SubprocessNone }
func (c *hookOnlyConnector) HookScriptNames(SetupOpts) []string {
	if c.pluginArtifact {
		return nil
	}
	// Cursor and Windsurf require connector-specific PowerShell adapters only
	// for their native Windows transports. Unix and macOS continue to use the
	// existing shell hooks.
	if runtime.GOOS == "windows" {
		switch c.name {
		case "cursor":
			return []string{c.scriptName, "cursor-hook.ps1"}
		case "windsurf":
			return []string{c.scriptName, "windsurf-hook.ps1"}
		}
	}
	return []string{c.scriptName}
}
func (c *hookOnlyConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return c.Capabilities(opts).Hooks
}

// HookProfile implements HookProfileProvider for the generic hook-only
// connectors. Today only geminicli has a DefenseClaw-integrated native OTLP
// path (via the JSON-block telemetry section in settings.json with a scoped
// path-token). Copilot upstream documents an optional OTel exporter, but
// DefenseClaw does not configure or certify that surface; its profile remains
// hook-only until a scoped-auth, custody, correlation, and teardown contract
// is implemented. Cursor, Windsurf, Hermes, and OpenHands likewise return
// spec=nil. A future reviewed integration can return a non-nil spec without
// changing the dispatcher.
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
	if c.name == "hermes" {
		// Hermes pre_verify is a bounded-control surface, not a blocking
		// surface. Keep it out of BlockEvents while allowing its documented
		// synchronous {"action":"continue"} response to reach the responder.
		profile.MapVerdict = hermesProfileMapVerdict
	}
	if c.name == "geminicli" {
		profile.NativeOTLP = geminiCLINativeOTLPSpec(opts)
	}
	if c.name == "openhands" {
		profile.NativeOTLP = openhandsNativeOTLPSpec(opts)
	}
	if c.name == "antigravity" {
		// Antigravity's documented stdin is camelCase and intentionally omits
		// the event name. Setup binds each handler to a distinct --event
		// argument; the bridge forwards that trusted registration metadata in
		// a header and the unified HTTP handler injects it before this decoder.
		// See antigravity_hook_profile.go for the exact official field mapping.
		profile.Decode = antigravityProfileDecode
	}
	if c.name == "cursor" {
		profile.Decode = cursorProfileDecode
	}
	if c.name == "windsurf" {
		profile.Decode = windsurfProfileDecode
	}
	// NOTE: hermes needs no Decode override. Its nested `extra` content
	// is recovered by the generic decoder's ContentEnvelopeKey fallback
	// (declared on the hermes hook contract), and its wire replies are
	// shaped by the hermes case in hookOnlyProfileRespond.
	return ApplyHookContract(profile, opts)
}

// Cursor documents generation_id as the identifier for one user-message
// generation. Keep that connector-native turn mapping out of the generic
// decoder so another connector's generation identifier cannot become a turn.
func cursorProfileDecode(payload map[string]interface{}) HookProfileRequest {
	return HookProfileRequest{
		ConnectorName: "cursor",
		HookEventName: hookFirstString(payload,
			"hook_event_name", "hookEventName",
			"event_type", "eventType",
			"event_name", "eventName",
			"agent_action_name",
		),
		TurnID: hookFirstString(payload,
			"generation_id", "generationId",
			"turn_id", "turnId", "turnID",
		),
		Payload: payload,
	}
}

// Windsurf documents execution_id as one Cascade agent turn. This is a
// connector-scoped semantic mapping, not a generic execution-to-turn alias.
func windsurfProfileDecode(payload map[string]interface{}) HookProfileRequest {
	return HookProfileRequest{
		ConnectorName: "windsurf",
		HookEventName: hookFirstString(payload,
			"hook_event_name", "hookEventName",
			"event_type", "eventType",
			"event_name", "eventName",
			"agent_action_name",
		),
		TurnID: hookFirstString(payload,
			"execution_id", "executionId",
			"turn_id", "turnId", "turnID",
		),
		Payload: payload,
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
		Kind:      NativeOTLPJSONBlock,
		Endpoint:  "http://" + strings.TrimSpace(opts.APIAddr),
		Protocol:  "http",
		PathScope: OTLPScopeGeminiCLI,
		// Native source capture must remain full-fidelity. Central v8 routing
		// applies the selected redaction profile to each destination copy.
		LogUserPrompts: true,
	}
	// Best-effort: mint or load the scoped token here so the spec
	// can render its endpoint deterministically. patchGeminiTelemetry
	// runs the same EnsureOTLPPathToken call before serializing the
	// block; this duplicates the cheap lookup so callers that only
	// want the descriptive spec (parity tests, doctor reports) see
	// the resolved URL.
	if opts.DataDir != "" || strings.TrimSpace(opts.OTLPPathToken) != "" {
		if tok, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI, opts.OTLPPathToken); err == nil && tok != "" {
			spec.PathToken = tok
		}
	}
	return spec
}

// openhandsNativeOTLPSpec describes the process environment consumed by the
// OpenHands SDK observability contract, source-reviewed through standalone SDK
// 1.39.1. OpenHands CLI 1.16.0 remains a separate compatibility axis and
// bundles SDK 1.21.0. Both initialize Laminar when an OTEL endpoint is present
// and export traces only. No OpenHands config file or shell profile is mutated.
func openhandsNativeOTLPSpec(opts SetupOpts) *NativeOTLPSpec {
	endpoint := "http://" + strings.TrimSpace(opts.APIAddr)
	headers := map[string]string{
		"x-defenseclaw-source": "openhands",
		"x-defenseclaw-client": "openhands-otel/1.0",
	}
	if token, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeOpenHands, opts.OTLPPathToken); err == nil && token != "" {
		headers["authorization"] = "Bearer " + token
	}
	traceHeaders := serializeOTLPHeaders(headers)
	return &NativeOTLPSpec{
		Kind:        NativeOTLPEnvBlock,
		Endpoint:    endpoint,
		Protocol:    "http/protobuf",
		Headers:     headers,
		PerSignal:   false,
		ServiceName: "openhands",
		ResourceAttributes: map[string]string{
			"defenseclaw.connector": "openhands",
		},
		ExtraEnv: map[string]string{
			"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT": endpoint + "/v1/traces",
			"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL": "http/protobuf",
			"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  traceHeaders,
			"OTEL_TRACES_EXPORTER":               "otlp",
			"OTEL_METRICS_EXPORTER":              "none",
			"OTEL_LOGS_EXPORTER":                 "none",
		},
	}
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
	case "opencode":
		if runtime.GOOS == "windows" {
			// Preserve PR #655's Windows component boundary. The managed
			// bridge plugin still has its explicit Setup destination, but
			// generic inventory/watchers must not create unproven OpenCode
			// skill, plugin, agent, rule, or MCP paths around it.
			caps.MCP = unsupportedSurface("OpenCode MCP component management is not supported on Windows.")
			caps.Skills = unsupportedSurface("OpenCode skill paths are not supported on Windows.")
			caps.Rules = unsupportedSurface("OpenCode rule paths are not supported on Windows.")
			caps.Plugins = unsupportedSurface("OpenCode plugin inventory paths are not supported on Windows.")
			caps.Agents = unsupportedSurface("OpenCode agent paths are not supported on Windows.")
			break
		}
		configDir := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR"))
		if configDir == "" {
			configDir = homePath(".config", "opencode")
		}
		projectConfigPaths := []string{}
		projectRulePaths := []string{}
		workspaceRoot := strings.TrimSpace(opts.WorkspaceDir)
		projectStop := workspaceRoot
		for probe := workspaceRoot; probe != ""; {
			if _, err := os.Stat(filepath.Join(probe, ".git")); err == nil {
				projectStop = probe
				break
			}
			parent := filepath.Dir(probe)
			if parent == probe {
				break
			}
			probe = parent
		}
		for root := workspaceRoot; root != ""; {
			projectConfigPaths = append(projectConfigPaths,
				filepath.Join(root, "opencode.json"),
				filepath.Join(root, "opencode.jsonc"),
				filepath.Join(root, ".opencode", "opencode.json"),
				filepath.Join(root, ".opencode", "opencode.jsonc"),
			)
			projectRulePaths = append(projectRulePaths,
				filepath.Join(root, "AGENTS.md"),
				filepath.Join(root, "CLAUDE.md"),
			)
			if root == projectStop {
				break
			}
			parent := filepath.Dir(root)
			if parent == root {
				break
			}
			root = parent
		}
		configPaths := []string{
			filepath.Join(configDir, "opencode.json"),
			filepath.Join(configDir, "opencode.jsonc"),
			strings.TrimSpace(os.Getenv("OPENCODE_CONFIG")),
		}
		configPaths = append(configPaths, projectConfigPaths...)
		configPaths = uniqueNonEmptyStrings(configPaths)
		caps.MCP = SurfaceCapability{
			Supported: true, Scope: "workspace,user", ConfigPaths: configPaths,
			WritePaths:     []string{filepath.Join(configDir, "opencode.json"), workspacePath(opts, "opencode.json")},
			SupportsBackup: true, SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported: true, Scope: "workspace,user",
			ReadPaths: []string{
				filepath.Join(configDir, "skills"), homePath(".claude", "skills"), homePath(".agents", "skills"),
				workspacePath(opts, ".opencode", "skills"), workspacePath(opts, ".claude", "skills"), workspacePath(opts, ".agents", "skills"),
			},
			WritePaths:     []string{filepath.Join(configDir, "skills"), workspacePath(opts, ".opencode", "skills")},
			InstallTargets: []string{"skill"}, RequiresOptIn: true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Rules = SurfaceCapability{
			Supported: true, Scope: "workspace,user", DiscoveryOnly: true,
			ReadPaths: uniqueNonEmptyStrings(append([]string{
				filepath.Join(configDir, "AGENTS.md"),
				filepath.Join(configDir, "CLAUDE.md"),
			}, append(configPaths, projectRulePaths...)...)),
			Notes: []string{"AGENTS.md, CLAUDE.md fallback files, and config instructions are discovery-only; DefenseClaw does not overwrite operator instructions."},
		}
		caps.Plugins = SurfaceCapability{
			Supported: true, Scope: "workspace,user", DiscoveryOnly: true,
			ReadPaths: []string{
				filepath.Join(configDir, "plugin"), filepath.Join(configDir, "plugins"),
				workspacePath(opts, ".opencode", "plugin"), workspacePath(opts, ".opencode", "plugins"),
			},
			Notes: []string{"Third-party plugins are inventory-only; Setup owns only defenseclaw.js with exact backup/restore."},
		}
		caps.Agents = SurfaceCapability{
			Supported: true, Scope: "workspace,user", DiscoveryOnly: true,
			ReadPaths: []string{
				filepath.Join(configDir, "agent"), filepath.Join(configDir, "agents"),
				workspacePath(opts, ".opencode", "agent"), workspacePath(opts, ".opencode", "agents"),
			},
		}
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
			ReadPaths:      hermesSkillReadPaths(),
			WritePaths:     []string{filepath.Join(hermespath.HomeDir(), "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			DiscoveryOnly: true,
			ReadPaths: []string{
				filepath.Join(hermespath.HomeDir(), "plugins"),
				filepath.Join(hermespath.HomeDir(), "agent-hooks"),
				filepath.Join(hermespath.HomeDir(), "hooks"),
				workspacePath(opts, ".hermes", "plugins"),
			},
			Notes: []string{
				"Hermes user/project plugins, conventional shell-hook scripts, and gateway-hook packages are inventory/discovery-only; connector setup does not install or modify them.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			DiscoveryOnly: true,
			ReadPaths:     hermesRuleReadPaths(opts),
			Notes: []string{
				"Hermes context files are prompt-bearing instructions and are scanned read-only. DefenseClaw never installs CodeGuard into SOUL.md or project instruction files.",
			},
		}
		caps.Agents = unsupportedSurface("Hermes subagent/agent asset locations are not installed by DefenseClaw v1.")
		caps.Telemetry.Notes = append(caps.Telemetry.Notes,
			"Hermes 0.19.1 also exposes optional monitoring.export.otlp for content-free gateway-health and diagnostic signals. DefenseClaw does not manage that upstream block; policy-event telemetry remains hook-derived.",
		)
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
			Supported: true,
			Scope:     "workspace",
			ReadPaths: []string{
				workspacePath(opts, ".cursor", "rules"),
				workspacePath(opts, "AGENTS.md"),
				workspacePath(opts, "CLAUDE.md"),
				workspacePath(opts, ".cursorrules"),
			},
			WritePaths:     []string{workspacePath(opts, ".cursor", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes: []string{
				"CLAUDE.md is read by Cursor Agent CLI; .cursorrules remains a deprecated compatibility surface.",
				"Cursor supports nested AGENTS.md files. DefenseClaw v1 inventories the workspace-root instruction files only and does not recursively traverse nested workspaces.",
				"Cursor custom commands under .cursor/commands are an official surface but have no DefenseClaw install/inventory category in v1.",
			},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "user",
			ReadPaths:     []string{homePath(".cursor", "plugins", "local")},
			DiscoveryOnly: true,
			Notes: []string{
				"Cursor local plugins use <plugin>/.cursor-plugin/plugin.json under ~/.cursor/plugins/local.",
				"DefenseClaw inventories existing Cursor plugins only; connector setup does not install, remove, or modify them.",
			},
		}
		caps.Agents = SurfaceCapability{
			Supported: true,
			Scope:     "workspace,user",
			ReadPaths: uniqueNonEmptyStrings([]string{
				workspacePath(opts, ".cursor", "agents"),
				homePath(".cursor", "agents"),
			}),
			DiscoveryOnly: true,
			Notes: []string{
				"Cursor subagents are read from <workspace>/.cursor/agents and ~/.cursor/agents.",
				"DefenseClaw inventories existing Cursor subagents only; connector setup does not install, remove, or modify them.",
			},
		}
	case "windsurf":
		if preserveWindsurfNonDarwinCapabilities(&caps, opts, runtime.GOOS) {
			break
		}
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     windsurfMCPPaths(),
			ReadPaths:       windsurfMCPPaths(),
			WritePaths:      windsurfMCPPaths(),
			InstallTargets:  []string{"mcp"},
			RequiresOptIn:   true,
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"Devin Desktop documents ~/.codeium/windsurf/mcp_config.json as Cascade's MCP configuration file."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      windsurfSkillPaths(opts),
			WritePaths:     windsurfSkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"Cascade also discovers cross-agent skills under .agents/skills and ~/.agents/skills."},
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      windsurfRulePaths(opts),
			WritePaths:     uniqueNonEmptyStrings([]string{workspacePath(opts, ".devin", "rules")}),
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes:          []string{"Devin Desktop prefers .devin/rules, retains .windsurf/rules as a fallback, and discovers AGENTS.md/agents.md as directory-scoped instructions."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.CodeGuard.Notes = append(caps.CodeGuard.Notes, "Devin Desktop Cascade accepts Project CodeGuard as an opt-in skill or rule asset.")
		caps.Plugins = unsupportedSurface("N/A for the Cascade connector: Devin Local plugins are a separate agent surface and Cascade exposes no documented local plugin directory.")
		caps.Agents = unsupportedSurface("N/A for the Cascade connector: Devin Local custom subagents are separate from Cascade and are not installed by the stable windsurf connector.")
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
		copilotPolicyReadPaths := []string{}
		copilotTelemetryConfigPaths := []string{copilotHomePath("settings.json")}
		copilotSkillPaths := []string{copilotHomePath("skills"), homePath(".agents", "skills"), workspacePath(opts, ".github", "skills"), workspacePath(opts, ".agents", "skills"), workspacePath(opts, ".claude", "skills")}
		copilotSkillPaths = append(copilotSkillPaths, copilotEnvPathList("COPILOT_SKILLS_DIRS")...)
		copilotInstructionPaths := []string{copilotHomePath("copilot-instructions.md"), copilotHomePath("instructions"), workspacePath(opts, "AGENTS.md"), workspacePath(opts, "CLAUDE.md"), workspacePath(opts, "GEMINI.md"), workspacePath(opts, ".claude", "CLAUDE.md"), workspacePath(opts, ".github", "copilot-instructions.md"), workspacePath(opts, ".github", "instructions")}
		copilotInstructionPaths = append(copilotInstructionPaths, copilotEnvPathList("COPILOT_CUSTOM_INSTRUCTIONS_DIRS")...)
		if runtime.GOOS == "darwin" {
			copilotPolicyReadPaths = append(
				copilotPolicyReadPaths,
				"/Library/Application Support/GitHubCopilot/managed-settings.json",
				"/etc/github-copilot/policy.d",
			)
			copilotTelemetryConfigPaths = append(
				copilotTelemetryConfigPaths,
				"/Library/Application Support/GitHubCopilot/managed-settings.json",
			)
		}
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     copilotMCPReadPaths(opts),
			WritePaths:      []string{copilotHomePath("mcp-config.json"), workspacePath(opts, ".github", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"Reads declared .mcp.json and .github/mcp.json from the pinned workspace through its Git root, then the Copilot user config. Declaration inventory is independent of folder trust; effective workspace activation requires a trusted folder, or GITHUB_COPILOT_PROMPT_MODE_WORKSPACE_MCP=true in untrusted prompt mode. Session --additional-mcp-config, plugin, built-in, and remote runtime servers require official-client live inspection."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      copilotSkillReadPaths(opts),
			WritePaths:     []string{copilotHomePath("skills"), workspacePath(opts, ".github", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"Reads documented local project, inherited .github, personal, and COPILOT_SKILLS_DIRS sources in Copilot precedence order. Plugin, built-in, and organization/remote skills are not expanded from private caches; plugins are listed separately through Copilot's official read-only command."},
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      append(copilotInstructionPaths, copilotPolicyReadPaths...),
			WritePaths:     []string{workspacePath(opts, ".github", "instructions")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			DiscoveryOnly: true,
			Notes:         []string{"Read-only discovery uses the official `copilot plugins list --kind plugin --json` command; DefenseClaw does not install, enable, disable, or remove Copilot plugins."},
		}
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      copilotAgentReadPaths(opts),
			WritePaths:     []string{copilotHomePath("agents"), workspacePath(opts, ".github", "agents")},
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
			Notes:          []string{"Reads .github/agents and .claude/agents from the pinned workspace through its Git root, then the Copilot user home. Inventory includes the reviewed Copilot CLI 1.0.77 built-in IDs, which cannot be shadowed. Plugin-contributed and remote organization/enterprise agents require official-client live-session inspection; owning plugins are listed separately."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Telemetry = TelemetryCapability{
			HookSignals: []string{"logs", "metrics", "traces"},
			SourceModes: []string{"hook"},
			Notes:       []string{"DefenseClaw derives Copilot telemetry from the documented hook bus. Copilot upstream documents optional OTel traces and metrics, but DefenseClaw does not configure or certify that native surface."},
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
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      antigravityPluginPaths(opts),
			WritePaths:     antigravityPluginWritePaths(opts),
			InstallTargets: []string{"plugin"},
			RequiresOptIn:  true,
			Notes:          []string{"DefenseClaw can scan, install, and remove Antigravity plugins at Google's documented manual global/workspace paths. The Antigravity CLI staging path is discovery-only. Runtime disable remains DefenseClaw policy/advisory state; the connector does not invoke agy plugin disable."},
		}
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user,plugin",
			ReadPaths:     antigravityAgentPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Antigravity agents under ~/.gemini/config/agents, <workspace>/.agents/agents, and <plugin>/agents are discovery-only; DefenseClaw does not install or modify them."},
		}
		caps.CodeGuard.Supported = false
	case "openhands":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     []string{openhandsMCPPath()},
			ReadPaths:       []string{openhandsMCPPath()},
			WritePaths:      []string{openhandsMCPPath()},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"OpenHands MCP servers use <OPENHANDS_PERSISTENCE_DIR>/mcp.json when configured, otherwise ~/.openhands/mcp.json."},
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
			ReadPaths:     openhandsInstructionPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"OpenHands loads AGENTS.md, AGENT.md, CLAUDE.md, GEMINI.md, and .cursorrules case-insensitively as permanent third-party instruction skills; DefenseClaw discovers but never overwrites them."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = unsupportedSurface("N/A for the OpenHands CLI: the SDK accepts plugins programmatically, but CLI 1.16.0 exposes no persistent plugin install/config path for DefenseClaw to manage.")
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      openhandsAgentPaths(opts),
			WritePaths:     openhandsAgentWritePaths(opts),
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
			Notes:          []string{"OpenHands loads file-based subagents from .agents/agents/*.md first and .openhands/agents/*.md as the legacy fallback. Built-in general-purpose/code-explorer/bash-runner agents are runtime-provided and are not filesystem assets; default/explore/bash are deprecated aliases."},
		}
		if runtime.GOOS == "darwin" {
			caps.Telemetry = TelemetryCapability{
				NativeOTLP:    true,
				NativeSignals: []string{"traces"},
				HookSignals:   []string{"logs", "metrics", "traces"},
				Env: []EnvRequirement{
					{Name: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", Scope: EnvScopeProcess, Required: false, Description: "Point OpenHands SDK native traces at the DefenseClaw gateway."},
					{Name: "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", Scope: EnvScopeProcess, Required: false, Description: "Set to http/protobuf for DefenseClaw OTLP trace ingestion."},
					{Name: "OTEL_EXPORTER_OTLP_TRACES_HEADERS", Scope: EnvScopeProcess, Required: false, Description: "Carry the connector-scoped bearer and OpenHands source/client attribution."},
				},
				AuthMode:         "scoped-header-token-loopback",
				EndpointTemplate: "http://" + opts.APIAddr + "/v1/traces",
				SourceModes:      []string{"native", "hook"},
				Notes: []string{
					"OpenHands CLI 1.16.0 bundles SDK 1.21.0; standalone SDK 1.39.1 preserves the same Laminar process-environment OTEL trace-export contract. The SDK review does not change the CLI compatibility range.",
					"DefenseClaw does not persist OTEL variables in OpenHands config or mutate shell profiles; launch OpenHands with the rendered process environment.",
					"Native trace attributes are not claimed as cross-rail identity until a stable exported session attribute is source-documented and live-validated.",
				},
			}
		}
	default:
		caps.MCP = unsupportedSurface("")
		caps.Skills = unsupportedSurface("")
		caps.Rules = unsupportedSurface("")
		caps.Plugins = unsupportedSurface("")
		caps.Agents = unsupportedSurface("")
	}
	return caps
}

func preserveWindsurfNonDarwinCapabilities(caps *ConnectorCapabilities, opts SetupOpts, goos string) bool {
	if goos == "darwin" {
		return false
	}
	caps.MCP = SurfaceCapability{
		Supported:     true,
		Scope:         "user",
		ConfigPaths:   windsurfMCPPaths(),
		ReadPaths:     windsurfMCPPaths(),
		DiscoveryOnly: true,
		RequiresOptIn: true,
		Notes:         []string{"DefenseClaw preserves the existing discovery-only MCP contract outside macOS."},
	}
	caps.Rules = SurfaceCapability{
		Supported:     true,
		Scope:         "workspace",
		ReadPaths:     existingWindsurfRulePaths(opts),
		DiscoveryOnly: true,
		Notes:         []string{"Windsurf rule writes remain deferred outside macOS unless a documented/pre-existing path is present."},
	}
	caps.CodeGuard.Supported = true
	caps.CodeGuard.InstallTargets = []string{"rule"}
	caps.CodeGuard.Notes = append(caps.CodeGuard.Notes, "Windsurf CodeGuard preserves the existing rule-only contract outside macOS.")
	caps.Skills = unsupportedSurface("Windsurf skills remain unsupported outside the native macOS connector.")
	caps.Plugins = pluginsAreOpenClawOnly()
	caps.Agents = unsupportedSurface("Windsurf agent/subagent asset installation is not supported.")
	return true
}

func (c *hookOnlyConnector) Setup(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	if c.pluginArtifact {
		return c.setupPluginArtifact(opts)
	}
	if c.name == "openhands" {
		target := c.configPath(opts)
		if err := c.migrateOpenHandsConfigTarget(opts, target); err != nil {
			return err
		}
		if _, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeOpenHands, opts.OTLPPathToken); err != nil {
			return fmt.Errorf("resolve scoped OpenHands OTLP token: %w", err)
		}
	}
	if err := c.migrateManagedBackup(opts); err != nil {
		return fmt.Errorf("%s managed backup migration: %w", c.name, err)
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

// migrateOpenHandsConfigTarget closes the previous managed ownership cycle
// before switching between the user and workspace hooks.json locations.
func (c *hookOnlyConnector) migrateOpenHandsConfigTarget(opts SetupOpts, target string) error {
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.name, "config"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load previous OpenHands config backup: %w", err)
	}
	oldPath, err := validateManagedFileBackupTarget(backup, c.name, "config", backup.Path)
	if err != nil {
		return fmt.Errorf("validate previous OpenHands config backup: %w", err)
	}
	newPath, err := normalizeManagedTargetPath(target)
	if err != nil {
		return fmt.Errorf("resolve new OpenHands config target: %w", err)
	}
	equal := oldPath == newPath
	if runtime.GOOS == "windows" {
		equal = strings.EqualFold(oldPath, newPath)
	}
	if equal {
		return nil
	}
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", oldPath)
	if err != nil {
		return fmt.Errorf("restore previous OpenHands config target: %w", err)
	}
	if restored {
		return nil
	}
	if err := c.removeConfigEntries(oldPath, c.hookCommand(opts), opts); err != nil {
		return fmt.Errorf("remove previous OpenHands hook entries: %w", err)
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
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
	asset := c.pluginArtifactAsset
	if c.name == "opencode" && runtime.GOOS == "windows" {
		asset = "opencode-plugin-windows.js"
	}
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		return fmt.Errorf("%s read plugin template %s: %w", c.name, asset, err)
	}
	failMode := normalizeHookFailMode(opts.HookFailMode)
	if failMode == "closed" && !c.capability(opts).SupportsFailClosed {
		failMode = "open"
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:  opts.APIAddr,
		APIToken: opts.APIToken,
		FailMode: failMode,
		Managed:  opts.ManagedEnterprise,
	})
	if err != nil {
		return fmt.Errorf("%s render plugin template: %w", c.name, err)
	}
	path := c.configPath(opts)
	if err := prepareOpenCodePluginArtifactDestination(path); err != nil {
		return fmt.Errorf("%s prepare plugin destination: %w", c.name, err)
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
// Unix it is the bundled .sh path. Most Windows connectors use the native
// DefenseClaw `hook` subcommand; Cursor and Windsurf use PowerShell adapters
// for their documented Windows transports. The same value is used at setup,
// teardown, and VerifyClean so the JSON/YAML hook removers (which match on the
// exact command string) recognize the entries DefenseClaw added.
func (c *hookOnlyConnector) hookCommand(opts SetupOpts) string {
	return c.hookCommandForOS(runtime.GOOS, opts)
}

func (c *hookOnlyConnector) hookCommandForOS(goos string, opts SetupOpts) string {
	unixCommand := filepath.Join(opts.DataDir, "hooks", c.scriptName)
	if goos == "windows" && c.name == "hermes" && strings.TrimSpace(opts.HookExecutable) != "" {
		return windowsHermesDirectHookCommand(opts.HookExecutable)
	}
	return hookInvocationCommandFor(goos, c.name, unixCommand)
}

// Teardown restores the host agent's config (or removes our entries when
// restoration is unsafe). Connectors whose hosts are known to retain hook
// paths also receive a disabled tombstone.
//
// Cursor is deliberately different. Its official hook contract says command
// hooks are spawned processes and hooks.json changes auto-reload; it does not
// document a cached hook-process/path lifecycle. After restoring hooks.json we
// therefore remove both Cursor-owned runtime files instead of leaving a POSIX
// tombstone beside the native PowerShell adapter. Other hook-only connectors
// retain the established tombstone behavior because their lifecycle is outside
// this Cursor-specific contract.
//
// Without a tombstone where one is required, a retained host path can hit:
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
	if err := c.migrateManagedBackup(opts); err != nil {
		return fmt.Errorf("%s managed backup migration: %w", c.name, err)
	}
	var errs []string

	logicalName := c.managedBackupLogicalName()
	path := managedFileBackupTargetPath(opts.DataDir, c.name, logicalName, c.configPath(opts))
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, logicalName, path)
	switch {
	case err != nil:
		errs = append(errs, fmt.Sprintf("restore config backup: %v", err))
	case restored:
	case !restored:
		if err := c.removeConfigEntriesWithManagedBackup(
			opts,
			logicalName,
			path,
			c.hookCommand(opts),
		); err != nil {
			errs = append(errs, fmt.Sprintf("remove hook entries: %v", err))
		} else {
			discardManagedFileBackup(opts.DataDir, c.name, logicalName)
		}
	}

	if c.name == "cursor" {
		if err := removeCursorHookArtifacts(opts); err != nil {
			errs = append(errs, fmt.Sprintf("remove Cursor hook artifacts: %v", err))
		}
	} else if err := writeDisabledHookTombstone(opts, c.scriptName, c.name); err != nil {
		errs = append(errs, fmt.Sprintf("disabled hook tombstone: %v", err))
	}
	if c.name == "windsurf" && runtime.GOOS == "windows" {
		if err := writeDisabledPowerShellHookTombstone(opts, "windsurf-hook.ps1", c.name); err != nil {
			errs = append(errs, fmt.Sprintf("disabled PowerShell hook tombstone: %v", err))
		}
	}
	if c.name == "openhands" {
		if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil {
			errs = append(errs, fmt.Sprintf("revoke scoped OpenHands OTLP token: %v", err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s teardown: %s", c.name, strings.Join(errs, "; "))
	}
	return nil
}

// removeCursorHookArtifacts removes only files that still carry the
// DefenseClaw ownership marker. A foreign replacement is retained and turns
// teardown into an actionable error rather than deleting operator data.
func removeCursorHookArtifacts(opts SetupOpts) error {
	var errs []string
	for _, name := range []string{"cursor-hook.sh", "cursor-hook.ps1"} {
		path := filepath.Join(opts.DataDir, "hooks", name)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
			continue
		}
		if !scriptHasMarker(path) {
			errs = append(errs, fmt.Sprintf("%s: refusing to remove file without DefenseClaw ownership marker", name))
			continue
		}
		if err := os.Remove(path); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", name, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
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
	logicalName := c.managedBackupLogicalName()
	path := managedFileBackupTargetPath(opts.DataDir, c.name, logicalName, c.configPath(opts))
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return c.verifyCursorHookArtifactsClean(opts)
		}
		return err
	} else if c.pluginArtifact {
		// The bridge plugin is a standalone managed file; a clean
		// teardown removes it entirely. Any residual DefenseClaw marker
		// means the heal did not complete.
		if bytes.Contains(data, []byte("DefenseClaw")) || bytes.Contains(data, []byte(c.apiPath)) {
			return fmt.Errorf("%s teardown incomplete: managed plugin still present at %s", c.name, path)
		}
		return nil
	}
	if c.name == "cursor" {
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err != nil {
			return fmt.Errorf("%s teardown verification could not parse hook config %s: %w", c.name, path, err)
		}
		if structuredHookCommandReferences(cfg, cursorOwnedHookCommands(opts)) {
			return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
		}
		return c.verifyCursorHookArtifactsClean(opts)
	}
	needle := c.hookCommand(opts)
	if c.name == "copilot" {
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err == nil && containsHookScript(cfg, needle) {
			return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
		}
	}
	if c.name == "windsurf" {
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err == nil &&
			structuredHookCommandReferences(cfg, []string{
				needle,
				legacyWindsurfWindowsHookCommand(),
			}) {
			return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
		}
	}
	if c.name == "antigravity" {
		ownedCommands := antigravityOwnedHookCommands(needle)
		ownedCommands = append(ownedCommands,
			legacyAntigravityWindowsHookCommand(),
			legacyAntigravityNonWaitingWindowsHookCommand(),
		)
		var cfg map[string]interface{}
		if err := json.Unmarshal(data, &cfg); err == nil &&
			structuredHookCommandReferences(cfg, ownedCommands) {
			return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
		}
	}
	if bytes.Contains(data, []byte(needle)) || bytes.Contains(data, []byte(c.scriptName)) ||
		(c.name == "antigravity" && bytes.Contains(data, []byte(legacyAntigravityWindowsHookCommand()))) ||
		(c.name == "antigravity" && bytes.Contains(data, []byte(legacyAntigravityNonWaitingWindowsHookCommand()))) ||
		(c.name == "windsurf" && bytes.Contains(data, []byte(legacyWindsurfWindowsHookCommand()))) {
		return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
	}
	return c.verifyCursorHookArtifactsClean(opts)
}

func (c *hookOnlyConnector) verifyCursorHookArtifactsClean(opts SetupOpts) error {
	if c.name != "cursor" {
		return nil
	}
	for _, name := range []string{"cursor-hook.sh", "cursor-hook.ps1"} {
		path := filepath.Join(opts.DataDir, "hooks", name)
		if _, err := os.Stat(path); err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if scriptHasMarker(path) {
			return fmt.Errorf("cursor teardown incomplete: managed runtime still present at %s", path)
		}
	}
	return nil
}

func (c *hookOnlyConnector) Authenticate(r *http.Request) bool {
	if c.pluginArtifact {
		// The OpenCode plugin always carries the connector-scoped token.
		// Do not grant it the legacy shell-hook loopback bypass or accept
		// the gateway master key: either would turn a local process into an
		// unauthenticated policy caller.
		provided := ExtractBearerKey(r.Header.Get("Authorization"))
		return c.gatewayToken != "" && SecureTokenMatch(provided, c.gatewayToken)
	}
	// Hermes on macOS always receives a connector-scoped token from the
	// managed POSIX hook. Once that token exists, accepting a master key or an
	// unauthenticated loopback request would let any local process forge
	// Hermes audit/correlation events. Keep the historical generic behavior
	// on other platforms so this macOS hardening does not alter PR #655's
	// Windows contract.
	if c.name == "hermes" && runtime.GOOS == "darwin" && strings.TrimSpace(c.gatewayToken) != "" {
		provided := ExtractBearerKey(r.Header.Get("Authorization"))
		return SecureTokenMatch(provided, c.gatewayToken)
	}
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
	if c.pluginArtifact {
		return AgentPaths{
			PatchedFiles: patched,
			BackupFiles:  []string{managedFileBackupPath(opts.DataDir, c.name, "config")},
		}
	}
	return AgentPaths{
		PatchedFiles: patched,
		BackupFiles:  []string{managedFileBackupPath(opts.DataDir, c.name, c.managedBackupLogicalName())},
		HookScripts:  hookScriptPathsForConnector(opts, c),
	}
}

func (c *hookOnlyConnector) ExclusiveManagedPaths(opts SetupOpts) []string {
	if !c.pluginArtifact {
		return nil
	}
	return []string{c.configPath(opts)}
}

func (c *hookOnlyConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

func (c *hookOnlyConnector) RequiredEnv() []EnvRequirement {
	if c.name == "copilot" || c.name == "openhands" {
		return append([]EnvRequirement{{
			Scope:       EnvScopeNone,
			Description: "DefenseClaw's Copilot hook integration requires no shell environment variables; upstream OTel process variables are not configured or managed by this connector.",
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
	logicalName := c.managedBackupLogicalName()
	if err := captureManagedFileBackup(opts.DataDir, c.name, logicalName, path); err != nil {
		return err
	}

	var err error
	switch c.name {
	case "hermes":
		err = patchHermesHooks(path, hookScript, opts.HookExecutable)
	case "cursor":
		err = patchCursorHooks(
			path,
			hookScript,
			filepath.Join(opts.DataDir, "hooks", c.scriptName),
			c.effectiveFailClosed(opts),
		)
	case "windsurf":
		err = patchWindsurfHooks(
			path,
			hookScript,
			filepath.Join(opts.DataDir, "hooks", c.scriptName),
		)
	case "geminicli":
		if err = patchGeminiHooks(path, hookScript); err == nil {
			err = patchGeminiTelemetry(path, opts)
		}
	case "copilot":
		events := c.HookProfile(opts).SupportedEvents
		if len(events) == 0 {
			events = copilotCurrentHookEvents
		}
		err = patchCopilotHooksForOS(path, hookScript, events, runtime.GOOS)
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
	return updateManagedFileBackupPostHash(opts.DataDir, c.name, logicalName, path)
}

func (c *hookOnlyConnector) managedBackupLogicalName() string {
	switch c.name {
	case "antigravity":
		return "hooks.json"
	case "hermes":
		return "config.yaml"
	default:
		return "config"
	}
}

func (c *hookOnlyConnector) migrateManagedBackup(opts SetupOpts) error {
	switch c.name {
	case "antigravity", "hermes":
		return migrateManagedFileBackupLogicalName(
			opts.DataDir,
			c.name,
			"config",
			c.managedBackupLogicalName(),
		)
	default:
		return nil
	}
}

func (c *hookOnlyConnector) removeConfigEntriesWithManagedBackup(
	opts SetupOpts,
	logicalName, path, hookScript string,
) error {
	if c.name != "hermes" {
		return c.removeConfigEntries(path, hookScript, opts)
	}
	backup, err := loadManagedFileBackupForTransform(
		opts.DataDir,
		c.name,
		logicalName,
		path,
	)
	if err != nil {
		return fmt.Errorf("load Hermes pristine custody: %w", err)
	}
	return removeHermesHooks(path, hookScript, backup)
}

func (c *hookOnlyConnector) removeConfigEntries(path, hookScript string, opts SetupOpts) error {
	switch c.name {
	case "hermes":
		return removeHermesHooks(path, hookScript, nil)
	case "geminicli":
		return removeGeminiConfigEntries(path, hookScript)
	case "cursor":
		return removeJSONHookReferences(path, cursorOwnedHookCommands(opts)...)
	case "copilot", "openhands":
		return removeJSONHookReferences(path, hookScript)
	case "windsurf":
		return removeJSONHookReferences(path, hookScript, legacyWindsurfWindowsHookCommand())
	case "antigravity":
		ownedCommands := antigravityOwnedHookCommands(hookScript)
		ownedCommands = append(ownedCommands,
			legacyAntigravityWindowsHookCommand(),
			legacyAntigravityNonWaitingWindowsHookCommand(),
		)
		return removeJSONHookReferences(path, ownedCommands...)
	default:
		return nil
	}
}

func (c *hookOnlyConnector) effectiveFailClosed(opts SetupOpts) bool {
	cap := c.HookCapabilities(opts)
	return cap.SupportsFailClosed && resolveHookFailMode(opts, c) == "closed"
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
	if configDir := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR")); configDir != "" {
		if absolute, err := filepath.Abs(configDir); err == nil {
			return filepath.Join(absolute, "plugins", "defenseclaw.js")
		}
	}
	return homePath(".config", "opencode", "plugins", "defenseclaw.js")
}

func cursorHooksPath(opts SetupOpts) string {
	if CursorHooksPathOverride != "" {
		return CursorHooksPathOverride
	}
	if strings.TrimSpace(opts.ConfigHome) != "" {
		return filepath.Join(opts.ConfigHome, "hooks.json")
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
	return copilotHomePath("hooks", "defenseclaw.json")
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
func antigravityHooksPath(opts SetupOpts) string {
	if AntigravityHooksPathOverride != "" {
		return AntigravityHooksPathOverride
	}
	if strings.TrimSpace(opts.ConfigHome) != "" {
		// Hidden native-maintenance commands use this DefenseClaw-internal
		// binding only to restore or migrate a path already recorded in Setup
		// custody. Ordinary calls always use Google's documented global path.
		return filepath.Join(opts.ConfigHome, "hooks.json")
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

func openhandsPersistenceRoot() string {
	if root := strings.TrimSpace(os.Getenv("OPENHANDS_PERSISTENCE_DIR")); root != "" {
		return filepath.Clean(root)
	}
	return homePath(".openhands")
}

func openhandsMCPPath() string {
	return filepath.Join(openhandsPersistenceRoot(), "mcp.json")
}

func openhandsInstructionPaths(opts SetupOpts) []string {
	root := openhandsWorkspaceRoot(opts)
	return uniqueNonEmptyStrings([]string{
		filepath.Join(root, "AGENTS.md"),
		filepath.Join(root, "AGENT.md"),
		filepath.Join(root, "CLAUDE.md"),
		filepath.Join(root, "GEMINI.md"),
		filepath.Join(root, ".cursorrules"),
	})
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

func copilotSkillReadPaths(opts SetupOpts) []string {
	roots := copilotWorkspaceAncestors(opts)
	paths := make([]string, 0, len(roots)+6)
	if len(roots) > 0 {
		paths = append(paths,
			filepath.Join(roots[0], ".github", "skills"),
			filepath.Join(roots[0], ".agents", "skills"),
			filepath.Join(roots[0], ".claude", "skills"),
		)
		for _, root := range roots[1:] {
			paths = append(paths, filepath.Join(root, ".github", "skills"))
		}
	}
	paths = append(paths, copilotHomePath("skills"), homePath(".agents", "skills"))
	for _, raw := range strings.Split(os.Getenv("COPILOT_SKILLS_DIRS"), ",") {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
			path = filepath.Join(homePath(), path[2:])
		} else if !filepath.IsAbs(path) {
			if workspaceRoot(opts) == "" {
				// Relative custom paths belong to Copilot's launch
				// workspace, not the gateway daemon's current directory.
				continue
			}
			path = filepath.Join(workspaceRoot(opts), path)
		}
		paths = append(paths, path)
	}
	return copilotUniquePaths(paths)
}

func copilotAgentReadPaths(opts SetupOpts) []string {
	roots := copilotWorkspaceAncestors(opts)
	paths := make([]string, 0, len(roots)*2+1)
	for _, root := range roots {
		paths = append(paths,
			filepath.Join(root, ".github", "agents"),
			filepath.Join(root, ".claude", "agents"),
		)
	}
	paths = append(paths, copilotHomePath("agents"))
	return copilotUniquePaths(paths)
}

func copilotMCPReadPaths(opts SetupOpts) []string {
	roots := copilotWorkspaceAncestors(opts)
	paths := make([]string, 0, len(roots)*2+1)
	for _, root := range roots {
		paths = append(paths,
			filepath.Join(root, ".mcp.json"),
			filepath.Join(root, ".github", "mcp.json"),
		)
	}
	paths = append(paths, copilotHomePath("mcp-config.json"))
	return copilotUniquePaths(paths)
}

func copilotWorkspaceAncestors(opts SetupOpts) []string {
	root := strings.TrimSpace(workspaceRoot(opts))
	if root == "" {
		return nil
	}
	if absolute, err := filepath.Abs(root); err == nil {
		root = absolute
	}
	current := filepath.Clean(root)
	candidates := make([]string, 0, 4)
	for {
		candidates = append(candidates, current)
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return candidates
		}
		parent := filepath.Dir(current)
		if parent == current {
			// A pinned non-repository workspace has only its immediate
			// project surface; never scan unrelated filesystem ancestors.
			return candidates[:1]
		}
		current = parent
	}
}

func copilotUniquePaths(paths []string) []string {
	seen := make(map[string]struct{}, len(paths))
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		path = strings.TrimSpace(path)
		if path == "" {
			continue
		}
		path = filepath.Clean(path)
		key := path
		if runtime.GOOS == "windows" {
			key = strings.ToLower(key)
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, path)
	}
	return out
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

func copilotHomePath(parts ...string) string {
	root := connectorEnvHomeDir("COPILOT_HOME", ".copilot")
	return filepath.Join(append([]string{root}, parts...)...)
}

func copilotCachePath(parts ...string) string {
	root := strings.TrimSpace(os.Getenv("COPILOT_CACHE_HOME"))
	if root == "" {
		if runtime.GOOS == "darwin" {
			root = homePath("Library", "Caches", "copilot")
		} else {
			root = homePath(".cache", "copilot")
		}
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func copilotEnvPathList(name string) []string {
	var out []string
	for _, raw := range strings.Split(os.Getenv(name), ",") {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if abs, err := filepath.Abs(path); err == nil {
			path = abs
		}
		out = append(out, filepath.Clean(path))
	}
	return out
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
	paths := []string{
		homePath(".cursor", "skills"),
		homePath(".agents", "skills"),
		workspacePath(opts, ".cursor", "skills"),
		workspacePath(opts, ".agents", "skills"),
	}
	if runtime.GOOS == "darwin" {
		paths = append(paths,
			homePath(".claude", "skills"),
			homePath(".codex", "skills"),
			workspacePath(opts, ".claude", "skills"),
			workspacePath(opts, ".codex", "skills"),
		)
	}
	return paths
}

func hermesSkillReadPaths() []string {
	home := hermespath.HomeDir()
	paths := []string{filepath.Join(home, "skills")}
	data, err := os.ReadFile(hermespath.ConfigPath())
	if err != nil {
		return paths
	}
	var document struct {
		Skills struct {
			ExternalDirs any `yaml:"external_dirs"`
		} `yaml:"skills"`
	}
	if err := yaml.Unmarshal(data, &document); err != nil {
		return paths
	}
	var configured []string
	switch value := document.Skills.ExternalDirs.(type) {
	case string:
		configured = []string{value}
	case []any:
		for _, entry := range value {
			configured = append(configured, fmt.Sprint(entry))
		}
	}
	userHome, _ := os.UserHomeDir()
	for _, entry := range configured {
		entry = strings.TrimSpace(os.ExpandEnv(entry))
		if entry == "" {
			continue
		}
		if entry == "~" {
			entry = userHome
		} else if strings.HasPrefix(entry, "~/") {
			entry = filepath.Join(userHome, strings.TrimPrefix(entry, "~/"))
		}
		if !filepath.IsAbs(entry) {
			entry = filepath.Join(home, entry)
		}
		entry = filepath.Clean(entry)
		if info, statErr := os.Stat(entry); statErr == nil && info.IsDir() {
			paths = append(paths, entry)
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func hermesRuleReadPaths(opts SetupOpts) []string {
	root := strings.TrimSpace(opts.WorkspaceDir)
	paths := []string{
		filepath.Join(hermespath.HomeDir(), "SOUL.md"),
		filepath.Join(hermespath.HomeDir(), "BOOT.md"),
	}
	if root != "" {
		paths = append(paths,
			filepath.Join(root, ".hermes.md"),
			filepath.Join(root, "HERMES.md"),
			filepath.Join(root, "AGENTS.md"),
			filepath.Join(root, "agents.md"),
			filepath.Join(root, "CLAUDE.md"),
			filepath.Join(root, "claude.md"),
			filepath.Join(root, ".cursorrules"),
			filepath.Join(root, ".cursor", "rules"),
		)
	}
	return uniqueNonEmptyStrings(paths)
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

func openhandsAgentPaths(opts SetupOpts) []string {
	paths := openhandsAgentWritePaths(opts)
	paths = append(paths,
		homePath(".openhands", "agents"),
	)
	if root := selectedWorkspaceRoot(OpenHandsWorkspaceDirOverride, opts.WorkspaceDir); root != "" && workspaceRootOutsideDataDir(root, opts.DataDir) {
		paths = append(paths, filepath.Join(root, ".openhands", "agents"))
	}
	return uniqueNonEmptyStrings(paths)
}

func openhandsAgentWritePaths(opts SetupOpts) []string {
	paths := []string{homePath(".agents", "agents")}
	if root := selectedWorkspaceRoot(OpenHandsWorkspaceDirOverride, opts.WorkspaceDir); root != "" && workspaceRootOutsideDataDir(root, opts.DataDir) {
		paths = append([]string{filepath.Join(root, ".agents", "agents")}, paths...)
	}
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
		antigravityWorkspacePath(opts, "GEMINI.md"),
		antigravityWorkspacePath(opts, "AGENTS.md"),
		antigravityWorkspacePath(opts, ".agents", "rules"),
	})
}

func antigravityPluginPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings(append(antigravityPluginWritePaths(opts),
		homePath(".gemini", "antigravity-cli", "plugins"),
	))
}

func antigravityPluginWritePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		homePath(".gemini", "config", "plugins"),
		antigravityWorkspacePath(opts, ".agents", "plugins"),
		antigravityWorkspacePath(opts, "_agents", "plugins"),
	})
}

func antigravityAgentPaths(opts SetupOpts) []string {
	paths := []string{
		homePath(".gemini", "config", "agents"),
		antigravityWorkspacePath(opts, ".agents", "agents"),
	}
	for _, pluginRoot := range antigravityPluginPaths(opts) {
		entries, err := os.ReadDir(pluginRoot)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() {
				paths = append(paths, filepath.Join(pluginRoot, entry.Name(), "agents"))
			}
		}
	}
	return uniqueNonEmptyStrings(paths)
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
	return []string{homePath(".codeium", "windsurf", "mcp_config.json")}
}

func windsurfSkillPaths(opts SetupOpts) []string {
	paths := []string{
		workspacePath(opts, ".windsurf", "skills"),
		workspacePath(opts, ".agents", "skills"),
		homePath(".codeium", "windsurf", "skills"),
		homePath(".agents", "skills"),
	}
	if runtime.GOOS == "darwin" {
		paths = append(paths, "/Library/Application Support/Windsurf/skills")
	}
	return uniqueNonEmptyStrings(paths)
}

func windsurfSkillWritePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		workspacePath(opts, ".windsurf", "skills"),
		homePath(".codeium", "windsurf", "skills"),
	})
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
	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			out = append(out, path)
		}
	}
	return out
}

func windsurfRulePaths(opts SetupOpts) []string {
	root := workspaceRoot(opts)
	candidates := []string{homePath(".codeium", "windsurf", "memories", "global_rules.md")}
	if runtime.GOOS == "darwin" {
		candidates = append(candidates,
			"/Library/Application Support/Devin/rules",
			"/Library/Application Support/Windsurf/rules",
		)
	}
	if strings.TrimSpace(root) != "" {
		candidates = append(candidates,
			filepath.Join(root, ".devin", "rules"),
			filepath.Join(root, ".windsurf", "rules"),
			filepath.Join(root, ".windsurfrules"),
			filepath.Join(root, "AGENTS.md"),
			filepath.Join(root, "agents.md"),
		)
	}
	return uniqueNonEmptyStrings(candidates)
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

func patchHermesHooks(path, hookScript, hookExecutable string) error {
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
	// hooks register without an interactive prompt. Selecting Hermes
	// Setup is an explicit request to register those hooks, so Setup sets
	// the key even when the prior value was false. The managed-file backup
	// restores the operator's exact prior bytes on teardown.
	cfg["hooks_auto_accept"] = true
	hookCommand := shellWord(hookScript)
	if bound := windowsHermesDirectHookCommand(hookExecutable); bound != "" && hookScript == bound {
		// Native maintenance may run from a quarantined or temporary gateway,
		// so generic process-local ownership cannot identify the stable command
		// that Setup explicitly bound. Preserve that exact direct argv without
		// adding shell quoting; Hermes will pass it through shlex.split and
		// subprocess.run(shell=False).
		hookCommand = hookScript
	}
	for _, spec := range []struct {
		event   string
		matcher string
	}{
		{"pre_tool_call", ".*"},
		{"post_tool_call", ".*"},
		{"transform_terminal_output", ""},
		{"transform_tool_result", ""},
		{"transform_llm_output", ""},
		{"pre_llm_call", ""},
		{"post_llm_call", ""},
		{"pre_verify", ""},
		{"pre_api_request", ""},
		{"post_api_request", ""},
		{"api_request_error", ""},
		{"on_session_start", ""},
		{"on_session_end", ""},
		{"on_session_finalize", ""},
		{"on_session_reset", ""},
		{"subagent_start", ""},
		{"subagent_stop", ""},
		{"pre_gateway_dispatch", ""},
		{"pre_approval_request", ""},
		{"post_approval_response", ""},
		{"kanban_task_claimed", ""},
		{"kanban_task_completed", ""},
		{"kanban_task_blocked", ""},
	} {
		entry := map[string]interface{}{
			"command": hookCommand,
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

func removeHermesHooks(path, hookScript string, backup *managedFileBackup) error {
	pristineAutoAccept, pristineHadAutoAccept, pristineKnown, err := hermesPristineAutoAccept(backup)
	if err != nil {
		return err
	}
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
	// Setup writes exactly boolean true. Restore the captured value/absence
	// only while that installed scalar remains unchanged; a later operator edit
	// belongs to the operator and survives surgical hook cleanup.
	currentAutoAccept, currentAutoAcceptPresent := cfg["hooks_auto_accept"]
	if pristineKnown && currentAutoAcceptPresent && currentAutoAccept == true {
		if pristineHadAutoAccept {
			cfg["hooks_auto_accept"] = pristineAutoAccept
		} else {
			delete(cfg, "hooks_auto_accept")
		}
	}
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return err
	}
	return atomicWriteFile(path, data, 0o600)
}

func hermesPristineAutoAccept(backup *managedFileBackup) (interface{}, bool, bool, error) {
	if backup == nil {
		return nil, false, false, nil
	}
	if !backup.Existed {
		if backup.PristineSHA256 != managedBackupMissingHash || len(backup.PristineBytes) != 0 {
			return nil, false, false, fmt.Errorf("Hermes pristine custody for a missing config is inconsistent")
		}
		return nil, false, true, nil
	}
	if backup.PristineSHA256 != sha256Hex(backup.PristineBytes) {
		return nil, false, false, fmt.Errorf("Hermes pristine custody hash does not match its captured config bytes")
	}
	var pristine map[string]interface{}
	if len(bytes.TrimSpace(backup.PristineBytes)) != 0 {
		if err := yaml.Unmarshal(backup.PristineBytes, &pristine); err != nil {
			return nil, false, false, fmt.Errorf("parse Hermes pristine custody: %w", err)
		}
	}
	value, present := pristine["hooks_auto_accept"]
	return value, present, true, nil
}

func patchCursorHooks(path, hookScript, legacyShellScript string, failClosed bool) error {
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
			"type":    "command",
			"command": shellWord(hookScript),
			// Cursor's hook schema defines timeout in seconds.
			"timeout":    30,
			"failClosed": failClosed,
		}
		// Replace instead of merely appending. This both migrates the previous
		// direct-native Windows command to the PowerShell adapter and refreshes
		// failClosed when the connector moves between observe and action mode.
		// Entries not owned by DefenseClaw are preserved in their original order.
		hooks[event] = replaceManagedCursorHooks(hooks[event], hookScript, legacyShellScript, entry)
	}
	return writeJSONObject(path, cfg)
}

func replaceManagedCursorHooks(raw interface{}, hookScript, legacyShellScript string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	ownedCommands := uniqueNonEmptyStrings(append(
		[]string{
			hookScript,
			legacyShellScript,
			hookInvocationCommandFor("windows", "cursor", legacyShellScript),
		},
		legacyCursorNativeHookCommands()...,
	))
	for _, item := range list {
		if managedCursorHookEntry(item, ownedCommands) {
			continue
		}
		out = append(out, item)
	}
	return append(out, entry)
}

func cursorOwnedHookCommands(opts SetupOpts) []string {
	portableScript := filepath.Join(opts.DataDir, "hooks", "cursor-hook.sh")
	return uniqueNonEmptyStrings(append(
		[]string{
			portableScript,
			hookInvocationCommandFor("windows", "cursor", portableScript),
		},
		legacyCursorNativeHookCommands()...,
	))
}

// legacyCursorNativeHookCommands returns only direct-native command strings
// emitted by the pre-adapter Windows implementation. Each executable path is
// one of DefenseClaw's finite installer or legacy user-install locations.
// Arbitrary commands that merely end in "hook --connector cursor" are foreign.
func legacyCursorNativeHookCommands() []string {
	binaries := append(
		nativeHookBinaryOwnershipCandidates(),
		defenseclawGatewayBinary(),
		canonicalNativeWindowsInstalledGatewayBinary(),
		filepath.Join(userHomeDir(), ".local", "bin", windowsGatewayBinaryName),
	)
	commands := make([]string, 0, len(binaries))
	for _, binary := range uniqueNonEmptyStrings(binaries) {
		commands = append(commands, windowsQuoteExe(binary)+" "+nativeHookFlag+"cursor")
	}
	return uniqueNonEmptyStrings(commands)
}

func managedCursorHookEntry(raw interface{}, ownedCommands []string) bool {
	for _, command := range ownedCommands {
		if managedHookCommandEntry(raw, command) {
			return true
		}
	}
	return false
}

func patchWindsurfHooks(path, hookScript, legacyShellScript string) error {
	return patchWindsurfHooksForOS(path, hookScript, legacyShellScript, runtime.GOOS)
}

func patchWindsurfHooksForOS(path, hookScript, legacyShellScript, goos string) error {
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
		entry := map[string]interface{}{"show_output": true}
		if goos == "windows" {
			// Windsurf executes this field with `powershell -Command`. Do not
			// provide `command`: the documented fallback would use bash -c on
			// other platforms and obscures whether native Windows enforcement
			// is actually active.
			entry["powershell"] = hookScript
		} else {
			entry["command"] = shellWord(hookScript)
		}
		hooks[event] = replaceManagedWindsurfHooks(
			hooks[event],
			hookScript,
			legacyShellScript,
			entry,
		)
	}
	return writeJSONObject(path, cfg)
}

func replaceManagedWindsurfHooks(raw interface{}, hookScript, legacyShellScript string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	for _, item := range list {
		if managedHookCommandEntry(item, hookScript) ||
			managedHookCommandEntry(item, legacyShellScript) ||
			managedHookCommandEntry(item, legacyWindsurfWindowsHookCommand()) {
			continue
		}
		out = append(out, item)
	}
	return append(out, entry)
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
	pathToken, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI, opts.OTLPPathToken)
	if err != nil {
		return fmt.Errorf("resolve scoped Gemini CLI OTLP token: %w", err)
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
	return patchCopilotHooksForOS(path, hookScript, copilotCurrentHookEvents, runtime.GOOS)
}

func patchCopilotHooksForOS(path, hookScript string, events []string, goos string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	cfg["version"] = 1
	selected := make(map[string]bool, len(events))
	for _, event := range events {
		if !ValidCopilotHookEvent(event) {
			return fmt.Errorf("copilot: unsupported hook event %q in resolved contract", event)
		}
		selected[event] = true
		entry := map[string]interface{}{
			"type":       "command",
			"timeoutSec": 30,
		}
		eventCommand := copilotHookInvocationCommandForEvent(goos, event, hookScript)
		if goos == "windows" {
			// Copilot selects this field itself and evaluates it with PowerShell.
			// eventCommand is therefore the complete vendor-specific program:
			// do not prepend a call operator or another PowerShell process.
			entry["powershell"] = eventCommand
		} else {
			entry["bash"] = eventCommand
		}
		hooks[event] = reconcileCopilotFlatHook(hooks[event], hookScript, entry)
	}
	// A version downgrade must remove only the now-out-of-contract managed
	// handler (currently userPromptTransformed), while retaining operator hooks
	// registered for that event and every unknown/future event verbatim.
	for _, event := range copilotCurrentHookEvents {
		if selected[event] {
			continue
		}
		remaining := removeOwnedFlatHooks(hooks[event], hookScript)
		if len(remaining) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = remaining
		}
	}
	return writeJSONObject(path, cfg)
}

func copilotHookInvocationCommandForEvent(goos, event, hookScript string) string {
	if goos == "windows" {
		return windowsCopilotPowerShellHookCommandForEvent(event, defenseclawHookBinary())
	}
	return shellWord(hookScript) + " --event " + shellWord(event)
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

// antigravityLifecycleEvents is the canonical Antigravity 2.0 hook lifecycle
// event list in its documented order:
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
var antigravityLifecycleEvents = []string{
	"PreInvocation",
	"PreToolUse",
	"PostToolUse",
	"PostInvocation",
	"Stop",
}

func antigravityOwnedHookCommands(hookScript string) []string {
	return antigravityOwnedHookCommandsForOS(runtime.GOOS, hookScript)
}

func antigravityOwnedHookCommandsForOS(goos, hookScript string) []string {
	commands := []string{hookScript}
	for _, event := range antigravityLifecycleEvents {
		commands = append(commands, antigravityHookInvocationCommandForEvent(goos, event, hookScript))
	}
	return uniqueNonEmptyStrings(commands)
}

// patchAntigravityHooks writes the documented mixed Antigravity hooks.json
// schema:
//
//	{
//	  "defenseclaw-antigravity-preinvocation":  { "PreInvocation":  [...] },
//	  "defenseclaw-antigravity-pretooluse":     { "PreToolUse":     [...] },
//	  "defenseclaw-antigravity-posttooluse":    { "PostToolUse":    [...] },
//	  "defenseclaw-antigravity-postinvocation": { "PostInvocation": [...] },
//	  "defenseclaw-antigravity-stop":           { "Stop":           [...] }
//	}
//
// PreToolUse and PostToolUse contain matcher groups with nested handlers.
// PreInvocation, PostInvocation, and Stop contain direct handler lists and
// ignore matchers. Every handler is synchronous and uses the documented
// 30-second default explicitly.
//
// Each outer key ("defenseclaw-antigravity-<event>") is a stable,
// DefenseClaw-owned identifier that scopes ownership for re-setup
// idempotence and for teardown — operators / other tools writing
// to the same hooks.json file under their own keys are not
// disturbed.
//
// The "command" field is written WITHOUT shellWord() quoting because
// Antigravity tokenizes the command before direct execution. On Unix hookScript
// is the bare absolute .sh path. On Windows it is a tokenizer-safe PowerShell
// command whose encoded script invokes the absolute managed
// defenseclaw-hook.exe path. The visible command has no quoted tokens or
// user-profile path segments for Antigravity to mis-tokenize, and the launcher
// lookup does not depend on Antigravity's current directory or PATH.
func patchAntigravityHooks(path, hookScript string) error {
	return patchAntigravityHooksForOS(path, hookScript, runtime.GOOS)
}

func patchAntigravityHooksForOS(path, hookScript, goos string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	for _, event := range antigravityLifecycleEvents {
		key := "defenseclaw-antigravity-" + strings.ToLower(event)
		handler := map[string]interface{}{
			"type":    "command",
			"command": antigravityHookInvocationCommandForEvent(goos, event, hookScript),
			"timeout": 30,
		}
		var handlers []interface{}
		if event == "PreToolUse" || event == "PostToolUse" {
			handlers = []interface{}{map[string]interface{}{
				"matcher": "*",
				"hooks":   []interface{}{handler},
			}}
		} else {
			handlers = []interface{}{handler}
		}
		cfg[key] = map[string]interface{}{event: handlers}
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
		if managedHookCommandEntry(item, hookScript) {
			return list
		}
	}
	return append(list, entry)
}

func reconcileCopilotFlatHook(raw interface{}, hookScript string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	replaced := false
	for _, item := range list {
		if managedHookCommandEntry(item, hookScript) {
			if !replaced {
				out = append(out, entry)
				replaced = true
			}
			continue
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, entry)
	}
	return out
}

func appendUniqueGeminiHookGroup(raw interface{}, hookScript string, group map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	for _, item := range list {
		if managedGeminiHookGroup(item, hookScript) {
			return list
		}
	}
	return append(list, group)
}

func removeJSONHookReferences(path string, hookScripts ...string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	pruned, _ := removeHookScriptReferences(cfg, hookScripts...).(map[string]interface{})
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

func removeHookScriptReferences(raw interface{}, hookScripts ...string) interface{} {
	switch v := raw.(type) {
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			if containsHookScript(item, hookScripts...) {
				continue
			}
			out = append(out, removeHookScriptReferences(item, hookScripts...))
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, value := range v {
			out[key] = removeHookScriptReferences(value, hookScripts...)
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

func containsHookScript(raw interface{}, hookScripts ...string) bool {
	switch v := raw.(type) {
	case []interface{}:
		for _, item := range v {
			if containsHookScript(item, hookScripts...) {
				return true
			}
		}
	case map[string]interface{}:
		for _, hookScript := range hookScripts {
			if managedHookCommandEntry(v, hookScript) {
				return true
			}
		}
		if hooks, ok := v["hooks"]; ok {
			return containsHookScript(hooks, hookScripts...)
		}
	}
	return false
}

func legacyAntigravityWindowsHookCommand() string {
	return windowsHookBinaryName + " " + nativeHookFlag + "antigravity"
}

func legacyAntigravityNonWaitingWindowsHookCommand() string {
	return legacyWindowsNativePowerShellHookCommandForBinary("antigravity", defenseclawHookBinary())
}

func legacyWindsurfWindowsHookCommand() string {
	return "& " + powershellQuoteLiteral(defenseclawHookBinary()) + " " + nativeHookFlag + "windsurf"
}

func managedHookCommandEntry(raw interface{}, hookScript string) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"command", "bash", "powershell"} {
		command, _ := entry[key].(string)
		command = strings.TrimSpace(command)
		if command == strings.TrimSpace(hookScript) || command == strings.TrimSpace(shellWord(hookScript)) {
			return true
		}
		if isCopilotNativeHookCommand(hookScript) && isCopilotNativeHookCommand(command) {
			return true
		}
		if isCopilotShellHookScript(hookScript) && isCopilotEventBoundShellCommand(command, hookScript) {
			return true
		}
	}
	return false
}

func isCopilotNativeHookCommand(command string) bool {
	command = strings.TrimSpace(command)
	for _, hookBinary := range nativeHookBinaryOwnershipCandidates() {
		if command == windowsCopilotPowerShellHookCommandForBinary(hookBinary) ||
			command == legacyWindowsCopilotPowerShellHookCommandForBinary(hookBinary) ||
			command == legacyWindowsCopilotDoubleCallOperatorHookCommandForBinary(hookBinary) {
			return true
		}
		for _, event := range copilotCurrentHookEvents {
			if command == windowsCopilotPowerShellHookCommandForEvent(event, hookBinary) {
				return true
			}
		}
	}
	return false
}

func isCopilotShellHookScript(command string) bool {
	command = strings.Trim(strings.TrimSpace(command), `"'`)
	return filepath.Base(filepath.FromSlash(command)) == "copilot-hook.sh"
}

func isCopilotEventBoundShellCommand(command, hookScript string) bool {
	command = strings.TrimSpace(command)
	for _, event := range copilotCurrentHookEvents {
		if command == copilotHookInvocationCommandForEvent("linux", event, hookScript) {
			return true
		}
	}
	return false
}

func managedGeminiHookGroup(raw interface{}, hookScript string) bool {
	group, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	hooks, _ := group["hooks"].([]interface{})
	for _, hook := range hooks {
		if managedHookCommandEntry(hook, hookScript) {
			return true
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
	// Cursor's Windows adapter is already a complete PowerShell invocation.
	// Wrapping it in shell single quotes would turn the call operator and path
	// into inert text when Cursor inserts the command after `$input |`.
	if strings.HasPrefix(s, "& '") && strings.HasSuffix(s, "'") {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
