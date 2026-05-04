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
	"net/url"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"gopkg.in/yaml.v3"
)

var (
	HermesConfigPathOverride    string
	CursorHooksPathOverride     string
	WindsurfHooksPathOverride   string
	GeminiSettingsPathOverride  string
	CopilotHooksPathOverride    string
	CopilotWorkspaceDirOverride string
)

type hookOnlyConnector struct {
	name        string
	description string
	apiPath     string
	scriptName  string
	configPath  func(SetupOpts) string
	capability  func(SetupOpts) HookCapability

	gatewayToken string
	masterKey    string
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
		description: ".github/hooks command hooks (Copilot CLI, workspace-scoped)",
		apiPath:     "/api/v1/copilot/hook",
		scriptName:  "copilot-hook.sh",
		configPath:  copilotHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents:    []string{"preToolUse", "PreToolUse"},
				BlockEvents: []string{
					"preToolUse",
					"PreToolUse",
					"permissionRequest",
					"PermissionRequest",
					"agentStop",
					"Stop",
					"subagentStop",
					"SubagentStop",
					"postToolUseFailure",
					"PostToolUseFailure",
				},
				SupportsFailClosed: false,
				Scope:              "workspace",
				ConfigPath:         copilotHooksPath(opts),
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

func (c *hookOnlyConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	caps := ConnectorCapabilities{
		Hooks: c.capability(opts),
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
			Notes:           []string{"MCP servers are merged into ~/.hermes/config.yaml."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			ReadPaths:      []string{homePath(".hermes", "skills")},
			WritePaths:     []string{homePath(".hermes", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			ReadPaths:      []string{homePath(".hermes", "plugins"), filepath.Join(workspaceRoot(opts), ".hermes", "plugins")},
			WritePaths:     []string{homePath(".hermes", "plugins")},
			InstallTargets: []string{"plugin"},
			RequiresOptIn:  true,
			DiscoveryOnly:  true,
			Notes:          []string{"Project .hermes/plugins is discovery-only until plugins.enabled is explicitly set."},
		}
		caps.Rules = unsupportedSurface("Hermes rules are not a separate documented local surface.")
		caps.Agents = unsupportedSurface("Hermes subagent/agent asset locations are not installed by DefenseClaw v1.")
	case "cursor":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     []string{filepath.Join(workspaceRoot(opts), ".cursor", "mcp.json"), homePath(".cursor", "mcp.json")},
			WritePaths:      []string{filepath.Join(workspaceRoot(opts), ".cursor", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      cursorSkillPaths(opts),
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".cursor", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".cursor", "rules"), filepath.Join(workspaceRoot(opts), "AGENTS.md")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".cursor", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Plugins = unsupportedSurface("Cursor plugin/extension installation is not supported by this connector.")
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
		caps.Plugins = unsupportedSurface("Windsurf plugin/extension installation is explicitly unsupported in this connector matrix.")
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
			Scope:          "workspace",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".gemini", "skills"), filepath.Join(workspaceRoot(opts), ".agents", "skills")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".gemini", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Plugins = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".gemini", "extensions"), homePath(".gemini", "extensions")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".gemini", "extensions")},
			InstallTargets: []string{"extension"},
			RequiresOptIn:  true,
		}
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".gemini", "agents"), homePath(".gemini", "agents")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".gemini", "agents")},
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".agents", "skills")},
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
			ConfigPaths:     []string{homePath(".copilot", "mcp-config.json"), filepath.Join(workspaceRoot(opts), ".github", "mcp.json"), filepath.Join(workspaceRoot(opts), ".mcp.json")},
			WritePaths:      []string{filepath.Join(workspaceRoot(opts), ".github", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".github", "skills"), filepath.Join(workspaceRoot(opts), ".agents", "skills"), homePath(".copilot", "skills")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".github", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".github", "instructions")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".github", "instructions")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
		}
		caps.Plugins = SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			InstallTargets: []string{"plugin"},
			RequiresOptIn:  true,
			Notes:          []string{"Copilot plugins are installed through the documented copilot plugin CLI flows, not by editing shell startup files."},
		}
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{filepath.Join(workspaceRoot(opts), ".github", "agents"), homePath(".copilot", "agents")},
			WritePaths:     []string{filepath.Join(workspaceRoot(opts), ".github", "agents")},
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
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("%s hook script: %w", c.name, err)
	}
	if err := c.patchConfig(opts, filepath.Join(hookDir, c.scriptName)); err != nil {
		return fmt.Errorf("%s hook config: %w", c.name, err)
	}
	return nil
}

func (c *hookOnlyConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	_ = ctx
	path := c.configPath(opts)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", path)
	if err != nil {
		return fmt.Errorf("%s restore config backup: %w", c.name, err)
	}
	if restored {
		return nil
	}
	hookScript := filepath.Join(opts.DataDir, "hooks", c.scriptName)
	if err := c.removeConfigEntries(path, hookScript); err != nil {
		return fmt.Errorf("%s remove hook entries: %w", c.name, err)
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
	return nil
}

func (c *hookOnlyConnector) VerifyClean(opts SetupOpts) error {
	path := c.configPath(opts)
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return err
	}
	needle := filepath.Join(opts.DataDir, "hooks", c.scriptName)
	if bytes.Contains(data, []byte(needle)) || bytes.Contains(data, []byte(c.scriptName)) {
		return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
	}
	return nil
}

func (c *hookOnlyConnector) Authenticate(r *http.Request) bool {
	if c.gatewayToken != "" && SecureTokenMatch(ExtractBearerKey(r.Header.Get("Authorization")), c.gatewayToken) {
		return true
	}
	return IsLoopback(r)
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
	hooks := make([]string, 0, len(HookScripts()))
	for _, name := range HookScripts() {
		hooks = append(hooks, filepath.Join(opts.DataDir, "hooks", name))
	}
	caps := c.Capabilities(opts)
	patched := uniqueNonEmptyStrings(append([]string{c.configPath(opts)}, caps.Telemetry.ConfigPaths...))
	return AgentPaths{
		PatchedFiles: patched,
		BackupFiles:  []string{managedFileBackupPath(opts.DataDir, c.name, "config")},
		HookScripts:  hooks,
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
	path := c.configPath(opts)
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
	case "cursor", "windsurf", "geminicli", "copilot":
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
	return homePath(".hermes", "config.yaml")
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
	root := strings.TrimSpace(CopilotWorkspaceDirOverride)
	if root == "" {
		root = strings.TrimSpace(opts.WorkspaceDir)
	}
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		}
	}
	if root == "" {
		root = "."
	}
	return filepath.Join(root, ".github", "hooks", "defenseclaw.json")
}

func workspaceRoot(opts SetupOpts) string {
	root := strings.TrimSpace(CopilotWorkspaceDirOverride)
	if root == "" {
		root = strings.TrimSpace(opts.WorkspaceDir)
	}
	if root == "" {
		if cwd, err := os.Getwd(); err == nil {
			root = cwd
		}
	}
	if root == "" {
		return "."
	}
	return root
}

func homePath(parts ...string) string {
	home := strings.TrimSpace(os.Getenv("HOME"))
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

func cursorSkillPaths(opts SetupOpts) []string {
	root := workspaceRoot(opts)
	return []string{
		filepath.Join(root, ".cursor", "skills"),
		filepath.Join(root, ".agents", "skills"),
		homePath(".cursor", "skills"),
		homePath(".agents", "skills"),
	}
}

func windsurfMCPPaths() []string {
	return []string{
		homePath(".codeium", "windsurf", "mcp_config.json"),
		homePath(".codeium", "windsurf", "mcp.json"),
	}
}

func existingWindsurfRulePaths(opts SetupOpts) []string {
	root := workspaceRoot(opts)
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
		"preToolUse",
		"postToolUse",
		"postToolUseFailure",
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
		"sessionStart",
		"sessionEnd",
		"preCompact",
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

func patchGeminiTelemetry(path string, opts SetupOpts) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	telemetry := ensureJSONObject(cfg, "telemetry")
	endpoint := "http://" + strings.TrimSpace(opts.APIAddr) + "/otlp/geminicli/" + url.PathEscape(opts.APIToken)
	telemetry["enabled"] = true
	telemetry["target"] = "otlp"
	telemetry["otlpEndpoint"] = endpoint
	telemetry["protocol"] = "http/json"
	telemetry["logPrompts"] = redaction.DisableAll()
	telemetry["managedBy"] = "defenseclaw"
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
		"PreToolUse",
		"PostToolUse",
		"PostToolUseFailure",
		"Stop",
		"SubagentStop",
		"PermissionRequest",
		"Notification",
		"PreCompact",
		"SessionStart",
		"SessionEnd",
		"UserPromptSubmit",
	} {
		entry := map[string]interface{}{
			"type":       "command",
			"bash":       shellWord(hookScript),
			"timeoutSec": 30,
		}
		hooks[event] = appendUniqueFlatHook(hooks[event], hookScript, entry)
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
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
