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
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"gopkg.in/yaml.v3"
)

var (
	HermesConfigPathOverride     string
	CursorHooksPathOverride      string
	CopilotHooksPathOverride     string
	CopilotWorkspaceDirOverride  string
	AntigravityHooksPathOverride string
	OpenCodePluginPathOverride   string
	// OpenCodeExecutablePathOverride is a process-local test seam for packages
	// that exercise the real Windows connector from a private fixture tree.
	// Production code never sets it and no environment/config input reaches it;
	// the default remains the current token's Known Folder WinGet package path.
	OpenCodeExecutablePathOverride string
)

var hermesConfigPathResolver = hermespath.ConfigPath

const (
	hermesAllowlistLogicalName      = "shell-hooks-allowlist.json"
	hermesAllowlistFileName         = "shell-hooks-allowlist.json"
	hermesAllowlistOwnerField       = "defenseclaw_managed"
	hermesAllowlistMaxBytes         = 2 << 20
	hermesDirectNativeStateFileName = "hermes-direct-native-state.json"
	hermesDirectNativeStateVersion  = 1
	hermesDirectNativePending       = "pending_reload"
	hermesDirectNativeDisabled      = "disabled_pending_reload"
	hermesInventoryConfigMaxBytes   = 1 << 20
)

var hermesRequiredHooks = []struct {
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
}

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

var openCodeWritePluginFile = atomicWriteFile

type openCodeFileSnapshot struct {
	data    []byte
	mode    os.FileMode
	existed bool
}

// PluginArtifactRegistrationSnapshot is an opaque, connector-local rollback
// point for an auto-loaded managed plugin and its custody receipt. It
// intentionally exposes no token or path contents outside this package.
type PluginArtifactRegistrationSnapshot struct {
	pluginPath     string
	plugin         openCodeFileSnapshot
	backupPath     string
	backup         openCodeFileSnapshot
	initiallyEmpty bool
}

// OpenCodeRegistrationSnapshot retains the established API name for callers
// that only manage OpenCode. Amp uses the same byte-exact plugin transaction.
type OpenCodeRegistrationSnapshot = PluginArtifactRegistrationSnapshot

func snapshotOpenCodeRegistrationFile(path string) (openCodeFileSnapshot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return openCodeFileSnapshot{}, nil
		}
		return openCodeFileSnapshot{}, err
	}
	if !info.Mode().IsRegular() {
		return openCodeFileSnapshot{}, fmt.Errorf("registration path is not a regular file: %s", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return openCodeFileSnapshot{}, err
	}
	mode := info.Mode().Perm()
	if runtime.GOOS == "windows" {
		// Go exposes synthetic 0666 mode bits for ordinary Windows files even
		// when their DACL is private. Rollback publication must still take the
		// atomic writer's owner-only path because the plugin contains a token and
		// the custody receipt can contain restored operator bytes.
		mode = 0o600
	}
	return openCodeFileSnapshot{data: body, mode: mode, existed: true}, nil
}

func restoreOpenCodeRegistrationFile(path string, snapshot openCodeFileSnapshot) error {
	if !snapshot.existed {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	mode := snapshot.mode
	if mode == 0 {
		mode = 0o600
	}
	return atomicWriteFile(path, snapshot.data, mode)
}

func rollbackOpenCodePluginPublication(
	pluginPath string,
	pluginSnapshot openCodeFileSnapshot,
	backupPath string,
	backupSnapshot openCodeFileSnapshot,
) error {
	var errs []error
	if err := restoreOpenCodeRegistrationFile(pluginPath, pluginSnapshot); err != nil {
		errs = append(errs, fmt.Errorf("restore plugin: %w", err))
	}
	if err := restoreOpenCodeRegistrationFile(backupPath, backupSnapshot); err != nil {
		errs = append(errs, fmt.Errorf("restore backup receipt: %w", err))
	}
	return errors.Join(errs...)
}

func capturePluginArtifactRegistrationSnapshot(
	opts SetupOpts,
	conn *hookOnlyConnector,
) (*PluginArtifactRegistrationSnapshot, error) {
	if conn == nil || !conn.pluginArtifact {
		return nil, errors.New("connector does not own a managed plugin artifact")
	}
	pluginPath := conn.configPath(opts)
	if err := prepareOpenCodePluginArtifactDestination(pluginPath, opts.DataDir); err != nil {
		return nil, fmt.Errorf("prepare %s plugin destination: %w", conn.name, err)
	}
	backupPath := managedFileBackupPath(opts.DataDir, conn.name, "config")
	plugin, err := snapshotOpenCodeRegistrationFile(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s plugin: %w", conn.name, err)
	}
	backup, err := snapshotOpenCodeRegistrationFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot %s custody receipt: %w", conn.name, err)
	}
	return &PluginArtifactRegistrationSnapshot{
		pluginPath:     pluginPath,
		plugin:         plugin,
		backupPath:     backupPath,
		backup:         backup,
		initiallyEmpty: !plugin.existed && !backup.existed,
	}, nil
}

// CapturePluginArtifactRegistrationSnapshot records the exact pre-reconcile
// plugin and receipt bytes for a supported auto-loaded plugin connector.
func CapturePluginArtifactRegistrationSnapshot(
	opts SetupOpts,
	connectorName string,
) (*PluginArtifactRegistrationSnapshot, error) {
	switch normalizeConnectorName(connectorName) {
	case "opencode":
		return capturePluginArtifactRegistrationSnapshot(opts, NewOpenCodeConnector())
	case "amp":
		return capturePluginArtifactRegistrationSnapshot(opts, NewAMPConnector().hookOnlyConnector)
	default:
		return nil, fmt.Errorf("connector %q does not own a supported managed plugin artifact", connectorName)
	}
}

// CaptureOpenCodeRegistrationSnapshot records OpenCode's exact pre-reconcile
// plugin and receipt bytes after validating destination custody.
func CaptureOpenCodeRegistrationSnapshot(opts SetupOpts) (*OpenCodeRegistrationSnapshot, error) {
	return CapturePluginArtifactRegistrationSnapshot(opts, "opencode")
}

// Restore atomically replaces or removes both connector-local files to match
// the pre-reconcile snapshot.
func (s *PluginArtifactRegistrationSnapshot) Restore() error {
	if s == nil {
		return errors.New("plugin registration snapshot is nil")
	}
	return rollbackOpenCodePluginPublication(s.pluginPath, s.plugin, s.backupPath, s.backup)
}

// InitiallyEmpty reports whether rollback should leave no managed plugin
// registration for VerifyClean to confirm.
func (s *PluginArtifactRegistrationSnapshot) InitiallyEmpty() bool {
	return s != nil && s.initiallyEmpty
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
		scriptName:  hermesHookScriptName,
		configPath:  hermesConfigPath,
		capability: func(opts SetupOpts) HookCapability {
			configPath := hermesConfigPath(opts)
			if validateHermesWindowsConfigPath(configPath) != nil {
				configPath = ""
			}
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"pre_tool_call"},
				SupportsFailClosed: false,
				Scope:              "user",
				ConfigPath:         configPath,
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
				// Cursor's documented user-hook contract accepts native deny
				// responses on these pre-action events. Higher-priority sources may
				// exist, but Cursor exposes no safe conflict-detection API; do not
				// infer a conflict when registering the ordinary user hook.
				CanBlock:     true,
				CanAskNative: false,
				BlockEvents: []string{
					"preToolUse", "subagentStart", "beforeShellExecution",
					"beforeMCPExecution", "beforeReadFile", "beforeTabFileRead",
					"beforeSubmitPrompt",
				},
				SupportsFailClosed: true,
				Scope:              "user",
				ConfigPath:         cursorHooksPath(opts),
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
			caps := HookCapability{
				CanBlock: true,
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
			// The vendor can ask, but its CLI hook omits prompt availability;
			// ordinary installs conservatively deny confirms. Secure Client
			// retains its established profile and response contract.
			if opts.SecureClientHookDelivery {
				caps.CanAskNative = true
				caps.AskEvents = []string{"preToolUse"}
			}
			return caps
		},
	}
}

// NewAntigravityConnector wires Google's Antigravity (`agy`) CLI through the
// unified hook collector. agy reads global hooks from
// ~/.gemini/config/hooks.json. PreToolUse and PostToolUse use matcher groups;
// PreInvocation, PostInvocation, and Stop use direct command-handler lists.
// PreToolUse supports documented allow/deny/ask/force_ask decisions;
// DefenseClaw sends deny for a block and force_ask for a confirmation.
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
	// Cursor and Copilot require connector-specific PowerShell adapters only
	// for their native Windows transports. Unix and macOS continue to use the
	// existing shell hooks.
	if runtime.GOOS == "windows" {
		switch c.name {
		case "cursor":
			return []string{c.scriptName, "cursor-hook.ps1"}
		case "copilot":
			return []string{c.scriptName, "copilot-hook.ps1"}
		}
	}
	return []string{c.scriptName}
}
func (c *hookOnlyConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return c.Capabilities(opts).Hooks
}

// HookProfile implements HookProfileProvider for the generic hook-only
// connectors, which are all hook-only: Copilot upstream documents an
// optional OTel exporter, but DefenseClaw does not configure or certify
// that surface.
//
// SupportsTraceparent is true for the entire generic family: every
// shipped hook script (cursor-hook.sh, hermes-hook.sh, copilot-hook.sh;
// see internal/gateway/connector/hooks/) sources _hardening.sh and
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
	if c.name == "opencode" {
		profile.MapVerdict = openCodeProfileMapVerdict
	}
	if c.name == "amp" {
		// Amp exposes an opaque plugin span ID but no documented W3C
		// traceparent propagation surface.
		profile.SupportsTraceparent = false
	}
	if c.name == "antigravity" {
		// Antigravity's documented stdin is camelCase and intentionally omits
		// the event name. Setup binds each handler to a distinct --event
		// argument; the bridge forwards that trusted registration metadata in
		// a header and the unified HTTP handler injects it before this decoder.
		// See antigravity_hook_profile.go for the exact official field mapping.
		profile.Decode = antigravityProfileDecode
		profile.DecodeToolArgs = antigravityToolArgsFromRawPayload
	}
	if c.name == "copilot" {
		// Copilot's hook body uses toolName/toolArgs on PreToolUse, while a
		// native PermissionRequest carries toolInput: the call's arguments
		// ({"command": ...} for bash and powershell), or a single-file diff
		// for an edit (copilotargs.PermissionToolArgs). Event identity
		// remains bound to Setup's registration and is supplied out-of-band
		// by the authenticated bridge.
		profile.Decode = copilotProfileDecode
	}
	if c.name == "cursor" {
		profile.Decode = cursorProfileDecode
	}
	if c.name == "devin" {
		profile.Decode = devinProfileDecode
	}
	// NOTE: hermes needs no Decode override. Its nested `extra` content
	// is read by the generic decoder from the ContentEnvelope its hook
	// contract declares, and its wire replies are
	// shaped by the hermes case in hookOnlyProfileRespond.
	profile = ApplyHookContract(profile, opts)
	if c.name == "copilot" {
		if opts.SecureClientHookDelivery {
			profile.Capabilities.CanAskNative = true
			profile.Capabilities.AskEvents = []string{"preToolUse"}
		} else {
			profile.MapVerdict = copilotCLIProfileMapVerdict
		}
	}
	return profile
}

func copilotProfileDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "copilot",
		CWD:           hookFirstString(payload, "cwd"),
		ToolName:      hookFirstString(payload, "toolName"),
	}
	args, present := payload["toolArgs"]
	if !present {
		if hookFirstString(payload, "hookName") == "permissionRequest" {
			if input, hasInput := payload["toolInput"]; hasInput {
				req.ToolArgsAuthoritative = true
				req.ToolArgs = copilotargs.PermissionToolArgs(req.ToolName, input)
			}
		}
		return req
	}
	req.ToolArgsAuthoritative = true
	// Copilot's hook reference types toolArgs as unknown, while the official
	// CLI hook tutorial documents and emits it as a JSON string. The hook-side
	// write-target resolver reads the same projection (hookpaths).
	req.ToolArgs = copilotargs.CLIToolArgs(req.ToolName, args)
	return req
}

// Cursor documents generation_id as the identifier for one user-message
// generation. Keep that connector-native turn mapping out of the generic
// decoder so another connector's generation identifier cannot become a turn.
func cursorProfileDecode(payload map[string]interface{}) HookProfileRequest {
	event := hookFirstString(payload,
		"hook_event_name", "hookEventName",
		"event_type", "eventType",
		"event_name", "eventName",
		"agent_action_name",
	)
	req := HookProfileRequest{
		ConnectorName: "cursor",
		HookEventName: event,
		TurnID: hookFirstString(payload,
			"generation_id", "generationId",
			"turn_id", "turnId", "turnID",
		),
		CWD:      hookFirstString(payload, "cwd"),
		ToolName: hookFirstString(payload, "tool_name"),
		Payload:  payload,
	}
	if input, ok := payload["tool_input"]; ok {
		if encoded, err := json.Marshal(input); err == nil {
			req.ToolArgs = encoded
		}
	}
	key := ""
	switch canonicalHookEvent(event) {
	case "posttooluse":
		key = "tool_output"
	case "posttoolusefailure":
		key = "error_message"
	case "aftershellexecution":
		key = "output"
	case "aftermcpexecution":
		key = "result_json"
	case "afterfileedit", "aftertabfileedit":
		key = "edits"
	case "afteragentresponse", "afteragentthought":
		key = "text"
	case "subagentstop":
		key = "summary"
	}
	if key != "" {
		req.Content = cursorHookContent(payload[key])
		req.Direction = "tool_result"
	}
	return req
}

const cursorHookContentMaxBytes = 256 * 1024

func cursorHookContent(value interface{}) string {
	var content string
	switch typed := value.(type) {
	case string:
		content = typed
	case nil:
		return ""
	default:
		encoded, err := json.Marshal(typed)
		if err != nil {
			return ""
		}
		content = string(encoded)
	}
	content = strings.ToValidUTF8(content, "\uFFFD")
	if len(content) <= cursorHookContentMaxBytes {
		return content
	}
	cut := cursorHookContentMaxBytes
	for cut > 0 && !utf8.RuneStart(content[cut]) {
		cut--
	}
	return content[:cut]
}

func (c *hookOnlyConnector) Capabilities(opts SetupOpts) ConnectorCapabilities {
	caps := ConnectorCapabilities{
		LLMTrafficMode: LLMTrafficModeForConnector(c.name),
		ACP:            ACPAgentCapabilityForConnector(c.name),
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
	case "amp":
		settings := ampSettingsPaths(opts)
		plugins := ampPluginPaths(opts)
		caps.MCP = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ConfigPaths:   settings,
			ReadPaths:     settings,
			DiscoveryOnly: true,
			RequiresOptIn: true,
			Notes: []string{
				"Amp MCP servers are discovered from the top-level amp.mcpServers setting; use `amp mcp add` for schema-preserving writes and workspace approval.",
				"Skill-bundled mcp.json servers are discovered through Amp skill roots and remain lower precedence than user/workspace settings.",
			},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      ampSkillPaths(opts),
			WritePaths:     ampSkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes: []string{
				"Amp AgentSkills use SKILL.md directories; amp.skills.path adds operator-configured roots and amp.skills.disableClaudeCodeSkills controls Claude-compatible roots.",
			},
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     plugins,
			DiscoveryOnly: true,
			Notes: []string{
				"Project and system TypeScript plugins are scanned. Connector setup manages only ~/.config/amp/plugins/defenseclaw.ts.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     ampRulePaths(opts),
			DiscoveryOnly: true,
			Notes: []string{
				"Amp consumes AGENTS.md and scoped/global .agents/checks definitions; DefenseClaw discovers these policy-bearing files without overwriting them.",
			},
		}
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "plugin",
			ReadPaths:     plugins,
			DiscoveryOnly: true,
			Notes: []string{
				"Amp custom agents and agent modes are plugin-defined rather than a standalone file surface.",
				"Built-in Oracle, Task, MCP, and plugin-tool delegation is enforced at tool.call; child threads are correlated independently when Amp emits their plugin events.",
			},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Telemetry = TelemetryCapability{
			NativeOTLP:  false,
			HookSignals: []string{"logs", "metrics", "traces"},
			ConfigPaths: []string{ampPluginPath(opts)},
			AuthMode:    "header-token",
			SourceModes: []string{"hook"},
			Notes: []string{
				"DefenseClaw emits Agent360, Galileo, audit, log, metric, and trace records from Amp's session.start, agent.start, tool.call, tool.result, and agent.end plugin events.",
				"Amp does not document a customer native-OTLP exporter or W3C traceparent propagation for plugins; thread, message, and toolUseID fields provide exact hook correlation.",
				"No dedicated subagent lifecycle callback is documented; delegation is controlled at tool.call and child-thread events are ingested when emitted.",
				"Headless `amp -x` action-mode runs must pass `--plugin-ready-timeout 30` so the policy plugin is loaded before the turn starts; fail-closed is authoritative only after plugin load.",
			},
		}
	case "hermes":
		configPath := hermesConfigPath(opts)
		if validateHermesWindowsConfigPath(configPath) != nil {
			caps.Hooks.ConfigPath = ""
			caps.MCP = SurfaceCapability{Supported: true, Scope: "user", SupportsBackup: true, SupportsRestore: true}
			caps.Skills = SurfaceCapability{Supported: true, Scope: "user", InstallTargets: []string{"skill"}, RequiresOptIn: true}
			caps.CodeGuard.Supported = true
			caps.CodeGuard.InstallTargets = []string{"skill"}
			caps.Plugins = SurfaceCapability{Supported: true, Scope: "user,installation", DiscoveryOnly: true}
			caps.Rules = SurfaceCapability{Supported: true, Scope: "user", DiscoveryOnly: true}
			caps.Agents = unsupportedSurface("Hermes subagent/agent asset locations are not installed by DefenseClaw v1.")
			break
		}
		hermesHome := filepath.Dir(configPath)
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "user",
			ConfigPaths:     []string{configPath},
			WritePaths:      []string{configPath},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"MCP servers are merged into the resolved Hermes config.yaml (HERMES_HOME or the platform default)."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user",
			ReadPaths:      hermesSkillPaths(configPath),
			WritePaths:     []string{filepath.Join(hermesHome, "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes: []string{
				"Inventory includes the default profile skills directory and existing skills.external_dirs resolved relative to HERMES_HOME.",
				"Named/multiplex profiles are unsupported and are not folded into this single-profile connector.",
			},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "user,installation",
			ReadPaths:     hermesPluginPaths(configPath),
			DiscoveryOnly: true,
			Notes: []string{
				"Hermes plugins are inventory/discovery-only in DefenseClaw v1; connector setup does not install or modify them.",
				"Inventory includes the default-profile user directory, the official HERMES_HOME/hermes-agent checkout, and the vendor HERMES_BUNDLED_PLUGINS override when present; official-venv Python entry-point activation is reported by the CLI inventory adapter.",
				"Project plugins depend on the Hermes process CWD plus HERMES_ENABLE_PROJECT_PLUGINS and remain unverified by this default-profile connector.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "user",
			ReadPaths:     []string{filepath.Join(hermesHome, "SOUL.md")},
			DiscoveryOnly: true,
			Notes: []string{
				"Hermes SOUL.md is the default profile identity source; project context files are session/CWD conditional and remain unverified.",
			},
		}
		caps.Agents = unsupportedSurface("Hermes subagent/agent asset locations are not installed by DefenseClaw v1.")
	case "cursor":
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     []string{workspacePath(opts, ".cursor", "mcp.json"), homePath(".cursor", "mcp.json")},
			WritePaths:      []string{workspacePath(opts, ".cursor", "mcp.json")},
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes: []string{
				"Project and user mcp.json files are locally inspectable; Cursor extension-registered dynamic servers and the effective same-name selection are unverified.",
				"Cloud, team, private marketplace, and multi-root runtime activation require official-client session evidence and are not inferred from this local inventory.",
			},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      cursorSkillPaths(opts),
			WritePaths:     []string{workspacePath(opts, ".cursor", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes: []string{
				"Cursor recursively discovers SKILL.md under .cursor/skills, .agents/skills, and the documented .claude/.codex compatibility roots at project and user scope; nested project .cursor/skills and .agents/skills roots are included.",
				"Discovery is bounded and does not follow links or Windows reparse points; multi-root, cloud, team, private, marketplace, and dynamic plugin skill activation remain unverified.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace",
			ReadPaths:      cursorRulePaths(opts),
			WritePaths:     []string{workspacePath(opts, ".cursor", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes: []string{
				"Inventory covers .cursor/rules/**/*.mdc and root or nested AGENTS.md without following links or reparse points.",
				"Cursor user rules, team rules, private sources, cloud activation, and multi-root effective selection are not represented by the local filesystem inventory.",
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
				"Marketplace, team/private, cloud, and dynamically registered plugin sources are unverified.",
			},
		}
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     cursorAgentPaths(opts),
			DiscoveryOnly: true,
			Notes: []string{
				"Cursor subagents are read from project and user .cursor/agents plus the documented .claude/agents and .codex/agents compatibility roots; project wins over user and .cursor wins within a scope.",
				"DefenseClaw inventories existing Cursor subagents only; connector setup does not install, remove, or modify them.",
				"Cloud, team/private, marketplace/dynamic, multi-root, and runtime-only subagent activation remain unverified.",
			},
		}
	case "devin":
		caps.MCP = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ConfigPaths:    devinMCPPaths(opts),
			ReadPaths:      devinMCPPaths(opts),
			WritePaths:     devinMCPWritePaths(opts),
			InstallTargets: []string{"mcp"},
			RequiresOptIn:  true,
			Notes: []string{
				"Devin CLI v3000.3 and later prefers dedicated mcp_config.json files; embedded MCP entries in config.json remain discovery-only for backward compatibility.",
				"Cloud Devin, proxy, team-managed, and dynamically registered MCP sources are outside this native local connector; devin acp is mediated separately by the shared ACP guard.",
			},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      devinSkillPaths(opts),
			WritePaths:     devinSkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes: []string{
				"Discovery covers Devin's user skills directory and the documented .agents/skills and .devin/skills project roots; installs use the native .devin/skills root.",
				"Discovery also reads the pre-rename Devin Desktop skill locations the vendor still loads; DefenseClaw never writes there.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      devinRulePaths(opts),
			WritePaths:     []string{workspacePath(opts, ".devin", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes: []string{
				"Discovery covers AGENTS.md/AGENT.md and Markdown rules under .devin/rules without claiming cloud or managed-policy precedence.",
				"Discovery also reads the pre-rename Devin Desktop rule locations the vendor still loads; DefenseClaw never writes there.",
			},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill", "rule"}
		caps.Plugins = unsupportedSurface("Devin plugins are closed beta; DefenseClaw makes no general plugin discovery or installation claim.")
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "user,workspace",
			ReadPaths:     devinAgentPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Custom Devin subagent definitions are inventoried read-only; DefenseClaw does not install or modify them."},
		}
	case "copilot":
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
			Notes:          []string{"Reads documented local project, inherited .github, personal, and COPILOT_SKILLS_DIRS sources in Copilot precedence order, followed by .claude/commands alternative Markdown skills. Same-name commands lose to every Agent Skill source. Plugin, built-in, and organization/remote skills are not expanded from private caches; plugins are listed separately through Copilot's official read-only command."},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "user,workspace,custom",
			ReadPaths:     copilotInstructionReadPaths(opts),
			DiscoveryOnly: true,
			Notes: []string{
				"Copilot combines applicable instruction files and documents no general precedence; inventory must surface collisions instead of choosing a winner.",
				"Path-specific applicability, active-file context, session toggles, folder trust, managed/organization policy, and remote instructions require official-client live inspection and remain unverified.",
			},
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			DiscoveryOnly: true,
			Notes:         []string{"Read-only discovery uses the official `copilot plugin list --json` command (falling back to `copilot plugins list --kind plugin --json` on older CLIs) under the validated pinned workspace and exact COPILOT_HOME. DefenseClaw does not install, enable, disable, or remove Copilot plugins; semantic activation and managed/organization policy remain unverified without live-session evidence."},
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
			Scope:         "workspace,user,plugin",
			ReadPaths:     antigravityRuleReadPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Antigravity global GEMINI.md, current .agents/rules, legacy .agent/rules, and plugin rules are bounded no-follow discovery-only sources. DefenseClaw does not write rules."},
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
	case "opencode":
		readPaths := opencodeMCPReadPaths(opts)
		writePaths := opencodeMCPWritePaths(opts)
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user,custom",
			ConfigPaths:     readPaths,
			ReadPaths:       readPaths,
			WritePaths:      writePaths,
			DiscoveryOnly:   len(writePaths) == 0,
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes: []string{
				"OpenCode MCP servers are read from locally representable global, project, home-component, and explicit OPENCODE_CONFIG/OPENCODE_CONFIG_DIR layers in client merge order.",
				"DefenseClaw writes the same authoritative local target as the CLI adapter and unsets a server from every active local file layer so a shadowed lower-precedence declaration cannot silently resurface.",
				"Authenticated remote .well-known configuration and Windows ProgramData enterprise policy are unverified; OPENCODE_CONFIG_CONTENT and unresolved relative environment paths make this surface discovery-only.",
			},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user,custom",
			ReadPaths:      opencodeSkillReadPaths(opts),
			WritePaths:     opencodeSkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"OpenCode loads Agent Skills from project .opencode/.claude/.agents roots and matching user/custom roots. DefenseClaw installs only to OpenCode's native .opencode or configuration-home skill target."},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"skill"}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user,custom",
			ReadPaths:     opencodeRuleReadPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"OpenCode AGENTS.md, CLAUDE.md fallback files, and config instructions are bounded discovery-only sources; DefenseClaw never overwrites operator instructions."},
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user,custom",
			ReadPaths:     opencodePluginReadPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"Third-party direct JS/TS plugins and configured plugin packages are inventory-only. Setup separately owns only the exact defenseclaw.js policy bridge with authenticated backup and restore custody."},
		}
		caps.Agents = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user,custom",
			ReadPaths:     opencodeAgentReadPaths(opts),
			DiscoveryOnly: true,
			Notes:         []string{"OpenCode singular/plural agent directories and config agent maps are discovery-only; DefenseClaw does not install or modify agents."},
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

// checkAgentSettings refuses Copilot's disableAllHooks, the operator's choice
// that Setup never overrides. Refusing before the hook scripts are written
// keeps the earlier registration; the patch refused after them, and the
// rollback removed it (GAP-0578).
func (c *hookOnlyConnector) checkAgentSettings(opts SetupOpts) error {
	if c.name != "copilot" {
		return nil
	}
	if err := validateCopilotOperatorSettings(opts); err != nil {
		return refuseForAgentConfig(fmt.Errorf("%w; fix that setting, then run: defenseclaw-gateway restart", err))
	}
	return nil
}

// hermesSetupWarningOutput receives Setup's warning about a Hermes release
// whose TUI runs tools without the hooks (the gateway's log).
var hermesSetupWarningOutput io.Writer = os.Stderr

func (c *hookOnlyConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := c.checkAgentSettings(opts); err != nil {
		return err
	}
	if c.name == "opencode" {
		if err := validateOpenCodeWindowsSetupAdmission(opts); err != nil {
			return executableAdmissionRefused(err)
		}
	}
	if c.name == "hermes" {
		// A Hermes whose TUI and dashboard chat run tools without the shell
		// hooks (GAP-0978) still runs them in its classic interface, cron,
		// ACP and messaging gateway: Setup registers them and says what they
		// miss. Refusing the release left every session unguarded.
		if warning := ResolveHookContract(c.name, opts.AgentVersion).Warning; warning != "" {
			fmt.Fprintf(hermesSetupWarningOutput, "[guardrail] WARNING: hermes %s: %s\n", strings.TrimSpace(opts.AgentVersion), warning)
		}
		configPath, err := hermesResolvedConfigPath(opts)
		if err != nil {
			return fmt.Errorf("%w; no changes made", err)
		}
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
			return err
		}
		if err := validateHermesSingleProfile(configPath); err != nil {
			return setupRefusedUnchanged{err: err}
		}
		if err := validateHermesWindowsSetupAdmission(ctx, opts); err != nil {
			return executableAdmissionRefused(err)
		}
		// An allowlist Setup cannot repair is refused before anything is
		// written: rolling back after the refusal tore down the hooks an
		// earlier DefenseClaw registered and left Hermes unguarded (GAP-1241).
		allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
		command := hermesConfiguredHookCommand(c.hookCommand(opts), opts.HookExecutable)
		if err := checkHermesAllowlistRepairable(allowlistPath, command); err != nil {
			return setupRefusedUnchanged{err: fmt.Errorf("%s hook config: %w", c.name, err)}
		}
		if err := prepareHermesLifecycleDataDir(opts); err != nil {
			return fmt.Errorf("prepare Hermes lifecycle state: %w", err)
		}
		return withOwnedFileLock(filepath.Join(opts.DataDir, ".hermes-lifecycle.lock"), func() error {
			// The home an earlier Setup bound the receipts to is released
			// first, or capturing the configured home fails on a target
			// mismatch (an upgrade from 1.0.3 on Windows, GAP-0499).
			bound, _, err := otherHermesHomes(opts, configPath)
			if err != nil {
				return fmt.Errorf("%w; no changes made", err)
			}
			if bound != "" {
				if errs := c.releaseHermesHome(opts, bound); len(errs) > 0 {
					return fmt.Errorf("hermes release the earlier Hermes home %s: %s", bound, strings.Join(errs, "; "))
				}
			}
			if err := c.setup(ctx, opts, configPath); err != nil {
				return err
			}
			// Best effort: without the record Verify counts every redirect
			// the hooks recorded, which only fails more.
			_ = recordHermesHomeSetUp(opts.DataDir, filepath.Dir(configPath), time.Now())
			return nil
		})
	}
	return c.setup(ctx, opts, "")
}

// prepareHermesLifecycleDataDir makes <data dir>, which holds Hermes'
// lifecycle lock, owner-private. On Windows the managed enterprise guardian
// creates and protects that directory itself: re-protecting it under the
// user's token needs the WRITE_DAC its DACL withholds (teardown failed with
// "Access is denied" and left Hermes' hooks), and doing so rewrote the
// inherited entries of every other subfolder to the user and SYSTEM only,
// so an administrator could not remove them. There it is used as it is.
func prepareHermesLifecycleDataDir(opts SetupOpts) error {
	if runtime.GOOS == "windows" && opts.ManagedEnterprise {
		if info, err := os.Lstat(opts.DataDir); err == nil && info.IsDir() {
			return nil
		}
	}
	return ensureManagedBackupDirRestricted(opts.DataDir)
}

func (c *hookOnlyConnector) setup(ctx context.Context, opts SetupOpts, hermesConfigPath string) error {
	_ = ctx
	if c.name == "hermes" {
		if err := validateHermesWindowsConfigPath(hermesConfigPath); err != nil {
			return err
		}
	}
	if c.pluginArtifact {
		return c.setupPluginArtifact(opts)
	}
	if c.name == "devin" {
		if err := c.migrateDevinConfigTarget(opts, c.configPath(opts)); err != nil {
			return err
		}
	}
	if c.name == "copilot" {
		// Pinning a workspace (for example `setup devin --workspace`) moves
		// Copilot's hooks between ~/.copilot/hooks and <workspace>/.github/hooks.
		if err := c.migrateConfigTarget(opts, c.configPath(opts), "Copilot"); err != nil {
			return err
		}
	}
	if err := c.migrateManagedBackup(opts); err != nil {
		return fmt.Errorf("%s managed backup migration: %w", c.name, err)
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("%s hook script: %w", c.name, err)
	}
	var err error
	if c.name == "hermes" {
		err = setupHermesFiles(opts, hermesConfigPath, c.hookCommand(opts))
	} else {
		err = c.patchConfig(opts, c.hookCommand(opts))
	}
	if err != nil {
		return fmt.Errorf("%s hook config: %w", c.name, err)
	}
	if c.name == "cursor" {
		present, err := c.ownedCursorHookContractPresent(opts)
		if err != nil {
			return fmt.Errorf("cursor verify persisted hook contract: %w", err)
		}
		if !present {
			return errors.New("cursor persisted hook contract does not match the requested mode")
		}
	}
	return nil
}

// migrateDevinConfigTarget closes the previous ownership cycle when the
// Devin hook config target changes, for example between the user-global
// config and a workspace hooks.v1.json. Without this, Setup over the old
// receipt fails with a backup target mismatch.
func (c *hookOnlyConnector) migrateDevinConfigTarget(opts SetupOpts, target string) error {
	return c.migrateConfigTarget(opts, target, "Devin")
}

// migrateConfigTarget restores or surgically cleans the file the "config"
// receipt is bound to when Setup now targets another path, then discards the
// receipt so patchConfig captures the new target.
func (c *hookOnlyConnector) migrateConfigTarget(opts SetupOpts, target, label string) error {
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.name, "config"))
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("load previous %s config backup: %w", label, err)
	}
	oldPath, err := validateManagedFileBackupTarget(backup, c.name, "config", backup.Path)
	if err != nil {
		return fmt.Errorf("validate previous %s config backup: %w", label, err)
	}
	newPath, err := normalizeManagedTargetPath(target)
	if err != nil {
		return fmt.Errorf("resolve new %s config target: %w", label, err)
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
		return fmt.Errorf("restore previous %s config target: %w", label, err)
	}
	if restored {
		return nil
	}
	if err := c.removeConfigEntries(oldPath, c.hookCommand(opts), opts); err != nil {
		return fmt.Errorf("remove previous %s hook entries: %w", label, err)
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
	return nil
}

// ownedHookContractPresent verifies the agent-visible plugin identity for
// plugin-artifact connectors. The generic config reader intentionally parses
// structured JSON/YAML/TOML hook registrations; an auto-loaded JavaScript
// plugin is instead authoritative when its exact versioned ownership marker
// is present in the installed regular file.
func (c *hookOnlyConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	if !c.pluginArtifact {
		hermesConfig := ""
		if c.name == "hermes" {
			// The config the account's Hermes reads, or not verified: an
			// unresolved home, another HERMES_HOME or a named profile. More
			// than one active config proves nothing either.
			var err error
			if hermesConfig, err = hermesVerifiedConfigPath(opts); err != nil {
				return false, err
			}
			if len(HookConfigPathsForConnector(c, opts)) != 1 {
				return false, nil
			}
		}
		present, err := ownedHooksPresentInConfig(c, opts)
		if err != nil || !present || c.name != "hermes" {
			return present, err
		}
		if !hermesRegisteredCommandExecutable(opts, c.hookCommand(opts)) {
			return false, nil
		}
		// Hermes runs a shell hook only once it is approved. Both per-user
		// and managed verification must read back every required approval;
		// an emptied allowlist makes the registration ineffective.
		command := hermesConfiguredHookCommand(c.hookCommand(opts), opts.HookExecutable)
		return hermesOwnedApprovalsPresent(filepath.Join(filepath.Dir(hermesConfig), hermesAllowlistFileName), command)
	}
	path := c.configPath(opts)
	const maxManagedPluginBytes = 4 << 20
	data, err := safefile.ReadRegularFileBounded(path, maxManagedPluginBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%s read managed plugin %s: %w", c.name, path, err)
	}
	tmpl, err := hookFS.ReadFile("hooks/" + c.pluginArtifactAsset)
	if err != nil {
		return false, fmt.Errorf("%s read plugin template %s: %w", c.name, c.pluginArtifactAsset, err)
	}
	marker, valid := managedPluginOwnershipMarker(tmpl)
	if !valid {
		return false, fmt.Errorf("%s managed plugin identity is invalid", c.name)
	}
	installedMarker, _, _ := bytes.Cut(data, []byte("\n"))
	installedMarker = bytes.TrimSuffix(installedMarker, []byte("\r"))
	if c.name == "opencode" {
		if pluginSecureClientProfile(opts) &&
			(!bytes.Contains(data, []byte(`const DC_NATIVE_POST_BINARY = "`)) ||
				!bytes.Contains(data, []byte(`return defenseclawNativePost(path, init);`))) {
			return false, nil
		}
		if !opts.ManagedEnterprise && (!bytes.Contains(data, []byte(`const DC_PER_USER_NATIVE_POST = "1";`)) ||
			!bytes.Contains(data, []byte(`execFileSync(binary, ["hook-post", "--api-addr", DC_API_ADDR]`))) {
			return false, nil
		}
		if managedPluginListenerProof(opts) {
			proofCall := []byte(`if (DC_LISTENER_PROOF) return defenseclawProvenTCPRequest(path, init, token);`)
			if !bytes.Contains(data, []byte(`const DC_LISTENER_PROOF = "1";`)) || !bytes.Contains(data, proofCall) {
				return false, nil
			}
		}
	}
	return bytes.Equal(installedMarker, marker), nil
}

// managedPluginHookSocket returns the unix hook socket and trusted service
// uid an in-agent plugin or connector shell hook must use, or ("", 0) to keep
// the TCP transport. Only a managed install on a unix host with an absolute
// socket path switches transports; Windows hooks and plugins keep TCP.
func managedPluginHookSocket(opts SetupOpts) (string, int) {
	socket := strings.TrimSpace(opts.ManagedHookSocket)
	if !opts.ManagedEnterprise || socket == "" || runtime.GOOS == "windows" || !filepath.IsAbs(socket) {
		return "", 0
	}
	uid := opts.ManagedServiceUID
	if uid < 0 {
		uid = 0
	}
	return filepath.Clean(socket), uid
}

// managedPluginForeignHookGuard returns the administrator-owned hook binary
// a standalone managed plugin runs for the foreign-hook guard, or "" for
// any other install.
func managedPluginForeignHookGuard(opts SetupOpts) string {
	binary := strings.TrimSpace(opts.ForeignHookGuardBinary)
	if !opts.ManagedEnterprise || binary == "" || !filepath.IsAbs(binary) {
		return ""
	}
	return filepath.Clean(binary)
}

// pluginSecureClientProfile reports a plugin rendered for the Secure Client
// managed profile: a managed install without the standalone profile's
// foreign-hook guard (standalone installs always render the guard). Its
// plugin bytes stay as the Secure Client release pins them.
func pluginSecureClientProfile(opts SetupOpts) bool {
	return opts.ManagedEnterprise && managedPluginForeignHookGuard(opts) == ""
}

// secureClientPluginAssets are the plugin templates the Secure Client
// profile renders instead of the current ones: copies of the templates its
// release pins, kept byte for byte (the plugin scanner recognizes both).
var secureClientPluginAssets = map[string]string{
	"opencode-plugin.js": "opencode-plugin-secure-client.js",
	"amp-plugin.ts":      "amp-plugin-secure-client.ts",
}

// pluginArtifactAssetFor is the embedded plugin template Setup renders for
// opts. Both templates share the ownership marker line, so verification
// reads either the same way.
func (c *hookOnlyConnector) pluginArtifactAssetFor(opts SetupOpts) string {
	if pluginSecureClientProfile(opts) {
		if pinned, ok := secureClientPluginAssets[c.pluginArtifactAsset]; ok {
			return pinned
		}
	}
	return c.pluginArtifactAsset
}

// managedPluginForeignHookGuardMarker is the rendered line a standalone
// managed plugin must carry; a plugin rendered before the guard existed
// (or with another binary) fails verification and is repaired.
func managedPluginForeignHookGuardMarker(opts SetupOpts, declaration, terminator string) []byte {
	binary := managedPluginForeignHookGuard(opts)
	if binary == "" {
		return nil
	}
	return []byte(declaration + `"` + javaScriptStringContent(binary) + `"` + terminator)
}

// managedPluginListenerProof reports whether an in-agent plugin must make
// the loopback TCP listener prove it is the gateway before sending its
// per-user credential (UserScopedListenerProof). Only a managed install that
// asks for it and keeps the TCP transport renders it; a plugin on the hook
// socket verifies the socket's owner instead.
func managedPluginListenerProof(opts SetupOpts) bool {
	if !opts.ManagedEnterprise || !opts.ManagedListenerProof || pluginSecureClientProfile(opts) {
		return false
	}
	socket, _ := managedPluginHookSocket(opts)
	return socket == ""
}

// managedPluginListenerProofJS is the rendered DC_LISTENER_PROOF value.
func managedPluginListenerProofJS(opts SetupOpts) string {
	if managedPluginListenerProof(opts) {
		return "1"
	}
	return ""
}

// managedPluginInstallMarker returns the install marker an in-agent plugin
// checks before failing closed, or "" when unused. Only a managed install
// with an absolute marker renders one.
func managedPluginInstallMarker(opts SetupOpts) string {
	marker := strings.TrimSpace(opts.ManagedInstallMarker)
	if !opts.ManagedEnterprise || marker == "" || !filepath.IsAbs(marker) {
		return ""
	}
	return filepath.Clean(marker)
}

// renderPluginArtifact is shared by Setup and standalone verification so
// verification compares the agent's executable plugin with the bytes Setup
// would install for the current options.
func (c *hookOnlyConnector) renderPluginArtifact(opts SetupOpts) ([]byte, error) {
	asset := c.pluginArtifactAssetFor(opts)
	tmpl, err := hookFS.ReadFile("hooks/" + asset)
	if err != nil {
		return nil, fmt.Errorf("%s read plugin template %s: %w", c.name, asset, err)
	}
	tokenPath, err := HookAPITokenFilePath(opts.DataDir, c.name)
	if err != nil {
		return nil, fmt.Errorf("%s resolve scoped hook credential: %w", c.name, err)
	}
	tokenPath, err = filepath.Abs(tokenPath)
	if err != nil {
		return nil, fmt.Errorf("%s resolve absolute scoped hook credential path: %w", c.name, err)
	}
	failMode := setupHookFailMode(opts)
	hookSocket, serviceUID := managedPluginHookSocket(opts)
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:             opts.APIAddr,
		TokenFileJS:         javaScriptStringContent(tokenPath),
		NativePostBinaryJS:  javaScriptStringContent(secureClientPluginNativePostBinary(opts)),
		HookSocketJS:        javaScriptStringContent(hookSocket),
		ServiceUID:          serviceUID,
		ForeignHookGuardJS:  javaScriptStringContent(managedPluginForeignHookGuard(opts)),
		InstallMarkerJS:     javaScriptStringContent(managedPluginInstallMarker(opts)),
		ListenerProofJS:     managedPluginListenerProofJS(opts),
		WindowsPowerShellJS: javaScriptStringContent(windowsSystemPowerShellExe()),
		FailMode:            failMode,
		Managed:             opts.ManagedEnterprise,
		SecureClient:        shellHookSecureClientProfile(opts),
		ConnectorName:       c.name,
	})
	if err != nil {
		return nil, fmt.Errorf("%s render plugin template: %w", c.name, err)
	}
	return []byte(rendered), nil
}

func secureClientPluginNativePostBinary(opts SetupOpts) string {
	if !pluginSecureClientProfile(opts) || !filepath.IsAbs(opts.HookExecutable) {
		return ""
	}
	return filepath.Clean(opts.HookExecutable)
}

// managedPluginArtifactDrift returns the managed plugin path when the
// installed plugin is missing or differs in any byte from the plugin Setup
// renders for opts, and "" when it matches or c installs no plugin.
func (c *hookOnlyConnector) managedPluginArtifactDrift(opts SetupOpts) (string, error) {
	if c == nil || !c.pluginArtifact {
		return "", nil
	}
	path := c.configPath(opts)
	expected, err := c.renderPluginArtifact(opts)
	if err != nil {
		return path, err
	}
	const maxManagedPluginBytes = 4 << 20
	installed, err := safefile.ReadRegularFileBounded(path, maxManagedPluginBytes)
	if os.IsNotExist(err) {
		return path, nil
	}
	if err != nil {
		return path, err
	}
	if !bytes.Equal(installed, expected) {
		return path, nil
	}
	return "", nil
}

// ManagedPluginArtifactDrift compares conn's managed in-agent plugin (Amp,
// OpenCode) with the bytes Setup renders for opts, and returns the plugin
// path when the installed file is missing or differs. The standalone
// guardian (Linux, macOS and Windows) relies on it rather than on the
// ownership markers or the recorded digests (the contract lock and the
// custody receipt): the user can edit the plugin and those digests together,
// a package upgrade leaves the previous release's plugin with both intact,
// and the agent runs every line of the plugin. It returns "" for a
// connector without a managed plugin. The file is read with the caller's
// credentials, bounded and without following a link.
func ManagedPluginArtifactDrift(conn Connector, opts SetupOpts) (string, error) {
	plugin, ok := conn.(interface {
		managedPluginArtifactDrift(SetupOpts) (string, error)
	})
	if !ok {
		return "", nil
	}
	return plugin.managedPluginArtifactDrift(opts)
}

// setupPluginArtifact writes the rendered bridge plugin to the host agent's
// auto-load directory at 0o600. Its scoped token stays in an owner-only
// sidecar. The managed-file backup lets Teardown restore a prior file only
// when it is unchanged since Setup.
func (c *hookOnlyConnector) setupPluginArtifact(opts SetupOpts) error {
	if !opts.ManagedEnterprise {
		if err := writePerUserGatewayHelperRecord(filepath.Join(opts.DataDir, "hooks")); err != nil {
			return fmt.Errorf("%s install helper record: %w", c.name, err)
		}
	}
	renderedBody, err := c.renderPluginArtifact(opts)
	if err != nil {
		return err
	}
	path := c.configPath(opts)
	if err := prepareOpenCodePluginArtifactDestination(path, opts.DataDir); err != nil {
		return fmt.Errorf("%s prepare plugin destination: %w", c.name, err)
	}
	backupPath := managedFileBackupPath(opts.DataDir, c.name, "config")
	pluginSnapshot, err := snapshotOpenCodeRegistrationFile(path)
	if err != nil {
		return fmt.Errorf("%s snapshot plugin destination: %w", c.name, err)
	}
	backupSnapshot, err := snapshotOpenCodeRegistrationFile(backupPath)
	if err != nil {
		return fmt.Errorf("%s snapshot plugin backup receipt: %w", c.name, err)
	}
	rollback := func(setupErr error) error {
		if rollbackErr := rollbackOpenCodePluginPublication(
			path, pluginSnapshot, backupPath, backupSnapshot,
		); rollbackErr != nil {
			return errors.Join(setupErr, fmt.Errorf("%s rollback plugin publication: %w", c.name, rollbackErr))
		}
		return setupErr
	}
	if err := validatePluginArtifactDestination(path); err != nil {
		return fmt.Errorf("%s validate plugin destination: %w", c.name, err)
	}
	if err := captureManagedFileBackup(opts.DataDir, c.name, "config", path); err != nil {
		return rollback(fmt.Errorf("%s capture plugin backup: %w", c.name, err))
	}
	// Finalize the custody receipt before the atomic plugin replacement. This
	// ordering guarantees that a visible DefenseClaw plugin never precedes the
	// backup/post-hash record needed to own and restore it.
	if err := updateManagedFileBackupPostHashValue(
		opts.DataDir,
		c.name,
		"config",
		path,
		managedFileSnapshotHash(renderedBody, true),
	); err != nil {
		return rollback(fmt.Errorf("%s finalize plugin backup receipt: %w", c.name, err))
	}
	receipt, err := loadManagedFileBackupPath(backupPath)
	if err != nil || managedFileBackupExpectedHash(&receipt) != managedFileSnapshotHash(renderedBody, true) {
		if err == nil {
			err = errors.New("receipt post hash does not match rendered plugin")
		}
		return rollback(fmt.Errorf("%s verify plugin backup receipt: %w", c.name, err))
	}
	if err := openCodeWritePluginFile(path, renderedBody, 0o600); err != nil {
		return rollback(fmt.Errorf("%s write plugin: %w", c.name, err))
	}
	// The plugin carries its own fail mode and reads no shell hook runtime
	// record. An earlier release or reconcile may have left a stale mode in
	// that record (GAP-0635). Clean it after publishing the plugin: damage to
	// unused shared state must neither block Setup nor alter that state.
	if !opts.ManagedEnterprise {
		hookDir := filepath.Join(opts.DataDir, "hooks")
		if err := clearHookConfigSidecarEntry(hookDir, c.name); err != nil {
			log.Printf("[connector] %s setup: could not remove unused hook runtime record in %s: %v", c.name, hookDir, err)
		}
	}
	return nil
}

// OpenCodeRegistrationCurrent verifies the connector-local publication unit:
// the managed plugin is the exact rendered artifact and its custody receipt
// names the same path and post-write digest. It does not claim that an
// OpenCode process is running; runtime load is diagnosed separately by the
// plugin heartbeat.
func OpenCodeRegistrationCurrent(opts SetupOpts) (bool, error) {
	conn := NewOpenCodeConnector()
	present, err := OwnedHooksPresent(conn, opts)
	if err != nil || !present {
		return false, err
	}
	path := conn.configPath(opts)
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, conn.name, "config"))
	if err != nil {
		return false, err
	}
	bound, err := validateManagedFileBackupTarget(backup, conn.name, "config", path)
	if err != nil {
		return false, err
	}
	body, info, err := readManagedTarget(bound)
	if err != nil {
		return false, err
	}
	if info == nil {
		return false, nil
	}
	return managedFileBackupExpectedHash(&backup) == managedFileSnapshotHash(body, true), nil
}

func javaScriptStringContent(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil || len(encoded) < 2 {
		return ""
	}
	return string(encoded[1 : len(encoded)-1])
}

// validatePluginArtifactDestination protects the integrity of the managed
// policy bridge. Plugin directories are host-agent auto-load locations, so
// they must meet the same owner/ACL requirements as the hook API token tree.
// Unlike ordinary agent config writes, plugin installation never follows a
// symlink: an existing target must be the trusted regular file we inspected.
func validatePluginArtifactDestination(path string) error {
	return validatePluginArtifactDestinationFor(path, "")
}

// validatePluginArtifactDestinationFor also trusts trustedOwnerSID, the
// per-user target a Windows guardian verifies without that user's token.
func validatePluginArtifactDestinationFor(path, trustedOwnerSID string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("plugin path must be absolute: %q", path)
	}
	if err := hookAPIValidateDirectoryFor(filepath.Dir(filepath.Clean(path)), trustedOwnerSID); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("inspect plugin target %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("plugin target must not be a symlink: %s", path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("plugin target must be a regular file: %s", path)
	}
	if err := hookAPIValidateOwnerFor(path, info, trustedOwnerSID); err != nil {
		return err
	}
	return nil
}

// hookCommand returns the command an agent runs for this connector's hook. On
// Unix it is the bundled .sh path. Most Windows connectors use the native
// DefenseClaw `hook` subcommand; Cursor and Copilot
// use PowerShell adapters for their documented Windows transports. The same value is used at setup,
// teardown, and VerifyClean so the JSON/YAML hook removers (which match on the
// exact command string) recognize the entries DefenseClaw added.
func (c *hookOnlyConnector) hookCommand(opts SetupOpts) string {
	return c.hookCommandForOS(runtime.GOOS, opts)
}

func (c *hookOnlyConnector) hookCommandForOS(goos string, opts SetupOpts) string {
	unixCommand := filepath.Join(opts.DataDir, "hooks", c.scriptName)
	if goos == "windows" && c.name == "hermes" {
		return windowsHermesDirectHookCommand(hermesHookExecutable(goos, opts))
	}
	if c.name == "devin" {
		if command := devinManagedHookCommand(goos, opts); command != "" {
			return command
		}
		if goos != "windows" {
			// Devin runs the command through bash (GAP-0382).
			return posixHookCommandWord(unixCommand)
		}
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
	if c.name == "hermes" {
		configPath := c.configPath(opts)
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
			return err
		}
		if err := prepareHermesLifecycleDataDir(opts); err != nil {
			return fmt.Errorf("prepare Hermes lifecycle state: %w", err)
		}
		if err := withOwnedFileLock(filepath.Join(opts.DataDir, ".hermes-lifecycle.lock"), func() error {
			return c.teardown(ctx, opts, configPath)
		}); err != nil {
			return err
		}
	} else {
		if c.name == "copilot" {
			removeOrphanedCopilotVSCodeLocalRendersForPerUser(opts)
		}
		if err := c.teardown(ctx, opts, ""); err != nil {
			return err
		}
	}
	if !opts.ManagedEnterprise && opts.DataDir != "" {
		// A cached hook command finds its disabled tombstone after teardown.
		// Revoke only once the host registration is proven gone.
		if err := c.VerifyClean(opts); err != nil {
			if !c.pluginArtifact {
				return err
			}
			// An operator-edited plugin remains by design; its registration
			// cannot be proven gone, so keep the credential for this teardown.
		} else {
			if err := revokePerUserHookAPIToken(opts, c.name); err != nil {
				return err
			}
		}
	}
	if c.name == "devin" && !opts.ManagedEnterprise {
		backupDir := filepath.Join(opts.DataDir, "connector_backups", c.name)
		info, err := os.Lstat(backupDir)
		switch {
		case os.IsNotExist(err):
			return nil
		case err != nil:
			return fmt.Errorf("devin inspect backup directory: %w", err)
		case !info.IsDir() || info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("devin backup directory is not a regular directory: %s", backupDir)
		}
		entries, err := os.ReadDir(backupDir)
		if err != nil {
			return fmt.Errorf("devin list backup directory: %w", err)
		}
		if len(entries) == 0 {
			if err := os.Remove(backupDir); err != nil && !os.IsNotExist(err) {
				return fmt.Errorf("devin remove empty backup directory: %w", err)
			}
		}
	}
	return nil
}

func (c *hookOnlyConnector) teardown(ctx context.Context, opts SetupOpts, hermesConfigPath string) error {
	_ = ctx
	if c.name == "hermes" {
		if err := validateHermesWindowsConfigPath(hermesConfigPath); err != nil {
			return err
		}
	}
	if c.pluginArtifact {
		return c.teardownPluginArtifact(opts)
	}
	if err := c.migrateManagedBackup(opts); err != nil {
		return fmt.Errorf("%s managed backup migration: %w", c.name, err)
	}
	if c.name == "hermes" && runtime.GOOS == "windows" && c.hookCommand(opts) != "" {
		if err := writeHermesDirectNativeState(opts, c.hookCommand(opts), hermesDirectNativeDisabled); err != nil {
			return fmt.Errorf("hermes disabled direct-native tombstone: %w", err)
		}
	}
	var errs []string

	logicalName := c.managedBackupLogicalName()
	path := hermesConfigPath
	if c.name == "hermes" {
		errs = append(errs, c.releaseOtherHermesHomes(opts, path)...)
		errs = append(errs, c.releaseHermesHome(opts, path)...)
	} else {
		path = managedFileBackupTargetPath(opts.DataDir, c.name, logicalName, c.configPath(opts))
		errs = append(errs, c.teardownConfig(opts, logicalName, path)...)
	}

	if c.name == "cursor" {
		if err := removeCursorHookArtifacts(opts); err != nil {
			errs = append(errs, fmt.Sprintf("remove Cursor hook artifacts: %v", err))
		}
	} else if err := writeDisabledHookTombstone(opts, c.scriptName, c.name); err != nil {
		errs = append(errs, fmt.Sprintf("disabled hook tombstone: %v", err))
	}
	// The last known good copy of an agent config holds the account's
	// settings and is of no use once DefenseClaw no longer manages the file
	// (GAP-0564).
	if spec, ok := agentConfigSpecFor(c.name); ok && len(errs) == 0 {
		if err := spec.removeCopies(opts.DataDir); err != nil {
			errs = append(errs, fmt.Sprintf("remove the copy of %s: %v", path, err))
		}
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s teardown: %s", c.name, strings.Join(errs, "; "))
	}
	return nil
}

// teardownConfig restores the agent config path the "config" receipt holds,
// or removes only DefenseClaw's entries from it, as Teardown does for every
// hook-only connector but Hermes (releaseHermesHome).
func (c *hookOnlyConnector) teardownConfig(opts SetupOpts, logicalName, path string) []string {
	var errs []string
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, logicalName, path)
	switch {
	case err != nil:
		errs = append(errs, restoreBackupFailure(err))
	case restored && c.name == "devin":
		// A Devin backup captured after an earlier DefenseClaw setup (the
		// per-user devin-hook.sh route) holds DefenseClaw's own hooks, which
		// the restore just put back; they go too.
		owned := devinOwnedHookCommands(opts, c.hookCommand(opts))
		if present, err := devinConfigReferencesHook(path, owned...); err != nil {
			errs = append(errs, fmt.Sprintf("inspect restored config: %v", err))
		} else if present {
			if err := removeDevinHookReferences(path, owned...); err != nil {
				errs = append(errs, fmt.Sprintf("remove hook entries from the restored config: %v", err))
			}
		}
	case restored && c.name == "copilot":
		// The same for a backup captured after a rollback: the earlier
		// release's gateway registered its own hooks again before this
		// release's setup took the backup (GAP-1926). A file that does not
		// parse is the operator's and stays as restored.
		hookScript := c.hookCommand(opts)
		if cfg, err := readJSONObject(path); err == nil && containsHookScript(cfg, hookScript) {
			if err := c.removeConfigEntries(path, hookScript, opts); err != nil {
				errs = append(errs, fmt.Sprintf("remove hook entries from the restored config: %v", err))
			}
		}
	case restored && c.name == "cursor":
		// The same for a Cursor hooks.json captured after an earlier
		// DefenseClaw setup whose data directory was removed (GAP-2064).
		owned := cursorOwnedHookCommands(opts)
		if cfg, err := readJSONObject(path); err == nil && structuredHookCommandReferences(cfg, owned) {
			if err := removeJSONHookReferencesProfile(path, pluginSecureClientProfile(opts), owned...); err != nil {
				errs = append(errs, fmt.Sprintf("remove hook entries from the restored config: %v", err))
			}
		}
	case restored:
	case !restored:
		if err := c.removeConfigEntriesWithManagedBackup(
			opts,
			logicalName,
			path,
			c.hookCommand(opts),
		); err != nil {
			errs = append(errs, fmt.Sprintf("remove hook entries: %v", err))
		} else if err := c.keepOperatorEmptyHooks(opts, logicalName, path); err != nil {
			errs = append(errs, fmt.Sprintf("keep the empty hooks object: %v", err))
		} else {
			discardManagedFileBackup(opts.DataDir, c.name, logicalName)
		}
	}
	if c.name == "antigravity" {
		// DefenseClaw's Antigravity entries are its own by their outer key,
		// also in a hooks.json the restore just put back that was captured
		// after an earlier DefenseClaw setup (one a rolled-back install left),
		// and when they run a command this release does not render.
		if err := removeAntigravityOwnedHookEntries(path); err != nil {
			errs = append(errs, fmt.Sprintf("remove DefenseClaw hook entries: %v", err))
		}
	}
	return errs
}

// releaseHermesHome takes DefenseClaw's hooks and approvals out of the
// Hermes home of configPath. A captured config.yaml is put back when the
// file is unchanged since Setup, unless the copy itself registers
// DefenseClaw's hook (a file put back from an earlier enrollment); otherwise
// only DefenseClaw's entries are removed. The allowlist follows
// (teardownHermesAllowlist), and the receipts are discarded.
func (c *hookOnlyConnector) releaseHermesHome(opts SetupOpts, configPath string) []string {
	var errs []string
	hookScript := c.hookCommand(opts)
	var restored bool
	var err error
	if !hermesConfigBackupHoldsOwnedHooks(opts.DataDir, hermesConfigLogicalName, configPath, hookScript) {
		restored, err = restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, hermesConfigLogicalName, configPath)
	}
	switch {
	case err != nil:
		errs = append(errs, restoreBackupFailure(err))
	case !restored:
		if err := c.removeConfigEntriesWithManagedBackup(opts, hermesConfigLogicalName, configPath, hookScript); err != nil {
			errs = append(errs, fmt.Sprintf("remove hook entries: %v", err))
		} else {
			discardManagedFileBackup(opts.DataDir, c.name, hermesConfigLogicalName)
		}
	}
	command := hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
	if err := teardownHermesAllowlist(opts, configPath, command); err != nil {
		errs = append(errs, fmt.Sprintf("restore shell hook allowlist: %v", err))
	}
	return errs
}

// hermesConfigLogicalName is the receipt of the Hermes config.yaml.
const hermesConfigLogicalName = "config.yaml"

// otherHermesHomes returns the Hermes configs besides configPath that can
// hold this data directory's hooks: the one the config receipt of an
// earlier Setup is bound to ("" when it is configPath or there is none),
// and the account's profile default when it differs from both. Up to
// 1.0.3 the Windows guardian set up the profile default
// %LOCALAPPDATA%\hermes whatever HERMES_HOME the account configured, and
// bound the receipts to it (GAP-0499). HermesConfigPathOverride names the
// only home.
func otherHermesHomes(opts SetupOpts, configPath string) (bound, profileDefault string, err error) {
	if HermesConfigPathOverride != "" {
		return "", "", nil
	}
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, "hermes", hermesConfigLogicalName))
	if err != nil && !os.IsNotExist(err) {
		return "", "", fmt.Errorf("load the Hermes config receipt: %w", err)
	}
	if err == nil {
		if bound, err = validateManagedFileBackupTarget(backup, "hermes", hermesConfigLogicalName, backup.Path); err != nil {
			return "", "", fmt.Errorf("validate the Hermes config receipt: %w", err)
		}
		if sameManagedTarget(bound, configPath) {
			bound = ""
		}
	}
	profileDefault = hermespath.ConfigPathForUserHome(userHomeDir())
	if profileDefault == "" || sameManagedTarget(profileDefault, configPath) || (bound != "" && sameManagedTarget(profileDefault, bound)) {
		profileDefault = ""
	}
	return bound, profileDefault, nil
}

func sameManagedTarget(a, b string) bool {
	a, errA := normalizeManagedTargetPath(a)
	b, errB := normalizeManagedTargetPath(b)
	if errA != nil || errB != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// releaseOtherHermesHomes takes this data directory's hooks out of the
// Hermes homes besides configPath (otherHermesHomes): the home the receipts
// are bound to is released as Teardown releases it, and the profile
// default loses DefenseClaw's own entries. Otherwise the receipts made
// Setup and Teardown of the configured home fail on a target mismatch, and
// the default home kept hooks that run a removed executable after
// uninstall.
func (c *hookOnlyConnector) releaseOtherHermesHomes(opts SetupOpts, configPath string) []string {
	bound, profileDefault, err := otherHermesHomes(opts, configPath)
	if err != nil {
		return []string{err.Error()}
	}
	var errs []string
	if bound != "" {
		for _, failure := range c.releaseHermesHome(opts, bound) {
			errs = append(errs, fmt.Sprintf("%s: %s", bound, failure))
		}
	}
	if profileDefault != "" {
		if err := c.removeHermesHomeEntries(opts, profileDefault); err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", profileDefault, err))
		}
	}
	return errs
}

// removeHermesHomeEntries removes this data directory's hooks and the
// approvals for them from a Hermes home no receipt is bound to.
func (c *hookOnlyConnector) removeHermesHomeEntries(opts SetupOpts, configPath string) error {
	hookScript := c.hookCommand(opts)
	command := hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
	hooks, approvals, err := hermesHomeHoldsOwnedEntries(configPath, hookScript, command)
	if err != nil {
		return err
	}
	if hooks {
		if err := removeHermesHooks(configPath, hookScript, nil); err != nil {
			return fmt.Errorf("remove hook entries: %w", err)
		}
	}
	if approvals {
		if err := removeHermesOwnedApprovals(filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName), command, nil); err != nil {
			return fmt.Errorf("remove shell hook approvals: %w", err)
		}
	}
	return nil
}

// hermesHomeHoldsOwnedEntries reports whether the Hermes home of configPath
// registers this data directory's hook (hookScript) or holds DefenseClaw's
// approval of its command.
func hermesHomeHoldsOwnedEntries(configPath, hookScript, command string) (hooks, approvals bool, err error) {
	cfg, err := readYAMLObject(configPath)
	if err != nil {
		return false, false, err
	}
	hooks = containsHookScript(cfg["hooks"], hookScript)
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	document, err := readHermesAllowlist(allowlistPath)
	if err != nil {
		return false, false, err
	}
	for _, raw := range document["approvals"].([]interface{}) {
		entry, _ := raw.(map[string]interface{})
		owned, _ := entry[hermesAllowlistOwnerField].(bool)
		entryCommand, _ := entry["command"].(string)
		if owned && entryCommand == command {
			approvals = true
		}
	}
	return hooks, approvals, nil
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
//
// Without a backup receipt (the user deleted the DefenseClaw data directory)
// there is no edit to protect: a plugin whose first line is DefenseClaw's
// ownership marker is DefenseClaw's and is removed; any other file stays.
func (c *hookOnlyConnector) teardownPluginArtifact(opts SetupOpts) error {
	if _, err := os.Lstat(managedFileBackupPath(opts.DataDir, c.name, "config")); os.IsNotExist(err) {
		return c.removeOwnedPluginWithoutBackup(c.configPath(opts))
	} else if err != nil {
		return fmt.Errorf("%s inspect plugin backup: %w", c.name, err)
	}
	path := managedFileBackupTargetPath(opts.DataDir, c.name, "config", c.configPath(opts))
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.name, "config", path)
	if err != nil {
		return fmt.Errorf("%s restore plugin backup: %w", c.name, err)
	}
	if !restored {
		// The plugin was hand-edited after setup; leave it, and its
		// receipt, for the operator rather than clobbering their changes.
		// Doctor surfaces the lingering managed plugin. A plugin
		// DefenseClaw created that is gone leaves nothing to restore.
		if b, loadErr := loadManagedFileBackupPath(managedFileBackupPath(opts.DataDir, c.name, "config")); loadErr == nil && !b.Existed {
			if _, statErr := os.Lstat(path); errors.Is(statErr, os.ErrNotExist) {
				discardManagedFileBackup(opts.DataDir, c.name, "config")
			}
		}
		return nil
	}
	discardManagedFileBackup(opts.DataDir, c.name, "config")
	// A plugin captured after an earlier DefenseClaw setup (one a
	// rolled-back install or a removed data directory left) is DefenseClaw's
	// own, so putting it back would leave the registration in place; it goes
	// too (GAP-2064). Any other restored file stays.
	return c.removeOwnedPluginWithoutBackup(path)
}

// removeOwnedPluginWithoutBackup deletes the plugin at path when it is a
// regular file whose first line is a DefenseClaw ownership marker (any
// version, so an older DefenseClaw's plugin is recognized too) in a trusted
// plugin directory. Any other file is left alone.
func (c *hookOnlyConnector) removeOwnedPluginWithoutBackup(path string) error {
	const maxManagedPluginBytes = 4 << 20
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return fmt.Errorf("%s inspect plugin %s: %w", c.name, path, err)
	}
	if !info.Mode().IsRegular() {
		return nil
	}
	data, err := safefile.ReadRegularFileBounded(path, maxManagedPluginBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("%s read plugin %s: %w", c.name, path, err)
	}
	firstLine, _, _ := bytes.Cut(data, []byte("\n"))
	if !validManagedPluginOwnershipMarker(bytes.TrimSuffix(firstLine, []byte("\r"))) {
		return nil
	}
	if err := validatePluginArtifactDestination(path); err != nil {
		return fmt.Errorf("%s validate plugin %s for removal: %w", c.name, path, err)
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("%s remove plugin %s: %w", c.name, path, err)
	}
	return nil
}

func (c *hookOnlyConnector) VerifyClean(opts SetupOpts) error {
	logicalName := c.managedBackupLogicalName()
	configPath := c.configPath(opts)
	if c.name == "hermes" {
		resolved, err := hermesResolvedConfigPath(opts)
		if err != nil {
			return fmt.Errorf("hermes teardown not verified: %w", err)
		}
		configPath = resolved
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
			return err
		}
		if err := verifyOtherHermesHomesClean(opts, configPath, c.hookCommand(opts)); err != nil {
			return err
		}
	}
	path := managedFileBackupTargetPath(opts.DataDir, c.name, logicalName, configPath)
	if c.name == "hermes" {
		path = configPath
	}
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			if c.name == "hermes" {
				command := hermesConfiguredHookCommand(c.hookCommand(opts), opts.HookExecutable)
				return verifyHermesCleanup(opts, configPath, command)
			}
			return c.verifyCursorHookArtifactsClean(opts)
		}
		return err
	} else if c.pluginArtifact && c.name == "amp" {
		if _, backupErr := os.Stat(managedFileBackupPath(opts.DataDir, c.name, "config")); backupErr == nil {
			return fmt.Errorf("%s teardown incomplete: managed plugin still present at %s", c.name, path)
		} else if !os.IsNotExist(backupErr) {
			return fmt.Errorf("%s inspect managed plugin backup: %w", c.name, backupErr)
		}
		tmpl, templateErr := hookFS.ReadFile("hooks/" + c.pluginArtifactAsset)
		if templateErr != nil {
			return fmt.Errorf("%s read managed plugin identity: %w", c.name, templateErr)
		}
		marker, valid := managedPluginOwnershipMarker(tmpl)
		if !valid {
			return fmt.Errorf("%s managed plugin identity is invalid", c.name)
		}
		if managedPluginOwnershipMarkerPresent(data, marker) {
			return fmt.Errorf("%s teardown incomplete: managed plugin still present at %s", c.name, path)
		}
		return nil
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
	if c.name == "devin" {
		present, parseErr := devinConfigReferencesHook(
			path,
			devinOwnedHookCommands(opts, needle)...,
		)
		if parseErr != nil {
			return fmt.Errorf("%s teardown verification could not parse hook config %s: %w", c.name, path, parseErr)
		}
		if present {
			return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
		}
	}
	if c.name == "antigravity" {
		if owned, err := AntigravityHooksHoldOwnedEntries(path); err != nil || owned {
			if err != nil {
				return fmt.Errorf("antigravity teardown verification could not read %s: %w", path, err)
			}
			return fmt.Errorf("antigravity teardown incomplete: DefenseClaw hook registrations remain in %s", path)
		}
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
		(c.name == "antigravity" && bytes.Contains(data, []byte(legacyAntigravityNonWaitingWindowsHookCommand()))) {
		return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
	}
	if c.name == "hermes" {
		return verifyHermesCleanup(opts, configPath, hermesConfiguredHookCommand(needle, opts.HookExecutable))
	}
	return c.verifyCursorHookArtifactsClean(opts)
}

// verifyOtherHermesHomesClean fails while a Hermes home besides configPath
// (otherHermesHomes) still holds this data directory's hooks or approvals.
func verifyOtherHermesHomesClean(opts SetupOpts, configPath, hookScript string) error {
	bound, profileDefault, err := otherHermesHomes(opts, configPath)
	if err != nil {
		return fmt.Errorf("hermes teardown not verified: %w", err)
	}
	command := hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
	for _, other := range []string{bound, profileDefault} {
		if other == "" {
			continue
		}
		hooks, approvals, err := hermesHomeHoldsOwnedEntries(other, hookScript, command)
		if err != nil {
			return fmt.Errorf("hermes teardown not verified: %s: %w", other, err)
		}
		if hooks || approvals {
			return fmt.Errorf("hermes teardown incomplete: DefenseClaw hook entries remain in %s", other)
		}
	}
	return nil
}

func verifyHermesCleanup(opts SetupOpts, configPath, command string) error {
	if err := validateHermesWindowsConfigPath(configPath); err != nil {
		return err
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	if _, err := os.Stat(allowlistPath); err == nil {
		document, err := readHermesAllowlist(allowlistPath)
		if err != nil {
			return err
		}
		for _, raw := range document["approvals"].([]interface{}) {
			entry, ok := raw.(map[string]interface{})
			if !ok {
				continue
			}
			if owned, _ := entry[hermesAllowlistOwnerField].(bool); owned {
				return fmt.Errorf("hermes teardown incomplete: managed shell hook approval remains at %s", allowlistPath)
			}
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	statePath := filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName)
	data, err := os.ReadFile(statePath)
	if err != nil {
		if os.IsNotExist(err) {
			// A fresh profile has never registered a direct-native Hermes hook and
			// therefore has no disabled state to prove. The lifecycle lock is a
			// persistent marker: once Setup or Teardown has run, a missing state
			// remains a cleanup failure instead of being mistaken for fresh state.
			lockPath := filepath.Join(opts.DataDir, ".hermes-lifecycle.lock")
			if _, lockErr := os.Lstat(lockPath); os.IsNotExist(lockErr) {
				return nil
			} else if lockErr != nil {
				return fmt.Errorf("hermes teardown incomplete: inspect lifecycle marker: %w", lockErr)
			}
		}
		return fmt.Errorf("hermes teardown incomplete: disabled direct-native tombstone is unavailable: %w", err)
	}
	var state struct {
		SchemaVersion  int    `json:"schema_version"`
		Connector      string `json:"connector"`
		Status         string `json:"status"`
		Command        string `json:"command"`
		ReloadRequired bool   `json:"reload_required"`
	}
	if err := json.Unmarshal(data, &state); err != nil {
		return fmt.Errorf("hermes teardown incomplete: parse disabled direct-native tombstone: %w", err)
	}
	if state.SchemaVersion != hermesDirectNativeStateVersion || state.Connector != "hermes" ||
		state.Status != hermesDirectNativeDisabled || state.Command != command || !state.ReloadRequired {
		return fmt.Errorf("hermes teardown incomplete: disabled direct-native tombstone does not match the registered command")
	}
	return nil
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

func managedPluginOwnershipMarker(template []byte) ([]byte, bool) {
	marker, _, _ := bytes.Cut(template, []byte("\n"))
	marker = bytes.TrimSuffix(marker, []byte("\r"))
	return marker, validManagedPluginOwnershipMarker(marker)
}

func managedPluginOwnershipMarkerPresent(data, marker []byte) bool {
	if !validManagedPluginOwnershipMarker(marker) {
		return false
	}
	for {
		line, rest, found := bytes.Cut(data, []byte("\n"))
		line = bytes.TrimSuffix(line, []byte("\r"))
		// VerifyClean is intentionally stricter than the live ownership check:
		// any exact canonical historical marker is residue, even if an edit moved
		// it away from the first line. Generic product prose and marker-like
		// suffixes remain operator content rather than ownership evidence.
		if validManagedPluginOwnershipMarker(line) {
			return true
		}
		if !found {
			return false
		}
		data = rest
	}
}

func validManagedPluginOwnershipMarker(marker []byte) bool {
	const prefix = "// defenseclaw-managed-plugin v"
	if !bytes.HasPrefix(marker, []byte(prefix)) {
		return false
	}
	version := marker[len(prefix):]
	if len(version) == 0 || version[0] < '1' || version[0] > '9' {
		return false
	}
	for _, digit := range version[1:] {
		if digit < '0' || digit > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(string(version), 10, 64)
	return err == nil
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
	if c.name == "hermes" {
		configPath := c.configPath(opts)
		if validateHermesWindowsConfigPath(configPath) != nil {
			return AgentPaths{}
		}
		patched := []string{
			configPath,
			filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName),
		}
		// Setup writes the direct-native state only on Windows; listing it
		// elsewhere made the enterprise installer refuse every POSIX Hermes
		// install and every managed Hermes repair fail on a file that is
		// never created (seen live on Linux and macOS).
		if runtime.GOOS == "windows" {
			patched = append(patched, filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName))
		}
		return AgentPaths{
			PatchedFiles: uniqueNonEmptyStrings(patched),
			BackupFiles: []string{
				managedFileBackupPath(opts.DataDir, c.name, c.managedBackupLogicalName()),
				managedFileBackupPath(opts.DataDir, c.name, hermesAllowlistLogicalName),
			},
			HookScripts: hookScriptPathsForConnector(opts, c),
		}
	}
	caps := c.Capabilities(opts)
	patched := uniqueNonEmptyStrings(append([]string{c.configPath(opts)}, caps.Telemetry.ConfigPaths...))
	backups := []string{managedFileBackupPath(opts.DataDir, c.name, c.managedBackupLogicalName())}
	hookScripts := hookScriptPathsForConnector(opts, c)
	if c.name == "amp" {
		hookScripts = []string{c.configPath(opts)}
	}
	generatedFiles := []string(nil)
	return AgentPaths{
		PatchedFiles:   uniqueNonEmptyStrings(patched),
		BackupFiles:    backups,
		HookScripts:    hookScripts,
		GeneratedFiles: generatedFiles,
	}
}

func (c *hookOnlyConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

func (c *hookOnlyConnector) RequiredEnv() []EnvRequirement {
	if c.name == "amp" {
		return []EnvRequirement{{
			Scope:       EnvScopeNone,
			Description: "No environment variables are required. For headless action mode, launch Amp with `amp -x --plugin-ready-timeout 30` so the managed policy plugin is ready before the turn starts.",
		}}
	}
	if c.name == "copilot" {
		description := "DefenseClaw's Copilot hook integration requires no shell environment variables; upstream OTel process variables are not configured or managed by this connector."
		return append([]EnvRequirement{{
			Scope:       EnvScopeNone,
			Description: description,
		}}, c.Capabilities(SetupOpts{APIAddr: "127.0.0.1:18970"}).Telemetry.Env...)
	}
	return []EnvRequirement{{
		Scope:       EnvScopeNone,
		Description: "No environment variables are required; this connector installs native hook configuration only.",
	}}
}

func (c *hookOnlyConnector) RequiresScopedHookToken() bool {
	return c != nil && c.pluginArtifact
}

func (c *hookOnlyConnector) ManagedPluginArtifacts(opts SetupOpts) []string {
	if c == nil || !c.pluginArtifact {
		return nil
	}
	return []string{c.configPath(opts)}
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
	if c.name == "cursor" {
		nestedSkills, rules := cursorDiscoveredComponentPaths(cwd)
		targets["skill"] = uniqueNonEmptyStrings(append(targets["skill"], nestedSkills...))
		targets["rule"] = uniqueNonEmptyStrings(append(targets["rule"], rules...))
	}
	if c.name == "hermes" {
		configPath := hermesConfigPath(opts)
		if validateHermesWindowsConfigPath(configPath) != nil {
			return targets
		}
		home := filepath.Dir(configPath)
		targets["memory"] = []string{
			filepath.Join(home, "memories", "MEMORY.md"),
			filepath.Join(home, "memories", "USER.md"),
		}
	}
	return targets
}

const cursorDiscoveryDirectoryLimit = 32768

func cursorDiscoveredComponentPaths(workspace string) ([]string, []string) {
	workspace = strings.TrimSpace(workspace)
	if workspace == "" || atomicTransformValidateNoReparsePathPlatform(workspace) != nil {
		return nil, nil
	}
	info, err := os.Lstat(workspace)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
		return nil, nil
	}
	rulesRoot := filepath.Join(workspace, ".cursor", "rules")
	var skills []string
	var rules []string
	visited := 0
	errCursorDiscoveryLimit := errors.New("cursor discovery directory limit reached")
	_ = filepath.WalkDir(workspace, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if entry != nil && entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if err := atomicTransformValidateNoReparsePathPlatform(path); err != nil {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.Type()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			visited++
			if visited > cursorDiscoveryDirectoryLimit {
				return errCursorDiscoveryLimit
			}
			if path != workspace && strings.EqualFold(entry.Name(), ".git") {
				return filepath.SkipDir
			}
			if strings.EqualFold(entry.Name(), "skills") {
				parent := filepath.Base(filepath.Dir(path))
				if strings.EqualFold(parent, ".cursor") || strings.EqualFold(parent, ".agents") {
					skills = append(skills, path)
				}
			}
			return nil
		}
		if entry.Name() == "AGENTS.md" {
			rules = append(rules, path)
			return nil
		}
		if strings.EqualFold(filepath.Ext(entry.Name()), ".mdc") && cursorPathWithin(path, rulesRoot) {
			rules = append(rules, path)
		}
		return nil
	})
	return uniqueNonEmptyStrings(skills), uniqueNonEmptyStrings(rules)
}

func cursorPathWithin(path, root string) bool {
	rel, err := filepath.Rel(root, path)
	if err != nil || rel == "." {
		return false
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))
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
		if err := validateCopilotLifecycleHome(opts); err != nil {
			return err
		}
	}
	path := c.configPath(opts)
	if strings.TrimSpace(path) == "" {
		return fmt.Errorf("%s setup could not resolve a hook config path", c.name)
	}
	if c.name == "hermes" {
		return setupHermesFiles(opts, path, hookScript)
	}
	if c.name == "copilot" {
		if err := validateCopilotOperatorSettings(opts); err != nil {
			return err
		}
		removeOrphanedCopilotVSCodeLocalRendersForPerUser(opts)
	}
	logicalName := c.managedBackupLogicalName()
	// Devin's config.json is the account's own settings file: one that went
	// missing after DefenseClaw managed it gets them back before the hooks
	// go in (GAP-0564).
	if err := seedMissingAgentConfig(c.name, opts.DataDir, path); err != nil {
		return err
	}
	if err := captureManagedFileBackup(opts.DataDir, c.name, logicalName, path); err != nil {
		return err
	}

	var err error
	switch c.name {
	case "cursor":
		err = patchCursorHooks(
			path,
			hookScript,
			filepath.Join(opts.DataDir, "hooks", c.scriptName),
			c.effectiveFailClosed(opts),
		)
	case "devin":
		err = patchDevinHooks(path, hookScript, devinOwnedHookCommands(opts, hookScript)...)
	case "copilot":
		err = patchCopilotHooksForOS(path, hookScript, c.copilotHookEvents(opts), runtime.GOOS)
	case "antigravity":
		err = patchAntigravityHooks(path, hookScript)
	default:
		err = fmt.Errorf("unknown hook connector %q", c.name)
	}
	if err != nil {
		return err
	}
	if err := updateManagedFileBackupPostHash(opts.DataDir, c.name, logicalName, path); err != nil {
		return err
	}
	recordAgentConfigCopy(c.name, opts.DataDir, path)
	return nil
}

// copilotHookEvents are the Copilot events Setup registers for opts: the
// resolved hook profile's, or every current event.
func (c *hookOnlyConnector) copilotHookEvents(opts SetupOpts) []string {
	if events := c.HookProfile(opts).SupportedEvents; len(events) != 0 {
		return events
	}
	return copilotCurrentHookEvents
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

// keepOperatorEmptyHooks puts back the operator's empty hooks object after
// the surgical removal of DefenseClaw's entries from a JSON hooks file.
func (c *hookOnlyConnector) keepOperatorEmptyHooks(opts SetupOpts, logicalName, path string) error {
	switch c.name {
	case "cursor", "antigravity":
		return keepPristineEmptyHooks(opts.DataDir, c.name, logicalName, path)
	default:
		return nil
	}
}

func (c *hookOnlyConnector) removeConfigEntries(path, hookScript string, opts SetupOpts) error {
	switch c.name {
	case "hermes":
		return removeHermesHooks(path, hookScript, nil)
	case "cursor":
		return removeJSONHookReferencesProfile(path, pluginSecureClientProfile(opts), cursorOwnedHookCommands(opts)...)
	case "copilot":
		return removeCopilotHookReferencesProfile(path, pluginSecureClientProfile(opts), hookScript)
	case "devin":
		return removeDevinHookReferences(path, devinOwnedHookCommands(opts, hookScript)...)
	case "antigravity":
		ownedCommands := antigravityOwnedHookCommands(hookScript)
		ownedCommands = append(ownedCommands,
			legacyAntigravityWindowsHookCommand(),
			legacyAntigravityNonWaitingWindowsHookCommand(),
		)
		return removeJSONHookReferencesProfile(path, pluginSecureClientProfile(opts), ownedCommands...)
	default:
		return nil
	}
}

func (c *hookOnlyConnector) effectiveFailClosed(opts SetupOpts) bool {
	if c != nil && c.name == "cursor" && !opts.SecureClientHookDelivery {
		// Cursor's host flag covers a hook process that never answers. The
		// rendered hook still makes the configured gateway-outage decision
		// when it runs, including an administrator's explicit open choice.
		return true
	}
	cap := c.HookCapabilities(opts)
	return cap.SupportsFailClosed && resolveHookFailMode(opts, c) == "closed"
}

// hermesConfigPath is hermesResolvedConfigPath for the lists that only name
// what to watch, grant or clean up. When the account's home cannot be
// resolved they keep the profile default of the bound home. Setup and every
// check resolve the home themselves (hermesResolvedConfigPath,
// hermesVerifiedConfigPath) and fail instead, so the default is never what
// a check proves.
func hermesConfigPath(opts SetupOpts) string {
	path, err := hermesResolvedConfigPath(opts)
	if err == nil {
		return path
	}
	if home := activeUserHomeOverride(); home != "" && (runtime.GOOS == "windows" || !isProcessUserHome(home)) {
		return hermespath.ConfigPathForUserHome(home)
	}
	return ""
}

// hermesResolvedConfigPath resolves the config.yaml of the Hermes home the
// hooks belong in. A privileged service acting for another user (the
// managed guardian) must resolve that user's home, not its own token's known
// folders or, on Linux and macOS, its own home: the root guardian watched
// root's ~/.hermes instead of the user's, so an in-place rewrite of the
// user's Hermes config waited for the interval pass (GAP-0122). It is the
// home the account configured (hermespath.ConfigPathForAccount: on Windows
// the HERMES_HOME of its persistent environment), never a profile default
// substituted for a home that cannot be read, so setup and verification
// work on the home the account's Hermes reads (GAP-0499). In the process's
// own home HERMES_HOME still applies.
func hermesResolvedConfigPath(SetupOpts) (string, error) {
	if HermesConfigPathOverride != "" {
		return HermesConfigPathOverride, nil
	}
	if home := activeUserHomeOverride(); home != "" && (runtime.GOOS == "windows" || !isProcessUserHome(home)) {
		return hermespath.ConfigPathForAccount(home)
	}
	path := hermesConfigPathResolver()
	if strings.TrimSpace(path) == "" {
		return "", errors.New("Hermes config path is unavailable; current-user LocalAppData or an absolute HERMES_HOME is required") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return path, nil
}

// hermesVerifiedConfigPath resolves the Hermes config a check inspects and
// fails, rather than inspecting another home, when the Hermes the account
// runs would not read it: a home that cannot be resolved, a HERMES_HOME the
// account's environment sets to another home or to a value a service
// cannot resolve (hermespath.VerifyAccountHome), or a named profile Hermes
// selects instead of the default one DefenseClaw set up (GAP-0499). A check
// that passed on the default home or profile proved nothing about another
// one Hermes runs from.
func hermesVerifiedConfigPath(opts SetupOpts) (string, error) {
	configPath, err := hermesResolvedConfigPath(opts)
	if err != nil {
		return "", fmt.Errorf("hermes hooks not verified: %w", err)
	}
	if home := activeUserHomeOverride(); HermesConfigPathOverride == "" && home != "" && (runtime.GOOS == "windows" || !isProcessUserHome(home)) {
		hermesHome := filepath.Dir(configPath)
		if err := hermespath.VerifyAccountHome(home, hermesHome, hermesHomeSetUpAt(opts.DataDir, hermesHome)); err != nil {
			return "", fmt.Errorf("hermes hooks not verified: %w", err)
		}
	}
	if err := validateHermesWindowsConfigPath(configPath); err != nil {
		return "", fmt.Errorf("hermes hooks not verified: %w", err)
	}
	if err := validateHermesSingleProfile(configPath); err != nil {
		return "", fmt.Errorf("hermes hooks not verified: %w", err)
	}
	return configPath, nil
}

// hermesHomeSetUpFileName records the Hermes home the last successful Setup
// registered the hooks in, and when. A redirect the DefenseClaw hooks last
// saw long enough before that no longer fails Verify
// (hermespath.VerifyAccountHome).
const hermesHomeSetUpFileName = "hermes-home-setup.json"

type hermesHomeSetUp struct {
	Home    string `json:"home"`
	SetUpAt string `json:"set_up_at"`
}

func recordHermesHomeSetUp(dataDir, home string, now time.Time) error {
	data, err := json.Marshal(hermesHomeSetUp{Home: home, SetUpAt: now.UTC().Format(time.RFC3339)})
	if err != nil {
		return err
	}
	return atomicWriteFileNoFollow(filepath.Join(dataDir, hermesHomeSetUpFileName), data, 0o600)
}

// hermesHomeSetUpAt is when Setup last registered the hooks in home, or
// zero when no readable record names home or its time is in the future.
func hermesHomeSetUpAt(dataDir, home string) time.Time {
	path := filepath.Join(dataDir, hermesHomeSetUpFileName)
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() || info.Size() > 64<<10 {
		return time.Time{}
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return time.Time{}
	}
	var record hermesHomeSetUp
	if json.Unmarshal(data, &record) != nil || !sameManagedTarget(record.Home, home) {
		return time.Time{}
	}
	at, err := time.Parse(time.RFC3339, record.SetUpAt)
	if err != nil || at.After(time.Now()) {
		return time.Time{}
	}
	return at
}

// isProcessUserHome reports whether home is this process's own home folder.
func isProcessUserHome(home string) bool {
	own, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(own) == "" {
		return false
	}
	return filepath.Clean(own) == filepath.Clean(strings.TrimSpace(home))
}

func validateHermesWindowsConfigPath(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("Hermes config path is unavailable; current-user LocalAppData or an absolute HERMES_HOME is required; no changes made") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	if strings.TrimSpace(configPath) != configPath ||
		strings.ContainsAny(configPath, "\x00\r\n") ||
		!filepath.IsAbs(configPath) ||
		filepath.Clean(configPath) != configPath {
		return errors.New("Hermes config path is not an absolute normalized Windows path; no changes made") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	home := filepath.Dir(configPath)
	if strings.TrimSpace(home) == "" || home == "." || !filepath.IsAbs(home) {
		return errors.New("Hermes config home is not an absolute Windows path; no changes made") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return nil
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

const copilotSettingsMaxBytes int64 = 1 << 20

func validateCopilotLifecycleHome(opts SetupOpts) error {
	raw, exists := os.LookupEnv("COPILOT_HOME")
	if exists {
		if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n") ||
			!filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
			return fmt.Errorf("COPILOT_HOME is not an absolute normalized path")
		}
	}
	bound := copilotHomePath()
	if configured := strings.TrimSpace(opts.ConfigHome); configured != "" &&
		!strings.EqualFold(filepath.Clean(configured), filepath.Clean(bound)) {
		return fmt.Errorf("COPILOT_HOME does not match the lifecycle-bound config home")
	}
	return nil
}

func copilotSettingsPaths(opts SetupOpts) []string {
	paths := []string{
		copilotHomePath("config.json"), // internal/legacy migration input only
		copilotHomePath("settings.json"),
	}
	roots := copilotWorkspaceAncestors(opts)
	if len(roots) == 0 {
		return paths
	}
	repository := roots[len(roots)-1]
	return append(paths,
		filepath.Join(repository, ".claude", "settings.json"),
		filepath.Join(repository, ".github", "copilot", "settings.json"),
		filepath.Join(repository, ".claude", "settings.local.json"),
		filepath.Join(repository, ".github", "copilot", "settings.local.json"),
	)
}

func validateCopilotOperatorSettings(opts SetupOpts) error {
	disabled := false
	disabledSource := ""
	for _, path := range copilotSettingsPaths(opts) {
		value, present, err := readCopilotDisableAllHooks(path)
		if err != nil {
			return fmt.Errorf("cannot verify Copilot settings %s: %w", path, err)
		}
		if present {
			disabled = value
			disabledSource = path
		}
	}
	if disabled {
		return fmt.Errorf("Copilot hooks are disabled by effective operator setting disableAllHooks=true at %s; refusing to overwrite operator policy", disabledSource) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return nil
}

func readCopilotDisableAllHooks(path string) (bool, bool, error) {
	if _, err := os.Lstat(path); err != nil {
		if os.IsNotExist(err) {
			return false, false, nil
		}
		return false, false, err
	}
	body, ok := ReadStableInventoryFile(path, copilotSettingsMaxBytes)
	if !ok {
		return false, false, fmt.Errorf("file is unsafe, changing, or exceeds the 1 MiB limit")
	}
	normalized, err := normalizeCopilotJSONC(body)
	if err != nil {
		return false, false, err
	}
	var document map[string]interface{}
	if err := json.Unmarshal(normalized, &document); err != nil {
		return false, false, fmt.Errorf("invalid JSON/JSONC: %w", err)
	}
	raw, present := document["disableAllHooks"]
	if !present {
		return false, false, nil
	}
	value, valid := raw.(bool)
	if !valid {
		return false, false, fmt.Errorf("disableAllHooks must be boolean")
	}
	return value, true, nil
}

func normalizeCopilotJSONC(input []byte) ([]byte, error) {
	withoutComments, err := stripJSONComments(input)
	if err != nil {
		return nil, err
	}
	return stripJSONTrailingCommas(withoutComments), nil
}

// stripJSONComments removes // and /* */ comments outside JSON strings, in
// the manner of the common strip-json-comments loader. It deliberately leaves
// trailing commas intact; Copilot applies its separate trailing-comma
// normalization after this helper.
func stripJSONComments(input []byte) ([]byte, error) {
	input = bytes.TrimPrefix(input, []byte{0xEF, 0xBB, 0xBF})
	withoutComments := make([]byte, 0, len(input))
	inString := false
	escaped := false
	for i := 0; i < len(input); i++ {
		current := input[i]
		if inString {
			withoutComments = append(withoutComments, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			withoutComments = append(withoutComments, current)
			continue
		}
		if current == '/' && i+1 < len(input) && input[i+1] == '/' {
			for i < len(input) && input[i] != '\n' {
				i++
			}
			if i < len(input) {
				withoutComments = append(withoutComments, '\n')
			}
			continue
		}
		if current == '/' && i+1 < len(input) && input[i+1] == '*' {
			i += 2
			closed := false
			for i+1 < len(input) && (input[i] != '*' || input[i+1] != '/') {
				if input[i] == '\n' {
					withoutComments = append(withoutComments, '\n')
				}
				i++
			}
			if i+1 < len(input) {
				closed = true
			}
			if !closed {
				return nil, fmt.Errorf("unterminated JSONC comment")
			}
			i++
			continue
		}
		withoutComments = append(withoutComments, current)
	}
	return withoutComments, nil
}

func stripJSONTrailingCommas(input []byte) []byte {
	out := make([]byte, 0, len(input))
	inString := false
	escaped := false
	for i := 0; i < len(input); i++ {
		current := input[i]
		if inString {
			out = append(out, current)
			if escaped {
				escaped = false
			} else if current == '\\' {
				escaped = true
			} else if current == '"' {
				inString = false
			}
			continue
		}
		if current == '"' {
			inString = true
			out = append(out, current)
			continue
		}
		if current == ',' {
			next := i + 1
			for next < len(input) && (input[next] == ' ' || input[next] == '\t' || input[next] == '\r' || input[next] == '\n') {
				next++
			}
			if next < len(input) && (input[next] == '}' || input[next] == ']') {
				continue
			}
		}
		out = append(out, current)
	}
	return out
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

// opencodeMCPReadPaths mirrors the locally representable file layers in the
// Python connector-path adapter. Remote authenticated .well-known state,
// inline OPENCODE_CONFIG_CONTENT, and Windows ProgramData enterprise policy
// deliberately have no local path and are therefore not watched here.
func opencodeMCPReadPaths(opts SetupOpts) []string {
	home := strings.TrimSpace(homePath())
	workspace := strings.TrimSpace(opts.WorkspaceDir)
	paths := []string{
		filepath.Join(home, ".config", "opencode", "config.json"),
		filepath.Join(home, ".config", "opencode", "opencode.json"),
		filepath.Join(home, ".config", "opencode", "opencode.jsonc"),
	}
	if explicit := opencodeEnvPath(os.Getenv("OPENCODE_CONFIG"), workspace); explicit != "" {
		paths = append(paths, explicit)
	}
	for _, root := range opencodeProjectRoots(opts) {
		paths = append(paths,
			filepath.Join(root, "opencode.json"),
			filepath.Join(root, "opencode.jsonc"),
			filepath.Join(root, ".opencode", "opencode.json"),
			filepath.Join(root, ".opencode", "opencode.jsonc"),
		)
	}
	paths = append(paths,
		filepath.Join(home, ".opencode", "opencode.json"),
		filepath.Join(home, ".opencode", "opencode.jsonc"),
	)
	if custom := opencodeEnvPath(os.Getenv("OPENCODE_CONFIG_DIR"), workspace); custom != "" {
		paths = append(paths,
			filepath.Join(custom, "opencode.json"),
			filepath.Join(custom, "opencode.jsonc"),
		)
	}
	return uniqueNonEmptyStrings(paths)
}

// opencodeMCPWritePaths resolves the one local document selected by the
// Python set/unset adapter. Returning no target is intentional when the
// adapter itself fails closed: inline configuration cannot be restored
// atomically, and relative environment overrides require a pinned workspace.
func opencodeMCPWritePaths(opts SetupOpts) []string {
	if strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_CONTENT")) != "" {
		return nil
	}
	workspace := strings.TrimSpace(opts.WorkspaceDir)
	customRaw := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG_DIR"))
	explicitRaw := strings.TrimSpace(os.Getenv("OPENCODE_CONFIG"))
	custom := opencodeEnvPath(customRaw, workspace)
	explicit := opencodeEnvPath(explicitRaw, workspace)
	if (customRaw != "" && custom == "") || (explicitRaw != "" && explicit == "") {
		return nil
	}
	if custom != "" {
		return []string{opencodePreferredConfigPath(custom)}
	}
	homeComponent := homePath(".opencode")
	if info, err := os.Stat(homeComponent); err == nil && info.IsDir() {
		return []string{opencodePreferredConfigPath(homeComponent)}
	}
	if workspace != "" {
		projectComponent := filepath.Join(workspace, ".opencode")
		if info, err := os.Stat(projectComponent); err == nil && info.IsDir() {
			return []string{opencodePreferredConfigPath(projectComponent)}
		}
		return []string{opencodePreferredConfigPath(workspace)}
	}
	if explicit != "" {
		return []string{explicit}
	}
	return []string{opencodePreferredConfigPath(homePath(".config", "opencode"))}
}

func opencodeEnvPath(raw, workspace string) string {
	value := strings.TrimSpace(raw)
	if value == "" {
		return ""
	}
	if value == "~" {
		value = homePath()
	} else if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
		value = filepath.Join(homePath(), value[2:])
	}
	if !filepath.IsAbs(value) {
		if strings.TrimSpace(workspace) == "" {
			return ""
		}
		value = filepath.Join(workspace, value)
	}
	absolute, err := filepath.Abs(value)
	if err != nil {
		return ""
	}
	return filepath.Clean(absolute)
}

func opencodePreferredConfigPath(root string) string {
	jsonc := filepath.Join(root, "opencode.jsonc")
	if _, err := os.Lstat(jsonc); err == nil {
		return jsonc
	}
	return filepath.Join(root, "opencode.json")
}

func opencodeConfigRoot(opts SetupOpts) string {
	if custom := opencodeEnvPath(os.Getenv("OPENCODE_CONFIG_DIR"), strings.TrimSpace(opts.WorkspaceDir)); custom != "" {
		return custom
	}
	return homePath(".config", "opencode")
}

func opencodeConfigComponentRoots(opts SetupOpts) []string {
	paths := []string{homePath(".config", "opencode")}
	for _, root := range opencodeProjectRoots(opts) {
		paths = append(paths, filepath.Join(root, ".opencode"))
	}
	paths = append(paths, homePath(".opencode"))
	if custom := opencodeEnvPath(os.Getenv("OPENCODE_CONFIG_DIR"), strings.TrimSpace(opts.WorkspaceDir)); custom != "" {
		paths = append(paths, custom)
	}
	return uniqueNonEmptyStrings(paths)
}

// opencodeProjectRoots returns the launch directory through its nearest Git
// root. Without a repository marker, OpenCode treats only the pinned launch
// directory as project state; DefenseClaw must not scan unrelated ancestors.
func opencodeProjectRoots(opts SetupOpts) []string {
	workspace := strings.TrimSpace(opts.WorkspaceDir)
	if workspace == "" {
		return nil
	}
	workspace = filepath.Clean(workspace)
	stop := workspace
	for probe := workspace; probe != ""; {
		if _, err := os.Stat(filepath.Join(probe, ".git")); err == nil {
			stop = probe
			break
		}
		parent := filepath.Dir(probe)
		if parent == probe {
			break
		}
		probe = parent
	}
	roots := []string{}
	for root := workspace; root != ""; {
		roots = append(roots, root)
		if root == stop {
			break
		}
		parent := filepath.Dir(root)
		if parent == root {
			break
		}
		root = parent
	}
	return uniqueNonEmptyStrings(roots)
}

func opencodeSkillReadPaths(opts SetupOpts) []string {
	paths := []string{homePath(".claude", "skills"), homePath(".agents", "skills")}
	for _, root := range opencodeConfigComponentRoots(opts) {
		paths = append(paths,
			filepath.Join(root, "skill"),
			filepath.Join(root, "skills"),
		)
	}
	for _, root := range opencodeProjectRoots(opts) {
		paths = append(paths,
			filepath.Join(root, ".claude", "skills"),
			filepath.Join(root, ".agents", "skills"),
		)
	}
	return uniqueNonEmptyStrings(paths)
}

func opencodeSkillWritePaths(opts SetupOpts) []string {
	paths := []string{filepath.Join(opencodeConfigRoot(opts), "skills")}
	if workspace := strings.TrimSpace(opts.WorkspaceDir); workspace != "" {
		paths = append(paths, filepath.Join(workspace, ".opencode", "skills"))
	}
	return uniqueNonEmptyStrings(paths)
}

func opencodeRuleReadPaths(opts SetupOpts) []string {
	configRoot := opencodeConfigRoot(opts)
	paths := []string{
		filepath.Join(configRoot, "AGENTS.md"),
		filepath.Join(configRoot, "CLAUDE.md"),
	}
	paths = append(paths, opencodeMCPReadPaths(opts)...)
	for _, root := range opencodeProjectRoots(opts) {
		paths = append(paths,
			filepath.Join(root, "AGENTS.md"),
			filepath.Join(root, "CLAUDE.md"),
		)
	}
	return uniqueNonEmptyStrings(paths)
}

func opencodePluginReadPaths(opts SetupOpts) []string {
	paths := []string{}
	for _, root := range opencodeConfigComponentRoots(opts) {
		paths = append(paths,
			filepath.Join(root, "plugin"),
			filepath.Join(root, "plugins"),
		)
	}
	return uniqueNonEmptyStrings(paths)
}

func opencodeAgentReadPaths(opts SetupOpts) []string {
	paths := []string{}
	for _, root := range opencodeConfigComponentRoots(opts) {
		paths = append(paths,
			filepath.Join(root, "agent"),
			filepath.Join(root, "agents"),
		)
	}
	return uniqueNonEmptyStrings(paths)
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
	if len(roots) > 0 {
		// Compatible Markdown commands are alternative skills and have lower
		// priority than all Agent Skill sources above.
		paths = append(paths, filepath.Join(roots[0], ".claude", "commands"))
	}
	return copilotUniquePaths(paths)
}

func copilotInstructionReadPaths(opts SetupOpts) []string {
	paths := []string{
		copilotHomePath("copilot-instructions.md"),
		copilotHomePath("instructions"),
	}
	roots := copilotWorkspaceAncestors(opts)
	for i := len(roots) - 1; i >= 0; i-- {
		root := roots[i]
		paths = append(paths,
			filepath.Join(root, ".github", "copilot-instructions.md"),
			filepath.Join(root, "AGENTS.md"),
			filepath.Join(root, "CLAUDE.md"),
			filepath.Join(root, ".claude", "CLAUDE.md"),
			filepath.Join(root, "GEMINI.md"),
		)
	}
	if len(roots) > 0 {
		paths = append(paths, filepath.Join(roots[len(roots)-1], ".github", "instructions"))
		paths = append(paths, filepath.Join(roots[0], ".github", "instructions"))
		// The inventory performs a bounded, no-follow scan under the repository
		// for general files that can become applicable for nested active files.
		paths = append(paths, roots[len(roots)-1])
	}
	for _, raw := range strings.Split(os.Getenv("COPILOT_CUSTOM_INSTRUCTIONS_DIRS"), ",") {
		path := strings.TrimSpace(raw)
		if path == "" {
			continue
		}
		if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, `~\`) {
			path = filepath.Join(homePath(), path[2:])
		} else if !filepath.IsAbs(path) {
			if workspaceRoot(opts) == "" {
				continue
			}
			path = filepath.Join(workspaceRoot(opts), path)
		}
		paths = append(paths, filepath.Join(path, "AGENTS.md"), path)
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
	root := ""
	if configured, exists := os.LookupEnv("COPILOT_HOME"); exists {
		if strings.TrimSpace(configured) != configured || strings.ContainsAny(configured, "\x00\r\n") ||
			!filepath.IsAbs(configured) || filepath.Clean(configured) != configured {
			return ""
		}
		root = configured
	} else {
		home := strings.TrimSpace(userHomeDir())
		if home == "" {
			return ""
		}
		root = filepath.Join(home, ".copilot")
	}
	return filepath.Join(append([]string{root}, parts...)...)
}

func unsupportedSurface(note string) SurfaceCapability {
	cap := SurfaceCapability{Supported: false}
	if strings.TrimSpace(note) != "" {
		cap.Notes = []string{note}
	}
	return cap
}

func cursorSkillPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		workspacePath(opts, ".cursor", "skills"),
		workspacePath(opts, ".agents", "skills"),
		workspacePath(opts, ".claude", "skills"),
		workspacePath(opts, ".codex", "skills"),
		homePath(".cursor", "skills"),
		homePath(".agents", "skills"),
		homePath(".claude", "skills"),
		homePath(".codex", "skills"),
	})
}

func cursorRulePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		workspacePath(opts, ".cursor", "rules"),
		workspacePath(opts, "AGENTS.md"),
	})
}

func cursorAgentPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		workspacePath(opts, ".cursor", "agents"),
		workspacePath(opts, ".claude", "agents"),
		workspacePath(opts, ".codex", "agents"),
		homePath(".cursor", "agents"),
		homePath(".claude", "agents"),
		homePath(".codex", "agents"),
	})
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
	return uniqueNonEmptyStrings(append([]string{
		homePath(".gemini", "GEMINI.md"),
		antigravityWorkspacePath(opts, ".agents", "rules"),
		antigravityWorkspacePath(opts, ".agent", "rules"),
	}, antigravityPluginPaths(opts)...))
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

type hermesFileSnapshot struct {
	path      string
	existed   bool
	mode      os.FileMode
	data      []byte
	ownedHash string
}

func snapshotHermesFile(path string) (*hermesFileSnapshot, error) {
	data, info, err := readManagedTarget(path)
	if err != nil {
		return nil, err
	}
	snapshot := &hermesFileSnapshot{path: path, existed: info != nil, data: data}
	if info != nil {
		snapshot.mode = info.Mode().Perm()
	}
	snapshot.ownedHash = managedFileSnapshotHash(data, info != nil)
	return snapshot, nil
}

func (s *hermesFileSnapshot) markOwned() error {
	data, info, err := readManagedTarget(s.path)
	if err != nil {
		return err
	}
	s.ownedHash = managedFileSnapshotHash(data, info != nil)
	return nil
}

func rollbackHermesFiles(snapshots []*hermesFileSnapshot) error {
	var errs []string
	for i := len(snapshots) - 1; i >= 0; i-- {
		snapshot := snapshots[i]
		data, info, err := readManagedTarget(snapshot.path)
		if err != nil {
			errs = append(errs, fmt.Sprintf("inspect %s: %v", snapshot.path, err))
			continue
		}
		if managedFileSnapshotHash(data, info != nil) != snapshot.ownedHash {
			errs = append(errs, fmt.Sprintf("refusing to roll back tampered path %s", snapshot.path))
			continue
		}
		if snapshot.existed {
			mode := snapshot.mode
			if mode == 0 {
				mode = 0o600
			}
			if err := atomicWriteFile(snapshot.path, snapshot.data, mode); err != nil {
				errs = append(errs, fmt.Sprintf("restore %s: %v", snapshot.path, err))
			}
		} else if err := os.Remove(snapshot.path); err != nil && !os.IsNotExist(err) {
			errs = append(errs, fmt.Sprintf("remove %s: %v", snapshot.path, err))
		}
	}
	if len(errs) > 0 {
		return errors.New(strings.Join(errs, "; "))
	}
	return nil
}

func managedHermesBackupOwnsCurrent(dataDir, logicalName, targetPath string) (bool, error) {
	backup, err := loadManagedFileBackupPath(managedFileBackupPath(dataDir, "hermes", logicalName))
	if err != nil {
		return false, err
	}
	if _, err := validateManagedFileBackupTarget(backup, "hermes", logicalName, targetPath); err != nil {
		return false, err
	}
	if err := validateHermesManagedBackupPristine(&backup); err != nil {
		return false, err
	}
	data, info, err := readManagedTarget(targetPath)
	if err != nil {
		return false, err
	}
	return managedFileBackupMatchesSnapshot(&backup, data, info != nil), nil
}

func setupHermesFiles(opts SetupOpts, configPath, hookScript string) (err error) {
	if err := validateHermesWindowsConfigPath(configPath); err != nil {
		return err
	}
	allowlistPath := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	configBackupPath := managedFileBackupPath(opts.DataDir, "hermes", "config.yaml")
	allowlistBackupPath := managedFileBackupPath(opts.DataDir, "hermes", hermesAllowlistLogicalName)
	statePath := filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName)
	paths := []string{configPath, allowlistPath, configBackupPath, allowlistBackupPath}
	if runtime.GOOS == "windows" {
		paths = append(paths, statePath)
	}
	snapshots := make([]*hermesFileSnapshot, 0, len(paths))
	byPath := map[string]*hermesFileSnapshot{}
	for _, path := range paths {
		snapshot, snapshotErr := snapshotHermesFile(path)
		if snapshotErr != nil {
			return snapshotErr
		}
		snapshots = append(snapshots, snapshot)
		byPath[path] = snapshot
	}
	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := rollbackHermesFiles(snapshots); rollbackErr != nil {
			err = fmt.Errorf("%w; Hermes setup rollback: %v", err, rollbackErr)
		}
	}()

	// A config.yaml that went missing after DefenseClaw managed it gets the
	// account's settings back before the hooks go in, not the hooks key
	// alone (GAP-0564). A rollback removes the file put back.
	if err = seedMissingAgentConfig("hermes", opts.DataDir, configPath); err != nil {
		return err
	}
	if err = byPath[configPath].markOwned(); err != nil {
		return err
	}
	if err = captureManagedFileBackup(opts.DataDir, "hermes", "config.yaml", configPath); err != nil {
		return err
	}
	if err = byPath[configBackupPath].markOwned(); err != nil {
		return err
	}
	if err = captureManagedFileBackup(opts.DataDir, "hermes", hermesAllowlistLogicalName, allowlistPath); err != nil {
		return err
	}
	if err = byPath[allowlistBackupPath].markOwned(); err != nil {
		return err
	}
	configCustodied, err := managedHermesBackupOwnsCurrent(opts.DataDir, "config.yaml", configPath)
	if err != nil {
		return err
	}
	allowlistCustodied, err := managedHermesBackupOwnsCurrent(opts.DataDir, hermesAllowlistLogicalName, allowlistPath)
	if err != nil {
		return err
	}

	if err = patchHermesHooks(configPath, hookScript, opts.HookExecutable, opts); err != nil {
		return err
	}
	if err = byPath[configPath].markOwned(); err != nil {
		return err
	}
	if configCustodied {
		if err = updateManagedFileBackupPostHash(opts.DataDir, "hermes", "config.yaml", configPath); err != nil {
			return err
		}
		if err = byPath[configBackupPath].markOwned(); err != nil {
			return err
		}
	}

	command := hermesConfiguredHookCommand(hookScript, opts.HookExecutable)
	if err = patchHermesAllowlist(allowlistPath, command, hermesHookExecutablePath(hookScript, hermesHookExecutable(runtime.GOOS, opts))); err != nil {
		return err
	}
	if err = byPath[allowlistPath].markOwned(); err != nil {
		return err
	}
	if allowlistCustodied {
		if err = updateManagedFileBackupPostHash(opts.DataDir, "hermes", hermesAllowlistLogicalName, allowlistPath); err != nil {
			return err
		}
		if err = byPath[allowlistBackupPath].markOwned(); err != nil {
			return err
		}
	}

	if runtime.GOOS == "windows" {
		if err = writeHermesDirectNativeState(opts, command, hermesDirectNativePending); err != nil {
			return err
		}
		if err = byPath[statePath].markOwned(); err != nil {
			return err
		}
	}
	// The file as it is now is the last known good copy. Best effort: the
	// guardian's next verify that passes keeps it too.
	recordAgentConfigCopy("hermes", opts.DataDir, configPath)
	return nil
}

func hermesConfiguredHookCommand(hookScript, hookExecutable string) string {
	if bound := windowsHermesDirectHookCommand(hookExecutable); bound != "" && hookScript == bound {
		return hookScript
	}
	return shellWord(hookScript)
}

// hermesHookExecutable is the launcher the Windows Hermes command names: the
// one SetupOpts pins (managed policy, native Setup maintenance) or, for an
// ordinary per-user install, which leaves HookExecutable empty, the packaged
// launcher hookInvocationCommandFor registers. Verify's execution probe and
// the allowlist's script time read the same one, so a per-user install no
// longer probes the whole command line as a file path and fails every Setup
// and upgrade (GAP-0837). Unix Hermes runs the data-dir script; "" there.
func hermesHookExecutable(goos string, opts SetupOpts) string {
	if executable := strings.TrimSpace(opts.HookExecutable); executable != "" || goos != "windows" {
		return executable
	}
	return defenseclawHookBinary()
}

func hermesHookExecutablePath(hookScript, hookExecutable string) string {
	if windowsHermesDirectHookCommand(hookExecutable) == hookScript {
		return hookExecutable
	}
	return hookScript
}

func readHermesAllowlist(path string) (map[string]interface{}, error) {
	data, err := safefile.ReadRegularFileBounded(path, hermesAllowlistMaxBytes)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{"approvals": []interface{}{}}, nil
		}
		return nil, err
	}
	var document map[string]interface{}
	if err := json.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse Hermes shell hook allowlist: %w", err)
	}
	if document == nil {
		return nil, fmt.Errorf("Hermes shell hook allowlist is not a JSON object") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	// Hermes reads a document without approvals ({}) as no approvals, so
	// repair adds DefenseClaw's to it instead of failing.
	raw, present := document["approvals"]
	if !present || raw == nil {
		document["approvals"] = []interface{}{}
		return document, nil
	}
	if _, ok := raw.([]interface{}); !ok {
		return nil, fmt.Errorf("Hermes shell hook allowlist approvals is not an array") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return document, nil
}

// hermesOwnedApprovalsPresent reports whether the allowlist holds
// DefenseClaw's approval of command for every required Hermes event.
func hermesOwnedApprovalsPresent(path, command string) (bool, error) {
	document, err := readHermesAllowlist(path)
	if err != nil {
		return false, err
	}
	approved := map[string]bool{}
	for _, raw := range document["approvals"].([]interface{}) {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			continue
		}
		event, _ := entry["event"].(string)
		entryCommand, _ := entry["command"].(string)
		if owned, _ := entry[hermesAllowlistOwnerField].(bool); owned && entryCommand == command {
			approved[event] = true
		}
	}
	for _, spec := range hermesRequiredHooks {
		if !approved[spec.event] {
			return false, nil
		}
	}
	return true, nil
}

func hermesHookEventSet() map[string]struct{} {
	events := make(map[string]struct{}, len(hermesRequiredHooks))
	for _, spec := range hermesRequiredHooks {
		events[spec.event] = struct{}{}
	}
	return events
}

// hermesConsentKeys are the keys of the approval Hermes records itself when
// a shell hook is accepted (at its prompt or through hooks_auto_accept).
var hermesConsentKeys = map[string]struct{}{
	"event":                    {},
	"command":                  {},
	"approved_at":              {},
	"script_mtime_at_approval": {},
}

// hermesConsentForCommand reports whether an allowlist entry without
// DefenseClaw's ownership marker is the consent Hermes recorded for command:
// Hermes' own keys only, and exactly that command. DefenseClaw 0.8.x
// registered its hook with hooks_auto_accept and never wrote the allowlist,
// so every approval an upgraded profile holds has this shape. Setup adopts it
// and Teardown removes it with the hook; refusing it stopped every 0.8.x
// upgrade with Hermes enrolled (GAP-1241). Any other unmarked entry naming a
// DefenseClaw command is still refused as ambiguous.
func hermesConsentForCommand(entry map[string]interface{}, command string) bool {
	if entryCommand, _ := entry["command"].(string); entryCommand != command {
		return false
	}
	for key := range entry {
		if _, ok := hermesConsentKeys[key]; !ok {
			return false
		}
	}
	return true
}

// checkHermesAllowlistRepairable makes Setup's allowlist decisions without
// writing anything, so Setup refuses an allowlist it cannot repair before it
// changes a file (GAP-1241).
func checkHermesAllowlistRepairable(path, command string) error {
	document, err := readHermesAllowlist(path)
	if err != nil {
		return err
	}
	_, _, err = planHermesAllowlistApprovals(path, document["approvals"].([]interface{}), command)
	return err
}

func patchHermesAllowlist(path, command, executablePath string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("Hermes hook command is empty") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	document, err := readHermesAllowlist(path)
	if err != nil {
		return err
	}
	kept, managedCurrent, err := planHermesAllowlistApprovals(path, document["approvals"].([]interface{}), command)
	if err != nil {
		return err
	}
	approvedAt := time.Now().UTC().Format(time.RFC3339Nano)
	var scriptMTime interface{}
	if info, statErr := os.Stat(executablePath); statErr == nil {
		scriptMTime = info.ModTime().UTC().Format(time.RFC3339Nano)
	}
	for _, spec := range hermesRequiredHooks {
		if managedCurrent[spec.event] {
			continue
		}
		kept = append(kept, map[string]interface{}{
			"event":                    spec.event,
			"command":                  command,
			"approved_at":              approvedAt,
			"script_mtime_at_approval": scriptMTime,
			hermesAllowlistOwnerField:  true,
		})
	}
	document["approvals"] = kept
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
		return nil
	}
	return atomicWriteFile(path, data, 0o600)
}

// planHermesAllowlistApprovals returns the approvals Setup keeps and the
// required events whose current DefenseClaw approval is already present.
func planHermesAllowlistApprovals(path string, approvals []interface{}, command string) ([]interface{}, map[string]bool, error) {
	events := hermesHookEventSet()
	recognizedCommands := hermesRecognizedHookCommands(command)
	managedCurrent := map[string]bool{}
	kept := make([]interface{}, 0, len(approvals)+len(events))
	for _, raw := range approvals {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			kept = append(kept, raw)
			continue
		}
		event, _ := entry["event"].(string)
		entryCommand, _ := entry["command"].(string)
		_, requiredEvent := events[event]
		owned, _ := entry[hermesAllowlistOwnerField].(bool)
		_, recognized := recognizedCommands[entryCommand]
		if owned {
			if !recognized {
				return nil, nil, fmt.Errorf("Hermes allowlist entry %q has a tampered DefenseClaw command; refusing non-exact repair", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			}
			if !requiredEvent || managedCurrent[event] {
				// Remove exact DefenseClaw-owned stale events and duplicates.
				continue
			}
			if entryCommand == command {
				managedCurrent[event] = true
				kept = append(kept, raw)
			}
			// A finite recognized historical command is replaced below.
			continue
		}
		if requiredEvent && recognized {
			if hermesConsentForCommand(entry, command) {
				// Adopted: a marked approval replaces it below.
				continue
			}
			return nil, nil, fmt.Errorf("Hermes allowlist entry %q lost its DefenseClaw ownership marker; refusing ambiguous repair (remove the entries for DefenseClaw's hook from %s, then run 'defenseclaw setup hermes')", event, path) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		kept = append(kept, raw)
	}
	return kept, managedCurrent, nil
}

func teardownHermesAllowlist(opts SetupOpts, configPath, command string) error {
	if err := validateHermesWindowsConfigPath(configPath); err != nil {
		return err
	}
	logicalName := hermesAllowlistLogicalName
	path := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	backup, backupErr := loadManagedFileBackupForTransform(opts.DataDir, "hermes", logicalName, path)
	if backupErr != nil && !os.IsNotExist(backupErr) {
		return backupErr
	}
	// Approvals that carry DefenseClaw's ownership marker are DefenseClaw's
	// even in the copy Setup captured (a file put back from an earlier
	// enrollment holds them), so that copy is restored only without them.
	if backup == nil || !hermesAllowlistHoldsOwnedApprovals(backup.PristineBytes) {
		restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, "hermes", logicalName, path)
		if err != nil {
			return err
		}
		if restored {
			return nil
		}
	}
	if backup == nil {
		if _, statErr := os.Stat(path); os.IsNotExist(statErr) {
			return nil
		} else if statErr != nil {
			return statErr
		}
	}
	if backupErr == nil && backup != nil {
		if err := validateHermesManagedBackupPristine(backup); err != nil {
			return err
		}
	}
	if err := removeHermesOwnedApprovals(path, command, backup); err != nil {
		return err
	}
	discardManagedFileBackup(opts.DataDir, "hermes", logicalName)
	return nil
}

// removeHermesOwnedApprovals removes DefenseClaw's approvals of command
// from the Hermes allowlist at path. The approvals the copy Setup captured
// (backup) held go back as Hermes wrote them.
func removeHermesOwnedApprovals(path, command string, backup *managedFileBackup) error {
	document, err := readHermesAllowlist(path)
	if err != nil {
		return err
	}
	pristinePairs := map[string]bool{}
	if backup != nil && backup.Existed && len(bytes.TrimSpace(backup.PristineBytes)) > 0 {
		var pristine map[string]interface{}
		if err := json.Unmarshal(backup.PristineBytes, &pristine); err != nil {
			return fmt.Errorf("parse Hermes pristine allowlist custody: %w", err)
		}
		if approvals, ok := pristine["approvals"].([]interface{}); ok {
			for _, raw := range approvals {
				if entry, ok := raw.(map[string]interface{}); ok {
					if owned, _ := entry[hermesAllowlistOwnerField].(bool); owned {
						continue
					}
					event, _ := entry["event"].(string)
					entryCommand, _ := entry["command"].(string)
					pristinePairs[event+"\x00"+entryCommand] = true
				}
			}
		}
	}
	events := hermesHookEventSet()
	approvals := document["approvals"].([]interface{})
	kept := make([]interface{}, 0, len(approvals))
	for _, raw := range approvals {
		entry, ok := raw.(map[string]interface{})
		if !ok {
			kept = append(kept, raw)
			continue
		}
		event, _ := entry["event"].(string)
		entryCommand, _ := entry["command"].(string)
		owned, _ := entry[hermesAllowlistOwnerField].(bool)
		_, requiredEvent := events[event]
		pair := event + "\x00" + entryCommand
		if owned && requiredEvent && !pristinePairs[pair] {
			if entryCommand != command {
				return fmt.Errorf("Hermes allowlist entry %s has a tampered DefenseClaw command; refusing non-exact cleanup", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			}
			continue
		}
		if owned && pristinePairs[pair] {
			// Setup adopted the consent Hermes had recorded in the copy it
			// captured; it goes back as Hermes wrote it (GAP-1241).
			delete(entry, hermesAllowlistOwnerField)
		} else if backup != nil && requiredEvent && entryCommand == command && !pristinePairs[pair] {
			if hermesConsentForCommand(entry, command) {
				// Consent Hermes recorded for DefenseClaw's hook after Setup
				// goes with the hook.
				continue
			}
			return fmt.Errorf("Hermes allowlist entry %s lost its DefenseClaw ownership marker; refusing ambiguous cleanup", event) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		kept = append(kept, raw)
	}
	document["approvals"] = kept
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(path, append(data, '\n'), 0o600)
}

// hermesConfigBackupHoldsOwnedHooks reports whether the config.yaml copy
// Setup captured registers DefenseClaw's hook.
func hermesConfigBackupHoldsOwnedHooks(dataDir, logicalName, path, hookScript string) bool {
	backup, err := loadManagedFileBackupForTransform(dataDir, "hermes", logicalName, path)
	if err != nil || backup == nil || !backup.Existed {
		return false
	}
	var cfg map[string]interface{}
	if yaml.Unmarshal(backup.PristineBytes, &cfg) != nil {
		return false
	}
	return containsHookScript(cfg["hooks"], hookScript)
}

// hermesAllowlistHoldsOwnedApprovals reports whether an allowlist document
// holds an approval with DefenseClaw's ownership marker.
func hermesAllowlistHoldsOwnedApprovals(data []byte) bool {
	var document struct {
		Approvals []interface{} `json:"approvals"`
	}
	if json.Unmarshal(data, &document) != nil {
		return false
	}
	for _, raw := range document.Approvals {
		if entry, ok := raw.(map[string]interface{}); ok {
			if owned, _ := entry[hermesAllowlistOwnerField].(bool); owned {
				return true
			}
		}
	}
	return false
}

func writeHermesDirectNativeState(opts SetupOpts, command, status string) error {
	if status != hermesDirectNativePending && status != hermesDirectNativeDisabled {
		return fmt.Errorf("invalid Hermes direct-native state %q", status)
	}
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("Hermes direct-native command is empty") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	state := map[string]interface{}{
		"schema_version":        hermesDirectNativeStateVersion,
		"connector":             "hermes",
		"status":                status,
		"command":               command,
		"reload_required":       true,
		"running_host_verified": false,
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName), append(data, '\n'), 0o600)
}

func validateHermesSingleProfile(configPath string) error {
	home := filepath.Clean(filepath.Dir(configPath))
	if strings.EqualFold(filepath.Base(filepath.Dir(home)), "profiles") {
		return fmt.Errorf("Hermes named profiles are unsupported by the single-HERMES_HOME connector; point HERMES_HOME at the default profile (run 'hermes profile use default') and retry; no changes made") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	activeProfile := filepath.Join(home, "active_profile")
	if info, err := os.Lstat(activeProfile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("Hermes active_profile is not a regular non-symlink file") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		if info.Size() > 4096 {
			return fmt.Errorf("Hermes active_profile exceeds the bounded inspection limit") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		data, readErr := os.ReadFile(activeProfile)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("inspect Hermes active_profile: %w", readErr)
		}
		if profile := strings.TrimSpace(string(data)); profile != "" && !strings.EqualFold(profile, "default") {
			return fmt.Errorf("Hermes active named profile %q is unsupported by the single-HERMES_HOME connector; switch back with 'hermes profile use default' and retry; no changes made", profile) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Hermes active_profile: %w", err)
	}
	profilesDir := filepath.Join(home, "profiles")
	if info, err := os.Lstat(profilesDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("Hermes profiles path is not a regular directory") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		directory, openErr := os.Open(profilesDir)
		if openErr != nil {
			return fmt.Errorf("inspect Hermes profiles directory: %w", openErr)
		}
		entries, readErr := directory.ReadDir(257)
		closeErr := directory.Close()
		// ReadDir(n > 0) reports an empty directory as io.EOF.
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("inspect Hermes profiles directory: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close Hermes profiles directory: %w", closeErr)
		}
		if len(entries) > 256 {
			return fmt.Errorf("Hermes profiles directory exceeds the bounded inspection limit") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		for _, entry := range entries {
			if !hermesProfileEntryName(entry.Name()) {
				continue
			}
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("Hermes named profile %q is unsupported by the single-HERMES_HOME connector; remove it with 'hermes profile delete %s' (or move it out of %s) and retry; no changes made", entry.Name(), entry.Name(), profilesDir) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Hermes profiles directory: %w", err)
	}
	// gateway.multiplex_profiles is not checked: Hermes writes its default
	// (true) into config.yaml on its own, and a multiplexing gateway serves
	// the default profile plus the named profiles under profiles/, which are
	// refused above. With none, it serves only this HERMES_HOME (GAP-1844).
	return nil
}

// hermesProfileEntryName reports whether an entry under profiles/ is one
// Hermes can run as a named profile. Hermes lists, serves and resolves the
// names its id pattern ^[a-z0-9][a-z0-9_-]{0,63}$ admits under Python's
// re.match, whose $ also matches before one final newline, so "coder\n" is
// a profile as well. Only the exact name "default" means the root
// HERMES_HOME; Hermes's own metadata (the .deleted 'hermes profile delete'
// can leave, other dot directories) and any other name are never a profile.
// The name is lowercased first: on a case-insensitive file system
// 'hermes -p coder' opens profiles/Coder. The Python CLI's preflight
// (hermes_profile_entry_name in cli/defenseclaw/connector_paths.py) applies
// the same rule; testdata/hermes_profile_names.json holds the cases both
// are tested against.
func hermesProfileEntryName(name string) bool {
	id, newline := strings.CutSuffix(strings.ToLower(name), "\n")
	if (id == "default" && !newline) || len(id) == 0 || len(id) > 64 {
		return false
	}
	for i, r := range id {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9':
		case i > 0 && (r == '_' || r == '-'):
		default:
			return false
		}
	}
	return true
}

func readHermesBoundedConfig(path string) (map[string]interface{}, error) {
	info, err := os.Lstat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return nil, fmt.Errorf("Hermes config is not a regular non-symlink file") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	if info.Size() > hermesInventoryConfigMaxBytes {
		return nil, fmt.Errorf("Hermes config exceeds the %d-byte inspection limit", hermesInventoryConfigMaxBytes) //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return readYAMLObject(path)
}

func hermesSkillPaths(configPath string) []string {
	home := filepath.Dir(configPath)
	paths := []string{filepath.Join(home, "skills")}
	cfg, err := readHermesBoundedConfig(configPath)
	if err != nil {
		return paths
	}
	skills, _ := cfg["skills"].(map[string]interface{})
	raw, ok := skills["external_dirs"]
	if !ok {
		return paths
	}
	entries := []interface{}{raw}
	if list, ok := raw.([]interface{}); ok {
		entries = list
	}
	if len(entries) > 256 {
		entries = entries[:256]
	}
	for _, entry := range entries {
		value, ok := entry.(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}
		value = os.ExpandEnv(strings.TrimSpace(value))
		if strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`) {
			value = filepath.Join(userHomeDir(), value[2:])
		} else if !filepath.IsAbs(value) {
			value = filepath.Join(home, value)
		}
		value = filepath.Clean(value)
		if info, statErr := os.Stat(value); statErr == nil && info.IsDir() {
			paths = append(paths, value)
		}
	}
	return uniqueNonEmptyStrings(paths)
}

func hermesPluginPaths(configPath string) []string {
	home := filepath.Dir(configPath)
	paths := []string{
		filepath.Join(home, "plugins"),
		filepath.Join(home, "hermes-agent", "plugins"),
	}
	if bundled := strings.TrimSpace(os.Getenv("HERMES_BUNDLED_PLUGINS")); bundled != "" {
		paths = append(paths, filepath.Clean(bundled))
	}
	return uniqueNonEmptyStrings(paths)
}

func patchHermesHooks(path, hookScript, hookExecutable string, setup ...SetupOpts) error {
	var opts SetupOpts
	if len(setup) > 0 {
		opts = setup[0]
	}
	cfg, err := readYAMLObject(path)
	if err != nil {
		return err
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if hooks == nil {
		hooks = map[string]interface{}{}
		cfg["hooks"] = hooks
	}
	// Hermes' global hooks_auto_accept switch belongs to the operator. Setup
	// leaves it byte-semantically untouched and separately provisions only the
	// exact DefenseClaw (event, command) approvals in the vendor allowlist.
	hookCommand := hermesConfiguredHookCommand(hookScript, hookExecutable)
	recognizedCommands := hermesRecognizedHookCommands(hookCommand)
	for _, spec := range hermesRequiredHooks {
		entry := hermesHookEntry(hookCommand, spec.event, spec.matcher, opts)
		reconciled, reconcileErr := reconcileHermesHookEntries(hooks[spec.event], recognizedCommands, entry)
		if reconcileErr != nil {
			return fmt.Errorf("reconcile Hermes event %s: %w", spec.event, reconcileErr)
		}
		hooks[spec.event] = reconciled
	}
	for event, raw := range hooks {
		if _, required := hermesHookEventSet()[event]; required {
			continue
		}
		reconciled, reconcileErr := removeStaleHermesHookEntries(raw, recognizedCommands)
		if reconcileErr != nil {
			return fmt.Errorf("reconcile unexpected Hermes event %s: %w", event, reconcileErr)
		}
		if len(reconciled) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = reconciled
		}
	}
	data, err := marshalTopLevelYAMLFieldPreservingOtherBytes(path, "hooks", hooks)
	if err != nil {
		return err
	}
	if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
		return nil
	}
	return atomicWriteFile(path, data, 0o600)
}

// marshalTopLevelYAMLFieldPreservingOtherBytes replaces one top-level YAML
// field while retaining every byte outside that field. Hermes owns the hooks
// mapping only; comments, quoting, ordering, line endings, and operator fields
// elsewhere in config.yaml must not be reformatted by reconciliation.
func marshalTopLevelYAMLFieldPreservingOtherBytes(
	path string,
	field string,
	value interface{},
) ([]byte, error) {
	original, err := os.ReadFile(path)
	if err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return replaceTopLevelYAMLFieldPreservingOtherBytes(path, original, field, value)
}

// replaceTopLevelYAMLFieldPreservingOtherBytes is
// marshalTopLevelYAMLFieldPreservingOtherBytes for bytes already read; path
// only names the document in errors.
func replaceTopLevelYAMLFieldPreservingOtherBytes(
	path string,
	original []byte,
	field string,
	value interface{},
) ([]byte, error) {
	rendered, err := yaml.Marshal(map[string]interface{}{field: value})
	if err != nil {
		return nil, err
	}
	lineEnding := []byte("\n")
	if bytes.Contains(original, []byte("\r\n")) {
		lineEnding = []byte("\r\n")
		rendered = bytes.ReplaceAll(rendered, []byte("\n"), lineEnding)
	}
	if len(bytes.TrimSpace(original)) == 0 {
		return rendered, nil
	}

	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return nil, fmt.Errorf("parse YAML %s for byte-preserving update: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse YAML %s for byte-preserving update: root is not a mapping", path)
	}
	root := document.Content[0]
	// Hermes bootstraps a fresh config.yaml as the compact flow mapping `{}`.
	// Appending a block-style `hooks:` field after that token produces two YAML
	// roots. yaml.v3 decodes only the first empty mapping, so Setup appears to
	// succeed while the effective-registration verifier cannot see any hook.
	// There are no operator fields to preserve in this exact minimal document;
	// replace it with the rendered mapping instead.
	if len(root.Content) == 0 && bytes.Equal(bytes.TrimSpace(original), []byte("{}")) {
		return rendered, nil
	}
	offsets := yamlLineOffsets(original)
	for index := 0; index+1 < len(root.Content); index += 2 {
		key := root.Content[index]
		if key.Value != field {
			continue
		}
		start, ok := yamlLineOffset(offsets, key.Line)
		if !ok {
			return nil, fmt.Errorf("parse YAML %s for byte-preserving update: invalid %s start", path, field)
		}
		end := len(original)
		if index+2 < len(root.Content) {
			var valid bool
			end, valid = yamlLineOffset(offsets, root.Content[index+2].Line)
			if !valid {
				return nil, fmt.Errorf("parse YAML %s for byte-preserving update: invalid %s end", path, field)
			}
		}
		end = preserveTrailingTopLevelYAMLTrivia(original, start, end)
		updated := make([]byte, 0, start+len(rendered)+len(original)-end)
		updated = append(updated, original[:start]...)
		updated = append(updated, rendered...)
		updated = append(updated, original[end:]...)
		return updated, nil
	}

	updated := append([]byte(nil), original...)
	if !bytes.HasSuffix(updated, []byte("\n")) {
		updated = append(updated, lineEnding...)
	}
	updated = append(updated, rendered...)
	return updated, nil
}

func yamlLineOffsets(data []byte) []int {
	offsets := []int{0}
	for index, value := range data {
		if value == '\n' && index+1 < len(data) {
			offsets = append(offsets, index+1)
		}
	}
	return offsets
}

func yamlLineOffset(offsets []int, line int) (int, bool) {
	if line < 1 || line > len(offsets) {
		return 0, false
	}
	return offsets[line-1], true
}

func preserveTrailingTopLevelYAMLTrivia(data []byte, start, end int) int {
	for cursor := end; cursor > start; {
		previousEnd := cursor
		if previousEnd > start && data[previousEnd-1] == '\n' {
			previousEnd--
		}
		if previousEnd > start && data[previousEnd-1] == '\r' {
			previousEnd--
		}
		previousStart := bytes.LastIndexByte(data[start:previousEnd], '\n')
		if previousStart < 0 {
			previousStart = start
		} else {
			previousStart += start + 1
		}
		line := data[previousStart:previousEnd]
		trimmed := bytes.TrimSpace(line)
		if len(trimmed) != 0 && (!(bytes.HasPrefix(trimmed, []byte("#"))) || len(line) != len(bytes.TrimLeft(line, " \t"))) {
			break
		}
		cursor = previousStart
		end = previousStart
	}
	return end
}

// hermesHookEntry is the one handler Setup registers for a Hermes event.
func hermesHookEntry(hookCommand, event, matcher string, opts SetupOpts) map[string]interface{} {
	entry := map[string]interface{}{
		"command": hookCommand,
		"timeout": 30,
	}
	contractID := strings.TrimSpace(opts.HookContractID)
	if contractID == "" {
		contractID = ResolveHookContract("hermes", opts.AgentVersion).Contract.ContractID
	}
	if event == "pre_tool_call" && contractID == "hermes-hooks-v2" && !shellHookSecureClientProfile(opts) {
		// Hermes 0.21+ blocks a spawn failure or timeout only when this
		// setting is present. A killed process can still fail open on its
		// non-2 exit with empty stdout; v1 and other events cannot use it.
		entry["fail_closed"] = true
	}
	if matcher != "" {
		entry["matcher"] = matcher
	}
	return entry
}

// hermesHookScriptName is the Hermes hook script Setup generates on Unix.
const hermesHookScriptName = "hermes-hook.sh"

// hermesReplaceableHookCommand reports whether Setup replaces a Hermes hook
// handler with its own: an exact current or historical DefenseClaw command,
// or the generated script at an edited path. Hermes hook failures are
// fail-open, so refusing to repair an edited path left the agent unguarded
// (GAP-0906). Other commands that only name DefenseClaw stay refused.
func hermesReplaceableHookCommand(command string, recognizedCommands map[string]struct{}) bool {
	if _, recognized := recognizedCommands[command]; recognized {
		return true
	}
	return editedDefenseClawHookCommand(command, hermesHookScriptName)
}

func hermesRecognizedHookCommands(current string) map[string]struct{} {
	commands := map[string]struct{}{}
	if current = strings.TrimSpace(current); current != "" {
		commands[current] = struct{}{}
	}
	for _, binary := range nativeHookBinaryOwnershipCandidates() {
		if command := windowsHermesDirectHookCommand(binary); command != "" {
			commands[command] = struct{}{}
		}
	}
	return commands
}

func hermesHookEntryCommand(raw interface{}) (string, bool) {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return "", false
	}
	command, ok := entry["command"].(string)
	return command, ok
}

func hermesCommandClaimsDefenseClaw(command string) bool {
	command = strings.ToLower(strings.TrimSpace(command))
	return strings.Contains(command, "--connector hermes") || strings.Contains(command, "hermes-hook.sh")
}

func hermesHookList(raw interface{}) ([]interface{}, error) {
	switch value := raw.(type) {
	case nil:
		return nil, nil
	case []interface{}:
		return value, nil
	case map[string]interface{}:
		// Repair the common exact-owned single-map shape into Hermes' required array.
		return []interface{}{value}, nil
	default:
		return nil, fmt.Errorf("hook registration is not an array")
	}
}

func reconcileHermesHookEntries(
	raw interface{},
	recognizedCommands map[string]struct{},
	expected map[string]interface{},
) ([]interface{}, error) {
	list, err := hermesHookList(raw)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(list)+1)
	replaced := false
	for _, item := range list {
		command, hasCommand := hermesHookEntryCommand(item)
		if hermesReplaceableHookCommand(command, recognizedCommands) {
			if !replaced {
				out = append(out, expected)
				replaced = true
			}
			continue
		}
		if hasCommand && hermesCommandClaimsDefenseClaw(command) {
			return nil, fmt.Errorf("handler has a tampered DefenseClaw command; refusing non-exact repair")
		}
		out = append(out, item)
	}
	if !replaced {
		out = append(out, expected)
	}
	return out, nil
}

func removeStaleHermesHookEntries(
	raw interface{},
	recognizedCommands map[string]struct{},
) ([]interface{}, error) {
	list, err := hermesHookList(raw)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(list))
	for _, item := range list {
		command, hasCommand := hermesHookEntryCommand(item)
		if hermesReplaceableHookCommand(command, recognizedCommands) {
			continue
		}
		if hasCommand && hermesCommandClaimsDefenseClaw(command) {
			return nil, fmt.Errorf("handler has a tampered DefenseClaw command; refusing non-exact repair")
		}
		out = append(out, item)
	}
	return out, nil
}

func removeHermesHooks(path, hookScript string, backup *managedFileBackup) error {
	if backup != nil {
		if err := validateHermesManagedBackupPristine(backup); err != nil {
			return err
		}
	}
	// A missing config reads as an empty document; teardown must not create
	// one for a user who never had it.
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	cfg, err := readYAMLObject(path)
	if err != nil {
		return err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return nil
	}
	for event, raw := range hooks {
		hooks[event] = removeOwnedFlatHooks(raw, hookScript)
	}
	pruneEmptyMapArrays(hooks)
	// DefenseClaw owns entries in the hooks mapping only: every other byte of
	// config.yaml (Hermes' commented template, the user's settings and their
	// order and quoting) stays as it is. A hooks field that Setup added to a
	// copy without one goes as a whole, so an edited config is the captured
	// copy plus the edit and an unedited one is the captured copy again;
	// leaving `hooks: {}` behind changed the file's bytes (GAP-0262).
	var data []byte
	if len(hooks) == 0 && !hermesPristineHasOwnHooksField(backup, hookScript) {
		data, err = removeTopLevelYAMLFieldPreservingOtherBytes(path, "hooks")
		if err != nil {
			return err
		}
	}
	if data == nil {
		data, err = marshalTopLevelYAMLFieldPreservingOtherBytes(path, "hooks", hooks)
		if err != nil {
			return err
		}
	}
	if current, readErr := os.ReadFile(path); readErr == nil && bytes.Equal(current, data) {
		return nil
	}
	return atomicWriteFile(path, data, 0o600)
}

// hermesPristineHasOwnHooksField reports whether the config.yaml copy Setup
// captured has a hooks field of the account's own, that is one that holds
// more than DefenseClaw's entries or that the account left empty. Without a
// copy, or with one that does not parse, the field is taken to be the
// account's and stays.
func hermesPristineHasOwnHooksField(backup *managedFileBackup, hookScript string) bool {
	if backup == nil {
		return true
	}
	if !backup.Existed || len(bytes.TrimSpace(backup.PristineBytes)) == 0 {
		return false
	}
	var pristine map[string]interface{}
	if err := yaml.Unmarshal(backup.PristineBytes, &pristine); err != nil {
		return true
	}
	raw, present := pristine["hooks"]
	if !present {
		return false
	}
	hooks, ok := raw.(map[string]interface{})
	if !ok || len(hooks) == 0 {
		return true
	}
	for event, value := range hooks {
		hooks[event] = removeOwnedFlatHooks(value, hookScript)
	}
	pruneEmptyMapArrays(hooks)
	return len(hooks) != 0
}

// removeTopLevelYAMLFieldPreservingOtherBytes removes one top-level field of
// the YAML document at path and keeps every other byte: the lines from the
// field's key to the next top-level key go, and top-level comments after the
// field stay with what follows (as replaceTopLevelYAMLFieldPreservingOtherBytes
// keeps them). A document left with nothing is the empty mapping {}. It
// returns nil, and no error, when it cannot cut the field out by lines (a
// flow-style root, or a cut that would change another field); the caller
// then renders the field instead. The bytes are returned unchanged when the
// field is absent.
func removeTopLevelYAMLFieldPreservingOtherBytes(path, field string) ([]byte, error) {
	original, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var document yaml.Node
	if err := yaml.Unmarshal(original, &document); err != nil {
		return nil, fmt.Errorf("parse YAML %s for byte-preserving update: %w", path, err)
	}
	if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("parse YAML %s for byte-preserving update: root is not a mapping", path)
	}
	root := document.Content[0]
	if root.Style&yaml.FlowStyle != 0 {
		return nil, nil
	}
	offsets := yamlLineOffsets(original)
	for index := 0; index+1 < len(root.Content); index += 2 {
		if root.Content[index].Value != field {
			continue
		}
		start, ok := yamlLineOffset(offsets, root.Content[index].Line)
		if !ok {
			return nil, nil
		}
		end := len(original)
		if index+2 < len(root.Content) {
			if end, ok = yamlLineOffset(offsets, root.Content[index+2].Line); !ok || end <= start {
				return nil, nil
			}
		}
		end = preserveTrailingTopLevelYAMLTrivia(original, start, end)
		updated := make([]byte, 0, len(original)-(end-start))
		updated = append(updated, original[:start]...)
		updated = append(updated, original[end:]...)
		if len(bytes.TrimSpace(updated)) == 0 {
			lineEnding := "\n"
			if bytes.Contains(original, []byte("\r\n")) {
				lineEnding = "\r\n"
			}
			return []byte("{}" + lineEnding), nil
		}
		if !yamlTopLevelKeysAre(updated, yamlTopLevelKeysWithout(root, field)) {
			return nil, nil
		}
		return updated, nil
	}
	return original, nil
}

// yamlTopLevelKeysWithout lists the keys of a mapping node except field.
func yamlTopLevelKeysWithout(root *yaml.Node, field string) []string {
	var keys []string
	for index := 0; index+1 < len(root.Content); index += 2 {
		if key := root.Content[index].Value; key != field {
			keys = append(keys, key)
		}
	}
	return keys
}

// yamlTopLevelKeysAre reports whether data is a YAML mapping with exactly
// the keys want, in that order.
func yamlTopLevelKeysAre(data []byte, want []string) bool {
	var document yaml.Node
	if err := yaml.Unmarshal(data, &document); err != nil ||
		len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
		return false
	}
	got := yamlTopLevelKeysWithout(document.Content[0], "")
	if len(got) != len(want) {
		return false
	}
	for index := range got {
		if got[index] != want[index] {
			return false
		}
	}
	return true
}

func validateHermesManagedBackupPristine(backup *managedFileBackup) error {
	if !backup.Existed {
		if backup.PristineSHA256 != managedBackupMissingHash || len(backup.PristineBytes) != 0 {
			return fmt.Errorf("Hermes pristine custody for a missing file is inconsistent") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
		}
		return nil
	}
	if backup.PristineSHA256 != sha256Hex(backup.PristineBytes) {
		return fmt.Errorf("Hermes pristine custody hash does not match its captured bytes") //nolint:staticcheck // Preserve the product or platform name in this operator diagnostic.
	}
	return nil
}

func patchCursorHooks(path, hookScript, legacyShellScript string, failClosed bool) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	ownedCommands := newCursorHookCommandMatcher(cursorManagedHookCommands(hookScript, legacyShellScript))
	cfg["version"] = 1
	for _, event := range cursorHookEvents {
		entry := map[string]interface{}{
			"type":    "command",
			"command": shellWord(hookScript),
			// Cursor's hooks.json timeout is in seconds; use the same
			// shared constant the enterprise writer emits so a bug in
			// one place cannot deviate. A raw 30000 was 30000 seconds
			// (>8 hours), long enough for a hung hook to freeze Cursor.
			"timeout":    windowsCursorEnterpriseHookTimeoutSeconds,
			"failClosed": failClosed,
		}
		// Replace instead of merely appending. This both migrates the previous
		// direct-native Windows command to the PowerShell adapter and refreshes
		// failClosed when the connector moves between observe and action mode.
		// Entries not owned by DefenseClaw are preserved in their original order.
		hooks[event] = replaceManagedCursorHooks(hooks[event], ownedCommands, filepath.Base(hookScript), entry)
	}
	return writeJSONObject(path, cfg)
}

// ownedCursorHookContractPresent validates the exact registration Setup writes
// before the gateway is allowed to publish active/contract-lock evidence. A
// substring hit is not readiness: all 21 documented events must contain one
// current command entry with the mode-matched type/timeout/failure contract, and
// no legacy or duplicate DefenseClaw entries may remain elsewhere.
func (c *hookOnlyConnector) ownedCursorHookContractPresent(opts SetupOpts) (bool, error) {
	if c == nil || c.name != "cursor" {
		return false, errors.New("cursor hook contract verifier called for a different connector")
	}
	path := c.configPath(opts)
	runtimePath := c.cursorRuntimePath(opts)
	runtimeInfo, err := os.Lstat(runtimePath)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	if !runtimeInfo.Mode().IsRegular() || runtimeInfo.Mode()&os.ModeSymlink != 0 || runtimeInfo.Size() > 512*1024 {
		return false, nil
	}
	runtimeBody, err := readHookConfigFile(runtimePath)
	if err != nil {
		return false, err
	}
	runtimeMarkers := []string{"defenseclaw-managed-hook v8"}
	if runtime.GOOS == "windows" {
		runtimeMarkers = []string{
			"defenseclaw-managed-hook v9",
			"defenseclaw-hook.exe",
			"ProcessStartInfo",
			"RedirectStandardInput",
			"RedirectStandardOutput",
			"WaitForExit",
		}
		failureResponseMarker := `{"continue":true}`
		if c.effectiveFailClosed(opts) {
			failureResponseMarker = `"permission":"deny"`
		}
		runtimeMarkers = append(runtimeMarkers, failureResponseMarker)
	}
	for _, marker := range runtimeMarkers {
		if !bytes.Contains(runtimeBody, []byte(marker)) {
			return false, nil
		}
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	version, ok := cfg["version"].(json.Number)
	if !ok || version.String() != "1" {
		return false, nil
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	currentCommand := shellWord(c.hookCommand(opts))
	ownedCommands := uniqueNonEmptyStrings(append(
		[]string{c.hookCommand(opts), currentCommand},
		cursorOwnedHookCommands(opts)...,
	))
	ownedMatcher := newCursorHookCommandMatcher(ownedCommands)
	return cursorHookContractPresent(hooks, currentCommand, ownedMatcher, c.effectiveFailClosed(opts)), nil
}

func cursorHookContractPresent(hooks map[string]interface{}, currentCommand string, ownedMatcher cursorHookCommandMatcher, expectedFailClosed bool) bool {
	expected := make(map[string]struct{}, len(cursorHookEvents))
	for _, event := range cursorHookEvents {
		expected[event] = struct{}{}
		entries, ok := hooks[event].([]interface{})
		if !ok {
			return false
		}
		ownedCount := 0
		for _, raw := range entries {
			if !ownedMatcher.matches(raw) {
				continue
			}
			ownedCount++
			entry, ok := raw.(map[string]interface{})
			if !ok || len(entry) != 4 || entry["type"] != "command" || entry["command"] != currentCommand {
				return false
			}
			timeout, ok := entry["timeout"].(json.Number)
			if !ok || timeout.String() != "30" {
				return false
			}
			failClosed, ok := entry["failClosed"].(bool)
			if !ok || failClosed != expectedFailClosed {
				return false
			}
		}
		if ownedCount != 1 {
			return false
		}
	}
	for event, raw := range hooks {
		if _, ok := expected[event]; ok {
			continue
		}
		entries, _ := raw.([]interface{})
		for _, entry := range entries {
			if ownedMatcher.matches(entry) {
				return false
			}
		}
	}
	return true
}

func (c *hookOnlyConnector) cursorRuntimePath(opts SetupOpts) string {
	name := "cursor-hook.sh"
	if runtime.GOOS == "windows" {
		name = "cursor-hook.ps1"
	}
	return filepath.Join(opts.DataDir, "hooks", name)
}

func cursorManagedHookCommands(hookScript, legacyShellScript string) []string {
	return uniqueNonEmptyStrings(append(
		[]string{
			hookScript,
			legacyShellScript,
			hookInvocationCommandFor("windows", "cursor", legacyShellScript),
		},
		legacyCursorNativeHookCommands()...,
	))
}

// replaceManagedCursorHooks drops DefenseClaw's entries, including one whose
// scriptName path was edited (GAP-0907), and appends entry.
func replaceManagedCursorHooks(
	raw interface{}, ownedCommands cursorHookCommandMatcher, scriptName string, entry map[string]interface{},
) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	for _, item := range list {
		if ownedCommands.matches(item) || editedDefenseClawHookEntry(item, scriptName) {
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

type cursorHookCommandMatcher map[string]struct{}

// newCursorHookCommandMatcher computes the exact strings accepted by
// managedHookCommandEntry once per Cursor reconciliation. Cursor ownership is
// deliberately path-bound; none of its commands use Copilot's cross-version
// native-command equivalence. Keeping Cursor on this exact-string rail avoids
// re-running the much broader Copilot recognizer for every foreign hook entry.
func newCursorHookCommandMatcher(ownedCommands []string) cursorHookCommandMatcher {
	matcher := make(cursorHookCommandMatcher, len(ownedCommands)*2)
	for _, owned := range ownedCommands {
		owned = strings.TrimSpace(owned)
		if owned == "" {
			continue
		}
		matcher[owned] = struct{}{}
		matcher[strings.TrimSpace(shellWord(owned))] = struct{}{}
	}
	return matcher
}

func (matcher cursorHookCommandMatcher) matches(raw interface{}) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"command", "bash", "powershell"} {
		command, _ := entry[key].(string)
		if _, ok := matcher[strings.TrimSpace(command)]; ok && strings.TrimSpace(command) != "" {
			return true
		}
	}
	return false
}

func managedCursorHookEntry(raw interface{}, ownedCommands []string) bool {
	return newCursorHookCommandMatcher(ownedCommands).matches(raw)
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
	// This file is DefenseClaw's registration. A user-added switch here
	// disables every hook in it, including the handlers restored below.
	delete(cfg, "disableAllHooks")
	selected := make(map[string]bool, len(events))
	for _, event := range events {
		if !ValidCopilotHookEvent(event) {
			return fmt.Errorf("copilot: unsupported hook event %q in resolved contract", event)
		}
		selected[event] = true
		// Copilot runs every entry in an event array. An independent entry in
		// this file must be moved before Setup can safely restore the current
		// hook. Check all entries before writing any event back to disk.
		if raw, present := hooks[event]; present {
			entries, ok := raw.([]interface{})
			if !ok {
				entries = []interface{}{raw}
			}
			for _, entry := range entries {
				if !copilotBoundEventOwnsHook(entry, hookScript) {
					return fmt.Errorf("copilot: cannot repair event %q in %s: an independent or unrecognized handler is present; move it to another hook file in the same hooks directory, then run defenseclaw setup copilot again", event, path)
				}
			}
		}
		hooks[event] = []interface{}{copilotHookRegistration(goos, event, hookScript)}
	}
	// Remove DefenseClaw's handler from events outside this contract too. An
	// operator's own handlers on those events stay intact.
	for event, raw := range hooks {
		if selected[event] {
			continue
		}
		remaining, changed, err := stripCopilotOwnedEntry(raw, hookScript)
		if err != nil {
			return fmt.Errorf("copilot: cannot repair event %q in %s: %w", event, path, err)
		}
		if !changed {
			continue
		}
		if remaining == nil {
			delete(hooks, event)
		} else {
			hooks[event] = remaining
		}
	}
	return writeJSONObject(path, cfg)
}

// A bound event may be replaced only when every executable command in its
// entry is a known DefenseClaw form. Do not claim a combined command or a
// nested handler merely because it also mentions our script.
func copilotBoundEventOwnsHook(raw interface{}, hookScript string) bool {
	if copilotLiveOperatorLookalike(raw, hookScript) {
		return false
	}
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	if kind, present := entry["type"]; present && kind != "command" {
		return false
	}
	for _, key := range []string{"handlers", "hooks", "action"} {
		if _, present := entry[key]; present {
			return false
		}
	}
	owned := false
	for _, key := range []string{"bash", "command", "powershell", "command_windows", "commandWindows"} {
		value, present := entry[key]
		if !present {
			continue
		}
		command, ok := value.(string)
		if !ok || !copilotBoundEventOwnsCommand(key, command, hookScript) {
			return false
		}
		owned = true
	}
	return owned
}

func copilotBoundEventOwnsCommand(key, command, hookScript string) bool {
	if isCopilotPowerShellAdapterCommand(hookScript) {
		if key != "powershell" && key != "command" {
			return false
		}
		if isCopilotNativeHookCommand(command) {
			return true
		}
		for _, event := range copilotCurrentHookEvents {
			if command == copilotHookInvocationCommandForEvent("windows", event, hookScript) {
				return true
			}
		}
		// A previous DefenseClaw adapter may have been deleted along with
		// its data directory. Its event-bound command still identifies it.
		if binding := copilotPowerShellAdapterBinding.FindStringSubmatch(strings.TrimSpace(command)); len(binding) == 3 {
			adapter := strings.ReplaceAll(binding[1], "''", "'")
			if _, err := os.Lstat(adapter); errors.Is(err, os.ErrNotExist) {
				return true
			}
		}
		return copilotMarkedAdapterCommand(command)
	}
	if managedHookCommandEntry(map[string]interface{}{key: command}, hookScript) {
		return true
	}
	if key == "powershell" {
		return copilotMarkedAdapterCommand(command)
	}
	if key != "bash" && key != "command" {
		return false
	}
	word, rest, ok := hookScriptWordAfterWrapper(strings.TrimSpace(command))
	if !ok || !filepath.IsAbs(word) || filepath.Clean(word) != word ||
		(rest != "" && !copilotBoundEventArgument(rest)) {
		return false
	}
	if copilotMarkedShellCopy(word) {
		return true
	}
	// A deleted copy has no marker to read. The exact DefenseClaw script
	// name with Copilot's event binding remains a repairable registration.
	if isCopilotShellHookScript(word) && copilotBoundEventArgument(rest) {
		if _, err := os.Lstat(word); errors.Is(err, os.ErrNotExist) {
			return true
		}
	}
	_, owned := editedDefenseClawHookScript(word+rest, "copilot-hook.sh")
	return owned
}

func copilotMarkedShellCopy(path string) bool {
	body, err := safefile.ReadRegularFileBounded(path, 1<<20)
	if err != nil {
		return false
	}
	if len(body) > 512 {
		body = body[:512]
	}
	return bytes.Contains(body, []byte("# defenseclaw-managed-hook v"))
}

func copilotMarkedAdapterCommand(command string) bool {
	binding := copilotPowerShellAdapterBinding.FindStringSubmatch(strings.TrimSpace(command))
	if len(binding) != 3 || !ValidCopilotHookEvent(binding[2]) {
		return false
	}
	adapter := strings.ReplaceAll(binding[1], "''", "'")
	body, err := safefile.ReadRegularFileBounded(adapter, 1<<20)
	if err != nil {
		return false
	}
	if len(body) > 512 {
		body = body[:512]
	}
	return bytes.Contains(body, []byte("# defenseclaw-managed-hook v")) &&
		bytes.Contains(bytes.ToLower(body), []byte("copilot"))
}

func copilotBoundEventArgument(rest string) bool {
	for _, event := range copilotCurrentHookEvents {
		if rest == " --event "+shellWord(event) || rest == " --event "+event {
			return true
		}
	}
	return false
}

func copilotUnexpectedEventOwnsHook(raw interface{}, hookScript string) bool {
	if copilotLiveOperatorLookalike(raw, hookScript) {
		return false
	}
	if copilotBoundEventOwnsHook(raw, hookScript) || containsHookScript(raw, hookScript) || editedDefenseClawHookEntry(raw, hookScriptBaseName(hookScript)) || copilotOldManagedCopyEntry(raw) {
		return true
	}
	if !isCopilotPowerShellAdapterCommand(hookScript) {
		return copilotCommandContainsScript(raw, hookScript)
	}
	adapter := strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(hookScript), "& '"), "'"))
	return copilotPowerShellCommandClaimsHandler(raw, adapter)
}

// A live operator script may share the DefenseClaw basename and Copilot's
// event argument. Its content has no DefenseClaw marker, so neither Setup
// nor teardown may claim it. A deleted copy remains repairable.
func copilotLiveOperatorLookalike(raw interface{}, hookScript string) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"bash", "command", "powershell", "command_windows", "commandWindows"} {
		command, _ := entry[key].(string)
		if command == "" {
			continue
		}
		if binding := copilotPowerShellAdapterBinding.FindStringSubmatch(strings.TrimSpace(command)); len(binding) == 3 {
			adapter := strings.ReplaceAll(binding[1], "''", "'")
			current := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(hookScript), "& '"), "'")
			if !strings.EqualFold(adapter, current) && !copilotMarkedAdapterCommand(command) {
				if info, err := os.Lstat(adapter); err == nil && info.Mode().IsRegular() {
					return true
				}
			}
			continue
		}
		word, rest, parsed := hookScriptWordAfterWrapper(strings.TrimSpace(command))
		if parsed && word != hookScript && isCopilotShellHookScript(word) && copilotBoundEventArgument(rest) &&
			!copilotMarkedShellCopy(word) {
			if info, err := os.Lstat(word); err == nil && info.Mode().IsRegular() {
				return true
			}
		}
	}
	return false
}

// stripCopilotOwnedEntry removes only handler entries that belong to
// DefenseClaw. An unexpected event can contain nested independent handlers;
// finding our command anywhere in the enclosing value is not ownership of
// that whole value. A handler with both our executable and an independent
// executable cannot be separated, so leave the file unchanged and report it.
func stripCopilotOwnedEntry(raw interface{}, hookScript string) (interface{}, bool, error) {
	switch value := raw.(type) {
	case []interface{}:
		remaining := make([]interface{}, 0, len(value))
		changed := false
		for _, item := range value {
			kept, removed, err := stripCopilotOwnedEntry(item, hookScript)
			if err != nil {
				return raw, false, err
			}
			changed = changed || removed
			if kept != nil {
				remaining = append(remaining, kept)
			}
		}
		if len(remaining) == 0 && changed {
			return nil, true, nil
		}
		return remaining, changed, nil
	case map[string]interface{}:
		ownCommand, foreignCommand := false, false
		for _, key := range []string{"command", "bash", "powershell", "command_windows", "commandWindows"} {
			command, present := value[key]
			if !present {
				continue
			}
			if text, ok := command.(string); ok {
				candidate := map[string]interface{}{key: text}
				owned := copilotBoundEventOwnsHook(candidate, hookScript)
				if !owned && copilotUnexpectedEventOwnsHook(candidate, hookScript) {
					owned = !strings.Contains(text, hookScript) || copilotCommandRunsCurrentHook(text, hookScript)
				}
				if owned {
					ownCommand = true
				} else {
					foreignCommand = true
				}
			}
		}
		if ownCommand {
			if foreignCommand {
				return raw, false, errors.New("a handler combines DefenseClaw and independent commands; move the independent command to its own handler")
			}
			for _, child := range value {
				switch child.(type) {
				case []interface{}, map[string]interface{}:
					return raw, false, errors.New("a handler combines DefenseClaw and independent nested content; separate the handlers")
				}
			}
			return nil, true, nil
		}
		remaining := make(map[string]interface{}, len(value))
		changed := false
		for key, child := range value {
			switch child.(type) {
			case []interface{}, map[string]interface{}:
				kept, removed, err := stripCopilotOwnedEntry(child, hookScript)
				if err != nil {
					return raw, false, err
				}
				changed = changed || removed
				if kept != nil {
					remaining[key] = kept
				}
			default:
				remaining[key] = child
			}
		}
		if len(remaining) == 0 && changed {
			return nil, true, nil
		}
		return remaining, changed, nil
	default:
		return raw, false, nil
	}
}

// A command can mention our hook path as data (for example an audit log
// argument). Only a command that starts the hook counts as an edited copy.
func copilotCommandRunsCurrentHook(command, hookScript string) bool {
	segments := strings.NewReplacer("&&", ";", "||", ";", "\n", ";").Replace(command)
	for _, segment := range strings.Split(segments, ";") {
		segment = strings.TrimSpace(segment)
		if strings.HasPrefix(segment, hookScript) {
			return true
		}
		word, _, ok := hookScriptWordAfterWrapper(segment)
		if ok && word == hookScript {
			return true
		}
	}
	return false
}

// copilotCommandContainsScript matches the POSIX doctor's command-key search.
// A changed command on an unexpected event must be removed by Setup, even
// when another command prefixes it or the handler is nested in a mapping.
func copilotCommandContainsScript(raw interface{}, hookScript string) bool {
	if hookScript == "" {
		return false
	}
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if copilotCommandContainsScript(item, hookScript) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			switch key {
			case "command", "bash", "powershell", "command_windows", "commandWindows":
				if command, ok := item.(string); ok && strings.Contains(command, hookScript) {
					return true
				}
			}
			if copilotCommandContainsScript(item, hookScript) {
				return true
			}
		}
	}
	return false
}

// Match the Windows doctor's adapter binding and legacy launcher forms on
// unexpected events. These handlers must be claimed by Setup and teardown
// even when an older install used a different data directory or binary.
var copilotPowerShellAdapterBinding = regexp.MustCompile(`(?i)^& '((?:[^']|'')+copilot-hook\.ps1)' -Event '([^']+)'$`)

func copilotPowerShellCommandClaimsHandler(raw interface{}, adapter string) bool {
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if copilotPowerShellCommandClaimsHandler(item, adapter) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			if key == "powershell" {
				if command, ok := item.(string); ok {
					lowered := strings.ToLower(command)
					missingAdapter := false
					if binding := copilotPowerShellAdapterBinding.FindStringSubmatch(strings.TrimSpace(command)); len(binding) == 3 {
						path := strings.ReplaceAll(binding[1], "''", "'")
						_, err := os.Lstat(path)
						missingAdapter = errors.Is(err, os.ErrNotExist)
					}
					if strings.Contains(lowered, adapter) || copilotMarkedAdapterCommand(command) || missingAdapter ||
						((strings.Contains(lowered, "hook --connector copilot") || strings.Contains(lowered, "'hook','--connector','copilot'")) &&
							(strings.Contains(lowered, "defenseclaw-hook") || strings.Contains(lowered, "$hookprocess") || strings.HasPrefix(lowered, "& "))) {
						return true
					}
				}
			}
			if copilotPowerShellCommandClaimsHandler(item, adapter) {
				return true
			}
		}
	}
	return false
}

// copilotHookRegistration is the one Copilot hook entry DefenseClaw registers
// for event: user and workspace hook files on the host, and the root-owned
// policy.d document in OpenShell sandbox images.
func copilotHookRegistration(goos, event, hookScript string) map[string]interface{} {
	entry := map[string]interface{}{
		"type":       "command",
		"timeoutSec": copilotHookTimeoutSeconds,
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
	return entry
}

// copilotHookTimeoutSeconds is Copilot's command-hook envelope.
const copilotHookTimeoutSeconds = 30

func copilotHookInvocationCommandForEvent(goos, event, hookScript string) string {
	if goos == "windows" {
		return windowsCopilotPowerShellAdapterCommand(hookScript) + " -Event " + powershellQuoteLiteral(event)
	}
	return shellWord(hookScript) + " --event " + shellWord(event)
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
	if goos != "windows" && strings.IndexFunc(hookScript, unicode.IsSpace) >= 0 {
		// Antigravity splits the command on whitespace and runs it directly.
		// Shell metacharacters and Unicode letters do not need shell quoting.
		return fmt.Errorf("antigravity cannot run a hook from %s: it splits hook commands at whitespace and runs them without a shell; set DEFENSECLAW_HOME to a directory whose path has no whitespace, then run: defenseclaw setup antigravity", hookScript)
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	for key, value := range antigravityOwnedHookKeys(goos, hookScript) {
		cfg[key] = value
	}
	return writeJSONObject(path, cfg)
}

// antigravityOwnedHookKeys renders the outer keys DefenseClaw owns in
// Antigravity's hooks.json, one per lifecycle event.
func antigravityOwnedHookKeys(goos, hookScript string) map[string]interface{} {
	keys := make(map[string]interface{}, len(antigravityLifecycleEvents))
	for _, event := range antigravityLifecycleEvents {
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
		keys[antigravityOwnedHookKeyPrefix+strings.ToLower(event)] = map[string]interface{}{event: handlers}
	}
	return keys
}

// antigravityOwnedHookKeyPrefix begins each outer key DefenseClaw owns in
// Antigravity's hooks.json (patchAntigravityHooks).
const antigravityOwnedHookKeyPrefix = "defenseclaw-antigravity-"

// AntigravityHooksHoldOwnedEntries reports whether the Antigravity hooks file
// at path still has one of DefenseClaw's own outer keys, whatever command
// the entry runs.
func AntigravityHooksHoldOwnedEntries(path string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	for key := range cfg {
		if strings.HasPrefix(key, antigravityOwnedHookKeyPrefix) {
			return true, nil
		}
	}
	return false, nil
}

// removeAntigravityOwnedHookEntries drops DefenseClaw's own outer keys from
// the Antigravity hooks file at path and keeps every other key.
func removeAntigravityOwnedHookEntries(path string) error {
	owned, err := AntigravityHooksHoldOwnedEntries(path)
	if err != nil || !owned {
		return err
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	for key := range cfg {
		if strings.HasPrefix(key, antigravityOwnedHookKeyPrefix) {
			delete(cfg, key)
		}
	}
	return writeJSONObject(path, cfg)
}

func readYAMLObject(path string) (map[string]interface{}, error) {
	data, err := readHookConfigFile(path)
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
	data, err := readHookConfigFile(path)
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

// copilotOldManagedCopyEntry recognizes a copied DefenseClaw launcher outside
// the usual data directory. A stale registered copy can still answer open
// after the current launcher is rendered closed. Only a regular script with
// DefenseClaw's Copilot marker is claimed; an unrelated operator hook stays.
func copilotOldManagedCopyEntry(raw interface{}) bool {
	entry, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	for _, key := range []string{"bash", "command"} {
		command, _ := entry[key].(string)
		word, rest, parsed := posixHookCommandSplit(strings.TrimSpace(command))
		if !parsed || !filepath.IsAbs(word) || filepath.Clean(word) != word ||
			(rest != "" && !strings.HasPrefix(rest, " --event ")) {
			continue
		}
		body, err := safefile.ReadRegularFileBounded(word, 1<<20)
		if err != nil {
			continue
		}
		if len(body) > 512 {
			body = body[:512]
		}
		if bytes.Contains(body, []byte("# defenseclaw-managed-hook v")) &&
			bytes.Contains(body, []byte("DefenseClaw Copilot CLI hook")) {
			return true
		}
	}
	return false
}

func appendUniqueMatcherHookGroup(raw interface{}, hookScript string, group map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	for _, item := range list {
		if managedMatcherHookGroup(item, hookScript) {
			return list
		}
	}
	return append(list, group)
}

// removeJSONHookReferences removes DefenseClaw's handlers from an agent's
// JSON hooks file. The file is the agent's (and the operator's), so teardown
// for a user who never had one leaves it absent instead of writing "{}";
// readJSONObject reads a missing file as an empty document, so the absence is
// checked first.
func removeJSONHookReferences(path string, hookScripts ...string) error {
	return removeJSONHookReferencesProfile(path, false, hookScripts...)
}

func removeJSONHookReferencesProfile(path string, secureClient bool, hookScripts ...string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	var pruned map[string]interface{}
	if secureClient {
		pruned, _ = removeHookScriptReferencesLegacy(cfg, hookScripts...).(map[string]interface{})
	} else {
		pruned, _ = removeHookScriptReferences(cfg, hookScripts...).(map[string]interface{})
	}
	if pruned == nil {
		pruned = map[string]interface{}{}
	}
	if !secureClient {
		if hooks, ok := pruned["hooks"].(map[string]interface{}); ok {
			before, _ := cfg["hooks"].(map[string]interface{})
			pruneNewlyEmptyHookEntries(before, hooks)
			// An empty hooks object the user already had is theirs (GAP-0650).
			if len(hooks) == 0 && len(before) > 0 {
				delete(pruned, "hooks")
			}
		}
	}
	if !secureClient && reflect.DeepEqual(pruned, cfg) {
		return nil
	}
	return writeJSONObject(path, pruned)
}

// removeCopilotHookReferences removes DefenseClaw's Copilot handlers from
// its own hooks file (<hooks>/defenseclaw.json, which Copilot loads with
// every other *.json there). Teardown for a user who never had the file must
// not create one, and a file left with nothing but the schema version (or an
// empty document an earlier teardown wrote) is DefenseClaw's leftover and is
// deleted; operator handlers in it are kept.
func removeCopilotHookReferences(path, hookScript string) error {
	return removeCopilotHookReferencesProfile(path, false, hookScript)
}

func removeCopilotHookReferencesProfile(path string, secureClient bool, hookScript string) error {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return nil
	}
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	var pruned map[string]interface{}
	if secureClient {
		pruned, _ = removeHookScriptReferencesLegacy(cfg, hookScript).(map[string]interface{})
	} else {
		pruned = make(map[string]interface{}, len(cfg))
		for key, value := range cfg {
			pruned[key] = value
		}
	}
	if pruned == nil {
		pruned = map[string]interface{}{}
	}
	if !secureClient {
		if hooks, ok := pruned["hooks"].(map[string]interface{}); ok {
			before := hooks
			hooks = make(map[string]interface{}, len(before))
			for event, raw := range before {
				hooks[event] = raw
			}
			pruned["hooks"] = hooks
			// Doctor and Setup claim an edited handler on any event in this
			// DefenseClaw-owned file. Teardown must use the same predicate:
			// the generic remover only recognizes exact commands in lists.
			for event, raw := range hooks {
				remaining, changed, err := stripCopilotOwnedEntry(raw, hookScript)
				if err != nil {
					return fmt.Errorf("copilot: cannot remove event %q in %s: %w", event, path, err)
				}
				if !changed {
					continue
				}
				if remaining == nil {
					delete(hooks, event)
				} else {
					hooks[event] = remaining
				}
			}
			pruneNewlyEmptyHookEntries(before, hooks)
			if len(hooks) == 0 {
				delete(pruned, "hooks")
			}
		}
	}
	if !secureClient && reflect.DeepEqual(pruned, cfg) && (!(strings.EqualFold(filepath.Base(path), "defenseclaw.json")) || !(copilotHooksDocumentEmpty(pruned))) {
		return nil
	}
	if strings.EqualFold(filepath.Base(path), "defenseclaw.json") && copilotHooksDocumentEmpty(pruned) {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	return writeJSONObject(path, pruned)
}

// copilotHooksDocumentEmpty reports a Copilot hooks document that holds no
// handler and nothing but its schema version.
func copilotHooksDocumentEmpty(cfg map[string]interface{}) bool {
	for key, value := range cfg {
		if key == "version" {
			continue
		}
		if hooks, ok := value.(map[string]interface{}); key == "hooks" && ok && len(hooks) == 0 {
			continue
		}
		return false
	}
	return true
}

func removeHookScriptReferences(raw interface{}, hookScripts ...string) interface{} {
	switch v := raw.(type) {
	case []interface{}:
		out := make([]interface{}, 0, len(v))
		for _, item := range v {
			owned := false
			for _, command := range hookScripts {
				owned = owned || managedHookCommandEntry(item, command) ||
					editedDefenseClawHookHandler(item, hookScriptBaseName(command))
			}
			if owned {
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
		return out
	default:
		return raw
	}
}

func removeOwnedFlatHooks(raw interface{}, hookScript string) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list))
	edited := hookScriptBaseName(hookScript)
	for _, item := range list {
		if containsHookScript(item, hookScript) || editedDefenseClawHookEntry(item, edited) {
			continue
		}
		out = append(out, item)
	}
	return out
}

// pruneNewlyEmptyHookEntries removes only containers emptied by removing an
// owned hook. Operator-owned empty lists and mappings are left untouched.
func pruneNewlyEmptyHookEntries(before, after map[string]interface{}) {
	for key, value := range after {
		previous := before[key]
		switch current := value.(type) {
		case []interface{}:
			old, ok := previous.([]interface{})
			if ok && len(old) > 0 && len(current) == 0 {
				delete(after, key)
			}
		case map[string]interface{}:
			old, ok := previous.(map[string]interface{})
			if ok {
				pruneNewlyEmptyHookEntries(old, current)
				if len(old) > 0 && len(current) == 0 {
					delete(after, key)
				}
			}
		}
	}
}

// removeHookScriptReferencesLegacy is main's JSON hook cleanup. Secure
// Client retains its matching and empty-container behavior until migration.
func removeHookScriptReferencesLegacy(raw interface{}, hookScripts ...string) interface{} {
	switch value := raw.(type) {
	case []interface{}:
		out := make([]interface{}, 0, len(value))
		for _, item := range value {
			if containsHookScript(item, hookScripts...) {
				continue
			}
			out = append(out, removeHookScriptReferencesLegacy(item, hookScripts...))
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(value))
		for key, item := range value {
			out[key] = removeHookScriptReferencesLegacy(item, hookScripts...)
		}
		pruneEmptyMapArrays(out)
		return out
	default:
		return raw
	}
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
			if containsHookScript(hooks, hookScripts...) {
				return true
			}
		}
		// Event-keyed hook blocks -- Kiro CLI 2.x writes
		// {"hooks": {"preToolUse": [{...}], ...}} -- put the entries one map
		// level below "hooks". Walking only the "hooks" value stopped at that
		// map, whose own keys are event names rather than "command", so a
		// correctly registered agent config read as unregistered. Recurse
		// through the remaining values so any nesting depth is reachable.
		for key, value := range v {
			if key == "hooks" {
				continue
			}
			if containsHookScript(value, hookScripts...) {
				return true
			}
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
		if isCopilotPowerShellAdapterCommand(hookScript) && isCopilotNativeHookCommand(command) {
			return true
		}
		if isCopilotPowerShellAdapterCommand(hookScript) && isCopilotEventBoundPowerShellAdapterCommand(command) {
			return true
		}
		for _, event := range copilotCurrentHookEvents {
			if command == copilotHookInvocationCommandForEvent("windows", event, hookScript) {
				return true
			}
		}
		if isCopilotShellHookScript(hookScript) && isCopilotEventBoundShellCommand(command, hookScript) {
			return true
		}
	}
	return false
}

func isCopilotPowerShellAdapterCommand(command string) bool {
	command = strings.TrimSpace(command)
	return strings.HasPrefix(command, "& '") &&
		strings.HasSuffix(strings.ToLower(command), "copilot-hook.ps1'")
}

func isCopilotEventBoundPowerShellAdapterCommand(command string) bool {
	command = strings.TrimSpace(command)
	for _, event := range copilotCurrentHookEvents {
		suffix := " -Event " + powershellQuoteLiteral(event)
		if strings.HasSuffix(command, suffix) &&
			isCopilotPowerShellAdapterCommand(strings.TrimSuffix(command, suffix)) {
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

func managedMatcherHookGroup(raw interface{}, hookScript string) bool {
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
