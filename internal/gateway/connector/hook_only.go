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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/hermespath"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
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

var hermesConfigPathResolver = hermespath.ConfigPath

const (
	hermesAllowlistLogicalName      = "shell-hooks-allowlist.json"
	hermesAllowlistFileName         = "shell-hooks-allowlist.json"
	hermesAllowlistOwnerField       = "defenseclaw_managed"
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

// OpenCodeRegistrationSnapshot is an opaque, connector-local rollback point
// for the plugin and its custody receipt. It intentionally exposes no token or
// path contents outside this package.
type OpenCodeRegistrationSnapshot struct {
	pluginPath     string
	plugin         openCodeFileSnapshot
	backupPath     string
	backup         openCodeFileSnapshot
	initiallyEmpty bool
}

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

// CaptureOpenCodeRegistrationSnapshot records the exact pre-reconcile plugin
// and receipt bytes after validating the plugin destination custody.
func CaptureOpenCodeRegistrationSnapshot(opts SetupOpts) (*OpenCodeRegistrationSnapshot, error) {
	conn := NewOpenCodeConnector()
	pluginPath := conn.configPath(opts)
	if err := prepareOpenCodePluginArtifactDestination(pluginPath); err != nil {
		return nil, fmt.Errorf("prepare OpenCode plugin destination: %w", err)
	}
	backupPath := managedFileBackupPath(opts.DataDir, conn.name, "config")
	plugin, err := snapshotOpenCodeRegistrationFile(pluginPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot OpenCode plugin: %w", err)
	}
	backup, err := snapshotOpenCodeRegistrationFile(backupPath)
	if err != nil {
		return nil, fmt.Errorf("snapshot OpenCode custody receipt: %w", err)
	}
	return &OpenCodeRegistrationSnapshot{
		pluginPath:     pluginPath,
		plugin:         plugin,
		backupPath:     backupPath,
		backup:         backup,
		initiallyEmpty: !plugin.existed && !backup.existed,
	}, nil
}

// Restore atomically replaces or removes both connector-local files to match
// the pre-reconcile snapshot.
func (s *OpenCodeRegistrationSnapshot) Restore() error {
	if s == nil {
		return errors.New("OpenCode registration snapshot is nil")
	}
	return rollbackOpenCodePluginPublication(s.pluginPath, s.plugin, s.backupPath, s.backup)
}

// InitiallyEmpty reports whether rollback should leave no managed plugin
// registration for VerifyClean to confirm.
func (s *OpenCodeRegistrationSnapshot) InitiallyEmpty() bool {
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
		scriptName:  "hermes-hook.sh",
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

func NewWindsurfConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "windsurf",
		description: "legacy Cascade-only hooks with bounded local customization discovery",
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

var windsurfCascadeHookEvents = []string{
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
}

var geminiCLIHookEvents = []string{
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
}

var geminiCLIBlockEvents = []string{
	"BeforeAgent",
	"BeforeModel",
	"BeforeTool",
	"AfterTool",
	"AfterModel",
	"AfterAgent",
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
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        append([]string(nil), geminiCLIBlockEvents...),
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
	// Cursor and the retired Windsurf cleanup connector require connector-specific PowerShell adapters only
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
// connectors. Gemini CLI has a managed JSON-block telemetry section with a
// scoped path-token. On Darwin, OpenHands additionally exposes a reviewed
// process-environment trace exporter with connector-scoped header auth; the
// connector deliberately does not persist those variables or mutate a shell
// profile. Copilot upstream documents an optional OTel exporter, but
// DefenseClaw does not configure or certify that surface. Cursor, Windsurf,
// Hermes, and the non-Darwin OpenHands profiles remain hook-only.
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
	if c.name == "opencode" {
		profile.MapVerdict = openCodeProfileMapVerdict
	}
	if c.name == "geminicli" {
		profile.NativeOTLP = geminiCLINativeOTLPSpec(opts)
	}
	if c.name == "openhands" {
		profile.NativeOTLP = openhandsNativeOTLPSpecForOS(opts, runtime.GOOS)
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
	}
	if c.name == "cursor" {
		profile.Decode = cursorProfileDecode
	}
	if c.name == "windsurf" {
		profile.Decode = windsurfProfileDecode
	}
	if c.name == "devin" {
		profile.Decode = devinProfileDecode
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

// openhandsNativeOTLPSpecForOS describes the process environment consumed by
// the OpenHands SDK observability layer on the reviewed macOS lane. The SDK
// exports traces through standard OTEL variables; DefenseClaw does not persist
// this block in hooks.json or a shell profile. The protected connector launch
// command renders it only for the admitted child. Native attributes remain
// exporter-only until upstream documents a stable cross-rail identity.
func openhandsNativeOTLPSpecForOS(opts SetupOpts, goos string) *NativeOTLPSpec {
	if strings.ToLower(strings.TrimSpace(goos)) != "darwin" {
		return nil
	}
	endpoint := "http://" + strings.TrimSpace(opts.APIAddr)
	headers := map[string]string{
		"x-defenseclaw-source": "openhands",
		"x-defenseclaw-client": "openhands-otel/1.0",
	}
	token := strings.TrimSpace(opts.OTLPPathToken)
	if token == "" && strings.TrimSpace(opts.DataDir) != "" {
		token, _ = LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands)
	}
	if token != "" {
		headers["authorization"] = "Bearer " + token
	}
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
			"OTEL_EXPORTER_OTLP_TRACES_HEADERS":  serializeOTLPHeaders(headers),
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
	case "windsurf":
		caps.MCP = SurfaceCapability{
			Supported:     true,
			Scope:         "user",
			ConfigPaths:   windsurfMCPPaths(opts),
			ReadPaths:     windsurfMCPPaths(opts),
			DiscoveryOnly: true,
			RequiresOptIn: true,
			Notes: []string{
				"This is the legacy Cascade mcp_config.json surface under the bound user profile; Devin Local uses separate config files and is unsupported.",
				"DefenseClaw discovers the existing file only and does not create guessed MCP paths.",
				"Cloud, Team/Enterprise registry, allowlist, and managed state are excluded and unverified.",
			},
		}
		caps.Rules = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     windsurfRulePaths(opts),
			DiscoveryOnly: true,
			Notes: []string{
				"Legacy Cascade inventory covers the user-global rule, preferred .devin/rules, legacy .windsurf/rules and .windsurfrules, plus bounded recursive/ancestor AGENTS.md discovery.",
				"ProgramData/system, cloud dashboard, MDM, and authoritative enforcement across higher layers are excluded and unverified.",
				"Rule writes remain deferred unless a documented or pre-existing path is present.",
			},
		}
		caps.CodeGuard.Supported = true
		caps.CodeGuard.InstallTargets = []string{"rule"}
		caps.CodeGuard.Notes = append(caps.CodeGuard.Notes, "Legacy Cascade CodeGuard rule installation is available only when a documented/pre-existing rules path exists.")
		caps.Skills = SurfaceCapability{
			Supported:     true,
			Scope:         "workspace,user",
			ReadPaths:     windsurfSkillPaths(opts),
			DiscoveryOnly: true,
			Notes: []string{
				"Legacy Cascade skills are inventoried from bound-user and pinned-workspace .windsurf/skills and .agents/skills roots.",
				"Optional Claude-config reading and ProgramData/system enterprise skills are excluded and unverified.",
			},
		}
		caps.Plugins = pluginsAreOpenClawOnly()
		caps.Agents = unsupportedSurface("Legacy Cascade has no supported agent/subagent asset surface; Devin Local and ACP agents are outside this connector.")
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
				"Cloud Devin, proxy, ACP, team-managed, and dynamically registered MCP sources are outside this native local connector.",
			},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      devinSkillPaths(opts),
			WritePaths:     devinSkillWritePaths(opts),
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
			Notes:          []string{"Discovery covers Devin's user skills directory and the documented .agents/skills and .devin/skills project roots; installs use the native .devin/skills root."},
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      devinRulePaths(opts),
			WritePaths:     []string{workspacePath(opts, ".devin", "rules")},
			InstallTargets: []string{"rule"},
			RequiresOptIn:  true,
			Notes:          []string{"Discovery covers AGENTS.md/AGENT.md and Markdown rules under .devin/rules without claiming cloud or managed-policy precedence."},
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
	case "geminicli":
		geminiHome := geminiConfigHome(opts)
		geminiSettings := geminiSettingsPaths(opts)
		caps.MCP = SurfaceCapability{
			Supported:       true,
			Scope:           "workspace,user",
			ConfigPaths:     geminiSettings,
			ReadPaths:       geminiSettings,
			WritePaths:      geminiSettings,
			SupportsBackup:  true,
			SupportsRestore: true,
			Notes:           []string{"A pinned workspace uses <workspace>/.gemini/settings.json ahead of the bound user settings file; system-level MCP definitions remain operator-managed."},
		}
		caps.Skills = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{geminiHomePath(geminiHome, "skills"), workspacePath(opts, ".gemini", "skills"), workspacePath(opts, ".agents", "skills")},
			WritePaths:     []string{geminiHomePath(geminiHome, "skills"), workspacePath(opts, ".gemini", "skills")},
			InstallTargets: []string{"skill"},
			RequiresOptIn:  true,
		}
		caps.Plugins = SurfaceCapability{
			Supported:     true,
			Scope:         "user",
			ReadPaths:     []string{geminiHomePath(geminiHome, "extensions")},
			DiscoveryOnly: true,
			Notes: []string{
				"Gemini CLI loads installed extensions from the bound user profile; workspace settings can enable or disable those installations but do not define a second extension root.",
				"DefenseClaw does not install, remove, or modify Gemini extensions.",
			},
		}
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{geminiHomePath(geminiHome, "agents"), workspacePath(opts, ".gemini", "agents")},
			WritePaths:     []string{geminiHomePath(geminiHome, "agents"), workspacePath(opts, ".gemini", "agents")},
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
		}
		caps.Rules = SurfaceCapability{
			Supported:      true,
			Scope:          "workspace,user",
			ReadPaths:      []string{geminiHomePath(geminiHome, "skills"), workspacePath(opts, ".agents", "skills")},
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
			ConfigPaths:      geminiSettings,
			AuthMode:         "path-token-loopback",
			EndpointTemplate: "http://" + opts.APIAddr + "/otlp/geminicli/<token>",
			SourceModes:      []string{"native", "hook"},
			Notes: []string{
				"Gemini CLI telemetry is configured in the bound user settings.json with a path token because custom OTLP headers are not documented.",
				"Setup and health inspect the pinned workspace and system settings for effective overrides; an unpinned future workspace or per-process environment can still change Gemini's effective telemetry.",
			},
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
			Notes:         []string{"Read-only discovery uses the official `copilot plugins list --kind plugin --json` command under the validated pinned workspace and exact COPILOT_HOME. DefenseClaw does not install, enable, disable, or remove Copilot plugins; semantic activation and managed/organization policy remain unverified without live-session evidence."},
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
		caps.Plugins = unsupportedSurface("N/A for the OpenHands CLI: the SDK accepts plugins programmatically, but the reviewed CLI exposes no persistent plugin install/config path for DefenseClaw to manage.")
		caps.Agents = SurfaceCapability{
			Supported:      true,
			Scope:          "user,workspace",
			ReadPaths:      openhandsAgentPaths(opts),
			WritePaths:     openhandsAgentWritePaths(opts),
			InstallTargets: []string{"agent"},
			RequiresOptIn:  true,
			Notes:          []string{"OpenHands loads file-based subagents from .agents/agents/*.md first and .openhands/agents/*.md as the legacy fallback. Built-in general-purpose, code-explorer, and bash-runner agents are runtime-provided and are not filesystem assets; default, explore, and bash are deprecated aliases."},
		}
		caps.Telemetry = TelemetryCapability{
			HookSignals: []string{"logs", "metrics", "traces"},
			SourceModes: []string{"hook"},
			Notes: []string{
				"OpenHands hook events supply DefenseClaw audit, metric, and trace telemetry on every supported platform.",
			},
		}
		if runtime.GOOS == "darwin" {
			caps.Telemetry.NativeOTLP = true
			caps.Telemetry.NativeSignals = []string{"traces"}
			caps.Telemetry.Env = []EnvRequirement{
				{Name: "OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", Scope: EnvScopeProcess, Required: false, Description: "Point OpenHands SDK native traces at the DefenseClaw gateway."},
				{Name: "OTEL_EXPORTER_OTLP_TRACES_PROTOCOL", Scope: EnvScopeProcess, Required: false, Description: "Set to http/protobuf for DefenseClaw OTLP trace ingestion."},
				{Name: "OTEL_EXPORTER_OTLP_TRACES_HEADERS", Scope: EnvScopeProcess, Required: false, Description: "Carry connector-scoped bearer and OpenHands source/client attribution."},
			}
			caps.Telemetry.AuthMode = "scoped-header-token-loopback"
			caps.Telemetry.EndpointTemplate = "http://" + strings.TrimSpace(opts.APIAddr) + "/v1/traces"
			caps.Telemetry.SourceModes = []string{"native", "hook"}
			caps.Telemetry.Notes = append(caps.Telemetry.Notes,
				"The reviewed macOS SDK lane accepts standard OTEL process variables and exports traces only.",
				"DefenseClaw does not persist OTEL variables or wrap arbitrary OpenHands launches; use `defenseclaw-gateway connector launch --connector openhands -- <args>` for the protected child environment.",
				"Native trace attributes are exporter-only and are not claimed as cross-rail identity.",
			)
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
	if c.name == "hermes" {
		configPath := c.configPath(opts)
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
			return err
		}
		if err := validateHermesSingleProfile(configPath); err != nil {
			return err
		}
		if err := validateHermesWindowsSetupAdmission(ctx, opts); err != nil {
			return err
		}
		if err := ensureManagedBackupDirRestricted(opts.DataDir); err != nil {
			return fmt.Errorf("prepare Hermes lifecycle state: %w", err)
		}
		return withOwnedFileLock(filepath.Join(opts.DataDir, ".hermes-lifecycle.lock"), func() error {
			return c.setup(ctx, opts, configPath)
		})
	}
	if c.name == "geminicli" {
		return c.setupGeminiWithTokenRollback(ctx, opts)
	}
	if c.name == "openhands" && runtime.GOOS == "darwin" {
		return c.setupOpenHandsWithTokenRollback(ctx, opts)
	}
	return c.setup(ctx, opts, "")
}

// setupGeminiWithTokenRollback provisions the connector-scoped OTLP token as
// one lifecycle unit with Gemini's settings registration. A token that existed
// before Setup belongs to an earlier successful registration and must survive
// a retry failure. Conversely, a token minted by this attempt is revoked when
// any later setup step fails so an unsuccessful install does not leave a live
// credential behind.
func (c *hookOnlyConnector) setupGeminiWithTokenRollback(ctx context.Context, opts SetupOpts) error {
	existingToken, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	if err != nil {
		return fmt.Errorf("geminicli inspect scoped OTLP token: %w", err)
	}
	suppliedToken := strings.TrimSpace(opts.OTLPPathToken)
	otlpToken, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI, suppliedToken)
	if err != nil {
		return fmt.Errorf("geminicli scoped OTLP token: %w", err)
	}
	freshlyMinted := suppliedToken == "" && existingToken == ""
	opts.OTLPPathToken = otlpToken

	if err := c.setup(ctx, opts, ""); err != nil {
		if freshlyMinted {
			if revokeErr := RemoveOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); revokeErr != nil {
				return errors.Join(err, fmt.Errorf("geminicli revoke scoped OTLP token after failed setup: %w", revokeErr))
			}
		}
		return err
	}
	return nil
}

// setupOpenHandsWithTokenRollback binds the optional process-environment OTLP
// exporter to a connector-scoped credential without leaving a live token after
// a failed hook installation. A pre-existing or explicitly supplied token is
// retained because it may belong to an earlier successful registration.
var openHandsSetupOperation = func(c *hookOnlyConnector, ctx context.Context, opts SetupOpts) error {
	return c.setup(ctx, opts, "")
}

func (c *hookOnlyConnector) setupOpenHandsWithTokenRollback(ctx context.Context, opts SetupOpts) error {
	return withOpenHandsLifecycleTransaction(opts, func() error {
		if runtime.GOOS == "darwin" {
			if _, err := validateOpenHandsDarwinExecutable(opts, false); err != nil {
				return fmt.Errorf("openhands setup executable admission: %w", err)
			}
		}
		return c.setupOpenHandsWithTokenRollbackLocked(ctx, opts)
	})
}

func (c *hookOnlyConnector) setupOpenHandsWithTokenRollbackLocked(ctx context.Context, opts SetupOpts) error {
	existingToken, err := LoadOTLPPathToken(opts.DataDir, OTLPScopeOpenHands)
	if err != nil {
		return fmt.Errorf("openhands inspect scoped OTLP token: %w", err)
	}
	suppliedToken := strings.TrimSpace(opts.OTLPPathToken)
	otlpToken, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeOpenHands, suppliedToken)
	if err != nil {
		return fmt.Errorf("openhands scoped OTLP token: %w", err)
	}
	freshlyMinted := suppliedToken == "" && existingToken == ""
	opts.OTLPPathToken = otlpToken

	if err := openHandsSetupOperation(c, ctx, opts); err != nil {
		if freshlyMinted {
			if revokeErr := RemoveOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); revokeErr != nil {
				return errors.Join(err, fmt.Errorf("openhands revoke scoped OTLP token after failed setup: %w", revokeErr))
			}
		}
		return err
	}
	return nil
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
	if c.name == "openhands" {
		if err := c.migrateOpenHandsConfigTarget(opts, c.configPath(opts)); err != nil {
			return err
		}
	}
	if c.name == "windsurf" && WindsurfHooksPathOverride == "" {
		if _, err := resolveWindsurfHooksPath(opts); err != nil {
			return fmt.Errorf("windsurf authoritative Cascade path: %w", err)
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
	if c.name == "geminicli" {
		present, err := c.geminiOwnedHookContractPresent(opts)
		if err != nil {
			return fmt.Errorf("geminicli verify effective hook/telemetry contract: %w", err)
		}
		if !present {
			return errors.New("geminicli persisted hook/telemetry contract does not match the requested mode")
		}
	}
	return nil
}

// migrateOpenHandsConfigTarget closes the previous managed ownership cycle
// before switching between the user-global and workspace hooks.json targets.
// The receipt is validated before its old path is touched. Unchanged managed
// bytes are restored exactly; an operator-edited target receives surgical
// removal of DefenseClaw entries and retains all foreign hooks.
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

// ownedHookContractPresent verifies the agent-visible plugin identity for
// plugin-artifact connectors. The generic config reader intentionally parses
// structured JSON/YAML/TOML hook registrations; an auto-loaded JavaScript
// plugin is instead authoritative when its exact versioned ownership marker
// is present in the installed regular file.
func (c *hookOnlyConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	if c.name == "geminicli" {
		return c.geminiOwnedHookContractPresent(opts)
	}
	if !c.pluginArtifact {
		return ownedHooksPresentInConfig(c, opts)
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
	marker, _, _ := bytes.Cut(tmpl, []byte("\n"))
	marker = bytes.TrimSuffix(marker, []byte("\r"))
	if len(marker) == 0 || !bytes.HasPrefix(marker, []byte("// defenseclaw-managed-plugin v")) {
		return false, fmt.Errorf("%s managed plugin identity is invalid", c.name)
	}
	installedMarker, _, _ := bytes.Cut(data, []byte("\n"))
	installedMarker = bytes.TrimSuffix(installedMarker, []byte("\r"))
	return bytes.Equal(installedMarker, marker), nil
}

func (c *hookOnlyConnector) geminiOwnedHookContractPresent(opts SetupOpts) (bool, error) {
	path := c.configPath(opts)
	cfg, err := readGeminiSettingsObject(path)
	if err != nil {
		return false, err
	}
	hooks, ok := cfg["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}
	expected := c.hookCommand(opts)
	for _, event := range geminiCLIHookEvents {
		groups, ok := hooks[event].([]interface{})
		if !ok {
			return false, nil
		}
		managed := 0
		for _, group := range groups {
			if geminiManagedHookGroupCurrent(group, expected) {
				managed++
			}
		}
		if managed != 1 {
			return false, nil
		}
	}
	if err := validateGeminiEffectiveSettings(opts, path, false); err != nil {
		return false, err
	}
	return true, nil
}

func geminiManagedHookGroupCurrent(raw interface{}, expectedCommand string) bool {
	group, ok := raw.(map[string]interface{})
	if !ok || len(group) != 2 || group["matcher"] != "*" {
		return false
	}
	hooks, ok := group["hooks"].([]interface{})
	if !ok || len(hooks) != 1 {
		return false
	}
	hook, ok := hooks[0].(map[string]interface{})
	if !ok || len(hook) != 5 || hook["name"] != "defenseclaw" ||
		hook["type"] != "command" || hook["command"] != shellWord(expectedCommand) ||
		hook["description"] != "DefenseClaw hook inspection" {
		return false
	}
	switch timeout := hook["timeout"].(type) {
	case json.Number:
		return timeout.String() == "30000"
	case float64:
		return timeout == 30000
	case int:
		return timeout == 30000
	default:
		return false
	}
}

// setupPluginArtifact renders the embedded bridge-plugin template
// (APIAddr / stable token-sidecar path / FailMode substituted) and writes it
// to the host agent's auto-load plugin directory at 0o600. The scoped token is
// deliberately loaded from its owner-only sidecar at request time rather than
// copied into this longer-lived artifact. The destination is
// captured in the managed-file backup so Teardown can heal it: if the
// plugin file is unchanged since setup it is removed (we created it);
// if the operator hand-edited it, the backup restore leaves it alone.
func (c *hookOnlyConnector) setupPluginArtifact(opts SetupOpts) error {
	tmpl, err := hookFS.ReadFile("hooks/" + c.pluginArtifactAsset)
	if err != nil {
		return fmt.Errorf("%s read plugin template %s: %w", c.name, c.pluginArtifactAsset, err)
	}
	tokenPath, err := HookAPITokenFilePath(opts.DataDir, c.name)
	if err != nil {
		return fmt.Errorf("%s resolve scoped hook credential: %w", c.name, err)
	}
	tokenPath, err = filepath.Abs(tokenPath)
	if err != nil {
		return fmt.Errorf("%s resolve absolute scoped hook credential path: %w", c.name, err)
	}
	failMode := normalizeHookFailMode(opts.HookFailMode)
	if failMode == "closed" && !c.capability(opts).SupportsFailClosed {
		failMode = "open"
	}
	rendered, err := renderTemplate(string(tmpl), templateData{
		APIAddr:     opts.APIAddr,
		TokenFileJS: javaScriptStringContent(tokenPath),
		FailMode:    failMode,
		Managed:     opts.ManagedEnterprise,
	})
	if err != nil {
		return fmt.Errorf("%s render plugin template: %w", c.name, err)
	}
	path := c.configPath(opts)
	if err := prepareOpenCodePluginArtifactDestination(path); err != nil {
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
	renderedBody := []byte(rendered)
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
	if !filepath.IsAbs(path) {
		return fmt.Errorf("plugin path must be absolute: %q", path)
	}
	if err := hookAPIValidateDirectory(filepath.Dir(filepath.Clean(path))); err != nil {
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
	if err := hookAPIValidateOwner(path, info); err != nil {
		return err
	}
	return nil
}

// hookCommand returns the command an agent runs for this connector's hook. On
// Unix it is the bundled .sh path. Most Windows connectors use the native
// DefenseClaw `hook` subcommand; Cursor and retired Cascade cleanup use PowerShell adapters
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
	if c.name == "hermes" {
		configPath := c.configPath(opts)
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
			return err
		}
		if err := ensureManagedBackupDirRestricted(opts.DataDir); err != nil {
			return fmt.Errorf("prepare Hermes lifecycle state: %w", err)
		}
		return withOwnedFileLock(filepath.Join(opts.DataDir, ".hermes-lifecycle.lock"), func() error {
			return c.teardown(ctx, opts, configPath)
		})
	}
	if c.name == "openhands" && runtime.GOOS == "darwin" {
		return c.teardownOpenHandsWithToken(ctx, opts)
	}
	return c.teardown(ctx, opts, "")
}

func (c *hookOnlyConnector) teardownOpenHandsWithToken(ctx context.Context, opts SetupOpts) error {
	return withOpenHandsLifecycleTransaction(opts, func() error {
		if err := c.teardown(ctx, opts, ""); err != nil {
			return err
		}
		if err := c.VerifyClean(opts); err != nil {
			return fmt.Errorf("openhands teardown: verify clean before token revocation: %w", err)
		}
		if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeOpenHands); err != nil {
			return fmt.Errorf("openhands teardown: revoke scoped OTLP token: %w", err)
		}
		return nil
	})
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
	if c.name != "hermes" {
		path = managedFileBackupTargetPath(opts.DataDir, c.name, logicalName, c.configPath(opts))
	}
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
	if c.name == "hermes" {
		command := hermesConfiguredHookCommand(c.hookCommand(opts), opts.HookExecutable)
		if err := teardownHermesAllowlist(opts, hermesConfigPath, command); err != nil {
			errs = append(errs, fmt.Sprintf("restore shell hook allowlist: %v", err))
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

	if len(errs) > 0 {
		return fmt.Errorf("%s teardown: %s", c.name, strings.Join(errs, "; "))
	}
	if c.name == "geminicli" {
		if err := c.VerifyClean(opts); err != nil {
			return fmt.Errorf("geminicli teardown: verify clean before token revocation: %w", err)
		}
		if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI); err != nil {
			return fmt.Errorf("geminicli teardown: revoke scoped OTLP token: %w", err)
		}
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
	configPath := c.configPath(opts)
	if c.name == "hermes" {
		if err := validateHermesWindowsConfigPath(configPath); err != nil {
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
		marker, _, _ := bytes.Cut(tmpl, []byte("\n"))
		if len(marker) == 0 || !bytes.HasPrefix(marker, []byte("// defenseclaw-managed-plugin v")) {
			return fmt.Errorf("%s managed plugin identity is invalid", c.name)
		}
		if bytes.Contains(data, marker) {
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
	if c.name == "geminicli" {
		cfg, parseErr := parseGeminiSettingsObject(data, path)
		if parseErr != nil {
			return fmt.Errorf("%s teardown verification could not parse settings %s: %w", c.name, path, parseErr)
		}
		return c.verifyGeminiSettingsCleanForOS(runtime.GOOS, opts, path, needle, cfg)
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
	if c.name == "hermes" {
		return verifyHermesCleanup(opts, configPath, hermesConfiguredHookCommand(needle, opts.HookExecutable))
	}
	return c.verifyCursorHookArtifactsClean(opts)
}

// verifyGeminiSettingsCleanForOS keeps teardown ownership tied to the exact
// commands DefenseClaw emitted on the target platform. The parameterized core
// also lets host-independent tests exercise JSON-decoded Windows
// EncodedCommand registrations without broadening Unix cleanup authority.
func (c *hookOnlyConnector) verifyGeminiSettingsCleanForOS(
	goos string,
	opts SetupOpts,
	path string,
	hookCommand string,
	cfg map[string]interface{},
) error {
	if structuredHookCommandReferences(cfg, geminiOwnedHookCommandsForOS(goos, opts, hookCommand)) {
		return fmt.Errorf("%s teardown incomplete: config still references %s", c.name, c.scriptName)
	}
	if removeManagedGeminiTelemetry(cfg) {
		return fmt.Errorf("%s teardown incomplete: managed native telemetry still present at %s", c.name, path)
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
		return AgentPaths{
			PatchedFiles: uniqueNonEmptyStrings([]string{
				configPath,
				filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName),
				filepath.Join(opts.DataDir, "hooks", hermesDirectNativeStateFileName),
			}),
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
	if c.name == "openhands" && runtime.GOOS == "darwin" {
		generatedFiles = []string{filepath.Join(opts.DataDir, "hooks", otlpPathTokenFileName(OTLPScopeOpenHands))}
	}
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
	if c.name == "copilot" || c.name == "openhands" {
		description := "DefenseClaw's Copilot hook integration requires no shell environment variables; upstream OTel process variables are not configured or managed by this connector."
		if c.name == "openhands" {
			description = "DefenseClaw's OpenHands hook integration requires no shell environment variables; the optional macOS native trace exporter is process-scoped, rendered only by the protected connector launch command, and not persisted by Setup."
		}
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
		if err := validateCopilotHookPolicy(opts, path); err != nil {
			return err
		}
	}
	if c.name == "geminicli" {
		if err := validateGeminiEffectiveSettings(opts, path, true); err != nil {
			return fmt.Errorf("Gemini effective hook/telemetry policy: %w", err)
		}
	}
	logicalName := c.managedBackupLogicalName()
	var geminiOwnedCommands []string
	if c.name == "geminicli" {
		geminiOwnedCommands = geminiOwnedHookCommands(opts, hookScript)
		if err := captureGeminiManagedFileBackup(
			opts.DataDir,
			logicalName,
			path,
			uniqueNonEmptyStrings(append([]string{hookScript}, geminiOwnedCommands...)),
		); err != nil {
			return err
		}
	} else if err := captureManagedFileBackup(opts.DataDir, c.name, logicalName, path); err != nil {
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
	case "windsurf":
		err = patchWindsurfHooks(
			path,
			hookScript,
			filepath.Join(opts.DataDir, "hooks", c.scriptName),
		)
	case "devin":
		err = patchDevinHooks(path, hookScript, devinOwnedHookCommands(opts, hookScript)...)
	case "geminicli":
		if err = patchGeminiHooks(path, hookScript, geminiOwnedCommands...); err == nil {
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

// captureGeminiManagedFileBackup records the operator-owned Gemini settings
// that teardown should restore, excluding exact DefenseClaw registrations
// left by an older installation. Without this normalization, setup over an
// orphaned legacy hook would treat that hook as pristine vendor state and an
// otherwise unchanged teardown would revive it verbatim.
//
// Existing receipts retain their target and post-write custody hash, but an
// authenticated receipt created by an older DefenseClaw release is migrated
// when its pristine JSON contains only exact recognized managed entries. This
// prevents already-captured legacy hooks from being revived on uninstall.
func captureGeminiManagedFileBackup(
	dataDir, logicalName, targetPath string,
	ownedHookScripts []string,
) error {
	const connectorName = "geminicli"

	boundPath, err := normalizeManagedTargetPath(targetPath)
	if err != nil {
		return fmt.Errorf("bind managed backup target: %w", err)
	}
	backupPath := managedFileBackupPath(dataDir, connectorName, logicalName)
	existing, err := loadManagedFileBackupPath(backupPath)
	if err == nil {
		if _, err = validateManagedFileBackupTarget(existing, connectorName, logicalName, boundPath); err != nil {
			return err
		}
		if !existing.Existed {
			if existing.PristineSHA256 != managedBackupMissingHash {
				return errors.New("Gemini managed backup missing-state hash is invalid")
			}
			return nil
		}
		if existing.PristineSHA256 != sha256Hex(existing.PristineBytes) {
			return errors.New("Gemini managed backup pristine hash does not match its payload")
		}
		sanitized, changed, absent, err := sanitizeGeminiPristineJSON(
			existing.PristineBytes,
			ownedHookScripts,
			boundPath,
		)
		if err != nil || !changed {
			return err
		}
		if absent {
			existing.Existed = false
			existing.Mode = 0
			existing.PristineBytes = nil
			existing.PristineSHA256 = managedBackupMissingHash
		} else {
			existing.PristineBytes = sanitized
			existing.PristineSHA256 = sha256Hex(sanitized)
		}
		existing.UpdatedAt = time.Now().UTC().Format(time.RFC3339Nano)
		return writeManagedFileBackup(backupPath, existing)
	}
	if !os.IsNotExist(err) {
		return fmt.Errorf("load managed backup: %w", err)
	}

	backup := managedFileBackup{
		Version:     managedBackupVersion,
		Connector:   connectorName,
		LogicalName: logicalName,
		Path:        boundPath,
		CapturedAt:  time.Now().UTC().Format(time.RFC3339Nano),
	}
	data, info, err := readManagedTarget(boundPath)
	if err != nil {
		return err
	}
	if info == nil {
		backup.PristineSHA256 = managedBackupMissingHash
		return writeManagedFileBackup(backupPath, backup)
	}

	backup.Existed = true
	backup.Mode = uint32(info.Mode().Perm())
	backup.PristineBytes = data
	backup.PristineSHA256 = sha256Hex(data)
	sanitized, changed, absent, err := sanitizeGeminiPristineJSON(data, ownedHookScripts, boundPath)
	if err != nil {
		return err
	}
	if !changed {
		return writeManagedFileBackup(backupPath, backup)
	}
	if absent {
		backup.Existed = false
		backup.Mode = 0
		backup.PristineBytes = nil
		backup.PristineSHA256 = managedBackupMissingHash
		return writeManagedFileBackup(backupPath, backup)
	}

	backup.PristineBytes = sanitized
	backup.PristineSHA256 = sha256Hex(sanitized)
	return writeManagedFileBackup(backupPath, backup)
}

func sanitizeGeminiPristineJSON(
	data []byte,
	ownedHookScripts []string,
	path string,
) (sanitized []byte, changed bool, absent bool, err error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return data, false, false, nil
	}
	cfg, err := parseGeminiSettingsObject(data, path)
	if err != nil {
		return nil, false, false, fmt.Errorf("parse settings before Gemini backup capture: %w", err)
	}
	if !pruneGeminiConfigEntries(cfg, ownedHookScripts) {
		return data, false, false, nil
	}
	if len(cfg) == 0 {
		return nil, true, true, nil
	}
	sanitized, err = json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return nil, false, false, fmt.Errorf("serialize sanitized Gemini backup: %w", err)
	}
	return append(sanitized, '\n'), true, false, nil
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
		return removeGeminiConfigEntries(path, hookScript, geminiOwnedHookCommands(opts, hookScript)...)
	case "cursor":
		return removeJSONHookReferences(path, cursorOwnedHookCommands(opts)...)
	case "copilot", "openhands":
		return removeJSONHookReferences(path, hookScript)
	case "devin":
		return removeDevinHookReferences(path, devinOwnedHookCommands(opts, hookScript)...)
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
	return hermesConfigPathResolver()
}

func validateHermesWindowsConfigPath(configPath string) error {
	if strings.TrimSpace(configPath) == "" {
		return errors.New("Hermes config path is unavailable; current-user LocalAppData or an absolute HERMES_HOME is required; no changes made")
	}
	if runtime.GOOS != "windows" {
		return nil
	}
	if strings.TrimSpace(configPath) != configPath ||
		strings.ContainsAny(configPath, "\x00\r\n") ||
		!filepath.IsAbs(configPath) ||
		filepath.Clean(configPath) != configPath {
		return errors.New("Hermes config path is not an absolute normalized Windows path; no changes made")
	}
	home := filepath.Dir(configPath)
	if strings.TrimSpace(home) == "" || home == "." || !filepath.IsAbs(home) {
		return errors.New("Hermes config home is not an absolute Windows path; no changes made")
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

func windsurfHooksPath(opts SetupOpts) string {
	if WindsurfHooksPathOverride != "" {
		return WindsurfHooksPathOverride
	}
	path, err := resolveWindsurfHooksPath(opts)
	if err != nil {
		return ""
	}
	return path
}

// resolveWindsurfUserHome keeps every Cascade-only surface bound to the same
// profile root captured by native Setup. The environment variables are
// internal custody passed by the launcher, not public connector knobs. The
// hidden ConfigHome binding is used by isolated lifecycle maintenance. When
// neither exists, userHomeDir retains the established non-native behavior.
func resolveWindsurfUserHome(opts SetupOpts) (string, error) {
	configHome := strings.TrimSpace(opts.ConfigHome)
	if configHome != "" {
		if err := validateWindsurfBoundPath("connector config home", configHome); err != nil {
			return "", err
		}
	}
	envHome := os.Getenv("WINDSURF_USER_HOME")
	if envHome != "" {
		if err := validateWindsurfBoundPath("WINDSURF_USER_HOME", envHome); err != nil {
			return "", err
		}
		if configHome != "" && !sameCleanPath(configHome, envHome) {
			return "", errors.New("WINDSURF_USER_HOME does not match the bound connector config home")
		}
		return envHome, nil
	}
	if configHome != "" {
		return configHome, nil
	}
	home := userHomeDir()
	if strings.TrimSpace(home) == "" {
		return "", errors.New("Windsurf user home is empty")
	}
	return filepath.Clean(home), nil
}

func resolveWindsurfHooksPath(opts SetupOpts) (string, error) {
	home, err := resolveWindsurfUserHome(opts)
	if err != nil {
		return "", err
	}
	expected := filepath.Join(home, ".codeium", "windsurf", "hooks.json")
	configured := os.Getenv("WINDSURF_HOOK_CONFIG_PATH")
	if configured == "" {
		return expected, nil
	}
	if err := validateWindsurfBoundPath("WINDSURF_HOOK_CONFIG_PATH", configured); err != nil {
		return "", err
	}
	if !sameCleanPath(configured, expected) {
		return "", errors.New("WINDSURF_HOOK_CONFIG_PATH does not match the bound Windsurf profile")
	}
	return configured, nil
}

func validateWindsurfBoundPath(label, path string) error {
	if strings.TrimSpace(path) != path ||
		strings.ContainsAny(path, "\x00\r\n") ||
		!filepath.IsAbs(path) ||
		filepath.Clean(path) != path {
		return fmt.Errorf("%s is not an absolute normalized path", label)
	}
	return nil
}

func sameCleanPath(left, right string) bool {
	left, right = filepath.Clean(left), filepath.Clean(right)
	if runtime.GOOS == "windows" {
		return strings.EqualFold(left, right)
	}
	return left == right
}

func geminiSettingsPath(opts SetupOpts) string {
	if GeminiSettingsPathOverride != "" {
		return GeminiSettingsPathOverride
	}
	return geminiHomePath(geminiConfigHome(opts), "settings.json")
}

func geminiWorkspaceSettingsPath(opts SetupOpts) string {
	root := strings.TrimSpace(opts.WorkspaceDir)
	if root == "" {
		return ""
	}
	return filepath.Join(root, ".gemini", "settings.json")
}

// geminiEffectiveWorkspaceSettingsPath follows the vendor's runtime behavior:
// when Setup/Verify does not carry an explicitly pinned workspace, Gemini uses
// the process working directory. Capability/write-target reporting remains
// explicit-only through geminiWorkspaceSettingsPath so inventory never guesses
// a project mutation target.
func geminiEffectiveWorkspaceSettingsPath(opts SetupOpts) (string, error) {
	root := strings.TrimSpace(opts.WorkspaceDir)
	if root == "" {
		var err error
		root, err = os.Getwd()
		if err != nil {
			return "", fmt.Errorf("resolve Gemini current workspace: %w", err)
		}
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return "", fmt.Errorf("resolve Gemini workspace %s: %w", root, err)
	}
	return filepath.Join(filepath.Clean(absRoot), ".gemini", "settings.json"), nil
}

// geminiSettingsPaths is ordered from the most specific locally writable
// scope to the user fallback, matching Gemini's workspace-over-user MCP
// precedence. System MCP policy remains operator-managed and is inspected as
// an effective layer rather than advertised as a DefenseClaw write target.
func geminiSettingsPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		geminiWorkspaceSettingsPath(opts),
		geminiSettingsPath(opts),
	})
}

// geminiConfigHome resolves all user-scoped Gemini surfaces through one
// custody binding. Isolated Setup maintenance supplies ConfigHome directly;
// packaged CLI/gateway processes receive the authenticated install-state path
// through DefenseClaw's private environment variable. Source installs without
// that binding follow Gemini's official GEMINI_CLI_HOME parent-root contract
// and append .gemini exactly once. GEMINI_CONFIG_DIR is not a Gemini CLI
// contract and is intentionally ignored.
func geminiConfigHome(opts SetupOpts) string {
	if opts.ConfigHome != "" {
		return normalizedGeminiConfigHome(opts.ConfigHome)
	}
	if raw, exists := os.LookupEnv("DEFENSECLAW_GEMINI_CONFIG_HOME"); exists {
		return normalizedGeminiConfigHome(raw)
	}
	if raw, exists := os.LookupEnv("GEMINI_CLI_HOME"); exists && raw != "" {
		root := normalizedGeminiConfigHome(raw)
		if root == "" {
			return ""
		}
		return filepath.Join(root, ".gemini")
	}
	return homePath(".gemini")
}

func normalizedGeminiConfigHome(raw string) string {
	if strings.TrimSpace(raw) != raw || strings.ContainsAny(raw, "\x00\r\n") ||
		!filepath.IsAbs(raw) || filepath.Clean(raw) != raw {
		return ""
	}
	return raw
}

func geminiHomePath(home string, parts ...string) string {
	if home == "" {
		return ""
	}
	return filepath.Join(append([]string{home}, parts...)...)
}

type geminiSettingsLayer struct {
	name     string
	path     string
	settings map[string]interface{}
}

func geminiSystemSettingsPaths() (defaultsPath, overridesPath string, err error) {
	switch runtime.GOOS {
	case "windows":
		overridesPath = `C:\ProgramData\gemini-cli\settings.json`
	case "darwin":
		overridesPath = "/Library/Application Support/GeminiCli/settings.json"
	default:
		overridesPath = "/etc/gemini-cli/settings.json"
	}
	if raw, exists := os.LookupEnv("GEMINI_CLI_SYSTEM_SETTINGS_PATH"); exists && raw != "" {
		overridesPath = raw
	}
	overridesPath, err = normalizeGeminiSettingsLayerPath("GEMINI_CLI_SYSTEM_SETTINGS_PATH", overridesPath)
	if err != nil {
		return "", "", err
	}
	defaultsPath = filepath.Join(filepath.Dir(overridesPath), "system-defaults.json")
	if raw, exists := os.LookupEnv("GEMINI_CLI_SYSTEM_DEFAULTS_PATH"); exists && raw != "" {
		defaultsPath = raw
	}
	defaultsPath, err = normalizeGeminiSettingsLayerPath("GEMINI_CLI_SYSTEM_DEFAULTS_PATH", defaultsPath)
	if err != nil {
		return "", "", err
	}
	return defaultsPath, overridesPath, nil
}

func normalizeGeminiSettingsLayerPath(label, path string) (string, error) {
	if strings.TrimSpace(path) != path || strings.ContainsAny(path, "\x00\r\n") ||
		!filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", fmt.Errorf("%s is not an absolute normalized path", label)
	}
	return path, nil
}

func loadGeminiSettingsLayers(opts SetupOpts, userPath string) ([]geminiSettingsLayer, error) {
	defaultsPath, systemPath, err := geminiSystemSettingsPaths()
	if err != nil {
		return nil, err
	}
	workspacePath, err := geminiEffectiveWorkspaceSettingsPath(opts)
	if err != nil {
		return nil, err
	}
	specs := []struct {
		name string
		path string
	}{
		{"system defaults", defaultsPath},
		{"user", userPath},
		{"current workspace", workspacePath},
		{"system overrides", systemPath},
	}
	layers := make([]geminiSettingsLayer, 0, len(specs))
	seenPaths := make([]string, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec.path) == "" {
			continue
		}
		duplicate := false
		for _, seen := range seenPaths {
			if sameCleanPath(spec.path, seen) {
				duplicate = true
				break
			}
		}
		if duplicate {
			// Gemini can resolve user and project settings to the same file
			// when launched from its home root. The managed user write updates
			// that single file; replaying its pristine bytes as a second layer
			// would manufacture an override that the post-write process cannot
			// observe.
			continue
		}
		settings, err := readGeminiSettingsObject(spec.path)
		if err != nil {
			return nil, fmt.Errorf("read Gemini %s settings %s: %w", spec.name, spec.path, err)
		}
		settings = expandGeminiSettingEnvironment(settings).(map[string]interface{})
		layers = append(layers, geminiSettingsLayer{
			name:     spec.name,
			path:     spec.path,
			settings: settings,
		})
		seenPaths = append(seenPaths, spec.path)
	}
	return layers, nil
}

var geminiSettingEnvironmentRE = regexp.MustCompile(`\$(?:[A-Za-z0-9_]+|\{[^}]+\})`)

// expandGeminiSettingEnvironment mirrors Gemini CLI's envVarResolver for the
// decoded settings tree. Expansion happens before settings layers merge and is
// distinct from the later dotenv load, which only fills process variables that
// were absent when settings were parsed.
func expandGeminiSettingEnvironment(raw interface{}) interface{} {
	switch value := raw.(type) {
	case string:
		return geminiSettingEnvironmentRE.ReplaceAllStringFunc(value, func(match string) string {
			name := strings.TrimPrefix(match, "$")
			fallback := ""
			hasFallback := false
			if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
				name = strings.TrimSuffix(strings.TrimPrefix(name, "{"), "}")
				if separator := strings.Index(name, ":-"); separator >= 0 {
					fallback = name[separator+2:]
					name = name[:separator]
					hasFallback = true
				}
			}
			if resolved, exists := os.LookupEnv(name); exists {
				return resolved
			}
			if hasFallback {
				return fallback
			}
			return match
		})
	case []interface{}:
		out := make([]interface{}, len(value))
		for index, item := range value {
			out[index] = expandGeminiSettingEnvironment(item)
		}
		return out
	case map[string]interface{}:
		out := make(map[string]interface{}, len(value))
		for key, item := range value {
			out[key] = expandGeminiSettingEnvironment(item)
		}
		return out
	default:
		return raw
	}
}

func geminiDesiredTelemetryBlock(opts SetupOpts, provision bool) (map[string]interface{}, error) {
	var (
		token string
		err   error
	)
	if provision {
		token, err = resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI, opts.OTLPPathToken)
	} else if supplied := strings.TrimSpace(opts.OTLPPathToken); supplied != "" {
		if !otlpTokenHexRE.MatchString(supplied) {
			return nil, errors.New("invalid supplied Gemini CLI OTLP path-token")
		}
		token = supplied
	} else {
		token, err = LoadOTLPPathToken(opts.DataDir, OTLPScopeGeminiCLI)
	}
	if err != nil {
		return nil, fmt.Errorf("resolve scoped Gemini CLI OTLP token: %w", err)
	}
	if token == "" {
		return nil, errors.New("Gemini CLI OTLP path-token is not provisioned")
	}
	spec := geminiCLINativeOTLPSpec(opts)
	if spec == nil {
		return nil, errors.New("geminicli: nil NativeOTLPSpec")
	}
	spec.PathToken = token
	block, err := spec.JSONBlock()
	if err != nil {
		return nil, fmt.Errorf("geminicli: render OTLP block: %w", err)
	}
	return block, nil
}

// validateGeminiEffectiveSettings mirrors the vendor's documented merge
// order: system defaults < user < pinned workspace < system overrides.
// hooksConfig.disabled is a union across layers while enabled and telemetry
// scalar values use the highest-precedence definition. Setup refuses a
// registration that a known higher layer would make inert or redirect.
func validateGeminiEffectiveSettings(opts SetupOpts, userPath string, provisionToken bool) error {
	layers, err := loadGeminiSettingsLayers(opts, userPath)
	if err != nil {
		return err
	}
	hooksEnabled := true
	enabledSource := "built-in default"
	disabledSource := ""
	for _, layer := range layers {
		rawConfig, present := layer.settings["hooksConfig"]
		if !present {
			continue
		}
		config, ok := rawConfig.(map[string]interface{})
		if !ok {
			return fmt.Errorf("Gemini hooksConfig in %s settings %s is not an object", layer.name, layer.path)
		}
		if rawEnabled, present := config["enabled"]; present {
			value, ok := rawEnabled.(bool)
			if !ok {
				return fmt.Errorf("Gemini hooksConfig.enabled in %s settings %s is not boolean", layer.name, layer.path)
			}
			hooksEnabled = value
			enabledSource = layer.path
		}
		if rawDisabled, present := config["disabled"]; present {
			entries, ok := rawDisabled.([]interface{})
			if !ok {
				return fmt.Errorf("Gemini hooksConfig.disabled in %s settings %s is not an array", layer.name, layer.path)
			}
			for _, rawEntry := range entries {
				entry, ok := rawEntry.(string)
				if !ok {
					return fmt.Errorf("Gemini hooksConfig.disabled in %s settings %s contains a non-string entry", layer.name, layer.path)
				}
				if strings.EqualFold(strings.TrimSpace(entry), "defenseclaw") && disabledSource == "" {
					disabledSource = layer.path
				}
			}
		}
	}
	if !hooksEnabled {
		return fmt.Errorf("Gemini hooks are disabled by effective hooksConfig.enabled=false at %s", enabledSource)
	}
	if disabledSource != "" {
		return fmt.Errorf("Gemini hook name defenseclaw is disabled by effective hooksConfig.disabled at %s", disabledSource)
	}

	desired, err := geminiDesiredTelemetryBlock(opts, provisionToken)
	if err != nil {
		return err
	}
	effective := map[string]interface{}{}
	sources := map[string]string{}
	for _, layer := range layers {
		if rawTelemetry, present := layer.settings["telemetry"]; present {
			telemetry, ok := rawTelemetry.(map[string]interface{})
			if !ok {
				return fmt.Errorf("Gemini telemetry in %s settings %s is not an object", layer.name, layer.path)
			}
			for key, value := range telemetry {
				effective[key] = value
				sources[key] = layer.path
			}
		}
		if sameCleanPath(layer.path, userPath) {
			for key, value := range desired {
				effective[key] = value
				sources[key] = userPath
			}
		}
	}
	for key, want := range desired {
		got, present := effective[key]
		if !present || !geminiScalarSettingEqual(got, want) {
			return fmt.Errorf("Gemini telemetry %s is overridden by effective setting at %s", key, sources[key])
		}
	}
	if err := validateGeminiTelemetryEnvironment(desired); err != nil {
		return err
	}
	return validateGeminiTelemetryDotEnv(opts, layers)
}

func geminiScalarSettingEqual(got, want interface{}) bool {
	switch expected := want.(type) {
	case bool:
		actual, ok := got.(bool)
		return ok && actual == expected
	case string:
		actual, ok := got.(string)
		return ok && actual == expected
	default:
		return false
	}
}

func validateGeminiTelemetryEnvironment(desired map[string]interface{}) error {
	desiredEndpoint, ok := desired["otlpEndpoint"].(string)
	if !ok || strings.TrimSpace(desiredEndpoint) == "" {
		return errors.New("Gemini managed telemetry endpoint is unresolved")
	}
	desiredLogPrompts, ok := desired["logPrompts"].(bool)
	if !ok {
		return errors.New("Gemini managed telemetry logPrompts value is unresolved")
	}
	desiredUseCLIAuth, ok := desired["useCliAuth"].(bool)
	if !ok {
		return errors.New("Gemini managed telemetry useCliAuth value is unresolved")
	}
	desiredOutfile, ok := desired["outfile"].(string)
	if !ok {
		return errors.New("Gemini managed telemetry outfile value is unresolved")
	}
	trueValue := func(value string) bool {
		value = strings.ToLower(strings.TrimSpace(value))
		return value == "true" || value == "1"
	}
	booleanValue := func(want bool) func(string) bool {
		return func(value string) bool { return trueValue(value) == want }
	}
	checks := []struct {
		name  string
		valid func(string) bool
	}{
		{"GEMINI_TELEMETRY_ENABLED", booleanValue(true)},
		{"GEMINI_TELEMETRY_TRACES_ENABLED", booleanValue(true)},
		{"GEMINI_TELEMETRY_TARGET", func(value string) bool {
			return strings.EqualFold(strings.TrimSpace(value), "local")
		}},
		{"GEMINI_TELEMETRY_OTLP_ENDPOINT", func(value string) bool {
			return value == desiredEndpoint
		}},
		{"OTEL_EXPORTER_OTLP_ENDPOINT", func(value string) bool {
			return value == desiredEndpoint
		}},
		{"GEMINI_TELEMETRY_OTLP_PROTOCOL", func(value string) bool {
			return strings.EqualFold(strings.TrimSpace(value), "http")
		}},
		{"GEMINI_TELEMETRY_LOG_PROMPTS", booleanValue(desiredLogPrompts)},
		{"GEMINI_TELEMETRY_OUTFILE", func(value string) bool {
			// An outfile duplicates native telemetry outside the authenticated
			// gateway path. Only an explicitly empty override is equivalent to
			// DefenseClaw's managed settings block.
			return value == desiredOutfile
		}},
		{"GEMINI_TELEMETRY_USE_COLLECTOR", booleanValue(true)},
		{"GEMINI_TELEMETRY_USE_CLI_AUTH", booleanValue(desiredUseCLIAuth)},
	}
	for _, check := range checks {
		if value, exists := os.LookupEnv(check.name); exists && !check.valid(value) {
			return fmt.Errorf("%s overrides DefenseClaw's managed Gemini telemetry contract", check.name)
		}
	}
	return nil
}

var geminiTelemetryEnvironmentNames = []string{
	"GEMINI_TELEMETRY_ENABLED",
	"GEMINI_TELEMETRY_TRACES_ENABLED",
	"GEMINI_TELEMETRY_TARGET",
	"GEMINI_TELEMETRY_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"GEMINI_TELEMETRY_OTLP_PROTOCOL",
	"GEMINI_TELEMETRY_LOG_PROMPTS",
	"GEMINI_TELEMETRY_OUTFILE",
	"GEMINI_TELEMETRY_USE_COLLECTOR",
	"GEMINI_TELEMETRY_USE_CLI_AUTH",
}

// validateGeminiTelemetryDotEnv models the first .env file Gemini will load for
// the current (or explicitly pinned) workspace. Gemini does not overwrite a
// process variable that is already present, so those names were already
// validated above and are ignored here. We conservatively treat the workspace
// as trusted: that prevents Setup from claiming an enforceable native telemetry
// route which would become redirectable as soon as the operator trusts it.
func validateGeminiTelemetryDotEnv(opts SetupOpts, layers []geminiSettingsLayer) error {
	ignoreLocalEnv, excluded, err := geminiEffectiveEnvPolicy(layers)
	if err != nil {
		return err
	}
	workspaceSettings, err := geminiEffectiveWorkspaceSettingsPath(opts)
	if err != nil {
		return err
	}
	workspaceRoot := filepath.Dir(filepath.Dir(workspaceSettings))
	configHome := geminiConfigHome(opts)
	if configHome == "" {
		return errors.New("Gemini config home is unresolved")
	}
	homeRoot := filepath.Dir(configHome)
	envPath, geminiSpecific, err := findGeminiEffectiveEnvFile(workspaceRoot, homeRoot, ignoreLocalEnv)
	if err != nil || envPath == "" {
		return err
	}
	data, err := safefile.ReadRegularFileBounded(envPath, safefile.MaxDotEnvBytes)
	if err != nil {
		return fmt.Errorf("read Gemini effective environment file %s: %w", envPath, err)
	}
	relevant := make(map[string]struct{}, len(geminiTelemetryEnvironmentNames))
	for _, name := range geminiTelemetryEnvironmentNames {
		if _, alreadySet := os.LookupEnv(name); !alreadySet {
			relevant[geminiTelemetryEnvironmentKeyForOS(name, runtime.GOOS)] = struct{}{}
		}
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	scanner.Buffer(make([]byte, 1024), safefile.MaxDotEnvBytes)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "export ") {
			line = strings.TrimSpace(strings.TrimPrefix(line, "export "))
		}
		separator := strings.IndexAny(line, "=:")
		if separator <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:separator])
		canonicalName := geminiTelemetryEnvironmentKeyForOS(name, runtime.GOOS)
		if _, watched := relevant[canonicalName]; !watched {
			continue
		}
		if !geminiSpecific {
			if _, filtered := excluded[name]; filtered {
				continue
			}
		}
		return fmt.Errorf("%s in Gemini's effective environment file %s overrides DefenseClaw's managed telemetry contract", name, envPath)
	}
	if err := scanner.Err(); err != nil {
		return fmt.Errorf("parse Gemini effective environment file %s: %w", envPath, err)
	}
	return nil
}

func geminiTelemetryEnvironmentKeyForOS(name, goos string) string {
	if goos == "windows" {
		return strings.ToUpper(name)
	}
	return name
}

func geminiEffectiveEnvPolicy(layers []geminiSettingsLayer) (bool, map[string]struct{}, error) {
	ignoreLocalEnv := false
	excluded := map[string]struct{}{}
	for _, layer := range layers {
		rawAdvanced, present := layer.settings["advanced"]
		if !present {
			continue
		}
		advanced, ok := rawAdvanced.(map[string]interface{})
		if !ok {
			return false, nil, fmt.Errorf("Gemini advanced settings in %s settings %s is not an object", layer.name, layer.path)
		}
		if rawIgnore, present := advanced["ignoreLocalEnv"]; present {
			value, ok := rawIgnore.(bool)
			if !ok {
				return false, nil, fmt.Errorf("Gemini advanced.ignoreLocalEnv in %s settings %s is not boolean", layer.name, layer.path)
			}
			ignoreLocalEnv = value
		}
		if rawExcluded, present := advanced["excludedEnvVars"]; present {
			entries, ok := rawExcluded.([]interface{})
			if !ok {
				return false, nil, fmt.Errorf("Gemini advanced.excludedEnvVars in %s settings %s is not an array", layer.name, layer.path)
			}
			excluded = map[string]struct{}{}
			for _, rawEntry := range entries {
				entry, ok := rawEntry.(string)
				if !ok {
					return false, nil, fmt.Errorf("Gemini advanced.excludedEnvVars in %s settings %s contains a non-string entry", layer.name, layer.path)
				}
				excluded[entry] = struct{}{}
			}
		}
	}
	return ignoreLocalEnv, excluded, nil
}

func findGeminiEffectiveEnvFile(workspaceRoot, homeRoot string, ignoreLocalEnv bool) (string, bool, error) {
	current, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return "", false, fmt.Errorf("resolve Gemini environment workspace %s: %w", workspaceRoot, err)
	}
	home, err := filepath.Abs(homeRoot)
	if err != nil {
		return "", false, fmt.Errorf("resolve Gemini environment home %s: %w", homeRoot, err)
	}
	find := func(path string) (bool, error) {
		_, err := os.Lstat(path)
		if err == nil {
			return true, nil
		}
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for {
		geminiPath := filepath.Join(current, ".gemini", ".env")
		if exists, statErr := find(geminiPath); statErr != nil {
			return "", false, fmt.Errorf("inspect Gemini environment file %s: %w", geminiPath, statErr)
		} else if exists {
			return geminiPath, true, nil
		}
		envPath := filepath.Join(current, ".env")
		if !ignoreLocalEnv || sameCleanPath(current, home) {
			if exists, statErr := find(envPath); statErr != nil {
				return "", false, fmt.Errorf("inspect Gemini environment file %s: %w", envPath, statErr)
			} else if exists {
				return envPath, false, nil
			}
		}
		parent := filepath.Dir(current)
		if sameCleanPath(parent, current) {
			break
		}
		current = parent
	}
	for _, candidate := range []struct {
		path           string
		geminiSpecific bool
	}{
		{filepath.Join(home, ".gemini", ".env"), true},
		{filepath.Join(home, ".env"), false},
	} {
		if exists, statErr := find(candidate.path); statErr != nil {
			return "", false, fmt.Errorf("inspect Gemini environment file %s: %w", candidate.path, statErr)
		} else if exists {
			return candidate.path, candidate.geminiSpecific, nil
		}
	}
	return "", false, nil
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

func validateCopilotHookPolicy(opts SetupOpts, registrationPath string) error {
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
		return fmt.Errorf("Copilot hooks are disabled by effective operator setting disableAllHooks=true at %s; refusing to overwrite operator policy", disabledSource)
	}
	if value, present, err := readCopilotDisableAllHooks(registrationPath); err != nil {
		return fmt.Errorf("cannot verify Copilot hook registration policy %s: %w", registrationPath, err)
	} else if present && value {
		return fmt.Errorf("Copilot hook registration is disabled by operator setting disableAllHooks=true at %s; refusing to overwrite operator policy", registrationPath)
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

// stripJSONComments mirrors the comment handling used by Gemini CLI's
// strip-json-comments loader. It deliberately leaves trailing commas intact:
// Gemini passes the result to JSON.parse, so a trailing comma remains invalid.
// Copilot applies its separate trailing-comma normalization after this helper.
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
			for i+1 < len(input) && !(input[i] == '*' && input[i+1] == '/') {
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
	paths = append(paths, homePath(".openhands", "agents"))
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

func windsurfMCPPaths(opts SetupOpts) []string {
	home, err := resolveWindsurfUserHome(opts)
	if err != nil {
		return nil
	}
	return []string{filepath.Join(home, ".codeium", "windsurf", "mcp_config.json")}
}

func windsurfRulePaths(opts SetupOpts) []string {
	home, err := resolveWindsurfUserHome(opts)
	if err != nil {
		return nil
	}
	return uniqueNonEmptyStrings([]string{
		filepath.Join(home, ".codeium", "windsurf", "memories", "global_rules.md"),
		workspacePath(opts, ".devin", "rules"),
		workspacePath(opts, ".windsurf", "rules"),
		workspacePath(opts, ".windsurfrules"),
		workspacePath(opts, "AGENTS.md"),
	})
}

func windsurfSkillPaths(opts SetupOpts) []string {
	home, err := resolveWindsurfUserHome(opts)
	if err != nil {
		return nil
	}
	return uniqueNonEmptyStrings([]string{
		filepath.Join(home, ".codeium", "windsurf", "skills"),
		filepath.Join(home, ".agents", "skills"),
		workspacePath(opts, ".windsurf", "skills"),
		workspacePath(opts, ".agents", "skills"),
	})
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

	if err = patchHermesHooks(configPath, hookScript, opts.HookExecutable); err != nil {
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
	if err = patchHermesAllowlist(allowlistPath, command, hermesHookExecutablePath(hookScript, opts.HookExecutable)); err != nil {
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
	return nil
}

func hermesConfiguredHookCommand(hookScript, hookExecutable string) string {
	if bound := windowsHermesDirectHookCommand(hookExecutable); bound != "" && hookScript == bound {
		return hookScript
	}
	return shellWord(hookScript)
}

func hermesHookExecutablePath(hookScript, hookExecutable string) string {
	if windowsHermesDirectHookCommand(hookExecutable) == hookScript {
		return hookExecutable
	}
	return hookScript
}

func readHermesAllowlist(path string) (map[string]interface{}, error) {
	data, err := os.ReadFile(path)
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
		return nil, fmt.Errorf("Hermes shell hook allowlist is not a JSON object")
	}
	if _, ok := document["approvals"].([]interface{}); !ok {
		return nil, fmt.Errorf("Hermes shell hook allowlist approvals is not an array")
	}
	return document, nil
}

func hermesHookEventSet() map[string]struct{} {
	events := make(map[string]struct{}, len(hermesRequiredHooks))
	for _, spec := range hermesRequiredHooks {
		events[spec.event] = struct{}{}
	}
	return events
}

func patchHermesAllowlist(path, command, executablePath string) error {
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("Hermes hook command is empty")
	}
	document, err := readHermesAllowlist(path)
	if err != nil {
		return err
	}
	approvals := document["approvals"].([]interface{})
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
				return fmt.Errorf("Hermes allowlist entry %q has a tampered DefenseClaw command; refusing non-exact repair", event)
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
			return fmt.Errorf("Hermes allowlist entry %q lost its DefenseClaw ownership marker; refusing ambiguous repair", event)
		}
		kept = append(kept, raw)
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

func teardownHermesAllowlist(opts SetupOpts, configPath, command string) error {
	if err := validateHermesWindowsConfigPath(configPath); err != nil {
		return err
	}
	logicalName := hermesAllowlistLogicalName
	path := filepath.Join(filepath.Dir(configPath), hermesAllowlistFileName)
	restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, "hermes", logicalName, path)
	if err != nil {
		return err
	}
	if restored {
		return nil
	}
	backup, backupErr := loadManagedFileBackupForTransform(opts.DataDir, "hermes", logicalName, path)
	if backupErr != nil && !os.IsNotExist(backupErr) {
		return backupErr
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
				return fmt.Errorf("Hermes allowlist entry %s has a tampered DefenseClaw command; refusing non-exact cleanup", event)
			}
			continue
		}
		if backup != nil && requiredEvent && entryCommand == command && !pristinePairs[pair] {
			return fmt.Errorf("Hermes allowlist entry %s lost its DefenseClaw ownership marker; refusing ambiguous cleanup", event)
		}
		kept = append(kept, raw)
	}
	document["approvals"] = kept
	data, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return err
	}
	if err := atomicWriteFile(path, append(data, '\n'), 0o600); err != nil {
		return err
	}
	discardManagedFileBackup(opts.DataDir, "hermes", logicalName)
	return nil
}

func writeHermesDirectNativeState(opts SetupOpts, command, status string) error {
	if status != hermesDirectNativePending && status != hermesDirectNativeDisabled {
		return fmt.Errorf("invalid Hermes direct-native state %q", status)
	}
	if strings.TrimSpace(command) == "" {
		return fmt.Errorf("Hermes direct-native command is empty")
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
		return fmt.Errorf("Hermes named profiles are unsupported by the single-HERMES_HOME connector; no changes made")
	}
	activeProfile := filepath.Join(home, "active_profile")
	if info, err := os.Lstat(activeProfile); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return fmt.Errorf("Hermes active_profile is not a regular non-symlink file")
		}
		if info.Size() > 4096 {
			return fmt.Errorf("Hermes active_profile exceeds the bounded inspection limit")
		}
		data, readErr := os.ReadFile(activeProfile)
		if readErr != nil && !errors.Is(readErr, io.EOF) {
			return fmt.Errorf("inspect Hermes active_profile: %w", readErr)
		}
		if profile := strings.TrimSpace(string(data)); profile != "" && !strings.EqualFold(profile, "default") {
			return fmt.Errorf("Hermes active named profile %q is unsupported by the single-HERMES_HOME connector; no changes made", profile)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Hermes active_profile: %w", err)
	}
	profilesDir := filepath.Join(home, "profiles")
	if info, err := os.Lstat(profilesDir); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return fmt.Errorf("Hermes profiles path is not a regular directory")
		}
		directory, openErr := os.Open(profilesDir)
		if openErr != nil {
			return fmt.Errorf("inspect Hermes profiles directory: %w", openErr)
		}
		entries, readErr := directory.ReadDir(257)
		closeErr := directory.Close()
		if readErr != nil {
			return fmt.Errorf("inspect Hermes profiles directory: %w", readErr)
		}
		if closeErr != nil {
			return fmt.Errorf("close Hermes profiles directory: %w", closeErr)
		}
		if len(entries) > 256 {
			return fmt.Errorf("Hermes profiles directory exceeds the bounded inspection limit")
		}
		for _, entry := range entries {
			if entry.IsDir() || entry.Type()&os.ModeSymlink != 0 {
				return fmt.Errorf("Hermes named profile %q is unsupported by the single-HERMES_HOME connector; no changes made", entry.Name())
			}
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("inspect Hermes profiles directory: %w", err)
	}
	cfg, err := readHermesBoundedConfig(configPath)
	if err != nil {
		return err
	}
	configMultiplex := hermesBool(cfg["multiplex_profiles"])
	if gateway, ok := cfg["gateway"].(map[string]interface{}); ok && cfg["multiplex_profiles"] == nil {
		configMultiplex = hermesBool(gateway["multiplex_profiles"])
	}
	if raw, present := os.LookupEnv("GATEWAY_MULTIPLEX_PROFILES"); present {
		switch strings.ToLower(strings.TrimSpace(raw)) {
		case "1", "true", "yes", "on":
			configMultiplex = true
		case "0", "false", "no", "off":
			configMultiplex = false
		}
	}
	if configMultiplex {
		return fmt.Errorf("Hermes multiplex profiles are unsupported by the single-HERMES_HOME connector; no changes made")
	}
	return nil
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
		return nil, fmt.Errorf("Hermes config is not a regular non-symlink file")
	}
	if info.Size() > hermesInventoryConfigMaxBytes {
		return nil, fmt.Errorf("Hermes config exceeds the %d-byte inspection limit", hermesInventoryConfigMaxBytes)
	}
	return readYAMLObject(path)
}

func hermesBool(value interface{}) bool {
	if boolean, ok := value.(bool); ok {
		return boolean
	}
	if text, ok := value.(string); ok {
		switch strings.ToLower(strings.TrimSpace(text)) {
		case "1", "true", "yes", "on":
			return true
		}
	}
	return false
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
	// Hermes' global hooks_auto_accept switch belongs to the operator. Setup
	// leaves it byte-semantically untouched and separately provisions only the
	// exact DefenseClaw (event, command) approvals in the vendor allowlist.
	hookCommand := hermesConfiguredHookCommand(hookScript, hookExecutable)
	recognizedCommands := hermesRecognizedHookCommands(hookCommand)
	for _, spec := range hermesRequiredHooks {
		entry := map[string]interface{}{
			"command": hookCommand,
			"timeout": 30,
		}
		if spec.matcher != "" {
			entry["matcher"] = spec.matcher
		}
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
		if len(trimmed) != 0 && !(bytes.HasPrefix(trimmed, []byte("#")) && len(line) == len(bytes.TrimLeft(line, " \t"))) {
			break
		}
		cursor = previousStart
		end = previousStart
	}
	return end
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
		_, recognized := recognizedCommands[command]
		if recognized {
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
		if _, recognized := recognizedCommands[command]; recognized {
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

func validateHermesManagedBackupPristine(backup *managedFileBackup) error {
	if !backup.Existed {
		if backup.PristineSHA256 != managedBackupMissingHash || len(backup.PristineBytes) != 0 {
			return fmt.Errorf("Hermes pristine custody for a missing file is inconsistent")
		}
		return nil
	}
	if backup.PristineSHA256 != sha256Hex(backup.PristineBytes) {
		return fmt.Errorf("Hermes pristine custody hash does not match its captured bytes")
	}
	return nil
}

var cursorHookEvents = []string{
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
			// Cursor's hook schema defines timeout in seconds.
			"timeout":    30,
			"failClosed": failClosed,
		}
		// Replace instead of merely appending. This both migrates the previous
		// direct-native Windows command to the PowerShell adapter and refreshes
		// failClosed when the connector moves between observe and action mode.
		// Entries not owned by DefenseClaw are preserved in their original order.
		hooks[event] = replaceManagedCursorHooks(hooks[event], ownedCommands, entry)
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
	runtimeBody, err := os.ReadFile(runtimePath)
	if err != nil {
		return false, err
	}
	runtimeMarkers := []string{"defenseclaw-managed-hook v8"}
	if runtime.GOOS == "windows" {
		failClosedMarker := "$failClosed = $false"
		if c.effectiveFailClosed(opts) {
			failClosedMarker = "$failClosed = $true"
		}
		runtimeMarkers = append(runtimeMarkers,
			"--input-file",
			"defenseclaw-hook.exe",
			"ProcessStartInfo",
			"RedirectStandardOutput",
			"WaitForExit",
			failClosedMarker,
		)
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

func replaceManagedCursorHooks(raw interface{}, ownedCommands cursorHookCommandMatcher, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	for _, item := range list {
		if ownedCommands.matches(item) {
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

func patchWindsurfHooks(path, hookScript, legacyShellScript string) error {
	return patchWindsurfHooksForOS(path, hookScript, legacyShellScript, runtime.GOOS)
}

func patchWindsurfHooksForOS(path, hookScript, legacyShellScript, goos string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	for _, event := range windsurfCascadeHookEvents {
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

func geminiOwnedHookCommands(opts SetupOpts, hookScript string) []string {
	return geminiOwnedHookCommandsForOS(runtime.GOOS, opts, hookScript)
}

// geminiOwnedHookCommandsForOS returns only byte-exact commands DefenseClaw
// has emitted for this connector. The finite list lets setup migrate legacy
// Windows launchers and teardown remove them without treating arbitrary
// encoded PowerShell as owned. The POSIX script identity remains included for
// profiles upgraded in place from a non-native registration.
func geminiOwnedHookCommandsForOS(goos string, opts SetupOpts, hookScript string) []string {
	commands := []string{hookScript}
	if strings.TrimSpace(opts.DataDir) != "" {
		commands = append(commands, filepath.Join(opts.DataDir, "hooks", "geminicli-hook.sh"))
	}
	if goos != "windows" {
		return uniqueNonEmptyStrings(commands)
	}
	for _, hookBinary := range nativeHookBinaryOwnershipCandidates() {
		commands = append(commands,
			windowsNativePowerShellHookCommandForBinary("geminicli", hookBinary),
			legacyUnqualifiedWindowsNativePowerShellHookCommandForBinary("geminicli", hookBinary),
			legacyWindowsNativePowerShellHookCommandForBinary("geminicli", hookBinary),
			legacyWindowsGeminiCallOperatorHookCommandForBinary(hookBinary),
		)
	}
	return uniqueNonEmptyStrings(commands)
}

func patchGeminiHooks(path, hookScript string, ownedHookScripts ...string) error {
	cfg, err := readGeminiSettingsObject(path)
	if err != nil {
		return err
	}
	hooks := ensureJSONObject(cfg, "hooks")
	ownedHookScripts = uniqueNonEmptyStrings(append([]string{hookScript}, ownedHookScripts...))
	for _, event := range geminiCLIHookEvents {
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
		hooks[event] = reconcileGeminiHookGroups(hooks[event], ownedHookScripts, group)
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
	cfg, err := readGeminiSettingsObject(path)
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
	// enabled/traces/target/useCollector/useCliAuth/otlpEndpoint/
	// otlpProtocol/outfile/logPrompts.
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
	// removeManagedGeminiTelemetry detects DefenseClaw-managed blocks for
	// teardown using only the exact loopback path-token endpoint shape (or the
	// explicit legacy managedBy marker), never a path substring alone.
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

const geminiSettingsReadLimit int64 = 4 << 20

// readGeminiSettingsObject accepts the JSON-with-comments format used by the
// official Gemini CLI settings loader while retaining DefenseClaw's bounded,
// regular-file read contract. Gemini strips comments before JSON.parse; it
// does not accept trailing commas, and this reader intentionally matches that
// behavior. Managed writes are canonical JSON, so comments are reformatted
// only when DefenseClaw actually updates the settings file.
func readGeminiSettingsObject(path string) (map[string]interface{}, error) {
	data, err := safefile.ReadRegularFileBounded(path, geminiSettingsReadLimit)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	return parseGeminiSettingsObject(data, path)
}

func parseGeminiSettingsObject(data []byte, path string) (map[string]interface{}, error) {
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	normalized, err := stripJSONComments(data)
	if err != nil {
		return nil, fmt.Errorf("parse Gemini settings %s: %w", path, err)
	}
	var out map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse Gemini settings %s: %w", path, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, fmt.Errorf("parse Gemini settings %s: %w", path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("parse Gemini settings %s: root must be a JSON object", path)
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

// reconcileGeminiHookGroups removes every exact current/legacy DefenseClaw
// handler and appends one canonical current group. Foreign handlers sharing a
// matcher group, plus unknown group fields, are preserved verbatim. This is
// deliberately narrower than removeHookScriptReferences: ownership of one
// nested handler does not confer ownership of the surrounding vendor group.
func reconcileGeminiHookGroups(raw interface{}, ownedHookScripts []string, group map[string]interface{}) []interface{} {
	list, ok := raw.([]interface{})
	if !ok {
		return []interface{}{group}
	}
	pruned, _ := pruneGeminiHookGroups(list, ownedHookScripts)
	return append(pruned, group)
}

func pruneGeminiHookGroups(list []interface{}, ownedHookScripts []string) ([]interface{}, bool) {
	out := make([]interface{}, 0, len(list))
	changed := false
	for _, item := range list {
		group, ok := item.(map[string]interface{})
		if !ok {
			out = append(out, item)
			continue
		}
		rawHooks, ok := group["hooks"].([]interface{})
		if !ok {
			out = append(out, item)
			continue
		}
		remaining := make([]interface{}, 0, len(rawHooks))
		removed := false
		for _, rawHook := range rawHooks {
			if managedGeminiHookEntry(rawHook, ownedHookScripts) {
				removed = true
				changed = true
				continue
			}
			remaining = append(remaining, rawHook)
		}
		if !removed {
			out = append(out, item)
			continue
		}
		if len(remaining) == 0 && canonicalGeminiManagedGroup(group) {
			// DefenseClaw creates exactly {matcher:"*", hooks:[...]}; once its
			// handlers are gone, that whole publication unit is ours to remove.
			continue
		}
		preserved := make(map[string]interface{}, len(group))
		for key, value := range group {
			preserved[key] = value
		}
		preserved["hooks"] = remaining
		out = append(out, preserved)
	}
	return out, changed
}

func managedGeminiHookEntry(raw interface{}, ownedHookScripts []string) bool {
	for _, hookScript := range ownedHookScripts {
		if managedHookCommandEntry(raw, hookScript) {
			return true
		}
	}
	return false
}

func canonicalGeminiManagedGroup(group map[string]interface{}) bool {
	if len(group) != 2 {
		return false
	}
	matcher, ok := group["matcher"].(string)
	return ok && matcher == "*"
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

func removeGeminiConfigEntries(path, hookScript string, ownedHookScripts ...string) error {
	cfg, err := readGeminiSettingsObject(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	ownedHookScripts = uniqueNonEmptyStrings(append([]string{hookScript}, ownedHookScripts...))
	pruneGeminiConfigEntries(cfg, ownedHookScripts)
	return writeJSONObject(path, cfg)
}

// pruneGeminiConfigEntries removes only exact current/legacy DefenseClaw
// Gemini registrations from an already-decoded settings object. It is shared
// by live teardown and pristine-backup normalization so both paths use the
// same narrow ownership predicate.
func pruneGeminiConfigEntries(cfg map[string]interface{}, ownedHookScripts []string) bool {
	changed := false
	if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
		hooksChanged := false
		for event, raw := range hooks {
			list, ok := raw.([]interface{})
			if !ok {
				continue
			}
			remaining, groupChanged := pruneGeminiHookGroups(list, ownedHookScripts)
			if !groupChanged {
				continue
			}
			hooksChanged = true
			if len(remaining) == 0 {
				delete(hooks, event)
			} else {
				hooks[event] = remaining
			}
		}
		if hooksChanged && len(hooks) == 0 {
			delete(cfg, "hooks")
		}
		changed = hooksChanged
	}
	return removeManagedGeminiTelemetry(cfg) || changed
}

func removeManagedGeminiTelemetry(cfg map[string]interface{}) bool {
	telemetry, ok := cfg["telemetry"].(map[string]interface{})
	if !ok {
		return false
	}
	// Detect both current and legacy DefenseClaw-managed telemetry:
	//   - current: exact loopback HTTP endpoint with the canonical
	//     /otlp/geminicli/<64-lowercase-hex> shape
	//   - legacy: managedBy == "defenseclaw" (pre-schema-fix installs)
	// A mere path substring is not ownership: an operator collector such as
	// https://operator.example/otlp/geminicli/team must survive lifecycle
	// reconciliation and pristine-receipt migration.
	managedBy, _ := telemetry["managedBy"].(string)
	endpoint, _ := telemetry["otlpEndpoint"].(string)
	if !strings.EqualFold(strings.TrimSpace(managedBy), "defenseclaw") && !managedGeminiOTLPEndpoint(endpoint) {
		return false
	}
	// Delete both the current schema keys and the legacy keys
	// ("protocol", "managedBy") so an upgrade from an older
	// defenseclaw install also leaves a clean settings.json.
	for _, key := range []string{
		"enabled",
		"traces",
		"target",
		"otlpEndpoint",
		"otlpProtocol",
		"useCollector",
		"useCliAuth",
		"outfile",
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
	return true
}

func managedGeminiOTLPEndpoint(endpoint string) bool {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Scheme != "http" || parsed.User != nil ||
		parsed.RawQuery != "" || parsed.Fragment != "" || parsed.Port() == "" {
		return false
	}
	host := strings.TrimSpace(parsed.Hostname())
	ip := net.ParseIP(host)
	if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
		return false
	}
	const prefix = "/otlp/geminicli/"
	if !strings.HasPrefix(parsed.EscapedPath(), prefix) {
		return false
	}
	token := strings.TrimPrefix(parsed.EscapedPath(), prefix)
	return !strings.Contains(token, "/") && otlpTokenHexRE.MatchString(token)
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
			if command == legacyWindowsCopilotPowerShellHookCommandForEvent(event, hookBinary) {
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
