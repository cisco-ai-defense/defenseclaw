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
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// ClaudeCodeConnector is the hook-only security surface for Claude
// Code. It does not interpose on chat traffic; the CLI talks directly
// to api.anthropic.com. The connector wires two telemetry/inspection
// channels into ~/.claude/settings.json:
//   - claude-code-hook.sh under hooks for tool-call inspection
//   - OTel env block for native OTLP telemetry to the gateway
//
// Implements ComponentScanner, StopScanner.
type ClaudeCodeConnector struct {
	gatewayToken string
	masterKey    string
}

// NewClaudeCodeConnector creates a new Claude Code connector.
func NewClaudeCodeConnector() *ClaudeCodeConnector {
	return &ClaudeCodeConnector{}
}

func (c *ClaudeCodeConnector) Name() string        { return "claudecode" }
func (c *ClaudeCodeConnector) HookAPIPath() string { return "/api/v1/claude-code/hook" }

// HookScriptNames implements HookScriptOwner (plan C2 / S2.5).
// claudecode-only template; the generic inspect-* scripts are
// added by WriteHookScriptsForConnector unconditionally.
func (c *ClaudeCodeConnector) HookScriptNames(SetupOpts) []string {
	return []string{"claude-code-hook.sh"}
}
func (c *ClaudeCodeConnector) Description() string {
	return "env var + settings.json hooks (20+ events, component scanning)"
}
func (c *ClaudeCodeConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *ClaudeCodeConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *ClaudeCodeConnector) Setup(ctx context.Context, opts SetupOpts) error {
	otlpToken, err := resolveSetupOTLPPathToken(opts.DataDir, OTLPScopeClaude, opts.OTLPPathToken)
	if err != nil {
		return fmt.Errorf("claudecode scoped OTLP token: %w", err)
	}
	opts.OTLPPathToken = otlpToken

	hookDir := filepath.Join(opts.DataDir, "hooks")
	// Plan C2: hand the connector itself so HookScriptOwner is the
	// single source of truth for which vendor templates land here.
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("claudecode hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "claude-code-hook.sh")
	settingsDir := filepath.Dir(claudeCodeSettingsPath())
	if err := ensureClaudeCodeConfigDir(settingsDir); err != nil {
		return fmt.Errorf("prepare Claude Code configuration directory %s: %w", settingsDir, err)
	}
	// Hooks register unconditionally — they post to
	// /api/v1/claudecode/hook (or the equivalent route) and are the
	// entry point for tool-call telemetry on every install. The hook
	// can return "allow" (observability) or "deny" based on the policy
	// decision returned by the gateway.
	if err := c.patchClaudeCodeHooks(opts, hookScript); err != nil {
		return fmt.Errorf("claudecode settings hooks: %w", err)
	}

	// patchClaudeCodeOtelEnv writes Claude Code's native OpenTelemetry
	// env vars into ~/.claude/settings.json's env block (Claude reads
	// these at process startup, exporting structured logs + metrics
	// directly to the gateway's OTLP-HTTP receiver). This is the
	// second independent observability channel after hooks: hooks
	// give us per-tool-call structured events, OTel gives us raw
	// model/token/timing telemetry that doesn't fit the hook bus.
	if err := c.patchClaudeCodeOtelEnv(opts); err != nil {
		return fmt.Errorf("claudecode otel env: %w", err)
	}

	if opts.InstallCodeGuard {
		if err := ensureClaudeCodeCodeGuardPlugin(ctx); err != nil {
			return fmt.Errorf("claude CodeGuard plugin install: %w", err)
		}
	}

	return nil
}

func (c *ClaudeCodeConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	var errs []string

	if err := c.restoreClaudeCodeHooks(opts); err != nil {
		errs = append(errs, fmt.Sprintf("restore hooks: %v", err))
	}

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		errs = append(errs, fmt.Sprintf("subprocess enforcement: %v", err))
	}

	// Cached-PID safety: long-lived Claude Code processes cache the
	// absolute hook path at startup. We replace claude-code-hook.sh in
	// place with the shared v0 tombstone (atomic rename, no ENOENT
	// window) instead of deleting it — see writeDisabledHookTombstone
	// for the full contract.
	if err := writeDisabledHookTombstone(opts, "claude-code-hook.sh", "Claude Code"); err != nil {
		errs = append(errs, fmt.Sprintf("disabled hook: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("claudecode teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (c *ClaudeCodeConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check for owned hooks still present in settings.json
	settingsPath := claudeCodeSettingsPath()
	if data, err := os.ReadFile(settingsPath); err == nil {
		var settings map[string]interface{}
		if json.Unmarshal(data, &settings) == nil {
			hooksDir := filepath.Join(opts.DataDir, "hooks")
			if hooks, ok := settings["hooks"].(map[string]interface{}); ok {
				for eventType, val := range hooks {
					list, _ := val.([]interface{})
					for _, entry := range list {
						if isOwnedHook(entry, hooksDir) {
							residual = append(residual, fmt.Sprintf("settings.json hooks[%s] still contains defenseclaw hook", eventType))
							break
						}
					}
				}
			}
			// Environment ownership is independent of hook shape. A missing or
			// malformed hooks subtree must not hide uninstall residue.
			if envMap, ok := settings["env"].(map[string]interface{}); ok {
				managedEnv := buildClaudeCodeOtelEnv(opts)
				if backup, err := c.loadBackup(opts.DataDir); err == nil && len(backup.ManagedEnv) > 0 {
					managedEnv = backup.ManagedEnv
				}
				for _, key := range claudeCodeOtelEnvKeys {
					if value, present := envMap[key]; present && claudeCodeOtelValueIsManaged(value, managedEnv[key]) {
						residual = append(residual, fmt.Sprintf("settings.json env[%s] still contains defenseclaw OTel env", key))
					}
				}
			}
		}
	}

	// Check shims directory
	shimDir := filepath.Join(opts.DataDir, "shims")
	if entries, err := os.ReadDir(shimDir); err == nil && len(entries) > 0 {
		residual = append(residual, fmt.Sprintf("shims/ still has %d entries", len(entries)))
	}

	if len(residual) > 0 {
		return fmt.Errorf("claudecode teardown incomplete: %s", strings.Join(residual, "; "))
	}
	return nil
}

func (c *ClaudeCodeConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && SecureTokenMatch(token, c.gatewayToken) {
			return true
		}
	}

	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && SecureTokenMatch(strings.TrimPrefix(auth, "Bearer "), c.masterKey) {
			return true
		}
	}

	// No gateway token configured: trust loopback callers. The masterKey is
	// an alternative credential for programmatic/remote access — its presence
	// alone should not revoke loopback trust. The operator opts into requiring
	// auth on all connections by setting DEFENSECLAW_GATEWAY_TOKEN.
	if c.gatewayToken == "" {
		return isLoopback
	}

	return false
}

func (c *ClaudeCodeConnector) SetCredentials(gatewayToken, masterKey string) {
	c.gatewayToken = gatewayToken
	c.masterKey = masterKey
}

func (c *ClaudeCodeConnector) Route(r *http.Request, body []byte) (*ConnectorSignals, error) {
	return &ConnectorSignals{
		ConnectorName:   "claudecode",
		RawBody:         body,
		RawModel:        ParseModelFromBody(body),
		Stream:          ParseStreamFromBody(body),
		PassthroughMode: !isChatPath(r.URL.Path),
	}, nil
}

// --- AgentPathProvider / EnvRequirementsProvider / HookScriptProvider ---

// AgentPaths reports the on-disk footprint Claude Code's connector
// touches. The connector patches ~/.claude/settings.json (hooks +
// OTel env block) and writes the inspect-* + claude-code-hook.sh
// scripts under <DataDir>/hooks/. The shims directory under
// <DataDir>/shims/ is created by SetupSubprocessEnforcement and is
// listed in CreatedDirs so VerifyClean and the audit surface treat
// it as connector-owned.
func (c *ClaudeCodeConnector) AgentPaths(opts SetupOpts) AgentPaths {
	return AgentPaths{
		PatchedFiles: []string{claudeCodeSettingsPath()},
		BackupFiles: []string{
			managedFileBackupPath(opts.DataDir, c.Name(), "settings.json"),
		},
		HookScripts: hookScriptPathsForConnector(opts, c),
	}
}

func (c *ClaudeCodeConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

func (c *ClaudeCodeConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{{
		Scope:       EnvScopeNone,
		Description: "Hooks and native OpenTelemetry are written to Claude Code settings; no shell environment variables are required.",
	}}
}

// HookCapabilities declares the Claude Code hook surface for the
// unified collector and the verdict mapper. The shape mirrors the
// events handled in evaluateClaudeCodeHook + claudeCodeOutput.
//
// CanBlock=true: PreToolUse/PermissionRequest honour permissionDecision=
// deny; UserPromptSubmit and other pre-action events honour decision=block;
// tasks honour continue=false. PostToolUse is advisory because the tool side
// effects have already occurred; PostToolBatch can still stop the agentic loop
// before the next model call. ConfigChange is blockable except for the
// policy_settings source.
//
// CanAskNative=true: PreToolUse renders permissionDecision=ask when a
// hook returns confirm, which Claude Code surfaces as a native HITL
// prompt.
//
// SupportsFailClosed=true: claude-code-hook.sh honours
// DEFENSECLAW_FAIL_MODE=closed at the shell layer.
func (c *ClaudeCodeConnector) HookCapabilities(opts SetupOpts) HookCapability {
	return HookCapability{
		CanBlock:     true,
		CanAskNative: true,
		AskEvents:    []string{"PreToolUse"},
		BlockEvents: []string{
			"UserPromptSubmit",
			"UserPromptExpansion",
			"PreToolUse",
			"PermissionRequest",
			"PostToolBatch",
			"TaskCreated",
			"TaskCompleted",
			"TeammateIdle",
			"Stop",
			"SubagentStop",
			"ConfigChange",
			"PreCompact",
			"Elicitation",
			"ElicitationResult",
		},
		SupportsFailClosed: true,
		Scope:              "user",
		ConfigPath:         claudeCodeSettingsPath(),
	}
}

// HookProfile implements HookProfileProvider. The returned
// NativeOTLPSpec is the declarative form of buildClaudeCodeOtelEnv:
// an env-block targeting the gateway's connector-scoped loopback OTLP-HTTP
// receiver, with source headers and a path token that has no general API
// authority.
// buildClaudeCodeOtelEnv renders this spec via spec.EnvBlock()
// instead of computing the map by hand.
//
// ExtraEnv carries the connector-specific vars that the OTel
// renderer does not emit: CLAUDE_CODE_ENABLE_TELEMETRY (the
// vendor's master switch), DEFENSECLAW_FAIL_MODE (read by the hook
// script for fail-closed handling), and OTEL_LOG_USER_PROMPTS when
// redaction is disabled.
func (c *ClaudeCodeConnector) HookProfile(opts SetupOpts) HookProfile {
	otlpToken := strings.TrimSpace(opts.OTLPPathToken)
	if otlpToken == "" && opts.DataDir != "" {
		otlpToken, _ = LoadOTLPPathToken(opts.DataDir, OTLPScopeClaude)
	}
	headers := map[string]string{
		"x-defenseclaw-source": "claudecode",
		"x-defenseclaw-client": "claudecode-otel/1.0",
	}
	failMode := "open"
	if strings.TrimSpace(opts.HookFailMode) != "" {
		failMode = normalizeHookFailMode(opts.HookFailMode)
	}
	extra := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"DEFENSECLAW_FAIL_MODE":        failMode,
		// Match V1's exporter selection: metrics + logs only.
		// Claude Code does not currently consume traces from its
		// CLI process; setting OTEL_TRACES_EXPORTER would force
		// the OTel SDK to push every span the CLI emits and the
		// gateway receiver would have to filter them out. Adding
		// traces is a future spec extension; today the parity test
		// pins the exact V1 keys.
		"OTEL_METRICS_EXPORTER": "otlp",
		"OTEL_LOGS_EXPORTER":    "otlp",
	}
	if redaction.DisableAll() {
		extra["OTEL_LOG_USER_PROMPTS"] = "1"
	}
	profile := HookProfile{
		Name:                "claudecode",
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		NativeOTLP: &NativeOTLPSpec{
			Kind:               NativeOTLPEnvBlock,
			Endpoint:           "http://" + opts.APIAddr,
			Protocol:           "http/json",
			Headers:            headers,
			PathToken:          otlpToken,
			PathScope:          OTLPScopeClaude,
			PerSignal:          false,
			ServiceName:        "claudecode",
			ResourceAttributes: map[string]string{"service.name": "claudecode", "defenseclaw.connector": "claudecode"},
			ExtraEnv:           extra,
			LogUserPrompts:     redaction.DisableAll(),
		},
		// Profile-driven callbacks are the canonical shape for
		// claudecode hook decode / verdict mapping / response. The
		// gateway profile-runtime registry uses these pure callbacks
		// for response/mode behavior and keeps APIServer-owned
		// scanner / asset-policy / notifier work in the unified
		// collector. Golden tests keep those layers in lockstep.
		Decode:     claudeCodeProfileDecode,
		MapVerdict: claudeCodeProfileMapVerdict,
		Respond:    claudeCodeProfileRespond,
	}
	return ApplyHookContract(profile, opts)
}

// --- ComponentScanner interface ---

func (c *ClaudeCodeConnector) SupportsComponentScanning() bool { return true }

func (c *ClaudeCodeConnector) ComponentTargets(cwd string) map[string][]string {
	userDir := claudeCodeConfigDir()
	workspaceDir := filepath.Join(cwd, ".claude")

	targets := map[string][]string{
		"skill":   {filepath.Join(userDir, "skills"), filepath.Join(workspaceDir, "skills")},
		"plugin":  {filepath.Join(userDir, "plugins"), filepath.Join(workspaceDir, "plugins")},
		"mcp":     {filepath.Join(userDir, "settings.json"), filepath.Join(cwd, ".mcp.json")},
		"agent":   {filepath.Join(userDir, "agents"), filepath.Join(workspaceDir, "agents")},
		"command": {filepath.Join(userDir, "commands"), filepath.Join(workspaceDir, "commands")},
		"config": {
			filepath.Join(userDir, "settings.json"),
			filepath.Join(workspaceDir, "rules"),
			filepath.Join(cwd, "CLAUDE.md"),
			filepath.Join(cwd, ".claude.json"),
		},
	}
	return targets
}

// --- StopScanner interface ---

func (c *ClaudeCodeConnector) SupportsStopScan() bool { return true }

// --- Settings.json patching ---

// claudeCodeBackup captures the pre-DefenseClaw shape of the two
// settings.json subtrees Setup() touches — [hooks] and [env] — so
// Teardown can restore them verbatim or remove keys we added. The
// byte-for-byte managed-file backup is the primary restore path;
// this JSON-encoded shape covers the drifted-config fallback (when
// the operator hand-edited settings.json after Setup).
type claudeCodeBackup struct {
	OriginalHooks json.RawMessage `json:"original_hooks"`
	HadHooksKey   bool            `json:"had_hooks_key"`

	// ManagedHookCommands records the exact native command lines written by
	// previous Setup runs. The gateway binary can move during an upgrade or a
	// source-build test. This exact allow-list lets the next Setup remove the
	// command it actually wrote, then replaces the list with the current command.
	ManagedHookCommands []string `json:"managed_hook_commands,omitempty"`

	// OTel env block backup (set on the very first patch only — see
	// patchClaudeCodeHooks). HadEnvKey distinguishes "operator had no
	// env block at all" from "operator had an empty env block". When
	// managed values remain unchanged, teardown can therefore restore
	// the original JSON shape without touching later operator edits.
	// OriginalEnv stores the raw JSON of the operator's env block
	// before DefenseClaw overlays its OTel keys. This includes any
	// pre-existing OTel settings so teardown can restore the user's
	// original collector/exporter values exactly.
	HadEnvKey   bool            `json:"had_env_key"`
	OriginalEnv json.RawMessage `json:"original_env,omitempty"`
	// ManagedEnv records the exact values written by the most recent Setup.
	// Teardown compares current values against this map before restoring or
	// deleting them, so operator changes made after Setup remain untouched.
	ManagedEnv map[string]string `json:"managed_env,omitempty"`
}

func (c *ClaudeCodeConnector) saveBackup(dataDir string, backup claudeCodeBackup) error {
	data, err := json.MarshalIndent(backup, "", "  ")
	if err != nil {
		return err
	}
	return atomicWriteFile(filepath.Join(dataDir, "claudecode_backup.json"), data, 0o600)
}

func (c *ClaudeCodeConnector) loadBackup(dataDir string) (claudeCodeBackup, error) {
	var backup claudeCodeBackup
	data, err := os.ReadFile(filepath.Join(dataDir, "claudecode_backup.json"))
	if err != nil {
		return backup, err
	}
	return backup, json.Unmarshal(data, &backup)
}

// ClaudeCodeSettingsPathOverride allows tests to redirect the settings path.
var ClaudeCodeSettingsPathOverride string

// claudeCodeConfigDir returns the same user-scoped configuration directory
// Claude Code resolves. CLAUDE_CONFIG_DIR is a supported first-class override;
// honoring it here keeps hook setup, teardown, health checks, and component
// discovery pointed at the configuration the running agent actually reads.
func claudeCodeConfigDir() string {
	if ClaudeCodeSettingsPathOverride != "" {
		return filepath.Dir(ClaudeCodeSettingsPathOverride)
	}
	if configDir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR")); configDir != "" {
		return configDir
	}
	return filepath.Join(userHomeDir(), ".claude")
}

func claudeCodeSettingsPath() string {
	if ClaudeCodeSettingsPathOverride != "" {
		return ClaudeCodeSettingsPathOverride
	}
	return filepath.Join(claudeCodeConfigDir(), "settings.json")
}

// fileChangedMatcher targets config files that affect Claude Code's
// behavior or the sandbox's trust boundary. Regular source file writes
// are already covered by PostToolUse — narrowing FileChanged keeps the
// hook bus from thundering on every edit.
const fileChangedMatcher = "CLAUDE.md|.claude/settings.json|.claude/settings.local.json|.mcp.json|.env|.envrc|package.json|pyproject.toml|go.mod|Cargo.toml|requirements.txt"

// hookGroups defines the full Claude Code event coverage. Mirrors the
// _CLAUDE_CODE_EVENTS list established by PR #140 so every server case
// in internal/gateway/claude_code_hook.go has a matching client
// registration.
//
// Matcher policy:
//   - Tool-use events: "*" so new Claude tools are inspected by default.
//     Hard-coded tool regexes silently drop coverage as Claude ships new
//     tools (Skill, ToolSearch, etc. appeared mid-release cycle).
//   - SessionStart: the four lifecycle phases worth observing.
//   - FileChanged: config-file allowlist — see fileChangedMatcher above.
//
// Timeouts in seconds, as required by Claude Code. Slow events get a larger budget:
//   - PostToolBatch summarizes many tool results → 90s.
//   - Stop / SubagentStop run Stop-time CodeGuard scans → 90s.
//   - SessionEnd can persist session-level audit → 60s.
//   - Everything else: 30s.
type claudeCodeHookGroup struct {
	eventType string
	matcher   string
	timeout   int
}

func newClaudeCodeHookGroup(eventType, matcher string) claudeCodeHookGroup {
	return claudeCodeHookGroup{
		eventType: eventType,
		matcher:   matcher,
		timeout:   hookexec.ClaudeCodeHookTimeoutSeconds(eventType),
	}
}

// Setup only observes initialization and cannot block. WorktreeCreate replaces
// Claude's default git behavior and must create/print a worktree path, so the
// generic security hook intentionally owns neither event.
var hookGroups = []claudeCodeHookGroup{
	newClaudeCodeHookGroup("SessionStart", "startup|resume|clear|compact"),
	newClaudeCodeHookGroup("InstructionsLoaded", "*"),
	newClaudeCodeHookGroup("UserPromptSubmit", ""),
	newClaudeCodeHookGroup("UserPromptExpansion", ""),
	newClaudeCodeHookGroup("MessageDisplay", ""),
	newClaudeCodeHookGroup("PreToolUse", "*"),
	newClaudeCodeHookGroup("PermissionRequest", "*"),
	newClaudeCodeHookGroup("PostToolUse", "*"),
	newClaudeCodeHookGroup("PostToolUseFailure", "*"),
	newClaudeCodeHookGroup("PostToolBatch", ""),
	newClaudeCodeHookGroup("PermissionDenied", "*"),
	newClaudeCodeHookGroup("Notification", "*"),
	newClaudeCodeHookGroup("SubagentStart", "*"),
	newClaudeCodeHookGroup("SubagentStop", "*"),
	newClaudeCodeHookGroup("TaskCreated", ""),
	newClaudeCodeHookGroup("TaskCompleted", ""),
	newClaudeCodeHookGroup("Stop", ""),
	newClaudeCodeHookGroup("StopFailure", "*"),
	newClaudeCodeHookGroup("TeammateIdle", ""),
	newClaudeCodeHookGroup("ConfigChange", "*"),
	newClaudeCodeHookGroup("CwdChanged", ""),
	newClaudeCodeHookGroup("FileChanged", fileChangedMatcher),
	newClaudeCodeHookGroup("WorktreeRemove", ""),
	newClaudeCodeHookGroup("PreCompact", "*"),
	newClaudeCodeHookGroup("PostCompact", "*"),
	newClaudeCodeHookGroup("SessionEnd", ""),
	newClaudeCodeHookGroup("Elicitation", "*"),
	newClaudeCodeHookGroup("ElicitationResult", "*"),
}

// ownedHookContractPresent performs the connector-specific presence check used
// by the runtime hook guardian. A single recognizable command is not enough:
// Claude can keep that command under an irrelevant event, a narrow matcher, or
// an asynchronous handler while all blockable surfaces remain unprotected.
func (c *ClaudeCodeConnector) ownedHookContractPresent(opts SetupOpts) (bool, error) {
	data, err := os.ReadFile(claudeCodeSettingsPath())
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var settings map[string]interface{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return false, fmt.Errorf("parse Claude Code settings: %w", err)
	}
	if rawDisabled, exists := settings["disableAllHooks"]; exists {
		disabled, ok := rawDisabled.(bool)
		if !ok || disabled {
			return false, nil
		}
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return false, nil
	}

	for _, group := range hookGroups {
		entries, ok := hooks[group.eventType].([]interface{})
		if !ok || !claudeCodeEventHasEnforcingHook(entries, group.eventType, group.matcher, opts) {
			return false, nil
		}
	}
	return true, nil
}

func claudeCodeEventHasEnforcingHook(
	entries []interface{}, eventType, requiredMatcher string, opts SetupOpts,
) bool {
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok || !claudeCodeMatcherCovers(eventType, entry["matcher"], requiredMatcher) {
			continue
		}
		handlers, ok := entry["hooks"].([]interface{})
		if !ok {
			continue
		}
		for _, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]interface{})
			if !ok || !claudeCodeHandlerEnforces(handler, opts) {
				continue
			}
			return true
		}
	}
	return false
}

func claudeCodeMatcherCovers(eventType string, raw interface{}, required string) bool {
	switch eventType {
	case "UserPromptSubmit", "PostToolBatch", "Stop", "TeammateIdle",
		"TaskCreated", "TaskCompleted", "WorktreeRemove", "CwdChanged":
		// Claude ignores matchers for these events, so their value cannot
		// narrow the effective registration.
		return true
	}
	matcher := ""
	if raw != nil {
		var ok bool
		matcher, ok = raw.(string)
		if !ok {
			return false
		}
	}
	// Empty and "*" both match every occurrence. They are safe supersets of
	// the deliberately narrower SessionStart and FileChanged registrations.
	if matcher == "" || matcher == "*" || matcher == required {
		return true
	}
	if eventType == "FileChanged" {
		actualFiles := make(map[string]struct{})
		for _, name := range strings.Split(matcher, "|") {
			actualFiles[name] = struct{}{}
		}
		for _, requiredFile := range strings.Split(required, "|") {
			if _, ok := actualFiles[requiredFile]; !ok {
				return false
			}
		}
		return true
	}
	return false
}

func claudeCodeHandlerEnforces(handler map[string]interface{}, opts SetupOpts) bool {
	for _, field := range [...]string{"async", "asyncRewake"} {
		if async, exists := handler[field]; exists {
			value, ok := async.(bool)
			if !ok || value {
				return false
			}
		}
	}
	if condition, exists := handler["if"]; exists {
		value, ok := condition.(string)
		if !ok || value != "" {
			return false
		}
	}
	if hookType, _ := handler["type"].(string); hookType != "command" {
		return false
	}
	if runtime.GOOS == "windows" {
		command, _ := handler["command"].(string)
		return isClaudeCodeNativeExecHook(handler) &&
			strings.EqualFold(filepath.Clean(command), filepath.Clean(defenseclawHookBinary()))
	}
	command, _ := handler["command"].(string)
	expected := hookInvocationCommand(
		"claudecode",
		filepath.ToSlash(filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh")),
	)
	return command == expected
}

// patchClaudeCodeHooks reads ~/.claude/settings.json, backs up the original
// hooks, and registers DefenseClaw hooks for all Claude Code events.
// The read-modify-write cycle is protected by an advisory file lock to
// prevent corruption from concurrent gateway starts.
func (c *ClaudeCodeConnector) patchClaudeCodeHooks(opts SetupOpts, hookScript string) error {
	// On Unix the agent runs the bundled .sh hook (ToSlash is a no-op there).
	// On Windows Claude Code's exec form invokes the native launcher directly,
	// without Git Bash or PowerShell parsing an absolute path that may contain
	// spaces. Older shell-form commands are still recognized during migration.
	hookCommand := hookInvocationCommand("claudecode", filepath.ToSlash(hookScript))
	hookArgs := []string(nil)
	if runtime.GOOS == "windows" {
		hookCommand = defenseclawHookBinary()
		hookArgs = []string{"hook", "--connector", "claudecode"}
	}
	settingsPath := claudeCodeSettingsPath()

	return withFileLock(settingsPath, func() error {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
			return fmt.Errorf("capture claude settings backup: %w", err)
		}

		settings := map[string]interface{}{}
		data, err := os.ReadFile(settingsPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read claude settings: %w", err)
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &settings); err != nil {
				return fmt.Errorf("parse claude settings: %w", err)
			}
		}

		backup, backupErr := c.loadBackup(opts.DataDir)
		if backupErr != nil {
			if !os.IsNotExist(backupErr) {
				return fmt.Errorf("load claudecode backup: %w", backupErr)
			}
			backup = claudeCodeBackup{}
			if hooks, ok := settings["hooks"]; ok {
				raw, _ := json.Marshal(hooks)
				backup.OriginalHooks = raw
				backup.HadHooksKey = true
			}
		}

		hooks, _ := settings["hooks"].(map[string]interface{})
		if hooks == nil {
			hooks = map[string]interface{}{}
		}

		hooksDir := filepath.Join(opts.DataDir, "hooks")
		managedCommands := append([]string(nil), backup.ManagedHookCommands...)
		for key, hk := range hooks {
			hooks[key] = removeOwnedClaudeCodeHooks(hk, hooksDir, managedCommands)
		}

		for _, group := range hookGroups {
			handler := map[string]interface{}{
				"type":    "command",
				"command": hookCommand,
				"timeout": group.timeout,
			}
			if hookArgs != nil {
				handler["args"] = hookArgs
			}
			entry := map[string]interface{}{
				"hooks": []interface{}{handler},
			}
			if group.matcher != "" {
				entry["matcher"] = group.matcher
			}

			existing, _ := hooks[group.eventType].([]interface{})
			hooks[group.eventType] = append(existing, entry)
		}

		settings["hooks"] = hooks

		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal claude settings: %w", err)
		}

		if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
			return err
		}
		if runtime.GOOS == "windows" {
			// Exec-form hooks are recognized by their exact argument vector. Keep
			// this legacy list empty so an unrelated use of the same executable
			// with different arguments can never be removed by command alone.
			backup.ManagedHookCommands = nil
		} else {
			backup.ManagedHookCommands = []string{hookCommand}
		}
		if err := c.saveBackup(opts.DataDir, backup); err != nil {
			return fmt.Errorf("save claudecode backup: %w", err)
		}
		return nil
	})
}

// claudeCodeOtelEnvKeys is the canonical set of DefenseClaw-managed
// Claude Code environment variable names, mostly OpenTelemetry-related
// (see https://code.claude.com/docs/en/monitoring-usage). We track them by
// name so Teardown can strip our additions without nuking unrelated
// operator-set keys, and so backup-on-first-patch preserves the
// operator's pristine values for any keys we overwrite. Keep this
// list in sync with the CLAUDE_CODE_* / OTEL_* vars Claude reads.
var claudeCodeOtelEnvKeys = []string{
	"CLAUDE_CODE_ENABLE_TELEMETRY",
	"DEFENSECLAW_FAIL_MODE",
	"OTEL_METRICS_EXPORTER",
	"OTEL_LOGS_EXPORTER",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_LOG_USER_PROMPTS",
	"OTEL_RESOURCE_ATTRIBUTES",
	"OTEL_SERVICE_NAME",
}

// buildClaudeCodeOtelEnv returns the OTel env vars Claude Code's
// settings.json should inject into the CLI process env. Endpoint is a
// connector-scoped gateway path; no master or hook bearer is exposed to the
// Claude process. Service name + resource attributes mark
// telemetry as originating from a Claude Code process so the gateway
// can fan out to per-connector dashboards.
//
// Privacy note: Claude Code redacts prompt content by default. When
// DefenseClaw redaction is explicitly disabled, we set
// OTEL_LOG_USER_PROMPTS=1 so Claude's native OTel follows the same raw
// prompt contract as DefenseClaw's own hook telemetry. Teardown restores
// unchanged managed values and preserves operator edits made afterward.
func buildClaudeCodeOtelEnv(opts SetupOpts) map[string]string {
	// Spec-driven: render from the connector's declarative
	// NativeOTLPSpec via spec.EnvBlock(). Returning an empty map on
	// validation error is the safest fail-closed behaviour for
	// claude code: an unset OTEL_EXPORTER_OTLP_ENDPOINT means the
	// CLI's OTel SDK disables the exporter entirely, so we never
	// silently leak telemetry to a wrong endpoint when the spec is
	// misconfigured in code.
	spec := (&ClaudeCodeConnector{}).HookProfile(opts).NativeOTLP
	if spec == nil {
		return map[string]string{}
	}
	env, err := spec.EnvBlock()
	if err != nil {
		return map[string]string{}
	}
	return env
}

// patchClaudeCodeOtelEnv merges OpenTelemetry env vars into
// ~/.claude/settings.json's `env` block. Claude Code reads this
// block at startup and exports it into the CLI process environment
// (https://code.claude.com/docs/en/monitoring-usage), so persisting
// the OTel wiring here means the operator does not need to source
// any shell file before launching `claude`.
//
// Read-modify-write is protected by the same advisory file lock as
// patchClaudeCodeHooks; concurrent gateway starts will serialize.
// On first patch (i.e. claudecode_backup.json doesn't yet have an
// HadEnvKey marker), we capture the operator's pristine env block. We also
// record the exact values written on every patch so teardown can distinguish
// still-managed values from later operator edits. Subsequent patches reuse the
// pristine backup — we never re-snapshot a partially-modified env.
func (c *ClaudeCodeConnector) patchClaudeCodeOtelEnv(opts SetupOpts) error {
	settingsPath := claudeCodeSettingsPath()

	return withFileLock(settingsPath, func() error {
		settings := map[string]interface{}{}
		data, err := os.ReadFile(settingsPath)
		if err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("read claude settings: %w", err)
		}
		if len(data) > 0 {
			if err := json.Unmarshal(data, &settings); err != nil {
				return fmt.Errorf("parse claude settings: %w", err)
			}
		}

		existing, _ := settings["env"].(map[string]interface{})
		if existing == nil {
			existing = map[string]interface{}{}
		}

		// Backup: only on first patch. patchClaudeCodeHooks runs
		// before this method in Setup() and creates the backup file
		// with HadHooksKey populated; here we augment the SAME
		// backup with HadEnvKey/OriginalEnv. This keeps the file
		// single-source-of-truth for Teardown.
		backup, backupErr := c.loadBackup(opts.DataDir)
		if backupErr != nil {
			if !os.IsNotExist(backupErr) {
				return fmt.Errorf("load claudecode backup (otel env): %w", backupErr)
			}
			backup = claudeCodeBackup{}
		}
		if !backup.HadEnvKey && len(backup.OriginalEnv) == 0 {
			if envRaw, present := settings["env"]; present {
				envMap, _ := envRaw.(map[string]interface{})
				pristine := map[string]interface{}{}
				for k, v := range envMap {
					pristine[k] = v
				}
				if raw, err := json.Marshal(pristine); err == nil {
					backup.OriginalEnv = raw
				}
				backup.HadEnvKey = true
			}
		}
		managedEnv := buildClaudeCodeOtelEnv(opts)
		backup.ManagedEnv = make(map[string]string, len(managedEnv))
		for key, value := range managedEnv {
			backup.ManagedEnv[key] = value
		}
		if err := c.saveBackup(opts.DataDir, backup); err != nil {
			return fmt.Errorf("save claudecode backup (otel env): %w", err)
		}

		// Overwrite our OTel keys with current values. Operator-set
		// keys outside our list (PATH, NODE_OPTIONS, etc.) are
		// preserved verbatim — we never touch them.
		for k, v := range managedEnv {
			existing[k] = v
		}
		settings["env"] = existing

		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal claude settings (otel env): %w", err)
		}
		if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
			return err
		}
		return updateManagedFileBackupPostHash(opts.DataDir, c.Name(), "settings.json", settingsPath)
	})
}

func claudeCodeOtelValueIsManaged(value interface{}, managed string) bool {
	got, _ := value.(string)
	// Ownership is exact-value based. Marker/prefix heuristics would report
	// operator-edited values as uninstall residue even though teardown correctly
	// preserved them.
	return managed != "" && got == managed
}

// restoreClaudeCodeHooks restores the original hooks from the backup file.
// Uses file locking to match patchClaudeCodeHooks and prevent corruption.
func (c *ClaudeCodeConnector) restoreClaudeCodeHooks(opts SetupOpts) error {
	settingsPath := claudeCodeSettingsPath()
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[claudecode] backup unavailable; falling back to surgical cleanup: %v\n", err)
		}
		backup = claudeCodeBackup{}
	}

	err = withFileLock(settingsPath, func() error {
		if restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
			return fmt.Errorf("managed settings restore: %w", err)
		} else if restored {
			return c.discardRestoreMetadata(opts)
		}

		data, err := os.ReadFile(settingsPath)
		if err != nil {
			if os.IsNotExist(err) {
				return c.discardRestoreMetadata(opts)
			}
			return fmt.Errorf("read claude settings for restore: %w", err)
		}

		settings := map[string]interface{}{}
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse claude settings for restore: %w", err)
		}

		if hooks, ok := settings["hooks"].(map[string]interface{}); ok {
			hooksDir := filepath.Join(opts.DataDir, "hooks")
			for eventType, val := range hooks {
				remaining := removeOwnedClaudeCodeHooks(val, hooksDir, backup.ManagedHookCommands)
				if len(remaining) == 0 {
					delete(hooks, eventType)
				} else {
					hooks[eventType] = remaining
				}
			}
			if len(hooks) == 0 {
				delete(settings, "hooks")
			} else {
				settings["hooks"] = hooks
			}
		} else if !backup.HadHooksKey {
			delete(settings, "hooks")
		}

		// Restore each env key only when its current value is still the exact
		// value written by the most recent Setup. An operator edit after Setup
		// transfers ownership back to the operator and must survive teardown.
		if envMap, ok := settings["env"].(map[string]interface{}); ok {
			originalEnv := map[string]interface{}{}
			if backup.HadEnvKey && len(backup.OriginalEnv) > 0 {
				if err := json.Unmarshal(backup.OriginalEnv, &originalEnv); err != nil {
					return fmt.Errorf("parse original Claude env backup: %w", err)
				}
			}
			managedEnv := backup.ManagedEnv
			if len(managedEnv) == 0 {
				// Compatibility for backups created before exact managed values
				// were recorded, and for best-effort backupless cleanup.
				managedEnv = buildClaudeCodeOtelEnv(opts)
			}
			for _, key := range claudeCodeOtelEnvKeys {
				written, managed := managedEnv[key]
				current, present := envMap[key].(string)
				if !managed || !present || current != written {
					continue
				}
				if original, existed := originalEnv[key]; existed {
					envMap[key] = original
				} else {
					delete(envMap, key)
				}
			}

			if backup.HadEnvKey {
				settings["env"] = envMap
			} else if len(envMap) == 0 {
				// Pristine state had no env block AND there are no
				// operator-added non-OTel keys: drop entirely.
				delete(settings, "env")
			} else {
				settings["env"] = envMap
			}
		}

		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal restored settings: %w", err)
		}

		if err := atomicWriteFile(settingsPath, out, 0o600); err != nil {
			return fmt.Errorf("write restored settings: %w", err)
		}

		return c.discardRestoreMetadata(opts)
	})
	// The settings parent can disappear before the lock file is opened (for
	// example, when Claude is uninstalled concurrently). Treat that the same
	// as a missing settings file and discard only DefenseClaw restore metadata.
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return c.discardRestoreMetadata(opts)
	}
	// On Windows, opening a child of a missing directory can report
	// ERROR_PATH_NOT_FOUND, which os.IsNotExist does not classify.
	if _, statErr := os.Stat(filepath.Dir(settingsPath)); os.IsNotExist(statErr) {
		return c.discardRestoreMetadata(opts)
	}
	return err
}

func (c *ClaudeCodeConnector) discardRestoreMetadata(opts SetupOpts) error {
	for _, path := range []string{
		filepath.Join(opts.DataDir, "claudecode_backup.json"),
		managedFileBackupPath(opts.DataDir, c.Name(), "settings.json"),
	} {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("remove Claude Code restore metadata %s: %w", path, err)
		}
	}
	return nil
}

// hookMarker is the version-agnostic prefix written on line 2 of every
// generated hook script. We match the prefix (not the full string)
// because the schema version is bumped whenever the script's
// behaviour changes (e.g. adding the .disabled fail-open guard in v2),
// and Teardown still has to recognise older hooks that were generated
// by previous DefenseClaw installs and never refreshed. The trailing
// version digit is therefore deliberately not part of the match.
const hookMarker = "# defenseclaw-managed-hook v"

// isOwnedHook returns true if a hook entry was generated by DefenseClaw.
// It checks both the script marker and the hook directory path.
func isOwnedHook(hookEntry interface{}, hooksDir string) bool {
	m, ok := hookEntry.(map[string]interface{})
	if !ok {
		return false
	}
	hooksList, _ := m["hooks"].([]interface{})
	for _, h := range hooksList {
		if isOwnedHookHandler(h, hooksDir) {
			return true
		}
	}
	return false
}

func isOwnedHookHandler(rawHook interface{}, hooksDir string) bool {
	hook, ok := rawHook.(map[string]interface{})
	if !ok {
		return false
	}
	command, _ := hook["command"].(string)
	if command == "" {
		return false
	}
	if hooksDir != "" && strings.HasPrefix(command, hooksDir+"/") {
		return true
	}
	// Native Go hook commands (Windows) are not a file path under hooksDir
	// and carry no on-disk marker, so recognize them by their entrypoint
	// invocation fragment.
	if isNativeHookCommand(command) {
		return true
	}
	if isClaudeCodeNativeExecHook(hook) {
		return true
	}
	return scriptHasMarker(command)
}

// isClaudeCodeNativeExecHook recognizes the shell-free Windows hook shape.
// Both the executable basename and the complete argument vector must match so
// teardown cannot claim an unrelated invocation of the DefenseClaw launcher.
func isClaudeCodeNativeExecHook(hook map[string]interface{}) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	command, _ := hook["command"].(string)
	base := strings.ToLower(filepath.Base(strings.TrimSpace(command)))
	// Setup now writes defenseclaw-hook.exe, but teardown must also recognize
	// defenseclaw-gateway.exe entries created by earlier Windows releases.
	if base != strings.ToLower(windowsHookBinaryName) && base != "defenseclaw-gateway.exe" {
		return false
	}
	var args []string
	switch rawArgs := hook["args"].(type) {
	case []interface{}:
		args = make([]string, len(rawArgs))
		for i, raw := range rawArgs {
			arg, ok := raw.(string)
			if !ok {
				return false
			}
			args[i] = arg
		}
	case []string:
		args = rawArgs
	default:
		return false
	}
	if len(args) != 3 {
		return false
	}
	want := []string{"hook", "--connector", "claudecode"}
	for i, arg := range args {
		if arg != want[i] {
			return false
		}
	}
	return true
}

// scriptHasMarker reads the first 512 bytes of a file and checks for the
// defenseclaw-managed-hook marker. Returns false on any I/O error (the
// file may have been deleted between runs).
func scriptHasMarker(path string) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	buf := make([]byte, 512)
	n, _ := f.Read(buf)
	return strings.Contains(string(buf[:n]), hookMarker)
}

// removeOwnedHooks removes DefenseClaw-owned handlers from a hook event's
// matcher groups and returns the compacted slice.
func removeOwnedHooks(hookEventValue interface{}, hooksDir string) []interface{} {
	return removeMatchingHookHandlers(hookEventValue, func(rawHook interface{}) bool {
		return isOwnedHookHandler(rawHook, hooksDir)
	})
}

// removeOwnedClaudeCodeHooks extends the generic marker/path recognizer with
// exact commands persisted by earlier Setup runs and the strict legacy native
// signature used before command tracking existed.
func removeOwnedClaudeCodeHooks(
	hookEventValue interface{},
	hooksDir string,
	managedCommands []string,
) []interface{} {
	return removeMatchingHookHandlers(hookEventValue, func(rawHook interface{}) bool {
		return isOwnedHookHandler(rawHook, hooksDir) ||
			hookUsesExactCommand(rawHook, managedCommands) ||
			hookUsesLegacyClaudeCodeNativeCommand(rawHook)
	})
}

// removeMatchingHookHandlers surgically filters handlers inside each matcher
// group. A matcher group can be shared by DefenseClaw and user-managed hooks;
// dropping the outer group when one owned handler matches would delete those
// unrelated hooks and their matcher metadata.
func removeMatchingHookHandlers(
	hookEventValue interface{},
	shouldRemove func(interface{}) bool,
) []interface{} {
	list, ok := hookEventValue.([]interface{})
	if !ok {
		return nil
	}
	filteredEntries := make([]interface{}, 0, len(list))
	for _, rawEntry := range list {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			filteredEntries = append(filteredEntries, rawEntry)
			continue
		}
		hooks, ok := entry["hooks"].([]interface{})
		if !ok {
			filteredEntries = append(filteredEntries, rawEntry)
			continue
		}

		keptHooks := make([]interface{}, 0, len(hooks))
		removed := false
		for _, rawHook := range hooks {
			if shouldRemove(rawHook) {
				removed = true
				continue
			}
			keptHooks = append(keptHooks, rawHook)
		}
		if !removed {
			filteredEntries = append(filteredEntries, rawEntry)
			continue
		}
		if len(keptHooks) == 0 {
			continue
		}

		filteredEntry := make(map[string]interface{}, len(entry))
		for key, value := range entry {
			filteredEntry[key] = value
		}
		filteredEntry["hooks"] = keptHooks
		filteredEntries = append(filteredEntries, filteredEntry)
	}
	return filteredEntries
}

func hookUsesLegacyClaudeCodeNativeCommand(rawHook interface{}) bool {
	hook, ok := rawHook.(map[string]interface{})
	if !ok {
		return false
	}
	command, _ := hook["command"].(string)
	return isLegacyClaudeCodeNativeHookCommand(command)
}

// isLegacyClaudeCodeNativeHookCommand recognizes the exact native command
// signature written by pre-command-tracking Windows releases, even when the
// gateway executable moved between the canonical install and a source build.
// It is deliberately scoped to Claude Code refresh: generic ownership checks
// remain tied to the current executable path.
func isLegacyClaudeCodeNativeHookCommand(command string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	command = strings.TrimSpace(command)
	// Accept commands operators repaired manually by adding PowerShell's call
	// operator, so Setup can replace them with the current managed launcher
	// without duplicating every Claude Code hook.
	if strings.HasPrefix(command, "& ") {
		command = strings.TrimSpace(strings.TrimPrefix(command, "& "))
	}
	marker := " " + nativeHookFlag
	idx := strings.LastIndex(command, marker)
	if idx <= 0 || strings.TrimSpace(command[idx+len(marker):]) != "claudecode" {
		return false
	}

	executable := strings.TrimSpace(command[:idx])
	if strings.ContainsAny(executable, "&|<>;\r\n") {
		return false
	}
	quoted := false
	if strings.HasPrefix(executable, `"`) || strings.HasSuffix(executable, `"`) {
		if len(executable) < 2 || !strings.HasPrefix(executable, `"`) || !strings.HasSuffix(executable, `"`) {
			return false
		}
		quoted = true
		executable = executable[1 : len(executable)-1]
	}
	if executable == "" || strings.ContainsAny(executable, `"'`) {
		return false
	}
	if !quoted && strings.ContainsAny(executable, " \t") {
		return false
	}

	normalized := strings.ReplaceAll(executable, `\`, "/")
	base := strings.ToLower(filepath.Base(normalized))
	return base == "defenseclaw-gateway.exe" || base == "defenseclaw-gateway"
}

func hookUsesExactCommand(rawHook interface{}, commands []string) bool {
	hook, ok := rawHook.(map[string]interface{})
	if !ok || len(commands) == 0 {
		return false
	}
	command, _ := hook["command"].(string)
	if command == "" {
		return false
	}
	for _, managed := range commands {
		if managed != "" && command == managed {
			return true
		}
	}
	return false
}
