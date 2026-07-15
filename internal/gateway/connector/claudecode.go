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
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
	"github.com/defenseclaw/defenseclaw/internal/pathidentity"
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

	if len(errs) == 0 {
		if err := c.VerifyClean(opts); err != nil {
			errs = append(errs, fmt.Sprintf("verify clean before token revocation: %v", err))
		}
	}
	if len(errs) == 0 {
		if err := RemoveOTLPPathToken(opts.DataDir, OTLPScopeClaude); err != nil {
			errs = append(errs, fmt.Sprintf("revoke scoped OTLP token: %v", err))
		}
	}
	if len(errs) == 0 {
		if err := c.discardRestoreMetadata(opts); err != nil {
			errs = append(errs, fmt.Sprintf("discard restore metadata: %v", err))
		}
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
				exactOwnership := false
				originalEnv := map[string]interface{}{}
				if backup, err := c.loadBackup(opts.DataDir); err == nil && len(backup.ManagedEnv) > 0 {
					managedEnv = backup.ManagedEnv
					exactOwnership = true
					if backup.HadEnvKey && len(backup.OriginalEnv) > 0 {
						_ = json.Unmarshal(backup.OriginalEnv, &originalEnv)
					}
				}
				for _, key := range claudeCodeOtelEnvKeys {
					value, present := envMap[key]
					if !present {
						continue
					}
					owned := claudeCodeOtelValueLooksManaged(key, value, managedEnv[key])
					if exactOwnership {
						owned = claudeCodeOtelValueIsManaged(value, managedEnv[key])
						if original, existed := originalEnv[key]; existed {
							originalString, originalIsString := original.(string)
							valueString, valueIsString := value.(string)
							if originalIsString && valueIsString && originalString == valueString {
								// An upgrade predecessor may have captured an already-managed
								// env block as pristine. Do not let that stale snapshot exempt
								// an explicit DefenseClaw endpoint or resource marker from the
								// teardown contract; generic operator OTel values remain exempt.
								owned = claudeCodeOtelValueLooksManaged(key, value, managedEnv[key])
							}
						}
					}
					if owned {
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
// an env-block targeting the gateway's loopback OTLP-HTTP receiver. Claude
// Code supports standard OTLP headers, so its connector-scoped credential is
// carried as an Authorization bearer rather than appearing in the endpoint
// URL. The receiver binds that narrow bearer to the claudecode source.
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
	if otlpToken != "" {
		headers["authorization"] = "Bearer " + otlpToken
	}
	failMode := "open"
	if strings.TrimSpace(opts.HookFailMode) != "" {
		failMode = normalizeHookFailMode(opts.HookFailMode)
	}
	extra := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"DEFENSECLAW_FAIL_MODE":        failMode,
		// DefenseClaw currently consumes metrics + logs only. Explicitly
		// disable traces so an inherited enhanced-telemetry switch cannot
		// activate a separately configured trace exporter.
		"OTEL_METRICS_EXPORTER": "otlp",
		"OTEL_LOGS_EXPORTER":    "otlp",
		"OTEL_TRACES_EXPORTER":  "none",
	}
	// Capture schema-supported prompt facts at the source. The unified v8
	// router owns destination-specific redaction; a connector-local privacy
	// switch would irreversibly discard content before routing.
	extra["OTEL_LOG_USER_PROMPTS"] = "1"
	profile := HookProfile{
		Name:                "claudecode",
		Capabilities:        c.HookCapabilities(opts),
		SupportsTraceparent: true,
		NativeOTLP: &NativeOTLPSpec{
			Kind:               NativeOTLPEnvBlock,
			Endpoint:           "http://" + opts.APIAddr,
			Protocol:           "http/json",
			Headers:            headers,
			PerSignal:          true,
			ServiceName:        "claudecode",
			ResourceAttributes: map[string]string{"service.name": "claudecode", "defenseclaw.connector": "claudecode"},
			ExtraEnv:           extra,
			LogUserPrompts:     true,
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
	// EnvBackupCaptured distinguishes a pristine missing env block from an old
	// backup that predates env capture. Without this marker, a repeated Setup
	// could mistake DefenseClaw's already-managed env block for operator state.
	EnvBackupCaptured bool `json:"env_backup_captured,omitempty"`
	// ManagedEnv records the exact values written by the most recent Setup.
	// Teardown compares current values against this map before restoring or
	// deleting them, so operator changes made after Setup remain untouched.
	ManagedEnv map[string]string `json:"managed_env,omitempty"`
	// ManagedAbsentEnv records keys that Setup intentionally removed. Teardown
	// restores their pristine values only while they remain absent; an operator
	// value added after Setup takes ownership and is preserved.
	ManagedAbsentEnv []string `json:"managed_absent_env,omitempty"`
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
	async     bool
}

func newClaudeCodeHookGroup(eventType, matcher string) claudeCodeHookGroup {
	return claudeCodeHookGroup{
		eventType: eventType,
		matcher:   matcher,
		timeout:   hookexec.ClaudeCodeHookTimeoutSeconds(eventType),
		// MessageDisplay is observational: the server records its streamed
		// response delta but cannot return an enforcement decision for this
		// event. Running it synchronously adds interactive latency without a
		// security benefit. Every other registered surface remains synchronous
		// so tool, permission, lifecycle, and stop decisions can block.
		async: eventType == "MessageDisplay",
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
	if runtime.GOOS == "windows" && opts.ManagedEnterprise {
		hookExecutable := strings.TrimSpace(opts.HookExecutable)
		if hookExecutable == "" || !filepath.IsAbs(hookExecutable) {
			return false, fmt.Errorf("Claude Code managed hook audit requires an absolute native hook executable")
		}
	}
	return claudeCodeEffectiveHookContract(opts)
}

func claudeCodeEventHasEnforcingHook(
	entries []interface{}, eventType, requiredMatcher string, requiredAsync bool, opts SetupOpts,
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
			if !ok || !claudeCodeHandlerMatchesContract(handler, requiredAsync, opts) {
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

func claudeCodeHandlerMatchesContract(handler map[string]interface{}, requiredAsync bool, opts SetupOpts) bool {
	asynchronous, err := claudeCodeHandlerAsync(handler)
	if err != nil || asynchronous != requiredAsync {
		return false
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
		expectedCommand := strings.TrimSpace(opts.HookExecutable)
		if expectedCommand == "" {
			expectedCommand = defenseclawHookBinary()
		}
		args, ok := claudeCodeNativeExecArguments(handler)
		if !ok || !pathidentity.Same(command, expectedCommand) {
			return false
		}
		expectedArgs := []string{"hook", "--connector", "claudecode"}
		if opts.ManagedEnterprise && strings.TrimSpace(opts.HookExecutable) != "" {
			expectedArgs = append(expectedArgs, "--enterprise-managed")
		}
		return codexValueMatches(args, expectedArgs)
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
func claudeCodeHookInvocation(opts SetupOpts, hookScript string) (string, []string) {
	hookCommand := hookInvocationCommand("claudecode", filepath.ToSlash(hookScript))
	if runtime.GOOS == "windows" {
		executable := strings.TrimSpace(opts.HookExecutable)
		if executable == "" {
			executable = defenseclawHookBinary()
		}
		return executable, []string{"hook", "--connector", "claudecode"}
	}
	return hookCommand, nil
}

func claudeCodeManagedHookInvocation(opts SetupOpts, hookScript string) (string, []string) {
	command, args := claudeCodeHookInvocation(opts, hookScript)
	if runtime.GOOS == "windows" {
		args = append(args, "--enterprise-managed")
	}
	return command, args
}

// ManagedHookPolicy renders the Claude Code settings fragment installed in
// the administrator-managed policy tier. Claude treats hooks from this tier as
// trusted even when allowManagedHooksOnly=true. The fragment intentionally
// contains hooks only: per-user OTLP credentials cannot safely be placed in a
// machine-wide policy document.
func (c *ClaudeCodeConnector) ManagedHookPolicy(opts SetupOpts) ([]byte, error) {
	if !opts.ManagedEnterprise {
		return nil, fmt.Errorf("Claude Code managed hook policy requires managed enterprise setup")
	}
	if err := validateClaudeCodeManagedFileDestination(); err != nil {
		return nil, err
	}
	hookExecutable := strings.TrimSpace(opts.HookExecutable)
	if runtime.GOOS == "windows" && (hookExecutable == "" || !filepath.IsAbs(hookExecutable)) {
		return nil, fmt.Errorf("Claude Code managed hook policy requires an absolute native hook executable")
	}
	hookCommand, hookArgs := claudeCodeManagedHookInvocation(
		opts,
		filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"),
	)
	hooks := map[string]interface{}{}
	appendClaudeCodeHookMatrix(hooks, hookCommand, hookArgs)
	if err := verifyClaudeCodeHookMatrix(hooks, hookCommand, hookArgs, filepath.Join(opts.DataDir, "hooks")); err != nil {
		return nil, fmt.Errorf("verify Claude Code managed hook policy: %w", err)
	}
	policy := map[string]interface{}{"hooks": hooks}
	body, err := json.MarshalIndent(policy, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("marshal Claude Code managed hook policy: %w", err)
	}
	return append(body, '\n'), nil
}

// VerifyManagedHookPolicy verifies the exact persisted managed-policy shape.
func (c *ClaudeCodeConnector) VerifyManagedHookPolicy(data []byte, opts SetupOpts) error {
	settings := map[string]interface{}{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return fmt.Errorf("parse Claude Code managed hook policy: %w", err)
	}
	hooks, ok := settings["hooks"].(map[string]interface{})
	if !ok {
		return fmt.Errorf("Claude Code managed hook policy hooks have unsupported type %T", settings["hooks"])
	}
	hookCommand, hookArgs := claudeCodeManagedHookInvocation(
		opts,
		filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"),
	)
	if err := verifyClaudeCodeHookMatrix(hooks, hookCommand, hookArgs, filepath.Join(opts.DataDir, "hooks")); err != nil {
		return err
	}
	expected, err := c.ManagedHookPolicy(opts)
	if err != nil {
		return fmt.Errorf("render expected Claude Code managed hook policy: %w", err)
	}
	var expectedSettings map[string]interface{}
	if err := json.Unmarshal(expected, &expectedSettings); err != nil {
		return fmt.Errorf("parse expected Claude Code managed hook policy: %w", err)
	}
	actualCanonical, err := json.Marshal(settings)
	if err != nil {
		return fmt.Errorf("canonicalize Claude Code managed hook policy: %w", err)
	}
	expectedCanonical, err := json.Marshal(expectedSettings)
	if err != nil {
		return fmt.Errorf("canonicalize expected Claude Code managed hook policy: %w", err)
	}
	if !bytes.Equal(actualCanonical, expectedCanonical) {
		return fmt.Errorf("Claude Code managed hook policy differs from the canonical DefenseClaw policy")
	}
	return nil
}

func appendClaudeCodeHookMatrix(hooks map[string]interface{}, hookCommand string, hookArgs []string) {
	for _, group := range hookGroups {
		handler := map[string]interface{}{
			"type":    "command",
			"command": hookCommand,
			"timeout": group.timeout,
		}
		if group.async {
			handler["async"] = true
		}
		if hookArgs != nil {
			handler["args"] = hookArgs
		}
		entry := map[string]interface{}{"hooks": []interface{}{handler}}
		if group.matcher != "" {
			entry["matcher"] = group.matcher
		}
		existing, _ := hooks[group.eventType].([]interface{})
		hooks[group.eventType] = append(existing, entry)
	}
}

func (c *ClaudeCodeConnector) patchClaudeCodeHooks(opts SetupOpts, hookScript string) error {
	// On Unix the agent runs the bundled .sh hook (ToSlash is a no-op there).
	// On Windows Claude Code's exec form invokes the native launcher directly,
	// without Git Bash or PowerShell parsing an absolute path that may contain
	// spaces. Older shell-form commands are still recognized during migration.
	hookCommand, hookArgs := claudeCodeHookInvocation(opts, hookScript)
	settingsPath := claudeCodeSettingsPath()

	return withFileLock(settingsPath, func() error {
		if err := captureManagedFileBackup(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
			return fmt.Errorf("capture claude settings backup: %w", err)
		}
		managedBackup, err := loadManagedFileBackupForTransform(
			opts.DataDir,
			c.Name(),
			"settings.json",
			settingsPath,
		)
		if err != nil {
			return fmt.Errorf("load managed claude settings backup: %w", err)
		}
		baseBackup, backupErr := c.loadBackup(opts.DataDir)
		backupExists := backupErr == nil
		if backupErr != nil && !os.IsNotExist(backupErr) {
			return fmt.Errorf("load claudecode backup: %w", backupErr)
		}

		var backupToSave claudeCodeBackup
		var transformed []byte
		exactBackupSafe := true
		if err := atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			if !managedFileBackupMatchesSnapshot(managedBackup, data, exists) {
				exactBackupSafe = false
			}
			settings := map[string]interface{}{}
			if len(data) > 0 {
				if err := json.Unmarshal(data, &settings); err != nil {
					return atomicTransformResult{}, fmt.Errorf("parse claude settings: %w", err)
				}
			}

			backup := baseBackup
			backup.ManagedHookCommands = append([]string(nil), baseBackup.ManagedHookCommands...)
			if !backupExists {
				if hooks, ok := settings["hooks"]; ok {
					raw, _ := json.Marshal(hooks)
					backup.OriginalHooks = raw
					backup.HadHooksKey = true
				}
				// Capture the pristine env block in the hooks transaction, before
				// patchClaudeCodeOtelEnv can overwrite any operator OTel values. If
				// the process stops between the two config replacements, teardown
				// still has the durable pre-DefenseClaw env state.
				if envRaw, present := settings["env"]; present {
					envMap, ok := envRaw.(map[string]interface{})
					if !ok {
						return atomicTransformResult{}, fmt.Errorf("Claude settings env has unsupported type %T", envRaw)
					}
					raw, err := json.Marshal(envMap)
					if err != nil {
						return atomicTransformResult{}, fmt.Errorf("capture original Claude env: %w", err)
					}
					backup.OriginalEnv = raw
					backup.HadEnvKey = true
				}
				backup.EnvBackupCaptured = true
			}

			hooks := map[string]interface{}{}
			if rawHooks, present := settings["hooks"]; present {
				var ok bool
				hooks, ok = rawHooks.(map[string]interface{})
				if !ok {
					return atomicTransformResult{}, fmt.Errorf("Claude settings hooks have unsupported type %T", rawHooks)
				}
			}
			hooksDir := filepath.Join(opts.DataDir, "hooks")
			managedCommands := append([]string(nil), backup.ManagedHookCommands...)
			pristineHooks, pristineHooksTrusted := claudeCodePristineHooksForMigration(backup, backupExists)
			migrationCommands, err := inferPreTrackedClaudeCodeManagedCommands(
				hooks,
				pristineHooks,
				pristineHooksTrusted,
			)
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("inspect pre-tracking Claude hooks: %w", err)
			}
			managedCommands = append(managedCommands, migrationCommands...)
			for key, hk := range hooks {
				remaining, err := removeOwnedClaudeCodeHooks(hk, hooksDir, managedCommands)
				if err != nil {
					return atomicTransformResult{}, fmt.Errorf("inspect Claude hooks.%s: %w", key, err)
				}
				hooks[key] = remaining
			}
			appendClaudeCodeHookMatrix(hooks, hookCommand, hookArgs)
			settings["hooks"] = hooks
			if err := verifyClaudeCodeHookMatrix(hooks, hookCommand, hookArgs, hooksDir); err != nil {
				return atomicTransformResult{}, fmt.Errorf("verify DefenseClaw Claude Code hooks: %w", err)
			}

			out, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("marshal claude settings: %w", err)
			}
			// Verify the exact JSON representation Claude Code will parse. This
			// catches type/field drift (including asynchronous aliases) before the
			// settings file is replaced.
			rendered := map[string]interface{}{}
			if err := json.Unmarshal(out, &rendered); err != nil {
				return atomicTransformResult{}, fmt.Errorf("parse rendered claude settings: %w", err)
			}
			renderedHooks, ok := rendered["hooks"].(map[string]interface{})
			if !ok {
				return atomicTransformResult{}, fmt.Errorf("rendered Claude hooks have unsupported type %T", rendered["hooks"])
			}
			if err := verifyClaudeCodeHookMatrix(renderedHooks, hookCommand, hookArgs, hooksDir); err != nil {
				return atomicTransformResult{}, fmt.Errorf("verify rendered DefenseClaw Claude Code hooks: %w", err)
			}
			// Persist the exact command written by this Setup. On Windows this is
			// the absolute exec-form launcher path; ownership additionally requires
			// the exact Claude Code argv below, so another use of that executable is
			// never removed by command alone. Recording the path lets a later Setup
			// or Teardown recognize the prior launcher after an upgrade moves it.
			backup.ManagedHookCommands = []string{hookCommand}
			backupToSave = backup
			transformed = append([]byte(nil), out...)
			if exactBackupSafe {
				if err := updateManagedFileBackupPostHashValue(
					opts.DataDir,
					c.Name(),
					"settings.json",
					settingsPath,
					managedFileSnapshotHash(transformed, true),
				); err != nil {
					return atomicTransformResult{}, fmt.Errorf("publish intended Claude hooks backup hash: %w", err)
				}
			}
			return atomicTransformResult{Data: out}, nil
		}); err != nil {
			if !exactBackupSafe {
				discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
			}
			return err
		}
		if err := c.saveBackup(opts.DataDir, backupToSave); err != nil {
			return fmt.Errorf("save claudecode backup: %w", err)
		}
		persisted, err := os.ReadFile(settingsPath)
		if err != nil {
			return fmt.Errorf("read persisted Claude settings for verification: %w", err)
		}
		persistedSettings := map[string]interface{}{}
		if err := json.Unmarshal(persisted, &persistedSettings); err != nil {
			return fmt.Errorf("parse persisted Claude settings for verification: %w", err)
		}
		persistedHooks, ok := persistedSettings["hooks"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("persisted Claude hooks have unsupported type %T", persistedSettings["hooks"])
		}
		if err := verifyClaudeCodeHookMatrix(persistedHooks, hookCommand, hookArgs, filepath.Join(opts.DataDir, "hooks")); err != nil {
			return fmt.Errorf("verify persisted DefenseClaw Claude Code hooks: %w", err)
		}
		if !bytes.Equal(persisted, transformed) {
			exactBackupSafe = false
		}
		if !exactBackupSafe {
			discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
			return nil
		}
		return updateManagedFileBackupPostHashValue(
			opts.DataDir,
			c.Name(),
			"settings.json",
			settingsPath,
			managedFileSnapshotHash(transformed, true),
		)
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
	"OTEL_TRACES_EXPORTER",
	"OTEL_EXPORTER_OTLP_PROTOCOL",
	"OTEL_EXPORTER_OTLP_ENDPOINT",
	"OTEL_EXPORTER_OTLP_HEADERS",
	"OTEL_EXPORTER_OTLP_METRICS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
	"OTEL_EXPORTER_OTLP_LOGS_PROTOCOL",
	"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
	"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
	"OTEL_EXPORTER_OTLP_TRACES_PROTOCOL",
	"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT",
	"OTEL_EXPORTER_OTLP_TRACES_HEADERS",
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
	hookCommand, hookArgs := claudeCodeHookInvocation(opts, filepath.Join(opts.DataDir, "hooks", "claude-code-hook.sh"))

	return withFileLock(settingsPath, func() error {
		managedBackup, err := loadManagedFileBackupForTransform(
			opts.DataDir,
			c.Name(),
			"settings.json",
			settingsPath,
		)
		if err != nil {
			return fmt.Errorf("load managed claude settings backup: %w", err)
		}
		baseBackup, err := c.loadBackup(opts.DataDir)
		if err != nil {
			return fmt.Errorf("load claudecode backup for OTel env: %w", err)
		}

		var backupToSave claudeCodeBackup
		backupNeedsSave := false
		var transformed []byte
		exactBackupSafe := true
		if err := atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			if !managedFileBackupMatchesSnapshot(managedBackup, data, exists) {
				exactBackupSafe = false
			}
			settings := map[string]interface{}{}
			if len(data) > 0 {
				if err := json.Unmarshal(data, &settings); err != nil {
					return atomicTransformResult{}, fmt.Errorf("parse claude settings: %w", err)
				}
			}

			existing := map[string]interface{}{}
			if envRaw, present := settings["env"]; present {
				var ok bool
				existing, ok = envRaw.(map[string]interface{})
				if !ok {
					return atomicTransformResult{}, fmt.Errorf("Claude settings env has unsupported type %T", envRaw)
				}
			}

			// Backup only before the first managed env application. The explicit
			// marker is necessary because HadEnvKey=false is a valid pristine state;
			// using it as the sentinel would bless our own env on repeated Setup.
			backup := baseBackup
			backup.ManagedHookCommands = append([]string(nil), baseBackup.ManagedHookCommands...)
			if !backup.EnvBackupCaptured {
				if envRaw, present := settings["env"]; present {
					envMap, ok := envRaw.(map[string]interface{})
					if !ok {
						return atomicTransformResult{}, fmt.Errorf("Claude settings env has unsupported type %T", envRaw)
					}
					pristine := map[string]interface{}{}
					for k, v := range envMap {
						pristine[k] = v
					}
					if raw, err := json.Marshal(pristine); err == nil {
						backup.OriginalEnv = raw
					}
					backup.HadEnvKey = true
				}
				backup.EnvBackupCaptured = true
			}

			previousManaged := baseBackup.ManagedEnv
			previousAbsent := make(map[string]struct{}, len(baseBackup.ManagedAbsentEnv))
			for _, key := range baseBackup.ManagedAbsentEnv {
				previousAbsent[key] = struct{}{}
			}
			hadManagedPolicy := len(previousManaged) > 0 || len(previousAbsent) > 0
			managedEnv := buildClaudeCodeOtelEnv(opts)
			backup.ManagedEnv = make(map[string]string, len(managedEnv))
			for key, value := range managedEnv {
				backup.ManagedEnv[key] = value
			}

			// Enforce intentional absence without erasing operator drift. On the
			// first application, every policy-managed key not rendered by the
			// current profile is removed and recorded. On later applications we
			// remove only our own unchanged prior value, or preserve an absence we
			// already owned. A newly-added operator value transfers ownership.
			backup.ManagedAbsentEnv = nil
			for _, key := range claudeCodeOtelEnvKeys {
				if _, rendered := managedEnv[key]; rendered {
					continue
				}
				current, present := existing[key]
				_, wasAbsent := previousAbsent[key]
				previousValue, wasManaged := previousManaged[key]
				remove := !hadManagedPolicy
				if wasAbsent && !present {
					remove = true
				}
				if wasManaged {
					currentString, isString := current.(string)
					remove = present && isString && currentString == previousValue
				}
				if !remove {
					continue
				}
				delete(existing, key)
				backup.ManagedAbsentEnv = append(backup.ManagedAbsentEnv, key)
			}
			for k, v := range managedEnv {
				existing[k] = v
			}
			backupNeedsSave = true
			backupToSave = backup
			settings["env"] = existing

			out, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("marshal claude settings (otel env): %w", err)
			}
			transformed = append([]byte(nil), out...)
			if exactBackupSafe {
				if err := updateManagedFileBackupPostHashValue(
					opts.DataDir,
					c.Name(),
					"settings.json",
					settingsPath,
					managedFileSnapshotHash(transformed, true),
				); err != nil {
					return atomicTransformResult{}, fmt.Errorf("publish intended Claude OTel backup hash: %w", err)
				}
			}
			return atomicTransformResult{Data: out}, nil
		}); err != nil {
			if !exactBackupSafe {
				discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
			}
			return err
		}
		if backupNeedsSave {
			if err := c.saveBackup(opts.DataDir, backupToSave); err != nil {
				return fmt.Errorf("save claudecode backup (otel env): %w", err)
			}
		}
		persisted, err := os.ReadFile(settingsPath)
		if err != nil {
			return fmt.Errorf("read persisted Claude settings after OTel patch: %w", err)
		}
		persistedSettings := map[string]interface{}{}
		if err := json.Unmarshal(persisted, &persistedSettings); err != nil {
			return fmt.Errorf("parse persisted Claude settings after OTel patch: %w", err)
		}
		persistedHooks, ok := persistedSettings["hooks"].(map[string]interface{})
		if !ok {
			return fmt.Errorf("persisted Claude hooks after OTel patch have unsupported type %T", persistedSettings["hooks"])
		}
		if err := verifyClaudeCodeHookMatrix(persistedHooks, hookCommand, hookArgs, filepath.Join(opts.DataDir, "hooks")); err != nil {
			return fmt.Errorf("verify persisted DefenseClaw Claude Code hooks after OTel patch: %w", err)
		}
		if !bytes.Equal(persisted, transformed) {
			exactBackupSafe = false
		}
		if !exactBackupSafe {
			discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
			return nil
		}
		return updateManagedFileBackupPostHashValue(
			opts.DataDir,
			c.Name(),
			"settings.json",
			settingsPath,
			managedFileSnapshotHash(transformed, true),
		)
	})
}

func claudeCodeOtelValueIsManaged(value interface{}, managed string) bool {
	got, _ := value.(string)
	// Ownership is exact-value based. Marker/prefix heuristics would report
	// operator-edited values as uninstall residue even though teardown correctly
	// preserved them.
	return managed != "" && got == managed
}

// claudeCodeOtelValueLooksManaged is the conservative fallback used when the
// exact backup is unavailable. Generic OpenTelemetry values such as "otlp" or
// "http/json" are not ownership proof; only DefenseClaw-scoped endpoints and
// explicit DefenseClaw markers can be classified without restore metadata.
func claudeCodeOtelValueLooksManaged(key string, value interface{}, managed string) bool {
	got, _ := value.(string)
	if got == "" {
		return false
	}
	switch key {
	case "OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_LOGS_ENDPOINT",
		"OTEL_EXPORTER_OTLP_TRACES_ENDPOINT":
		if managed != "" && got == managed {
			return true
		}
		base := strings.TrimRight(managed, "/")
		if index := strings.Index(base, "/otlp/"); index >= 0 {
			base = base[:index]
		}
		if !strings.HasPrefix(base, "http://") {
			return false
		}
		apiAddr := strings.TrimPrefix(base, "http://")
		parsed, err := url.Parse(got)
		if err != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.User != nil {
			return false
		}
		parts := strings.Split(strings.Trim(parsed.Path, "/"), "/")
		if len(parts) != 3 && len(parts) != 5 {
			return false
		}
		if !otlpTokenHexRE.MatchString(parts[2]) {
			return false
		}
		if len(parts) == 3 {
			return isScopedOTLPBaseEndpoint(got, apiAddr, OTLPScopeClaude)
		}
		for _, signal := range AllNativeOTLPSignals() {
			if isScopedOTLPEndpoint(got, apiAddr, OTLPScopeClaude, signal) {
				return true
			}
		}
		return false
	case "OTEL_EXPORTER_OTLP_HEADERS",
		"OTEL_EXPORTER_OTLP_METRICS_HEADERS",
		"OTEL_EXPORTER_OTLP_LOGS_HEADERS",
		"OTEL_EXPORTER_OTLP_TRACES_HEADERS":
		return (managed != "" && got == managed) ||
			claudeCodeOtelHeadersAreDefenseClawOnly(got)
	case "OTEL_RESOURCE_ATTRIBUTES":
		return (managed != "" && got == managed) ||
			got == "defenseclaw.connector=claudecode,service.name=claudecode"
	default:
		return false
	}
}

func claudeCodeOtelHeadersAreDefenseClawOnly(value string) bool {
	parts := strings.Split(value, ",")
	if len(parts) == 0 {
		return false
	}
	for _, part := range parts {
		name, headerValue, ok := strings.Cut(strings.TrimSpace(part), "=")
		if !ok || strings.TrimSpace(headerValue) == "" {
			return false
		}
		switch strings.ToLower(strings.TrimSpace(name)) {
		case "x-defenseclaw-client", "x-defenseclaw-source", "x-defenseclaw-token":
		default:
			// A mixed block belongs to the operator even when it also contains
			// DefenseClaw headers; teardown must not discard the other headers.
			return false
		}
	}
	return true
}

// restoreClaudeCodeHooks restores the original hooks from the backup file.
// Uses file locking to match patchClaudeCodeHooks and prevent corruption.
func (c *ClaudeCodeConnector) restoreClaudeCodeHooks(opts SetupOpts) error {
	settingsPath := claudeCodeSettingsPath()
	backup, err := c.loadBackup(opts.DataDir)
	backupAvailable := err == nil
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[claudecode] backup unavailable; falling back to surgical cleanup: %v\n", err)
		}
		backup = claudeCodeBackup{}
	}
	managedBackup, err := loadManagedFileBackupForTransform(
		opts.DataDir,
		c.Name(),
		"settings.json",
		settingsPath,
	)
	if err != nil {
		return fmt.Errorf("load managed settings backup: %w", err)
	}

	err = withFileLock(settingsPath, func() error {
		if err := atomicTransformFileWithStateDir(settingsPath, opts.DataDir, 0o600, func(data []byte, exists bool) (atomicTransformResult, error) {
			var restorePerm os.FileMode
			var exactData []byte
			if exact, ok := managedFileBackupTransform(managedBackup, data, exists); ok {
				if exact.Remove {
					return exact, nil
				}
				// A predecessor can capture an already-managed settings file as
				// its "pristine" snapshot during an upgrade. Passing restored
				// bytes through the same ownership-aware cleanup keeps that stale
				// snapshot from resurrecting every DefenseClaw hook and OTel key.
				data = exact.Data
				exists = true
				restorePerm = exact.Perm
				exactData = exact.Data
			}
			if !exists {
				return atomicTransformResult{Remove: true}, nil
			}
			settings := map[string]interface{}{}
			if err := json.Unmarshal(data, &settings); err != nil {
				return atomicTransformResult{}, fmt.Errorf("parse claude settings for restore: %w", err)
			}
			var exactCanonical []byte
			if exactData != nil {
				exactCanonical, err = json.Marshal(settings)
				if err != nil {
					return atomicTransformResult{}, fmt.Errorf("canonicalize exact Claude settings snapshot: %w", err)
				}
			}

			if rawHooks, present := settings["hooks"]; present {
				hooks, ok := rawHooks.(map[string]interface{})
				if !ok {
					return atomicTransformResult{}, fmt.Errorf("Claude settings hooks have unsupported type %T", rawHooks)
				}
				hooksDir := filepath.Join(opts.DataDir, "hooks")
				managedCommands := append([]string(nil), backup.ManagedHookCommands...)
				pristineHooks, pristineHooksTrusted := claudeCodePristineHooksForMigration(backup, backupAvailable)
				migrationCommands, err := inferPreTrackedClaudeCodeManagedCommands(
					hooks,
					pristineHooks,
					pristineHooksTrusted,
				)
				if err != nil {
					return atomicTransformResult{}, fmt.Errorf("inspect pre-tracking Claude hooks for restore: %w", err)
				}
				managedCommands = append(managedCommands, migrationCommands...)
				for eventType, val := range hooks {
					remaining, err := removeOwnedClaudeCodeHooks(val, hooksDir, managedCommands)
					if err != nil {
						return atomicTransformResult{}, fmt.Errorf("inspect Claude hooks.%s for restore: %w", eventType, err)
					}
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
			}

			// Exact managed metadata makes generic ownership literal, so an
			// operator edit after Setup survives teardown. Conservative strong
			// markers also recognize stale DefenseClaw values from older installs.
			if envMap, ok := settings["env"].(map[string]interface{}); ok {
				originalEnv := map[string]interface{}{}
				if backup.HadEnvKey && len(backup.OriginalEnv) > 0 {
					if err := json.Unmarshal(backup.OriginalEnv, &originalEnv); err != nil {
						return atomicTransformResult{}, fmt.Errorf("parse original Claude env backup: %w", err)
					}
				}
				managedEnv := backup.ManagedEnv
				exactManagedEnv := len(managedEnv) > 0
				if !exactManagedEnv {
					// Compatibility for backups created before exact managed values
					// were recorded, and for best-effort backupless cleanup.
					managedEnv = buildClaudeCodeOtelEnv(opts)
				}
				for _, key := range claudeCodeOtelEnvKeys {
					written, managed := managedEnv[key]
					current, present := envMap[key]
					if !managed || !present {
						continue
					}
					owned := claudeCodeOtelValueIsManaged(current, written) ||
						claudeCodeOtelValueLooksManaged(key, current, written)
					if !owned {
						continue
					}
					if original, existed := originalEnv[key]; existed &&
						!claudeCodeOtelValueLooksManaged(key, original, written) {
						envMap[key] = original
					} else {
						// A predecessor can lose its ownership metadata and later
						// capture DefenseClaw's own env as pristine. Strong ownership
						// markers must be removed instead of resurrected; conservative
						// classification preserves generic/user-defined OTel values.
						delete(envMap, key)
					}
				}
				for _, key := range backup.ManagedAbsentEnv {
					if _, operatorSupplied := envMap[key]; operatorSupplied {
						continue
					}
					if original, existed := originalEnv[key]; existed {
						envMap[key] = original
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

			canonical, err := json.Marshal(settings)
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("canonicalize restored settings: %w", err)
			}
			if exactData != nil && bytes.Equal(canonical, exactCanonical) {
				return atomicTransformResult{Data: exactData, Perm: restorePerm}, nil
			}
			out, err := json.MarshalIndent(settings, "", "  ")
			if err != nil {
				return atomicTransformResult{}, fmt.Errorf("marshal restored settings: %w", err)
			}
			return atomicTransformResult{Data: out, Perm: restorePerm}, nil
		}); err != nil {
			return fmt.Errorf("write restored settings: %w", err)
		}
		return nil
	})
	// The settings parent can disappear before the lock file is opened (for
	// example, when Claude is uninstalled concurrently). Treat that the same
	// as a missing settings file and discard only DefenseClaw restore metadata.
	if err == nil {
		return nil
	}
	if os.IsNotExist(err) {
		return nil
	}
	// On Windows, opening a child of a missing directory can report
	// ERROR_PATH_NOT_FOUND, which os.IsNotExist does not classify.
	if _, statErr := os.Stat(filepath.Dir(settingsPath)); os.IsNotExist(statErr) {
		return nil
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

// isClaudeCodeNativeExecHook recognizes the shell-free Windows hook shape only
// when its executable is the active DefenseClaw launcher or a narrowly scoped
// legacy install path. A matching basename is not ownership: another product
// may ship a different C:\OtherProduct\defenseclaw-hook.exe.
func isClaudeCodeNativeExecHook(hook map[string]interface{}) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	command, _ := hook["command"].(string)
	if !isDefenseClawHookExecutable(command) {
		return false
	}
	return hasClaudeCodeNativeExecArgs(hook)
}

// hasClaudeCodeNativeExecArgs validates the complete argv that Setup writes.
// Callers that already established an exact backup-recorded executable path may
// use this independently of the active install path.
func hasClaudeCodeNativeExecArgs(hook map[string]interface{}) bool {
	args, ok := claudeCodeNativeExecArguments(hook)
	if !ok {
		return false
	}
	if len(args) != 3 && len(args) != 4 {
		return false
	}
	want := []string{"hook", "--connector", "claudecode"}
	for i, arg := range want {
		if args[i] != arg {
			return false
		}
	}
	if len(args) == 4 && args[3] != "--enterprise-managed" {
		return false
	}
	return true
}

func claudeCodeNativeExecArguments(hook map[string]interface{}) ([]string, bool) {
	var args []string
	switch rawArgs := hook["args"].(type) {
	case []interface{}:
		args = make([]string, len(rawArgs))
		for i, raw := range rawArgs {
			arg, ok := raw.(string)
			if !ok {
				return nil, false
			}
			args[i] = arg
		}
	case []string:
		args = append([]string(nil), rawArgs...)
	default:
		return nil, false
	}
	return args, true
}

type claudeCodeOwnedHookLocation struct {
	groupIndex   int
	handlerIndex int
	matcher      interface{}
	handler      map[string]interface{}
}

func ownedClaudeCodeHookLocations(
	rawGroups interface{}, hooksDir, expectedCommand string, expectedArgs []string,
) ([]claudeCodeOwnedHookLocation, error) {
	groups, ok := rawGroups.([]interface{})
	if !ok {
		return nil, fmt.Errorf("event groups have unsupported type %T", rawGroups)
	}
	locations := make([]claudeCodeOwnedHookLocation, 0, 1)
	for groupIndex, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			return nil, fmt.Errorf("event group %d has unsupported type %T", groupIndex, rawGroup)
		}
		handlers, ok := group["hooks"].([]interface{})
		if !ok {
			return nil, fmt.Errorf("event group %d hooks have unsupported type %T", groupIndex, group["hooks"])
		}
		for handlerIndex, rawHandler := range handlers {
			handler, ok := rawHandler.(map[string]interface{})
			if !ok {
				return nil, fmt.Errorf("event group %d handler %d has unsupported type %T", groupIndex, handlerIndex, rawHandler)
			}
			owned := isOwnedHookHandler(rawHandler, hooksDir)
			if !owned && expectedCommand != "" {
				command, _ := handler["command"].(string)
				owned = command == expectedCommand && codexValueMatches(handler["args"], expectedArgs)
			}
			if !owned {
				continue
			}
			locations = append(locations, claudeCodeOwnedHookLocation{
				groupIndex:   groupIndex,
				handlerIndex: handlerIndex,
				matcher:      group["matcher"],
				handler:      handler,
			})
		}
	}
	return locations, nil
}

// claudeCodeHandlerAsync treats every spelling accepted by current and older
// Claude Code settings decoders as asynchronous. In particular,
// asyncRewake/async_rewake must not slip through a verifier that only checks
// async: an asynchronous PreToolUse or PermissionRequest hook cannot block.
func claudeCodeHandlerAsync(handler map[string]interface{}) (bool, error) {
	active := false
	for _, key := range []string{"async", "asyncRewake", "async_rewake"} {
		raw, exists := handler[key]
		if !exists {
			continue
		}
		value, ok := raw.(bool)
		if !ok {
			return false, fmt.Errorf("%s has unsupported type %T", key, raw)
		}
		active = active || value
	}
	return active, nil
}

func claudeCodeHookInteger(value interface{}) (int, bool) {
	switch typed := value.(type) {
	case int:
		return typed, true
	case int64:
		return int(typed), int64(int(typed)) == typed
	case float64:
		converted := int(typed)
		return converted, float64(converted) == typed
	default:
		return 0, false
	}
}

// verifyClaudeCodeHookMatrix validates the exact DefenseClaw-owned effective
// user registration. Unrelated operator hooks may coexist, but every required
// event must have exactly one owned command with its expected matcher, timeout,
// argv, and blocking behavior. MessageDisplay is the sole asynchronous surface:
// it is observational and has no enforcement verdict.
func verifyClaudeCodeHookMatrix(
	hooks map[string]interface{},
	expectedCommand string,
	expectedArgs []string,
	hooksDir string,
) error {
	expectedEvents := make(map[string]struct{}, len(hookGroups))
	for _, expected := range hookGroups {
		expectedEvents[expected.eventType] = struct{}{}
		locations, err := ownedClaudeCodeHookLocations(
			hooks[expected.eventType], hooksDir, expectedCommand, expectedArgs,
		)
		if err != nil {
			return fmt.Errorf("%s: %w", expected.eventType, err)
		}
		if len(locations) != 1 {
			return fmt.Errorf("%s has %d DefenseClaw handlers, want 1", expected.eventType, len(locations))
		}
		location := locations[0]
		var expectedMatcher interface{}
		if expected.matcher != "" {
			expectedMatcher = expected.matcher
		}
		if !codexValueMatches(location.matcher, expectedMatcher) {
			return fmt.Errorf("%s matcher = %#v, want %#v", expected.eventType, location.matcher, expectedMatcher)
		}
		if kind, _ := location.handler["type"].(string); kind != "command" {
			return fmt.Errorf("%s handler type = %#v, want command", expected.eventType, location.handler["type"])
		}
		if command, _ := location.handler["command"].(string); command != expectedCommand {
			return fmt.Errorf("%s command = %q, want %q", expected.eventType, command, expectedCommand)
		}
		if expectedArgs == nil {
			if _, exists := location.handler["args"]; exists {
				return fmt.Errorf("%s has unexpected args %#v", expected.eventType, location.handler["args"])
			}
		} else if !codexValueMatches(location.handler["args"], expectedArgs) {
			return fmt.Errorf("%s args = %#v, want %#v", expected.eventType, location.handler["args"], expectedArgs)
		}
		timeout, ok := claudeCodeHookInteger(location.handler["timeout"])
		if !ok || timeout != expected.timeout {
			return fmt.Errorf("%s timeout = %#v, want %d", expected.eventType, location.handler["timeout"], expected.timeout)
		}
		asynchronous, err := claudeCodeHandlerAsync(location.handler)
		if err != nil {
			return fmt.Errorf("%s handler: %w", expected.eventType, err)
		}
		if asynchronous != expected.async {
			if asynchronous {
				return fmt.Errorf("%s DefenseClaw handler is asynchronous and cannot enforce policy", expected.eventType)
			}
			return fmt.Errorf("%s observational handler must be asynchronous", expected.eventType)
		}
	}
	for eventType, rawGroups := range hooks {
		if _, expected := expectedEvents[eventType]; expected {
			continue
		}
		locations, err := ownedClaudeCodeHookLocations(rawGroups, hooksDir, expectedCommand, expectedArgs)
		if err != nil {
			return fmt.Errorf("%s: %w", eventType, err)
		}
		if len(locations) > 0 {
			return fmt.Errorf("unexpected event %s has %d DefenseClaw handlers", eventType, len(locations))
		}
	}
	return nil
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
) ([]interface{}, error) {
	if err := validateClaudeCodeHookEventShape(hookEventValue); err != nil {
		return nil, err
	}
	return removeMatchingHookHandlers(hookEventValue, func(rawHook interface{}) bool {
		return isOwnedHookHandler(rawHook, hooksDir) ||
			hookUsesTrackedClaudeCodeCommand(rawHook, managedCommands) ||
			hookUsesLegacyClaudeCodeNativeCommand(rawHook)
	}), nil
}

func validateClaudeCodeHookEventShape(hookEventValue interface{}) error {
	groups, ok := hookEventValue.([]interface{})
	if !ok {
		return fmt.Errorf("event groups have unsupported type %T", hookEventValue)
	}
	for groupIndex, rawGroup := range groups {
		group, ok := rawGroup.(map[string]interface{})
		if !ok {
			return fmt.Errorf("event group %d has unsupported type %T", groupIndex, rawGroup)
		}
		handlers, ok := group["hooks"].([]interface{})
		if !ok {
			return fmt.Errorf("event group %d hooks have unsupported type %T", groupIndex, group["hooks"])
		}
		for handlerIndex, rawHandler := range handlers {
			if _, ok := rawHandler.(map[string]interface{}); !ok {
				return fmt.Errorf("event group %d handler %d has unsupported type %T", groupIndex, handlerIndex, rawHandler)
			}
		}
	}
	return nil
}

// claudeCodePristineHooksForMigration returns the protected pre-Setup hook
// snapshot recorded by predecessor releases. A missing hooks key is a trusted
// empty snapshot only when the backup itself exists; a missing/corrupt backup
// must never authorize broad legacy ownership.
func claudeCodePristineHooksForMigration(
	backup claudeCodeBackup,
	backupAvailable bool,
) (map[string]interface{}, bool) {
	if !backupAvailable {
		return nil, false
	}
	if !backup.HadHooksKey {
		return map[string]interface{}{}, true
	}
	if len(bytes.TrimSpace(backup.OriginalHooks)) == 0 {
		return nil, false
	}
	var hooks map[string]interface{}
	if err := json.Unmarshal(backup.OriginalHooks, &hooks); err != nil || hooks == nil {
		return nil, false
	}
	return hooks, true
}

type claudeCodePreTrackedInvocation struct {
	executable string
	execForm   bool
}

// inferPreTrackedClaudeCodeManagedCommands handles the one-time upgrade from
// Windows releases that deliberately left ManagedHookCommands empty. It never
// falls back to basename ownership for an isolated hook. Instead, a candidate
// must form the complete DefenseClaw event matrix and must be absent from the
// protected pristine snapshot for every required event. This distinguishes the
// old generated registration from a third-party binary with the same basename.
func inferPreTrackedClaudeCodeManagedCommands(
	hooks map[string]interface{},
	pristineHooks map[string]interface{},
	pristineHooksTrusted bool,
) ([]string, error) {
	if runtime.GOOS != "windows" || !pristineHooksTrusted {
		return nil, nil
	}

	type candidate struct {
		commands map[string]struct{}
	}
	candidates := map[claudeCodePreTrackedInvocation]*candidate{}
	for eventIndex, group := range hookGroups {
		rawCurrent, present := hooks[group.eventType]
		if !present {
			return nil, nil
		}
		current, err := claudeCodePreTrackedInvocations(rawCurrent, group)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", group.eventType, err)
		}

		pristine := map[claudeCodePreTrackedInvocation]map[string]struct{}{}
		if rawPristine, present := pristineHooks[group.eventType]; present {
			// Any matching native invocation in the protected pre-Setup
			// snapshot makes the candidate ambiguous, even when that original
			// user hook did not have DefenseClaw's generated matcher/timeout
			// shape. This keeps migration inference conservative while requiring
			// the current candidate itself to match the predecessor exactly.
			pristine, err = claudeCodePreTrackedPristineInvocations(rawPristine)
			if err != nil {
				// An unfamiliar pristine shape cannot safely prove ownership. Keep
				// every candidate foreign and let ordinary exact ownership apply.
				return nil, nil
			}
		}

		if eventIndex == 0 {
			for identity, commands := range current {
				if _, existedBeforeSetup := pristine[identity]; existedBeforeSetup {
					continue
				}
				copied := make(map[string]struct{}, len(commands))
				for command := range commands {
					copied[command] = struct{}{}
				}
				candidates[identity] = &candidate{commands: copied}
			}
			continue
		}

		for identity, candidate := range candidates {
			commands, present := current[identity]
			_, existedBeforeSetup := pristine[identity]
			if !present || existedBeforeSetup {
				delete(candidates, identity)
				continue
			}
			for command := range commands {
				candidate.commands[command] = struct{}{}
			}
		}
		if len(candidates) == 0 {
			return nil, nil
		}
	}

	commands := make([]string, 0, len(candidates))
	for _, candidate := range candidates {
		for command := range candidate.commands {
			commands = append(commands, command)
		}
	}
	return commands, nil
}

func claudeCodePreTrackedInvocations(
	rawGroups interface{},
	expected claudeCodeHookGroup,
) (map[claudeCodePreTrackedInvocation]map[string]struct{}, error) {
	if err := validateClaudeCodeHookEventShape(rawGroups); err != nil {
		return nil, err
	}
	result := map[claudeCodePreTrackedInvocation]map[string]struct{}{}
	for _, rawGroup := range rawGroups.([]interface{}) {
		group := rawGroup.(map[string]interface{})
		if !claudeCodePreTrackedGroupMatches(group, expected) {
			continue
		}
		for _, rawHandler := range group["hooks"].([]interface{}) {
			handler := rawHandler.(map[string]interface{})
			if !claudeCodePreTrackedHandlerMatches(handler, expected) {
				continue
			}
			identity, command, ok := claudeCodePreTrackedInvocationIdentity(handler)
			if !ok {
				continue
			}
			commands := result[identity]
			if commands == nil {
				commands = map[string]struct{}{}
				result[identity] = commands
			}
			commands[command] = struct{}{}
		}
	}
	return result, nil
}

// claudeCodePreTrackedPristineInvocations deliberately ignores generated
// matcher/timeout metadata. A protected pristine hook with the same native
// invocation is enough to make automatic ownership inference unsafe.
func claudeCodePreTrackedPristineInvocations(
	rawGroups interface{},
) (map[claudeCodePreTrackedInvocation]map[string]struct{}, error) {
	if err := validateClaudeCodeHookEventShape(rawGroups); err != nil {
		return nil, err
	}
	result := map[claudeCodePreTrackedInvocation]map[string]struct{}{}
	for _, rawGroup := range rawGroups.([]interface{}) {
		group := rawGroup.(map[string]interface{})
		for _, rawHandler := range group["hooks"].([]interface{}) {
			handler := rawHandler.(map[string]interface{})
			identity, command, ok := claudeCodePreTrackedInvocationIdentity(handler)
			if !ok {
				continue
			}
			commands := result[identity]
			if commands == nil {
				commands = map[string]struct{}{}
				result[identity] = commands
			}
			commands[command] = struct{}{}
		}
	}
	return result, nil
}

// claudeCodePreTrackedGroupMatches requires the exact group metadata emitted
// by the predecessor Windows release. In particular, an empty matcher was
// omitted rather than serialized as an empty string.
func claudeCodePreTrackedGroupMatches(
	group map[string]interface{},
	expected claudeCodeHookGroup,
) bool {
	matcher, present := group["matcher"]
	if expected.matcher == "" {
		return !present
	}
	value, ok := matcher.(string)
	return present && ok && value == expected.matcher
}

// claudeCodePreTrackedHandlerMatches recognizes only the exact command,
// timeout, and async shape DefenseClaw generated before command tracking was
// introduced. Equivalent-but-user-authored variants remain foreign.
func claudeCodePreTrackedHandlerMatches(
	handler map[string]interface{},
	expected claudeCodeHookGroup,
) bool {
	kind, ok := handler["type"].(string)
	if !ok || kind != "command" {
		return false
	}
	timeout, ok := claudeCodeHookInteger(handler["timeout"])
	if !ok || timeout != expected.timeout {
		return false
	}
	for _, alias := range []string{"asyncRewake", "async_rewake"} {
		if _, present := handler[alias]; present {
			return false
		}
	}
	async, present := handler["async"]
	if expected.async {
		value, ok := async.(bool)
		return present && ok && value
	}
	return !present
}

func claudeCodePreTrackedInvocationIdentity(
	hook map[string]interface{},
) (claudeCodePreTrackedInvocation, string, bool) {
	if kind, _ := hook["type"].(string); kind != "command" {
		return claudeCodePreTrackedInvocation{}, "", false
	}
	command, _ := hook["command"].(string)
	if command == "" {
		return claudeCodePreTrackedInvocation{}, "", false
	}

	executable := ""
	execForm := false
	if _, hasArgs := hook["args"]; hasArgs {
		if !hasClaudeCodeNativeExecArgs(hook) {
			return claudeCodePreTrackedInvocation{}, "", false
		}
		executable = strings.TrimSpace(command)
		execForm = true
	} else {
		var ok bool
		executable, ok = parseLegacyClaudeCodeNativeHookCommand(command)
		if !ok {
			return claudeCodePreTrackedInvocation{}, "", false
		}
	}
	if !hasDefenseClawHookExecutableBasename(executable) {
		return claudeCodePreTrackedInvocation{}, "", false
	}
	return claudeCodePreTrackedInvocation{
		executable: normalizeWindowsHookExecutable(executable),
		execForm:   execForm,
	}, command, true
}

func hasDefenseClawHookExecutableBasename(executable string) bool {
	normalized := strings.ReplaceAll(strings.TrimSpace(executable), `\`, "/")
	if slash := strings.LastIndex(normalized, "/"); slash >= 0 {
		normalized = normalized[slash+1:]
	}
	switch strings.ToLower(normalized) {
	case windowsHookBinaryName, "defenseclaw-hook", windowsGatewayBinaryName, "defenseclaw-gateway":
		return true
	default:
		return false
	}
}

func normalizeWindowsHookExecutable(executable string) string {
	cleaned := filepath.Clean(strings.TrimSpace(executable))
	cleaned = strings.ReplaceAll(cleaned, "/", `\`)
	return strings.ToLower(cleaned)
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
// signature written by pre-command-tracking Windows releases, but only at the
// active launcher or a known legacy user install path. Arbitrary absolute paths
// are owned only when the protected backup recorded that exact command.
func isLegacyClaudeCodeNativeHookCommand(command string) bool {
	if runtime.GOOS != "windows" {
		return false
	}
	executable, ok := parseLegacyClaudeCodeNativeHookCommand(command)
	return ok && isDefenseClawHookExecutable(executable)
}

func parseLegacyClaudeCodeNativeHookCommand(command string) (string, bool) {
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
		return "", false
	}

	executable := strings.TrimSpace(command[:idx])
	if strings.ContainsAny(executable, "&|<>;\r\n") {
		return "", false
	}
	quoted := byte(0)
	if strings.HasPrefix(executable, `"`) || strings.HasSuffix(executable, `"`) {
		if len(executable) < 2 || !strings.HasPrefix(executable, `"`) || !strings.HasSuffix(executable, `"`) {
			return "", false
		}
		quoted = '"'
		executable = executable[1 : len(executable)-1]
	} else if strings.HasPrefix(executable, `'`) || strings.HasSuffix(executable, `'`) {
		if len(executable) < 2 || !strings.HasPrefix(executable, `'`) || !strings.HasSuffix(executable, `'`) {
			return "", false
		}
		quoted = '\''
		executable = strings.ReplaceAll(executable[1:len(executable)-1], `''`, `'`)
	}
	if executable == "" || strings.Contains(executable, `"`) {
		return "", false
	}
	if quoted == 0 && strings.ContainsAny(executable, " \t") {
		return "", false
	}
	return executable, true
}

func hookUsesTrackedClaudeCodeCommand(rawHook interface{}, commands []string) bool {
	hook, ok := rawHook.(map[string]interface{})
	if !ok || len(commands) == 0 {
		return false
	}
	command, _ := hook["command"].(string)
	if command == "" {
		return false
	}
	for _, managed := range commands {
		if managed == "" {
			continue
		}
		if runtime.GOOS != "windows" {
			if command == managed {
				return true
			}
			continue
		}
		if _, hasArgs := hook["args"]; hasArgs {
			if command == managed && hasClaudeCodeNativeExecArgs(hook) {
				return true
			}
			continue
		}
		currentExecutable, currentLegacyShape := parseLegacyClaudeCodeNativeHookCommand(command)
		if !currentLegacyShape {
			continue
		}
		if command == managed {
			return true
		}
		managedExecutable, managedLegacyShape := parseLegacyClaudeCodeNativeHookCommand(managed)
		if managedLegacyShape && sameWindowsHookExecutable(currentExecutable, managedExecutable) {
			return true
		}
	}
	return false
}

func sameWindowsHookExecutable(left, right string) bool {
	return normalizeWindowsHookExecutable(left) == normalizeWindowsHookExecutable(right)
}
