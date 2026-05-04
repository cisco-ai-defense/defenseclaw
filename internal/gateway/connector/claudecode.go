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
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// ClaudeCodeConnector handles all security surfaces for Claude Code.
// LLM traffic: sets ANTHROPIC_BASE_URL to route through proxy.
// Tool inspection: registers hooks in ~/.claude/settings.json pointing to
// claude-code-hook.sh which calls /api/v1/claude-code/hook.
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

// AllowedHosts returns the Anthropic CDN hostnames Claude Code
// touches outside the LLM endpoint itself — skill manifests,
// plugin registry, telemetry. api.anthropic.com is already in the
// firewall's static defaults; this list adds the auxiliary hosts.
// See S3.3 / F26.
func (c *ClaudeCodeConnector) AllowedHosts() []string {
	return []string{
		// Skill/plugin registry CDN.
		"claude.ai",
		// Marketplace + docs CDN.
		"docs.anthropic.com",
		"console.anthropic.com",
		// Project CodeGuard native plugin installation.
		"github.com",
		"api.github.com",
		"objects.githubusercontent.com",
	}
}

func (c *ClaudeCodeConnector) Setup(ctx context.Context, opts SetupOpts) error {
	// writeEnvOverride installs the ANTHROPIC_BASE_URL redirect that
	// puts the DefenseClaw proxy in Claude Code's data path. Gated
	// on opts.ClaudeCodeEnforcement so the default install runs in
	// observability-only mode: claude code talks DIRECTLY to
	// api.anthropic.com, no env-override file is written, and no
	// proxy interception happens. Hooks (next block) and OTel env
	// (the new patchClaudeCodeOtelEnv block — added in a follow-up
	// commit) still run, giving complete telemetry without traffic
	// interception. Operator can flip enforcement back on with
	// guardrail.claudecode_enforcement_enabled: true in config.yaml.
	if opts.ClaudeCodeEnforcement {
		if err := c.writeEnvOverride(opts); err != nil {
			return fmt.Errorf("claudecode env override: %w", err)
		}
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	// Plan C2: hand the connector itself so HookScriptOwner is the
	// single source of truth for which vendor templates land here.
	if err := WriteHookScriptsForConnectorObjectWithOpts(hookDir, opts, c); err != nil {
		return fmt.Errorf("claudecode hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "claude-code-hook.sh")
	// Hooks register unconditionally — they post to
	// /api/v1/claudecode/hook (or the equivalent route) and are the
	// entry point for tool-call telemetry on every install. In
	// observability mode the hook returns "allow" because the
	// subprocess sandbox JSON is absent; in enforcement mode the
	// sandbox decision can also block.
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
	// Runs unconditionally — telemetry is on by default in both
	// observability and enforcement modes.
	if err := c.patchClaudeCodeOtelEnv(opts); err != nil {
		return fmt.Errorf("claudecode otel env: %w", err)
	}

	if opts.InstallCodeGuard {
		if err := ensureClaudeCodeCodeGuardPlugin(ctx); err != nil {
			return fmt.Errorf("claude CodeGuard plugin install: %w", err)
		}
	}

	// Subprocess sandbox is part of enforcement: it's consulted by
	// claude-code-hook.sh's PreToolUse handler to decide whether to
	// BLOCK a tool call. Skipped in observability mode — the hook
	// still runs but always allows.
	if opts.ClaudeCodeEnforcement {
		policy := ResolveSubprocessPolicy(SubprocessSandbox)
		if err := SetupSubprocessEnforcement(policy, opts); err != nil {
			return fmt.Errorf("claudecode subprocess enforcement: %w", err)
		}
	}

	return nil
}

func (c *ClaudeCodeConnector) Teardown(ctx context.Context, opts SetupOpts) error {
	var errs []string

	if err := c.restoreClaudeCodeHooks(opts); err != nil {
		errs = append(errs, fmt.Sprintf("restore hooks: %v", err))
	}

	c.removeEnvOverride(opts)

	if err := TeardownSubprocessEnforcement(opts); err != nil {
		errs = append(errs, fmt.Sprintf("subprocess enforcement: %v", err))
	}

	if len(errs) > 0 {
		return fmt.Errorf("claudecode teardown errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

func (c *ClaudeCodeConnector) VerifyClean(opts SetupOpts) error {
	var residual []string

	// Check env override files
	for _, name := range []string{claudeCodeEnvFileName, "claudecode.env"} {
		if _, err := os.Stat(filepath.Join(opts.DataDir, name)); err == nil {
			residual = append(residual, name)
		}
	}

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
				if envMap, ok := settings["env"].(map[string]interface{}); ok {
					managedEnv := buildClaudeCodeOtelEnv(opts)
					for _, key := range claudeCodeOtelEnvKeys {
						if value, present := envMap[key]; present && claudeCodeOtelValueLooksManaged(key, value, managedEnv[key]) {
							residual = append(residual, fmt.Sprintf("settings.json env[%s] still contains defenseclaw OTel env", key))
						}
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
	cs := &ConnectorSignals{
		ConnectorName: "claudecode",
		RawBody:       body,
		RawModel:      ParseModelFromBody(body),
		Stream:        ParseStreamFromBody(body),
	}

	cs.RawAPIKey = r.Header.Get("x-api-key")
	if cs.RawAPIKey == "" {
		cs.RawAPIKey = ExtractAPIKey(r)
	}

	cs.ExtraHeaders = map[string]string{}
	if v := r.Header.Get("anthropic-version"); v != "" {
		cs.ExtraHeaders["anthropic-version"] = v
	}

	if !isChatPath(r.URL.Path) {
		cs.PassthroughMode = true
	}

	return cs, nil
}

// --- AgentPathProvider / EnvRequirementsProvider / HookScriptProvider ---

// AgentPaths reports the on-disk footprint Claude Code's connector
// touches. The connector patches ~/.claude/settings.json (hooks
// table), backs it up via claudecode_backup.json, and writes the
// inspect-* + claude-code-hook.sh scripts under <DataDir>/hooks/.
// Legacy env files (claudecode_env.sh / claudecode.env) are
// surfaced for audit completeness even though they are scoped to
// <DataDir> and never sourced into the user's shell.
func (c *ClaudeCodeConnector) AgentPaths(opts SetupOpts) AgentPaths {
	hookDir := filepath.Join(opts.DataDir, "hooks")
	hooks := make([]string, 0, len(HookScripts()))
	for _, name := range HookScripts() {
		hooks = append(hooks, filepath.Join(hookDir, name))
	}
	return AgentPaths{
		PatchedFiles: []string{claudeCodeSettingsPath()},
		BackupFiles:  []string{filepath.Join(opts.DataDir, "claudecode_backup.json")},
		HookScripts:  hooks,
		CreatedDirs:  []string{filepath.Join(opts.DataDir, "shims")},
	}
}

func (c *ClaudeCodeConnector) HookScripts(opts SetupOpts) []string {
	return c.AgentPaths(opts).HookScripts
}

// RequiredEnv reports Claude Code's env requirements. The CLI honors
// ANTHROPIC_BASE_URL at startup; setting it points the agent at the
// DefenseClaw proxy. The connector currently writes a scoped env
// file the operator can `source` before launching Claude Code, but
// it is not strictly required because the connector also patches
// settings.json. Mark Required=false so `defenseclaw doctor` shows
// it as recommended-but-not-blocking.
func (c *ClaudeCodeConnector) RequiredEnv() []EnvRequirement {
	return []EnvRequirement{
		{
			Name:        "ANTHROPIC_BASE_URL",
			Scope:       EnvScopeProcess,
			Required:    false,
			Description: "Recommended. When set in Claude Code's process env it pins LLM traffic to the DefenseClaw proxy. The connector also patches ~/.claude/settings.json hooks so guardrail enforcement runs even when this var is unset.",
		},
	}
}

// HasUsableProviders implements ProviderProbe (plan A4). Claude Code is
// fully configured by patched settings.json + env-resolved
// ANTHROPIC_API_KEY; the connector itself does not maintain a snapshot.
// We return (1, nil) when the conventional Anthropic key var is set
// (or when the operator has provided a master key), and (0, error)
// otherwise so the gateway refuses to start with no usable upstream.
func (c *ClaudeCodeConnector) HasUsableProviders() (int, error) {
	if strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY")) != "" {
		return 1, nil
	}
	if strings.TrimSpace(c.masterKey) != "" {
		return 1, nil
	}
	return 0, errors.New("claudecode: no upstream API key (ANTHROPIC_API_KEY) configured")
}

// --- ComponentScanner interface ---

func (c *ClaudeCodeConnector) SupportsComponentScanning() bool { return true }

func (c *ClaudeCodeConnector) ComponentTargets(cwd string) map[string][]string {
	home := os.Getenv("HOME")
	userDir := filepath.Join(home, ".claude")
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

type claudeCodeBackup struct {
	OriginalHooks json.RawMessage `json:"original_hooks"`
	HadBaseURL    bool            `json:"had_base_url"`
	OldBaseURL    string          `json:"old_base_url"`
	HadHooksKey   bool            `json:"had_hooks_key"`

	// OTel env block backup (set on the very first patch only — see
	// patchClaudeCodeHooks). HadEnvKey distinguishes "operator had no
	// env block at all" from "operator had an empty env block": on
	// Teardown we delete the key entirely in the first case so the
	// settings.json shape exactly matches the pristine state.
	// OriginalEnv stores the raw JSON of the operator's env block
	// before DefenseClaw overlays its OTel keys. This includes any
	// pre-existing OTel settings so teardown can restore the user's
	// original collector/exporter values exactly.
	HadEnvKey   bool            `json:"had_env_key"`
	OriginalEnv json.RawMessage `json:"original_env,omitempty"`
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

func claudeCodeSettingsPath() string {
	if ClaudeCodeSettingsPathOverride != "" {
		return ClaudeCodeSettingsPathOverride
	}
	return filepath.Join(os.Getenv("HOME"), ".claude", "settings.json")
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
// Timeouts in milliseconds. Slow events get a larger budget:
//   - PostToolBatch summarizes many tool results → 90s.
//   - Stop / SubagentStop run Stop-time CodeGuard scans → 90s.
//   - SessionEnd can persist session-level audit → 60s.
//   - Everything else: 30s.
var hookGroups = []struct {
	eventType string
	matcher   string
	timeout   int
}{
	{"SessionStart", "startup|resume|clear|compact", 30000},
	{"InstructionsLoaded", "*", 30000},
	{"UserPromptSubmit", "", 30000},
	{"UserPromptExpansion", "", 30000},
	{"PreToolUse", "*", 30000},
	{"PermissionRequest", "*", 30000},
	{"PostToolUse", "*", 30000},
	{"PostToolUseFailure", "*", 30000},
	{"PostToolBatch", "", 90000},
	{"PermissionDenied", "*", 30000},
	{"Notification", "*", 30000},
	{"SubagentStart", "*", 30000},
	{"SubagentStop", "*", 90000},
	{"TaskCreated", "", 30000},
	{"TaskCompleted", "", 30000},
	{"Stop", "", 90000},
	{"StopFailure", "*", 30000},
	{"TeammateIdle", "", 30000},
	{"ConfigChange", "*", 30000},
	{"CwdChanged", "", 30000},
	{"FileChanged", fileChangedMatcher, 30000},
	{"WorktreeRemove", "", 30000},
	{"PreCompact", "*", 30000},
	{"PostCompact", "*", 30000},
	{"SessionEnd", "", 60000},
	{"Elicitation", "*", 30000},
	{"ElicitationResult", "*", 30000},
}

// patchClaudeCodeHooks reads ~/.claude/settings.json, backs up the original
// hooks, and registers DefenseClaw hooks for all Claude Code events.
// The read-modify-write cycle is protected by an advisory file lock to
// prevent corruption from concurrent gateway starts.
func (c *ClaudeCodeConnector) patchClaudeCodeHooks(opts SetupOpts, hookScript string) error {
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

		backupPath := filepath.Join(opts.DataDir, "claudecode_backup.json")
		if _, statErr := os.Stat(backupPath); os.IsNotExist(statErr) {
			backup := claudeCodeBackup{}
			if v := os.Getenv("ANTHROPIC_BASE_URL"); v != "" {
				backup.HadBaseURL = true
				backup.OldBaseURL = v
			}
			if hooks, ok := settings["hooks"]; ok {
				raw, _ := json.Marshal(hooks)
				backup.OriginalHooks = raw
				backup.HadHooksKey = true
			}
			if err := c.saveBackup(opts.DataDir, backup); err != nil {
				return fmt.Errorf("save claudecode backup: %w", err)
			}
		}

		hooks, _ := settings["hooks"].(map[string]interface{})
		if hooks == nil {
			hooks = map[string]interface{}{}
		}

		hooksDir := filepath.Join(opts.DataDir, "hooks")
		for key, hk := range hooks {
			hooks[key] = removeOwnedHooks(hk, hooksDir)
		}

		for _, group := range hookGroups {
			entry := map[string]interface{}{
				"hooks": []interface{}{
					map[string]interface{}{
						"type":    "command",
						"command": hookScript,
						"timeout": group.timeout,
					},
				},
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
// settings.json should inject into the CLI process env. Endpoint is
// the gateway's OTLP-HTTP receiver; headers carry the gateway token
// so the receiver can authenticate the Claude CLI process the same
// way the hook script does. Service name + resource attributes mark
// telemetry as originating from a Claude Code process so the gateway
// can fan out to per-connector dashboards.
//
// Privacy note: Claude Code redacts prompt content by default. When
// DefenseClaw redaction is explicitly disabled, we set
// OTEL_LOG_USER_PROMPTS=1 so Claude's native OTel follows the same raw
// prompt contract as DefenseClaw's own hook/proxy telemetry. Teardown
// restores the operator's pristine env block.
func buildClaudeCodeOtelEnv(opts SetupOpts) map[string]string {
	endpoint := "http://" + opts.APIAddr
	headers := []string{
		"x-defenseclaw-source=claudecode",
		// X-DefenseClaw-Client is required by the gateway's CSRF
		// gate (apiCSRFProtect rejects POSTs without it). OTel
		// exporters propagate OTEL_EXPORTER_OTLP_HEADERS verbatim
		// into every outbound request, so adding it here ensures
		// claude code's OTel POSTs satisfy the same auth contract
		// as the python CLI and the inspect hooks.
		"x-defenseclaw-client=claudecode-otel/1.0",
	}
	if opts.APIToken != "" {
		// OTEL_EXPORTER_OTLP_HEADERS is a comma-separated key=value
		// list per the spec. URL-encoding is not required for the
		// token (we generate it from a controlled charset) but we
		// keep the format strict to match third-party OTel consumers.
		headers = append(headers, "x-defenseclaw-token="+opts.APIToken)
	}
	// Switch to OTLP-JSON over HTTP so the gateway's permissive
	// JSON receiver (internal/gateway/otel_ingest.go) can decode
	// the payload without a protobuf dependency. Claude Code
	// supports both protocols; "http/json" is documented at
	// https://code.claude.com/docs/en/monitoring-usage and is
	// the safe default for a forwarder that doesn't have an OTel
	// SDK on the receive path.
	failMode := "open"
	if opts.ClaudeCodeEnforcement {
		failMode = "closed"
	}
	env := map[string]string{
		"CLAUDE_CODE_ENABLE_TELEMETRY": "1",
		"DEFENSECLAW_FAIL_MODE":        failMode,
		"OTEL_METRICS_EXPORTER":        "otlp",
		"OTEL_LOGS_EXPORTER":           "otlp",
		"OTEL_EXPORTER_OTLP_PROTOCOL":  "http/json",
		"OTEL_EXPORTER_OTLP_ENDPOINT":  endpoint,
		"OTEL_EXPORTER_OTLP_HEADERS":   strings.Join(headers, ","),
		"OTEL_SERVICE_NAME":            "claudecode",
		"OTEL_RESOURCE_ATTRIBUTES":     "service.name=claudecode,defenseclaw.connector=claudecode",
	}
	if redaction.DisableAll() {
		env["OTEL_LOG_USER_PROMPTS"] = "1"
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
// HadEnvKey marker), we capture the operator's pristine env block so
// Teardown can restore it verbatim. Subsequent patches reuse the
// captured backup — we never re-snapshot a partially-modified env.
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
		backup, _ := c.loadBackup(opts.DataDir)
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
			if err := c.saveBackup(opts.DataDir, backup); err != nil {
				return fmt.Errorf("save claudecode backup (otel env): %w", err)
			}
		}

		// Overwrite our OTel keys with current values. Operator-set
		// keys outside our list (PATH, NODE_OPTIONS, etc.) are
		// preserved verbatim — we never touch them.
		for k, v := range buildClaudeCodeOtelEnv(opts) {
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

// isClaudeCodeOtelKey reports whether an env-var name belongs to the
// OTel-related set this connector manages. Used both for backup-time
// filtering and for Teardown stripping.
func isClaudeCodeOtelKey(name string) bool {
	for _, k := range claudeCodeOtelEnvKeys {
		if name == k {
			return true
		}
	}
	return false
}

func claudeCodeOtelValueLooksManaged(key string, value interface{}, managed string) bool {
	got, _ := value.(string)
	if got == "" {
		return false
	}
	switch key {
	case "DEFENSECLAW_FAIL_MODE":
		return true
	case "OTEL_EXPORTER_OTLP_ENDPOINT":
		return managed != "" && got == managed
	case "OTEL_EXPORTER_OTLP_HEADERS":
		return strings.Contains(got, "x-defenseclaw-source=claudecode") ||
			strings.Contains(got, "x-defenseclaw-client=claudecode-otel/1.0") ||
			strings.Contains(got, "x-defenseclaw-token=")
	case "OTEL_RESOURCE_ATTRIBUTES":
		return strings.Contains(got, "defenseclaw.connector=claudecode")
	case "OTEL_SERVICE_NAME":
		return got == "claudecode"
	default:
		return false
	}
}

// restoreClaudeCodeHooks restores the original hooks from the backup file.
// Uses file locking to match patchClaudeCodeHooks and prevent corruption.
func (c *ClaudeCodeConnector) restoreClaudeCodeHooks(opts SetupOpts) error {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "[claudecode] backup unavailable; falling back to surgical cleanup: %v\n", err)
		}
		backup = claudeCodeBackup{}
	}

	settingsPath := claudeCodeSettingsPath()

	return withFileLock(settingsPath, func() error {
		if restored, err := restoreManagedFileBackupIfUnchanged(opts.DataDir, c.Name(), "settings.json", settingsPath); err != nil {
			return fmt.Errorf("managed settings restore: %w", err)
		} else if restored {
			os.Remove(filepath.Join(opts.DataDir, "claudecode_backup.json"))
			return nil
		}

		data, err := os.ReadFile(settingsPath)
		if err != nil {
			if os.IsNotExist(err) {
				os.Remove(filepath.Join(opts.DataDir, "claudecode_backup.json"))
				discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
				return nil
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
				remaining := removeOwnedHooks(val, hooksDir)
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

		// Restore env: strip our OTel keys (always), then either
		// merge back the operator's pristine env block or drop the
		// key entirely. Non-OTel keys the operator added AFTER our
		// patch are preserved — restoring blindly would erase them,
		// which is more destructive than leaving them in place.
		if envMap, ok := settings["env"].(map[string]interface{}); ok {
			for _, k := range claudeCodeOtelEnvKeys {
				delete(envMap, k)
			}
			if backup.HadEnvKey && len(backup.OriginalEnv) > 0 {
				var orig map[string]interface{}
				if err := json.Unmarshal(backup.OriginalEnv, &orig); err == nil {
					for k, v := range orig {
						if _, present := envMap[k]; !present {
							envMap[k] = v
						}
					}
				}
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

		os.Remove(filepath.Join(opts.DataDir, "claudecode_backup.json"))
		discardManagedFileBackup(opts.DataDir, c.Name(), "settings.json")
		return nil
	})
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
		hm, _ := h.(map[string]interface{})
		cmd, _ := hm["command"].(string)
		if cmd == "" {
			continue
		}
		if hooksDir != "" && strings.HasPrefix(cmd, hooksDir+"/") {
			return true
		}
		if scriptHasMarker(cmd) {
			return true
		}
	}
	return false
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

// removeOwnedHooks removes DefenseClaw-owned entries from a hook event's list
// and returns the compacted slice.
func removeOwnedHooks(hookEventValue interface{}, hooksDir string) []interface{} {
	list, ok := hookEventValue.([]interface{})
	if !ok {
		return nil
	}
	n := 0
	for _, entry := range list {
		if !isOwnedHook(entry, hooksDir) {
			list[n] = entry
			n++
		}
	}
	return list[:n]
}

// --- Env override ---

const claudeCodeEnvFileName = "claudecode_env.sh"

func (c *ClaudeCodeConnector) writeEnvOverride(opts SetupOpts) error {
	proxyURL := "http://" + opts.ProxyAddr + "/c/claudecode"
	content := fmt.Sprintf(
		"# Generated by defenseclaw setup — source this file before running claude.\n"+
			"export ANTHROPIC_BASE_URL=%q\n",
		proxyURL,
	)

	envPath := filepath.Join(opts.DataDir, claudeCodeEnvFileName)
	if err := os.WriteFile(envPath, []byte(content), 0o644); err != nil {
		return fmt.Errorf("write claudecode env file: %w", err)
	}

	dotenvPath := filepath.Join(opts.DataDir, "claudecode.env")
	dotenvContent := fmt.Sprintf("ANTHROPIC_BASE_URL=%s\n", proxyURL)
	if err := os.WriteFile(dotenvPath, []byte(dotenvContent), 0o644); err != nil {
		return fmt.Errorf("write claudecode .env: %w", err)
	}

	return nil
}

func (c *ClaudeCodeConnector) removeEnvOverride(opts SetupOpts) {
	os.Remove(filepath.Join(opts.DataDir, claudeCodeEnvFileName))
	os.Remove(filepath.Join(opts.DataDir, "claudecode.env"))
}
