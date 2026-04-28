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
	}
}

func (c *ClaudeCodeConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := c.writeEnvOverride(opts); err != nil {
		return fmt.Errorf("claudecode env override: %w", err)
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	// Plan C2: hand the connector itself so HookScriptOwner is the
	// single source of truth for which vendor templates land here.
	if err := WriteHookScriptsForConnectorObject(hookDir, opts.APIAddr, opts.APIToken, c); err != nil {
		return fmt.Errorf("claudecode hook script: %w", err)
	}

	hookScript := filepath.Join(hookDir, "claude-code-hook.sh")
	if err := c.patchClaudeCodeHooks(opts, hookScript); err != nil {
		return fmt.Errorf("claudecode settings hooks: %w", err)
	}

	policy := ResolveSubprocessPolicy(SubprocessSandbox)
	if err := SetupSubprocessEnforcement(policy, opts); err != nil {
		return fmt.Errorf("claudecode subprocess enforcement: %w", err)
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

		return atomicWriteFile(settingsPath, out, 0o644)
	})
}

// restoreClaudeCodeHooks restores the original hooks from the backup file.
// Uses file locking to match patchClaudeCodeHooks and prevent corruption.
func (c *ClaudeCodeConnector) restoreClaudeCodeHooks(opts SetupOpts) error {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		return fmt.Errorf("load claudecode backup: %w", err)
	}

	settingsPath := claudeCodeSettingsPath()

	return withFileLock(settingsPath, func() error {
		data, err := os.ReadFile(settingsPath)
		if err != nil {
			return fmt.Errorf("read claude settings for restore: %w", err)
		}

		settings := map[string]interface{}{}
		if err := json.Unmarshal(data, &settings); err != nil {
			return fmt.Errorf("parse claude settings for restore: %w", err)
		}

		if backup.HadHooksKey && len(backup.OriginalHooks) > 0 && string(backup.OriginalHooks) != "null" {
			var orig interface{}
			if err := json.Unmarshal(backup.OriginalHooks, &orig); err != nil {
				return fmt.Errorf("unmarshal original hooks from backup: %w", err)
			}
			settings["hooks"] = orig
		} else {
			delete(settings, "hooks")
		}

		out, err := json.MarshalIndent(settings, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal restored settings: %w", err)
		}

		if err := atomicWriteFile(settingsPath, out, 0o644); err != nil {
			return fmt.Errorf("write restored settings: %w", err)
		}

		os.Remove(filepath.Join(opts.DataDir, "claudecode_backup.json"))
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
