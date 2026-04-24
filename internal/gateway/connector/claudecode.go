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
	"strings"
)

// ClaudeCodeConnector handles all security surfaces for Claude Code.
// LLM traffic: sets ANTHROPIC_BASE_URL to route through proxy.
// Tool inspection: registers hooks in ~/.claude/settings.json pointing to
// claude-code-hook.sh which calls /api/v1/claude-code/hook.
// Implements HookEventHandler, ComponentScanner, StopScanner.
type ClaudeCodeConnector struct {
	gatewayToken string
	masterKey    string
}

// NewClaudeCodeConnector creates a new Claude Code connector.
func NewClaudeCodeConnector() *ClaudeCodeConnector {
	return &ClaudeCodeConnector{}
}

func (c *ClaudeCodeConnector) Name() string { return "claudecode" }
func (c *ClaudeCodeConnector) Description() string {
	return "env var + settings.json hooks (20+ events, component scanning)"
}
func (c *ClaudeCodeConnector) ToolInspectionMode() ToolInspectionMode { return ToolModeBoth }
func (c *ClaudeCodeConnector) SubprocessPolicy() SubprocessPolicy {
	return ResolveSubprocessPolicy(SubprocessSandbox)
}

func (c *ClaudeCodeConnector) Setup(ctx context.Context, opts SetupOpts) error {
	if err := c.writeEnvOverride(opts); err != nil {
		return fmt.Errorf("claudecode env override: %w", err)
	}

	hookDir := filepath.Join(opts.DataDir, "hooks")
	if err := WriteHookScriptsWithToken(hookDir, opts.APIAddr, opts.APIToken); err != nil {
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
	c.restoreClaudeCodeHooks(opts)
	c.removeEnvOverride(opts)
	TeardownSubprocessEnforcement(opts)
	return nil
}

func (c *ClaudeCodeConnector) Authenticate(r *http.Request) bool {
	isLoopback := IsLoopback(r)

	if dcAuth := r.Header.Get("X-DC-Auth"); dcAuth != "" {
		token := strings.TrimPrefix(dcAuth, "Bearer ")
		if c.gatewayToken != "" && token == c.gatewayToken {
			return true
		}
	}

	if c.masterKey != "" {
		auth := r.Header.Get("Authorization")
		if strings.HasPrefix(auth, "Bearer ") && strings.TrimPrefix(auth, "Bearer ") == c.masterKey {
			return true
		}
	}

	if isLoopback && c.gatewayToken == "" {
		return true
	}

	if c.gatewayToken == "" && c.masterKey == "" {
		return true
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

// --- HookEventHandler interface ---

func (c *ClaudeCodeConnector) HookEndpointPath() string {
	return "/api/v1/claude-code/hook"
}

func (c *ClaudeCodeConnector) HandleHookEvent(ctx context.Context, payload []byte) ([]byte, error) {
	var req struct {
		HookEventName string `json:"hook_event_name"`
	}
	if err := json.Unmarshal(payload, &req); err != nil {
		return nil, fmt.Errorf("parse hook event: %w", err)
	}

	resp := map[string]interface{}{
		"action": "allow",
	}
	return json.Marshal(resp)
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
	return os.WriteFile(filepath.Join(dataDir, "claudecode_backup.json"), data, 0o644)
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

// hookGroups defines the Claude Code events to register, grouped by hook type.
// Each group has an optional matcher (for tool-specific events) and a timeout.
var hookGroups = []struct {
	eventType string
	matcher   string
	timeout   int
}{
	{"PreToolUse", "Bash|Read|Edit|Write|Agent|WebFetch|WebSearch|NotebookEdit|Skill|ToolSearch", 30000},
	{"PostToolUse", "Bash|Read|Edit|Write|Agent|WebFetch|WebSearch|NotebookEdit|Skill|ToolSearch", 30000},
	{"PreCompact", "", 30000},
	{"PostCompact", "", 30000},
	{"UserPromptSubmit", "", 30000},
	{"SessionStart", "", 30000},
	{"Stop", "", 30000},
	{"SubagentStop", "", 30000},
}

// patchClaudeCodeHooks reads ~/.claude/settings.json, backs up the original
// hooks, and registers DefenseClaw hooks for all Claude Code events.
func (c *ClaudeCodeConnector) patchClaudeCodeHooks(opts SetupOpts, hookScript string) error {
	settingsPath := claudeCodeSettingsPath()

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

	for key, hk := range hooks {
		hooks[key] = removeOwnedHooks(hk)
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

	if err := os.MkdirAll(filepath.Dir(settingsPath), 0o755); err != nil {
		return fmt.Errorf("create claude settings dir: %w", err)
	}

	return os.WriteFile(settingsPath, out, 0o644)
}

// restoreClaudeCodeHooks restores the original hooks from the backup file.
func (c *ClaudeCodeConnector) restoreClaudeCodeHooks(opts SetupOpts) {
	backup, err := c.loadBackup(opts.DataDir)
	if err != nil {
		return
	}

	settingsPath := claudeCodeSettingsPath()
	data, err := os.ReadFile(settingsPath)
	if err != nil {
		return
	}

	settings := map[string]interface{}{}
	if err := json.Unmarshal(data, &settings); err != nil {
		return
	}

	if backup.HadHooksKey && len(backup.OriginalHooks) > 0 && string(backup.OriginalHooks) != "null" {
		var orig interface{}
		json.Unmarshal(backup.OriginalHooks, &orig)
		settings["hooks"] = orig
	} else {
		delete(settings, "hooks")
	}

	out, _ := json.MarshalIndent(settings, "", "  ")
	os.WriteFile(settingsPath, out, 0o644)
	os.Remove(filepath.Join(opts.DataDir, "claudecode_backup.json"))
}

// isOwnedHook returns true if a hook entry's command path contains "defenseclaw".
func isOwnedHook(hookEntry interface{}) bool {
	m, ok := hookEntry.(map[string]interface{})
	if !ok {
		return false
	}
	hooksList, _ := m["hooks"].([]interface{})
	for _, h := range hooksList {
		hm, _ := h.(map[string]interface{})
		cmd, _ := hm["command"].(string)
		if strings.Contains(cmd, "defenseclaw") {
			return true
		}
	}
	return false
}

// removeOwnedHooks removes DefenseClaw-owned entries from a hook event's list
// and returns the compacted slice.
func removeOwnedHooks(hookEventValue interface{}) []interface{} {
	list, ok := hookEventValue.([]interface{})
	if !ok {
		return nil
	}
	n := 0
	for _, entry := range list {
		if !isOwnedHook(entry) {
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
