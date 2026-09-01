// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

const devinConfigReadLimit int64 = 4 << 20

var DevinHooksPathOverride string

var devinHookEvents = []string{
	"PreToolUse",
	"PostToolUse",
	"PermissionRequest",
	"UserPromptSubmit",
	"Stop",
	"PostCompaction",
	"SessionStart",
	"SessionEnd",
}

var devinBlockEvents = []string{
	"PreToolUse",
	"PermissionRequest",
	"UserPromptSubmit",
	"Stop",
}

// NewDevinConnector integrates the native Devin CLI lifecycle-hook contract.
// It intentionally has no relationship to the retired Cascade/Windsurf state:
// the legacy connector remains available only to installer teardown code.
func NewDevinConnector() *hookOnlyConnector {
	return &hookOnlyConnector{
		name:        "devin",
		description: "native Devin CLI lifecycle hooks with MCP, skills, rules, and agent discovery",
		apiPath:     "/api/v1/devin/hook",
		scriptName:  "devin-hook.sh",
		configPath:  devinHooksPath,
		capability: func(opts SetupOpts) HookCapability {
			return HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        append([]string(nil), devinBlockEvents...),
				SupportsFailClosed: true,
				Scope:              "user,workspace",
				ConfigPath:         devinHooksPath(opts),
			}
		},
	}
}

func devinConfigRoot(opts SetupOpts) string {
	if root := strings.TrimSpace(opts.ConfigHome); root != "" {
		return filepath.Clean(root)
	}
	if runtime.GOOS == "windows" {
		if root := strings.TrimSpace(os.Getenv("APPDATA")); root != "" {
			return filepath.Join(filepath.Clean(root), "devin")
		}
	}
	if root, err := os.UserConfigDir(); err == nil && strings.TrimSpace(root) != "" {
		return filepath.Join(filepath.Clean(root), "devin")
	}
	return homePath(".config", "devin")
}

func devinHooksPath(opts SetupOpts) string {
	if DevinHooksPathOverride != "" {
		return DevinHooksPathOverride
	}
	if workspace := strings.TrimSpace(opts.WorkspaceDir); workspace != "" {
		return filepath.Join(filepath.Clean(workspace), ".devin", "hooks.v1.json")
	}
	return filepath.Join(devinConfigRoot(opts), "config.json")
}

func devinMCPPaths(opts SetupOpts) []string {
	root := devinConfigRoot(opts)
	return uniqueNonEmptyStrings([]string{
		filepath.Join(root, "mcp_config.json"),
		filepath.Join(root, "config.json"), // legacy embedded MCP is read-only
		workspacePath(opts, ".devin", "mcp_config.json"),
		workspacePath(opts, ".devin", "mcp_config.local.json"),
		workspacePath(opts, ".devin", "config.json"),
		workspacePath(opts, ".devin", "config.local.json"),
	})
}

func devinMCPWritePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		filepath.Join(devinConfigRoot(opts), "mcp_config.json"),
		workspacePath(opts, ".devin", "mcp_config.json"),
	})
}

func devinSkillPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		filepath.Join(devinConfigRoot(opts), "skills"),
		homePath(".agents", "skills"),
		workspacePath(opts, ".devin", "skills"),
		workspacePath(opts, ".agents", "skills"),
	})
}

func devinSkillWritePaths(opts SetupOpts) []string {
	if workspace := strings.TrimSpace(opts.WorkspaceDir); workspace != "" {
		return []string{filepath.Join(filepath.Clean(workspace), ".devin", "skills")}
	}
	return []string{filepath.Join(devinConfigRoot(opts), "skills")}
}

func devinAgentPaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		filepath.Join(devinConfigRoot(opts), "agents"),
		workspacePath(opts, ".devin", "agents"),
		workspacePath(opts, ".agents", "agents"),
	})
}

func devinRulePaths(opts SetupOpts) []string {
	return uniqueNonEmptyStrings([]string{
		filepath.Join(devinConfigRoot(opts), "AGENTS.md"),
		filepath.Join(devinConfigRoot(opts), "AGENT.md"),
		workspacePath(opts, "AGENTS.md"),
		workspacePath(opts, "AGENT.md"),
		workspacePath(opts, "AGENTS.local.md"),
		workspacePath(opts, ".devin", "rules"),
		workspacePath(opts, ".devin", "global_rules.md"),
	})
}

func devinProfileDecode(payload map[string]interface{}) HookProfileRequest {
	event := hookFirstString(payload, "hook_event_name", "hookEventName")
	req := HookProfileRequest{
		ConnectorName: "devin",
		HookEventName: event,
		SessionID:     hookFirstString(payload, "session_id", "sessionId"),
		TurnID:        hookFirstString(payload, "prompt_id", "promptId"),
		CWD:           hookFirstString(payload, "cwd"),
		ToolName:      hookFirstString(payload, "tool_name", "toolName"),
		Payload:       payload,
	}
	if input, ok := payload["tool_input"]; ok {
		if encoded, err := json.Marshal(input); err == nil {
			req.ToolArgs = encoded
		}
	}
	switch canonicalHookEvent(event) {
	case "posttooluse":
		if response, ok := payload["tool_response"]; ok {
			if encoded, err := json.Marshal(response); err == nil {
				req.Content = string(encoded)
				req.Direction = "tool_result"
			}
		}
	case "userpromptsubmit":
		req.Content = hookFirstString(payload, "prompt")
		req.Direction = "prompt"
	case "postcompaction":
		req.Content = hookFirstString(payload, "summary")
	}
	return req
}

func devinHookOutput(event, action, reason, additional string) map[string]interface{} {
	if action == "block" && eventInProfile(event, devinBlockEvents) {
		return map[string]interface{}{"decision": "block", "reason": reason}
	}
	switch canonicalHookEvent(event) {
	case "userpromptsubmit", "sessionstart", "posttooluse":
		if additional != "" {
			return map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":     canonicalDevinEvent(event),
					"additionalContext": additional,
				},
			}
		}
	}
	return nil
}

func canonicalDevinEvent(event string) string {
	canonical := canonicalHookEvent(event)
	for _, candidate := range devinHookEvents {
		if canonicalHookEvent(candidate) == canonical {
			return candidate
		}
	}
	return event
}

func readDevinJSONObject(path string) (map[string]interface{}, error) {
	data, err := safefile.ReadRegularFileBounded(path, devinConfigReadLimit)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	if len(bytes.TrimSpace(data)) == 0 {
		return map[string]interface{}{}, nil
	}
	normalized, err := normalizeCopilotJSONC(data)
	if err != nil {
		return nil, fmt.Errorf("parse Devin JSONC %s: %w", path, err)
	}
	var out map[string]interface{}
	decoder := json.NewDecoder(bytes.NewReader(normalized))
	decoder.UseNumber()
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("parse Devin JSONC %s: %w", path, err)
	}
	var trailing interface{}
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			err = errors.New("multiple JSON values")
		}
		return nil, fmt.Errorf("parse Devin JSONC %s: %w", path, err)
	}
	if out == nil {
		return nil, fmt.Errorf("parse Devin JSONC %s: root must be a JSON object", path)
	}
	return out, nil
}

func devinHooksObject(path string, cfg map[string]interface{}) map[string]interface{} {
	if strings.EqualFold(filepath.Base(path), "hooks.v1.json") {
		return cfg
	}
	return ensureJSONObject(cfg, "hooks")
}

func patchDevinHooks(path, hookScript string, ownedHookScripts ...string) error {
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		return err
	}
	hooks := devinHooksObject(path, cfg)
	ownedHookScripts = uniqueNonEmptyStrings(append([]string{hookScript}, ownedHookScripts...))
	for _, event := range devinHookEvents {
		entry := map[string]interface{}{
			"matcher": "",
			"hooks": []interface{}{
				map[string]interface{}{
					"type":    "command",
					"command": hookScript,
					"timeout": json.Number("10"),
				},
			},
		}
		hooks[event] = replaceManagedDevinHooks(hooks[event], ownedHookScripts, entry)
	}
	return writeJSONObject(path, cfg)
}

func replaceManagedDevinHooks(raw interface{}, ownedHookScripts []string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list)+1)
	for _, item := range list {
		if devinHookGroupReferences(item, ownedHookScripts...) {
			continue
		}
		out = append(out, item)
	}
	return append(out, entry)
}

func devinHookGroupReferences(raw interface{}, hookScripts ...string) bool {
	group, ok := raw.(map[string]interface{})
	if !ok {
		return false
	}
	entries, _ := group["hooks"].([]interface{})
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]interface{})
		if !ok {
			continue
		}
		command, _ := entry["command"].(string)
		command = strings.TrimSpace(command)
		for _, hookScript := range hookScripts {
			if command != "" && command == strings.TrimSpace(hookScript) {
				return true
			}
		}
	}
	return false
}

func removeDevinHookReferences(path string, hookScripts ...string) error {
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		return err
	}
	hooks := devinHooksObject(path, cfg)
	changed := false
	for _, event := range devinHookEvents {
		list, _ := hooks[event].([]interface{})
		out := make([]interface{}, 0, len(list))
		for _, item := range list {
			if devinHookGroupReferences(item, hookScripts...) {
				changed = true
				continue
			}
			out = append(out, item)
		}
		if len(out) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = out
		}
	}
	if !changed {
		return nil
	}
	if !strings.EqualFold(filepath.Base(path), "hooks.v1.json") && len(hooks) == 0 {
		delete(cfg, "hooks")
	}
	return writeJSONObject(path, cfg)
}

func devinConfigReferencesHook(path string, hookScripts ...string) (bool, error) {
	cfg, err := readDevinJSONObject(path)
	if err != nil {
		return false, err
	}
	hooks := devinHooksObject(path, cfg)
	for _, event := range devinHookEvents {
		list, _ := hooks[event].([]interface{})
		for _, item := range list {
			if devinHookGroupReferences(item, hookScripts...) {
				return true, nil
			}
		}
	}
	return false, nil
}

func devinOwnedHookCommands(opts SetupOpts, hookScript string) []string {
	return devinOwnedHookCommandsForOS(runtime.GOOS, opts, hookScript)
}

func devinOwnedHookCommandsForOS(goos string, opts SetupOpts, hookScript string) []string {
	commands := []string{hookScript}
	if strings.TrimSpace(opts.DataDir) != "" {
		commands = append(commands, filepath.Join(opts.DataDir, "hooks", "devin-hook.sh"))
	}
	if goos != "windows" {
		return uniqueNonEmptyStrings(commands)
	}
	for _, hookBinary := range nativeHookBinaryOwnershipCandidates() {
		commands = append(commands,
			windowsDevinBashHookCommand(hookBinary),
			legacyWindowsDevinDirectBashHookCommandForBinary(hookBinary),
			legacyWindowsDevinUnquotedPowerShellHookCommandForBinary(hookBinary),
			legacyWindowsDevinPowerShellHookCommandForBinary(hookBinary),
		)
	}
	return uniqueNonEmptyStrings(commands)
}

func devinOwnedHooksPresent(conn *hookOnlyConnector, opts SetupOpts) (bool, error) {
	if conn == nil {
		return false, errors.New("devin hook contract requires the native Devin connector")
	}
	hookScript := strings.TrimSpace(conn.hookCommand(opts))
	if hookScript == "" {
		return true, nil
	}
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) == 0 {
		return true, nil
	}
	for _, path := range paths {
		cfg, err := readDevinJSONObject(path)
		if err != nil {
			return false, err
		}
		hooks := devinHooksObject(path, cfg)
		for _, event := range devinHookEvents {
			list, _ := hooks[event].([]interface{})
			managed := 0
			for _, item := range list {
				if devinHookGroupReferences(item, hookScript) {
					managed++
				}
			}
			if managed != 1 {
				return false, nil
			}
		}
	}
	return true, nil
}
