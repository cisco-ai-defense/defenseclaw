// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

var kiroV3HookSpecs = []struct {
	name        string
	description string
	trigger     string
	matcher     string
}{
	{"defenseclaw-user-prompt", "DefenseClaw prompt inspection", "UserPromptSubmit", ""},
	{"defenseclaw-pre-tool", "DefenseClaw tool-use inspection", "PreToolUse", ".*"},
	{"defenseclaw-post-tool", "DefenseClaw tool-use audit", "PostToolUse", ".*"},
	{"defenseclaw-stop", "DefenseClaw session stop", "Stop", ""},
}

var kiroV2HookSpecs = []struct {
	event       string
	description string
	matcher     string
}{
	{"userPromptSubmit", "DefenseClaw prompt inspection", ".*"},
	{"preToolUse", "DefenseClaw tool-use inspection", ".*"},
	{"postToolUse", "DefenseClaw tool-use audit", ".*"},
	// kiro-cli 2.22's agent schema accepts `stop` only. `agentStop` is
	// documented as an alias but fails validation, so /hooks stays empty.
	{"stop", "DefenseClaw session stop", ".*"},
}

const kiroV2StopAlias = "agentStop"

func patchKiroV3Hooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	cfg["version"] = "v1"
	hooks, _ := cfg["hooks"].([]interface{})
	kept := make([]interface{}, 0, len(hooks)+len(kiroV3HookSpecs))
	for _, item := range hooks {
		if kiroOwnedV3Hook(item, hookScript) {
			continue
		}
		kept = append(kept, item)
	}
	for _, spec := range kiroV3HookSpecs {
		entry := map[string]interface{}{
			"name":        spec.name,
			"description": spec.description,
			"trigger":     spec.trigger,
			"action": map[string]interface{}{
				"type":    "command",
				"command": hookScript,
			},
			"timeout": 30,
			"enabled": true,
		}
		if spec.matcher != "" {
			entry["matcher"] = spec.matcher
		}
		kept = append(kept, entry)
	}
	cfg["hooks"] = kept
	return writeJSONObject(path, cfg)
}

func removeKiroV3Hooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	hooks, _ := cfg["hooks"].([]interface{})
	kept := make([]interface{}, 0, len(hooks))
	for _, item := range hooks {
		if kiroOwnedV3Hook(item, hookScript) {
			continue
		}
		kept = append(kept, item)
	}
	if len(kept) == 0 && kiroFileIsDefenseClawOwned(cfg, hookScript) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	cfg["hooks"] = kept
	return writeJSONObject(path, cfg)
}

func patchKiroV2AgentHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if name, _ := cfg["name"].(string); strings.TrimSpace(name) == "" {
		cfg["name"] = kiroManagedAgentName
	}
	seedKiroDefaultAgentOverlay(cfg)
	hooks := ensureJSONObject(cfg, "hooks")
	migrateKiroV2StopAlias(hooks, hookScript)
	for _, spec := range kiroV2HookSpecs {
		entry := map[string]interface{}{
			"command":     hookScript,
			"matcher":     spec.matcher,
			"description": spec.description,
		}
		hooks[spec.event] = reconcileKiroV2Hooks(hooks[spec.event], hookScript, entry)
	}
	return writeJSONObject(path, cfg)
}

func removeKiroV2AgentHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if len(cfg) == 0 {
		return nil
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if hooks == nil {
		return nil
	}
	migrateKiroV2StopAlias(hooks, hookScript)
	for event, raw := range hooks {
		remaining := removeOwnedFlatHooks(raw, hookScript)
		if len(remaining) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = remaining
		}
	}
	if len(hooks) == 0 {
		delete(cfg, "hooks")
	}
	if kiroV2AgentIsDefenseClawOverlay(cfg) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeJSONObject(path, cfg)
}

func kiroV3FileReferencesHook(path, hookScript string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse kiro hooks %s: %w", path, err)
	}
	hooks, _ := cfg["hooks"].([]interface{})
	for _, item := range hooks {
		if kiroOwnedV3Hook(item, hookScript) {
			return true, nil
		}
	}
	return false, nil
}

func kiroV2AgentReferencesHook(path, hookScript string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse kiro agent %s: %w", path, err)
	}
	return containsHookScript(cfg, hookScript), nil
}

func kiroOwnedV3Hook(item interface{}, hookScript string) bool {
	obj, ok := item.(map[string]interface{})
	if !ok {
		return false
	}
	name := strings.TrimSpace(fmt.Sprint(obj["name"]))
	if strings.HasPrefix(name, "defenseclaw-") {
		return true
	}
	action, _ := obj["action"].(map[string]interface{})
	if action == nil {
		return false
	}
	command := strings.TrimSpace(fmt.Sprint(action["command"]))
	return kiroCommandOwned(command, hookScript)
}

func kiroFileIsDefenseClawOwned(cfg map[string]interface{}, hookScript string) bool {
	hooks, _ := cfg["hooks"].([]interface{})
	if len(hooks) != 0 {
		return false
	}
	if version := strings.TrimSpace(fmt.Sprint(cfg["version"])); version != "" && version != "v1" {
		return false
	}
	for key := range cfg {
		if key != "version" && key != "hooks" {
			return false
		}
	}
	return hookScript != ""
}

func kiroV2AgentIsDefenseClawOverlay(cfg map[string]interface{}) bool {
	if len(cfg) == 0 {
		return true
	}
	if !kiroV2AgentAllowsSeed(cfg) {
		return false
	}
	name, _ := cfg["name"].(string)
	if name = strings.TrimSpace(name); name != "" && name != kiroManagedAgentName && name != kiroBuiltInDefaultAgentName {
		return false
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	return len(hooks) == 0
}

func seedKiroDefaultAgentOverlay(cfg map[string]interface{}) {
	if !kiroV2AgentAllowsSeed(cfg) {
		return
	}
	if description, ok := cfg["description"].(string); !ok || strings.TrimSpace(description) == "" {
		cfg["description"] = "DefenseClaw-guarded Kiro agent"
	}
	if _, ok := cfg["tools"]; !ok {
		cfg["tools"] = []interface{}{"*"}
	}
	if _, ok := cfg["includeMcpJson"]; !ok {
		cfg["includeMcpJson"] = true
	}
}

func kiroV2AgentAllowsSeed(cfg map[string]interface{}) bool {
	for key := range cfg {
		switch key {
		case "name", "hooks", "description", "tools", "includeMcpJson":
			continue
		default:
			return false
		}
	}
	return true
}

func migrateKiroV2StopAlias(hooks map[string]interface{}, hookScript string) {
	raw, ok := hooks[kiroV2StopAlias]
	if !ok {
		return
	}
	delete(hooks, kiroV2StopAlias)
	remaining := removeOwnedFlatHooks(raw, hookScript)
	if len(remaining) == 0 {
		return
	}
	current, _ := hooks["stop"].([]interface{})
	hooks["stop"] = append(append([]interface{}{}, current...), remaining...)
}

func reconcileKiroV2Hooks(raw interface{}, hookScript string, entry map[string]interface{}) []interface{} {
	list, _ := raw.([]interface{})
	kept := make([]interface{}, 0, len(list)+1)
	for _, item := range list {
		if managedHookCommandEntry(item, hookScript) {
			continue
		}
		kept = append(kept, item)
	}
	return append(kept, entry)
}

func kiroBuiltInAgentName(name string) bool {
	switch strings.TrimSpace(name) {
	case "", kiroBuiltInDefaultAgentName, "kiro_help", "kiro_planner":
		return true
	default:
		return false
	}
}

func patchKiroDefaultAgentSetting(path string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	current, _ := cfg[kiroDefaultAgentSettingKey].(string)
	if strings.TrimSpace(current) != "" && !kiroBuiltInAgentName(current) {
		return nil
	}
	cfg[kiroDefaultAgentSettingKey] = kiroManagedAgentName
	return writeJSONObject(path, cfg)
}

func removeKiroDefaultAgentSetting(path string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	current, _ := cfg[kiroDefaultAgentSettingKey].(string)
	if strings.TrimSpace(current) != kiroManagedAgentName {
		return nil
	}
	delete(cfg, kiroDefaultAgentSettingKey)
	if len(cfg) == 0 {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
	return writeJSONObject(path, cfg)
}

func kiroSettingsSelectsManagedAgent(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	var cfg map[string]interface{}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return false, fmt.Errorf("parse kiro settings %s: %w", path, err)
	}
	current, _ := cfg[kiroDefaultAgentSettingKey].(string)
	return strings.TrimSpace(current) == kiroManagedAgentName, nil
}

func removeStaleKiroDefaultOverlay(hookScript string) error {
	return removeKiroV2AgentHooks(kiroBuiltInDefaultAgentPath(), hookScript)
}

func kiroCommandOwned(command, hookScript string) bool {
	command = strings.TrimSpace(command)
	hookScript = strings.TrimSpace(hookScript)
	if command == "" {
		return false
	}
	if hookScript != "" && (command == hookScript || strings.Contains(command, hookScript)) {
		return true
	}
	return strings.Contains(command, kiroHookScriptName) || strings.Contains(command, "hook --connector kiro")
}
