// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
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

// kiroV2MatchAllTools is the CLI 2.x agent-hook matcher for every tool.
// kiro-cli matches a hook's matcher against the tool name as a glob
// (measured on 2.24.1), so "*" matches every tool. The regular expression
// ".*" that earlier releases wrote matches none: their preToolUse and
// postToolUse hooks never ran, so no tool call was checked. The prompt and
// stop triggers ignore the matcher. Setup replaces DefenseClaw's own entries
// on every run, so the first gateway start after an upgrade rewrites an old
// agent file.
const kiroV2MatchAllTools = "*"

var kiroV2HookSpecs = []struct {
	event       string
	description string
	matcher     string
}{
	{"userPromptSubmit", "DefenseClaw prompt inspection", kiroV2MatchAllTools},
	{"preToolUse", "DefenseClaw tool-use inspection", kiroV2MatchAllTools},
	{"postToolUse", "DefenseClaw tool-use audit", kiroV2MatchAllTools},
	// kiro-cli 2.22's agent schema accepts `stop` only. `agentStop` is
	// documented as an alias but fails validation, so /hooks stays empty.
	{"stop", "DefenseClaw session stop", kiroV2MatchAllTools},
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
	// Judge ownership on what is left: with DefenseClaw's entries out, a
	// file that holds nothing else is DefenseClaw's own and goes, instead
	// of staying behind as an empty {"hooks": []}.
	cfg["hooks"] = kept
	if len(kept) == 0 && kiroFileIsDefenseClawOwned(cfg, hookScript) {
		if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
			return err
		}
		return nil
	}
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
		remaining := removeKiroOwnedV2Hooks(raw, hookScript)
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

// kiroV2AgentReferencesHook reports whether the CLI 2.x agent holds
// DefenseClaw's entry for every kiroV2HookSpecs event with the matcher this
// build writes. An entry an earlier build rendered with another matcher does
// not count, so verification fails and the guardian re-renders the agent.
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
	if !containsHookScript(cfg, hookScript) {
		return false, nil
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	for _, spec := range kiroV2HookSpecs {
		list, _ := hooks[spec.event].([]interface{})
		current := false
		for _, item := range list {
			entry, _ := item.(map[string]interface{})
			if kiroV2EntryOwned(item, hookScript) && entry["matcher"] == spec.matcher {
				current = true
				break
			}
		}
		if !current {
			return false, nil
		}
	}
	return true, nil
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
	// A file without a version (Kiro can drop the key when it rewrites the
	// file) is still DefenseClaw's; fmt.Sprint of the missing key is "<nil>",
	// which kept every such file.
	if raw, present := cfg["version"]; present {
		if version := strings.TrimSpace(fmt.Sprint(raw)); version != "" && version != "v1" {
			return false
		}
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
	remaining := removeKiroOwnedV2Hooks(raw, hookScript)
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
		if kiroV2EntryOwned(item, hookScript) {
			continue
		}
		kept = append(kept, item)
	}
	return append(kept, entry)
}

// kiroV2EntryOwned reports whether a CLI 2.x agent hook entry is
// DefenseClaw's: its command is hookScript or, on Windows, a Kiro command an
// earlier build wrote (kiroOwnedHookCommands). The match stays exact, so a
// user's own entry is never claimed.
func kiroV2EntryOwned(item interface{}, hookScript string) bool {
	for _, owned := range kiroOwnedHookCommands(hookScript) {
		if managedHookCommandEntry(item, owned) {
			return true
		}
	}
	return false
}

// removeKiroOwnedV2Hooks drops DefenseClaw's entries (kiroV2EntryOwned) from
// one event's hook list.
func removeKiroOwnedV2Hooks(raw interface{}, hookScript string) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list))
	for _, item := range list {
		if kiroV2EntryOwned(item, hookScript) {
			continue
		}
		out = append(out, item)
	}
	return out
}

// kiroV2AgentReferencesAnyHook reports whether an agent file still holds any
// DefenseClaw Kiro entry, including a form an earlier build wrote; teardown
// verification uses it.
func kiroV2AgentReferencesAnyHook(path, hookScript string) (bool, error) {
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
	return containsHookScript(cfg, kiroOwnedHookCommands(hookScript)...), nil
}

func kiroBuiltInAgentName(name string) bool {
	switch strings.TrimSpace(name) {
	case "", kiroBuiltInDefaultAgentName, "kiro_help", "kiro_planner":
		return true
	default:
		return false
	}
}

// patchKiroDefaultAgentSetting makes the defenseclaw agent the one bare
// `kiro-cli` runs. A per-user install keeps a custom default the user chose
// (Setup adds DefenseClaw's hooks to that agent instead); force, for a
// managed install, replaces it, because a managed install never edits the
// user's agents. Teardown takes the setting out again
// (removeKiroDefaultAgentSetting).
func patchKiroDefaultAgentSetting(path string, force bool) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	current, _ := cfg[kiroDefaultAgentSettingKey].(string)
	if !force && strings.TrimSpace(current) != "" && !kiroBuiltInAgentName(current) {
		return nil
	}
	if strings.TrimSpace(current) == kiroManagedAgentName {
		return nil
	}
	cfg[kiroDefaultAgentSettingKey] = kiroManagedAgentName
	return writeJSONObject(path, cfg)
}

// removeKiroDefaultAgentSetting takes DefenseClaw's chat.defaultAgent out of
// the Kiro CLI settings file and keeps every other key, including the ones
// the user or Kiro added after Setup. backup is the file as Setup first found
// it (nil for none): the default agent it named, which a managed install
// replaces, is put back, and when nothing else in the file changed since,
// so are its exact bytes.
func removeKiroDefaultAgentSetting(path string, backup *managedFileBackup) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	current, _ := cfg[kiroDefaultAgentSettingKey].(string)
	if strings.TrimSpace(current) != kiroManagedAgentName {
		return nil
	}
	delete(cfg, kiroDefaultAgentSettingKey)
	existed := backup != nil && backup.Existed
	var pristine map[string]interface{}
	if existed {
		pristine = map[string]interface{}{}
		if len(bytes.TrimSpace(backup.PristineBytes)) > 0 {
			decoder := json.NewDecoder(bytes.NewReader(backup.PristineBytes))
			decoder.UseNumber()
			if decoder.Decode(&pristine) != nil {
				pristine = nil
			}
		}
	}
	if previous, ok := pristine[kiroDefaultAgentSettingKey]; ok {
		if name, _ := previous.(string); strings.TrimSpace(name) != kiroManagedAgentName {
			cfg[kiroDefaultAgentSettingKey] = previous
		}
	}
	if pristine != nil && reflect.DeepEqual(cfg, pristine) {
		mode := os.FileMode(backup.Mode)
		if mode == 0 {
			mode = 0o600
		}
		return atomicWriteFile(path, backup.PristineBytes, mode)
	}
	if len(cfg) == 0 && !existed {
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
	if strings.Contains(command, kiroHookScriptName) || strings.Contains(command, "hook --connector kiro") {
		return true
	}
	// The Windows encoded bridge carries its arguments base64-encoded.
	for _, owned := range kiroOwnedHookCommands(hookScript) {
		if command == owned {
			return true
		}
	}
	return false
}
