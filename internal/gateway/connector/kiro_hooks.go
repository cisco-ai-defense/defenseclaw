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

// kiroV3MatchAllTools is the .kiro/hooks matcher for every tool. Kiro's v3
// agent engine (kiro-cli --v3, whose agent server is @kiro/agent 0.66.8 in
// kiro-cli 2.24.1) and Kiro IDE 1.1.14 compile a hook's matcher with
// JavaScript's RegExp and test the tool name unanchored, so ".*" matches
// every tool (execute_bash, fs_write, read_file, ...). Measured live on
// kiro-cli 2.24.1 --v3: PreToolUse and PostToolUse hooks with ".*" or with
// no matcher fire for every tool call; "*", the CLI 2.x glob
// (kiroV2MatchAllTools), is not a valid regular expression, so Kiro logs
// "Hook matcher regex failed to compile" and the hook never fires. The two
// configs therefore keep different matchers. The CLI 2.x engine does not
// read .kiro/hooks at all.
const kiroV3MatchAllTools = ".*"

var kiroV3HookSpecs = []struct {
	name        string
	description string
	trigger     string
	matcher     string
}{
	{"defenseclaw-user-prompt", "DefenseClaw prompt inspection", "UserPromptSubmit", ""},
	{"defenseclaw-pre-tool", "DefenseClaw tool-use inspection", "PreToolUse", kiroV3MatchAllTools},
	{"defenseclaw-post-tool", "DefenseClaw tool-use audit", "PostToolUse", kiroV3MatchAllTools},
	{"defenseclaw-stop", "DefenseClaw session stop", "Stop", ""},
}

// kiroV2MatchAllTools is the CLI 2.x agent-hook matcher for every tool.
// kiro-cli matches a hook's matcher against the tool name as a glob
// (measured on 2.24.1), so "*" matches every tool. The regular expression
// ".*" that earlier releases wrote matches none: their preToolUse and
// postToolUse hooks never ran, so no tool call was checked. The prompt and
// stop triggers ignore the matcher. Setup replaces DefenseClaw's own entries
// on every run, so the first gateway start after an upgrade rewrites an old
// agent file. kiro-cli --v3 also runs the selected agent's hooks, but reads
// their matchers as regular expressions (kiroV3MatchAllTools): measured on
// 2.24.1, these "*" entries do not fire there for tools or at the end of a
// turn, so each of those events reaches DefenseClaw once, through
// .kiro/hooks.
const kiroV2MatchAllTools = "*"

// kiroV2HookTimeoutMillis is the timeout_ms of DefenseClaw's CLI 2.x agent
// hooks: the 30-second envelope the hook scripts budget for (the v3 file's
// "timeout": 30). Without it Kiro applies its own default, about ten
// seconds (Kiro's /upgrade-agent writes "timeout": 10 for a hook that set
// none), and a hook that answers later is ignored: measured on kiro-cli
// 2.24.1, a preToolUse hook that took 12 s and then exited 2 did not stop
// the tool, while the same hook with timeout_ms 30000 blocked it. A slow
// verdict therefore let the tool run.
const kiroV2HookTimeoutMillis = 30000

// kiroV2HookSpecs has no userPromptSubmit entry. Kiro CLI 2.x adds every
// successful userPromptSubmit hook's stdout to the prompt inside a context
// entry that tells the model to "follow any requests" in it, and it adds the
// entry even when the hook prints nothing (measured on kiro-cli 2.26.1: every
// prompt carried an empty DefenseClaw entry, and the model refused harmless
// prompts as prompt injection). The 2.x engine cannot veto a prompt
// (KiroBlockEventsForSurface), so the hook only audited it; tool calls are
// still checked by preToolUse, and the v3 engine checks prompts through
// .kiro/hooks.
var kiroV2HookSpecs = []struct {
	event       string
	description string
	matcher     string
}{
	{"preToolUse", "DefenseClaw tool-use inspection", kiroV2MatchAllTools},
	{"postToolUse", "DefenseClaw tool-use audit", kiroV2MatchAllTools},
	// kiro-cli 2.22's agent schema accepts `stop` only. `agentStop` is
	// documented as an alias but fails validation, so /hooks stays empty.
	{"stop", "DefenseClaw session stop", kiroV2MatchAllTools},
}

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
	if list, ok := cfg["hooks"].([]interface{}); ok {
		// An agent Kiro upgraded to the universal form keeps that form.
		cfg["hooks"] = reconcileKiroUniversalHooks(list, hookScript)
		return writeJSONObject(path, cfg)
	}
	hooks := ensureJSONObject(cfg, "hooks")
	for _, spec := range kiroV2HookSpecs {
		entry := map[string]interface{}{
			"command":     hookScript,
			"matcher":     spec.matcher,
			"timeout_ms":  kiroV2HookTimeoutMillis,
			"description": spec.description,
		}
		hooks[spec.event] = reconcileKiroV2Hooks(hooks[spec.event], hookScript, entry)
	}
	return writeJSONObject(path, cfg)
}

// kiroV2HookTimeoutIs reports whether a decoded JSON number is want.
func kiroV2HookTimeoutIs(raw interface{}, want int) bool {
	switch v := raw.(type) {
	case float64:
		return v == float64(want)
	case int:
		return v == want
	case json.Number:
		n, err := v.Int64()
		return err == nil && n == int64(want)
	}
	return false
}

// The universal agent form. Kiro's /upgrade-agent, and the "Enable
// auto-upgrade" choice kiro-cli --v3 offers at start, rewrite a CLI 2.x
// agent's event-keyed hooks into one array read by both engines ("Upgrade
// V2 agent configs to universal (V2 + V3) format"): each entry is
// {"name", "trigger", "matcher", "action": {"type": "command", "command"},
// "timeout"}, with the 2.x event as the trigger, the matcher unchanged and
// the timeout in seconds (10 for a hook that set none), and the old file
// kept as <agent>.json.bak. Measured on kiro-cli 2.24.1: the 2.x engine
// reads that form with the same glob matchers, and an entry with
// "timeout": 30 whose hook took 12 s still blocked. Setup keeps an agent in
// the form it finds, so the user's own entries survive, and verification
// and teardown read both forms.

// kiroUniversalHookTimeoutSeconds is the universal form's timeout of
// DefenseClaw's entries (kiroV2HookTimeoutMillis in seconds).
const kiroUniversalHookTimeoutSeconds = kiroV2HookTimeoutMillis / 1000

// kiroUniversalEntryOwned reports whether a universal-form entry is
// DefenseClaw's: its action runs the hook command exactly
// (kiroV2EntryOwned), so a user's own entry is never claimed.
func kiroUniversalEntryOwned(item interface{}, hookScript string) bool {
	obj, _ := item.(map[string]interface{})
	if obj == nil {
		return false
	}
	return kiroV2EntryOwned(obj["action"], hookScript)
}

// kiroUniversalHookEntry is DefenseClaw's universal-form entry for one
// CLI 2.x event, in the shape Kiro's upgrade writes.
func kiroUniversalHookEntry(event, matcher, hookScript string) map[string]interface{} {
	return map[string]interface{}{
		"name":    "defenseclaw-" + event,
		"trigger": event,
		"matcher": matcher,
		"action":  map[string]interface{}{"type": "command", "command": hookScript},
		"timeout": kiroUniversalHookTimeoutSeconds,
	}
}

// reconcileKiroUniversalHooks replaces DefenseClaw's universal-form entries
// (an agentStop one included) with one per kiroV2HookSpecs event and keeps
// every other entry in place.
func reconcileKiroUniversalHooks(list []interface{}, hookScript string) []interface{} {
	kept := removeKiroOwnedUniversalHooks(list, hookScript)
	for _, spec := range kiroV2HookSpecs {
		kept = append(kept, kiroUniversalHookEntry(spec.event, spec.matcher, hookScript))
	}
	return kept
}

// removeKiroOwnedUniversalHooks drops DefenseClaw's universal-form entries,
// including one whose script path or name was edited (GAP-0907).
func removeKiroOwnedUniversalHooks(list []interface{}, hookScript string) []interface{} {
	kept := make([]interface{}, 0, len(list)+len(kiroV2HookSpecs))
	edited := hookScriptBaseName(hookScript)
	for _, item := range list {
		if !kiroUniversalEntryOwned(item, hookScript) && !editedDefenseClawHookEntry(item, edited) {
			kept = append(kept, item)
		}
	}
	return kept
}

// kiroUniversalHooksCurrent reports whether a universal-form hook list holds
// DefenseClaw's entry for every kiroV2HookSpecs event with the matcher and
// timeout this build writes.
func kiroUniversalHooksCurrent(list []interface{}, hookScript string) bool {
	for _, spec := range kiroV2HookSpecs {
		current := false
		for _, item := range list {
			obj, _ := item.(map[string]interface{})
			if kiroUniversalEntryOwned(item, hookScript) && obj["trigger"] == spec.event && obj["matcher"] == spec.matcher &&
				kiroV2HookTimeoutIs(obj["timeout"], kiroUniversalHookTimeoutSeconds) {
				current = true
				break
			}
		}
		if !current {
			return false
		}
	}
	return true
}

func removeKiroV2AgentHooks(path, hookScript string) error {
	cfg, err := readJSONObject(path)
	if err != nil {
		return err
	}
	if len(cfg) == 0 {
		return nil
	}
	if list, ok := cfg["hooks"].([]interface{}); ok {
		if kept := removeKiroOwnedUniversalHooks(list, hookScript); len(kept) == 0 {
			delete(cfg, "hooks")
		} else {
			cfg["hooks"] = kept
		}
		if kiroV2AgentIsDefenseClawOverlay(cfg) {
			if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
				return err
			}
			return nil
		}
		return writeJSONObject(path, cfg)
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	if hooks == nil {
		return nil
	}
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

// kiroV3HooksCurrent reports whether the v3 hook file at path holds
// DefenseClaw's entry for every kiroV3HookSpecs trigger exactly as Setup
// writes it: the command hookCommand, the matcher, the 30-second timeout,
// and not turned off. Kiro skips an entry with "enabled": false
// (kiro.dev/docs/hooks: "Set false to skip the hook without deleting it"),
// and the presence check kiroV3FileReferencesHook, which teardown uses,
// accepts any entry named defenseclaw-*, so a user who turned DefenseClaw's
// entries off or pointed them at another command still passed verification
// and the guardian never repaired the file.
func kiroV3HooksCurrent(path, hookCommand string) (bool, error) {
	cfg, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	hooks, _ := cfg["hooks"].([]interface{})
	for _, spec := range kiroV3HookSpecs {
		current := false
		for _, item := range hooks {
			obj, _ := item.(map[string]interface{})
			action, _ := obj["action"].(map[string]interface{})
			if obj == nil || action == nil || obj["name"] != spec.name || obj["trigger"] != spec.trigger ||
				action["type"] != "command" || action["command"] != hookCommand ||
				obj["enabled"] == false || !kiroV2HookTimeoutIs(obj["timeout"], 30) {
				continue
			}
			if matcher, _ := obj["matcher"].(string); matcher != spec.matcher {
				continue
			}
			current = true
			break
		}
		if !current {
			return false, nil
		}
	}
	return true, nil
}

// kiroV2AgentReferencesHook reports whether the CLI 2.x agent holds
// DefenseClaw's entry for every kiroV2HookSpecs event with the matcher and
// timeout this build writes. An entry an earlier build rendered with another
// matcher or without the timeout does not count, so verification fails and
// the guardian re-renders the agent.
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
	if list, ok := cfg["hooks"].([]interface{}); ok {
		return kiroUniversalHooksCurrent(list, hookScript), nil
	}
	hooks, _ := cfg["hooks"].(map[string]interface{})
	for _, spec := range kiroV2HookSpecs {
		list, _ := hooks[spec.event].([]interface{})
		current := false
		for _, item := range list {
			entry, _ := item.(map[string]interface{})
			if kiroV2EntryOwned(item, hookScript) && entry["matcher"] == spec.matcher &&
				kiroV2HookTimeoutIs(entry["timeout_ms"], kiroV2HookTimeoutMillis) {
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
	return kiroCommandOwned(command, hookScript) || editedDefenseClawHookCommand(command, kiroHookScriptName)
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
	switch hooks := cfg["hooks"].(type) {
	case nil:
		return true
	case map[string]interface{}:
		return len(hooks) == 0
	case []interface{}:
		// The universal form Kiro's /upgrade-agent writes.
		return len(hooks) == 0
	default:
		return false
	}
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

func reconcileKiroV2Hooks(raw interface{}, hookScript string, entry map[string]interface{}) []interface{} {
	return append(removeKiroOwnedV2Hooks(raw, hookScript), entry)
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
// one event's hook list, including one whose script path or name was edited
// (GAP-0907).
func removeKiroOwnedV2Hooks(raw interface{}, hookScript string) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list))
	edited := hookScriptBaseName(hookScript)
	for _, item := range list {
		if kiroV2EntryOwned(item, hookScript) || editedDefenseClawHookEntry(item, edited) {
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
	// A backup taken over DefenseClaw's own setting (it named only the
	// defenseclaw agent) is no earlier user content: remove the file rather
	// than leave an empty '{}' behind.
	onlyManaged := len(pristine) == 1 && strings.TrimSpace(fmt.Sprint(pristine[kiroDefaultAgentSettingKey])) == kiroManagedAgentName
	if len(cfg) == 0 && (!existed || onlyManaged) {
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
