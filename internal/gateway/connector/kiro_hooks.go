// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
		if kiroOwnedV3Hook(item, hookScript) || kiroV3BoundTrigger(item) {
			continue
		}
		kept = append(kept, item)
	}
	for _, spec := range kiroV3HookSpecs {
		kept = append(kept, kiroV3HookEntry(spec.name, spec.description, spec.trigger, spec.matcher, hookScript))
	}
	cfg["hooks"] = kept
	return writeJSONObject(path, cfg)
}

// kiroV3HookEntry is the v3 hook entry Setup writes for one kiroV3HookSpecs
// trigger.
func kiroV3HookEntry(name, description, trigger, matcher, hookScript string) map[string]interface{} {
	entry := map[string]interface{}{
		"name":        name,
		"description": description,
		"trigger":     trigger,
		"action": map[string]interface{}{
			"type":    "command",
			"command": hookScript,
		},
		"timeout": 30,
		"enabled": true,
	}
	if matcher != "" {
		entry["matcher"] = matcher
	}
	return entry
}

// kiroReclaimScope limits the teardown of an unconfigured connector to what
// this install provably wrote (KiroConnector.reclaimScope): the files in
// files, and in them only the entries that run exactly one of commands. A
// nil scope, the teardown of a configured connector, covers every Kiro file
// and every DefenseClaw entry (kiroOwnedV3Hook, kiroV2EntryOwned and the
// edited forms). script, when set, is this install's POSIX hook script: an
// entry that runs it in another command form (kiroCommandRunsScript) is the
// scope's too.
type kiroReclaimScope struct {
	files    map[string]bool
	commands []string
	script   string
}

func (s *kiroReclaimScope) covers(path string) bool {
	return s == nil || s.files[filepath.Clean(path)]
}

// remaining lists, sorted, the scope's files that still hold an entry running
// one of its commands, read as the scope found them (kiroV3FileHoldsCommand,
// kiroAgentFileHoldsCommand): what the reclaim had to remove and did not.
func (s *kiroReclaimScope) remaining() ([]string, error) {
	var left []string
	for path := range s.files {
		present, err := kiroV3FileHoldsCommand(path, s.commands)
		if err == nil && !present {
			present, err = kiroAgentFileHoldsCommand(path, s.commands)
		}
		if err != nil {
			return nil, err
		}
		if present {
			left = append(left, path)
		}
	}
	slices.Sort(left)
	return left, nil
}

// runsOwnCommand reports whether raw, a CLI 2.x hook handler or the action of
// a v3 or universal entry, runs exactly one of the scope's commands, or the
// scope's script in another form (kiroCommandRunsScript).
func (s *kiroReclaimScope) runsOwnCommand(raw interface{}) bool {
	for _, command := range s.commands {
		if managedHookCommandEntry(raw, command) {
			return true
		}
	}
	if s.script == "" {
		return false
	}
	entry, _ := raw.(map[string]interface{})
	for _, key := range []string{"command", "bash"} {
		if command, _ := entry[key].(string); kiroCommandRunsScript(command, s.script) {
			return true
		}
	}
	return false
}

// holds reports whether the Kiro hook or agent file at path, in any of its
// forms, has an entry that runs one of the scope's commands
// (runsOwnCommand). A file that cannot be read as a JSON object is an error.
func (s *kiroReclaimScope) holds(path string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cfg, err := kiroDecodeJSONObject(data)
	if err != nil {
		return false, fmt.Errorf("parse kiro file %s: %w", path, err)
	}
	return s.holdsIn(cfg), nil
}

func (s *kiroReclaimScope) holdsIn(raw interface{}) bool {
	switch v := raw.(type) {
	case []interface{}:
		return slices.ContainsFunc(v, s.holdsIn)
	case map[string]interface{}:
		if s.runsOwnCommand(v) {
			return true
		}
		for _, value := range v {
			if s.holdsIn(value) {
				return true
			}
		}
	}
	return false
}

// kiroCommandRunsScript reports whether a POSIX hook command runs script, a
// data folder's own kiro-hook.sh, in a form other than the ones Setup writes
// now: the script word, quoted or not and after one shell or env wrapper
// (hookScriptWordAfterWrapper), is exactly script, alone or with
// DefenseClaw's --event or --hook-surface binding. The path names that data
// folder, so no other install's or user's entry matches.
func kiroCommandRunsScript(command, script string) bool {
	if script == "" {
		return false
	}
	word, rest, ok := hookScriptWordAfterWrapper(strings.TrimSpace(command))
	return ok && word == script && (rest == "" || defenseClawHookBinding(rest))
}

// ownsActionEntry is the ownership of a v3 or universal-form entry: with no
// scope kiroOwnedV3Hook, with one an action that runs one of its commands.
func (s *kiroReclaimScope) ownsActionEntry(item interface{}, hookScript string) bool {
	if s == nil {
		return kiroOwnedV3Hook(item, hookScript)
	}
	obj, _ := item.(map[string]interface{})
	return obj != nil && s.runsOwnCommand(obj["action"])
}

// keepUniversal drops the scope's universal-form entries from list.
func (s *kiroReclaimScope) keepUniversal(list []interface{}, hookScript string) []interface{} {
	if s == nil {
		return removeKiroOwnedUniversalHooks(list, hookScript)
	}
	return slices.DeleteFunc(slices.Clone(list), func(item interface{}) bool {
		return s.ownsActionEntry(item, hookScript)
	})
}

// keepV2 drops the scope's entries from one CLI 2.x event's hook list.
func (s *kiroReclaimScope) keepV2(raw interface{}, hookScript string) []interface{} {
	if s == nil {
		return removeKiroOwnedV2Hooks(raw, hookScript)
	}
	list, _ := raw.([]interface{})
	return slices.DeleteFunc(slices.Clone(list), s.runsOwnCommand)
}

// removeKiroV3HooksKeeping removes DefenseClaw's entries from a v3 hook file,
// and the file when nothing else is left in it unless operatorFile: the
// operator had it before Setup (kiroPristineIsOperators). With a scope only
// its entries go.
func removeKiroV3HooksKeeping(path, hookScript string, operatorFile bool, scope *kiroReclaimScope) error {
	cfg, err := kiroReadJSONObject(path)
	if err != nil {
		return err
	}
	hooks, _ := cfg["hooks"].([]interface{})
	kept := make([]interface{}, 0, len(hooks))
	for _, item := range hooks {
		if scope.ownsActionEntry(item, hookScript) {
			continue
		}
		kept = append(kept, item)
	}
	// Judge ownership on what is left: with DefenseClaw's entries out, a
	// file that holds nothing else is DefenseClaw's own and goes, instead
	// of staying behind as an empty {"hooks": []}.
	cfg["hooks"] = kept
	if len(kept) == 0 && !operatorFile && kiroFileIsDefenseClawOwned(cfg, hookScript) {
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
// including one whose script path or name was edited (GAP-0907) or that is a
// copy named by a Windows path, on every OS: on Windows hookScript is the
// cmd.exe bridge, which names no script (GAP-1942).
func removeKiroOwnedUniversalHooks(list []interface{}, hookScript string) []interface{} {
	kept := make([]interface{}, 0, len(list)+len(kiroV2HookSpecs))
	for _, item := range list {
		if !kiroUniversalEntryOwned(item, hookScript) && !editedDefenseClawHookEntry(item, kiroHookScriptName) {
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

// removeKiroV2AgentHooksKeeping removes DefenseClaw's entries from a CLI 2.x
// agent file, in either form, and the file when it is left looking like
// DefenseClaw's overlay unless operatorFile: the operator had it before Setup
// (kiroPristineIsOperators). With a scope only its entries go.
func removeKiroV2AgentHooksKeeping(path, hookScript string, operatorFile bool, scope *kiroReclaimScope) error {
	cfg, err := kiroReadJSONObject(path)
	if err != nil {
		return err
	}
	if len(cfg) == 0 {
		return nil
	}
	if list, ok := cfg["hooks"].([]interface{}); ok {
		if kept := scope.keepUniversal(list, hookScript); len(kept) == 0 {
			delete(cfg, "hooks")
		} else {
			cfg["hooks"] = kept
		}
		if !operatorFile && kiroV2AgentIsDefenseClawOverlay(cfg) {
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
		remaining := scope.keepV2(raw, hookScript)
		if len(remaining) == 0 {
			delete(hooks, event)
		} else {
			hooks[event] = remaining
		}
	}
	if len(hooks) == 0 {
		delete(cfg, "hooks")
	}
	if !operatorFile && kiroV2AgentIsDefenseClawOverlay(cfg) {
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
// writes it (kiroV3HookEntry), and no other entry on those triggers
// (kiroV3BoundTrigger). Kiro skips an entry with "enabled": false
// (kiro.dev/docs/hooks: "Set false to skip the hook without deleting it"),
// and the presence check kiroV3FileReferencesHook, which teardown uses,
// accepts any entry named defenseclaw-*, so a user who turned DefenseClaw's
// entries off, pointed them at another command or gave them another key (a
// per-entry env or cwd) still passed verification and the guardian never
// repaired the file.
func kiroV3HooksCurrent(path, hookCommand string) (bool, error) {
	cfg, err := readJSONObject(path)
	if err != nil {
		return false, err
	}
	hooks, _ := cfg["hooks"].([]interface{})
	for _, spec := range kiroV3HookSpecs {
		want := kiroV3HookEntry(spec.name, spec.description, spec.trigger, spec.matcher, hookCommand)
		if !slices.ContainsFunc(hooks, func(item interface{}) bool { return sameHookJSON(item, want) }) {
			return false, nil
		}
	}
	bound := 0
	for _, item := range hooks {
		if kiroV3BoundTrigger(item) {
			bound++
		}
	}
	return bound == len(kiroV3HookSpecs), nil
}

// kiroV3BoundTrigger reports whether item is a v3 hook entry on a trigger
// DefenseClaw binds. defenseclaw.json is DefenseClaw's file, so on those
// triggers it holds Setup's entries alone: another entry there (an old copy,
// a wrapper, a renamed script) ran beside DefenseClaw's (rel-1-0-4 GAP-0600).
func kiroV3BoundTrigger(item interface{}) bool {
	obj, _ := item.(map[string]interface{})
	trigger, _ := obj["trigger"].(string)
	for _, spec := range kiroV3HookSpecs {
		if trigger == spec.trigger {
			return true
		}
	}
	return false
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
	return kiroCommandOwned(command, hookScript) || editedDefenseClawHookCommandByAnyPath(command, kiroHookScriptName)
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
	if !kiroV2AgentAllowsSeed(cfg) && !kiroV2AgentIsKnownDefenseClawShape(cfg) {
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
		cfg["description"] = kiroManagedAgentDescription
	}
	if _, ok := cfg["tools"]; !ok {
		cfg["tools"] = []interface{}{"*"}
	}
	if _, ok := cfg["includeMcpJson"]; !ok {
		cfg["includeMcpJson"] = true
	}
}

// kiroManagedAgentDescription is the description Setup gives the defenseclaw
// agent; it marks the file as DefenseClaw's own.
const kiroManagedAgentDescription = "DefenseClaw-guarded Kiro agent"

// kiroAgentEmptyKeys are keys of a Kiro agent file that Kiro writes with an
// empty value when it converts or normalizes an agent. Empty, they change
// nothing; with a value they are the operator's.
var kiroAgentEmptyKeys = []string{"prompt", "resources", "mcpServers", "allowedTools", "toolAliases", "toolsSettings"}

// kiroV2AgentIsKnownDefenseClawShape reports whether cfg is a defenseclaw
// agent file holding only keys that Setup writes (name, description, tools,
// includeMcpJson, hooks), the $schema pointer, and the keys of
// kiroAgentEmptyKeys with an empty value, and carrying Setup's description.
// Any other key, or a non-empty value of those, is the operator's content, so
// the file stays when its last DefenseClaw hook goes (rel-1-0-10 GAP-1174).
func kiroV2AgentIsKnownDefenseClawShape(cfg map[string]interface{}) bool {
	if description, _ := cfg["description"].(string); strings.TrimSpace(description) != kiroManagedAgentDescription {
		return false
	}
	for key, value := range cfg {
		switch {
		case key == "name" || key == "hooks" || key == "description" || key == "tools" || key == "includeMcpJson" || key == "$schema":
		case slices.Contains(kiroAgentEmptyKeys, key) && kiroEmptyJSONValue(value):
		default:
			return false
		}
	}
	return true
}

func kiroEmptyJSONValue(value interface{}) bool {
	switch v := value.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(v) == ""
	case []interface{}:
		return len(v) == 0
	case map[string]interface{}:
		return len(v) == 0
	}
	return false
}

// removeKiroFileResidue removes what sits beside a Kiro file DefenseClaw has
// just removed: its empty lock file when no one holds it (removeIdleLockFile:
// a lock file still there may belong to a live holder, and unlinking a held
// one lets a second writer lock a new file), and, for a CLI 2.x agent, the
// <agent>.json.bak copies Kiro's /upgrade-agent keeps, when each is itself
// only DefenseClaw's overlay and no operator key. Its hooks must each run
// exactly a command this teardown owns: in a reclaim the install's own
// (the scope's), otherwise kiroOwnedHookCommands, the install's script
// command on POSIX (a copy with another data folder's kiro-hook.sh is that
// install's) and on Windows every launcher form of the account, managed ones
// included, which do not name a data folder. A copy with anything else in it
// stays.
func removeKiroFileResidue(path, hookScript string, agent bool, scope *kiroReclaimScope) {
	removeIdleLockFile(path + ".lock")
	if !agent {
		return
	}
	entries, err := os.ReadDir(filepath.Dir(path))
	if err != nil {
		return
	}
	prefix := filepath.Base(path) + ".bak"
	for _, entry := range entries {
		if !strings.HasPrefix(entry.Name(), prefix) || !entry.Type().IsRegular() {
			continue
		}
		backup := filepath.Join(filepath.Dir(path), entry.Name())
		if info, err := os.Stat(backup); err != nil || info.Size() > 1<<20 {
			continue
		}
		cfg, err := readJSONObject(backup)
		if err != nil || len(cfg) == 0 {
			continue
		}
		if list, ok := cfg["hooks"].([]interface{}); ok {
			kept := slices.DeleteFunc(slices.Clone(list), func(item interface{}) bool {
				if scope != nil {
					return scope.ownsActionEntry(item, hookScript)
				}
				return kiroUniversalEntryOwned(item, hookScript)
			})
			if len(kept) == 0 {
				delete(cfg, "hooks")
			} else {
				cfg["hooks"] = kept
			}
		} else if hooks, ok := cfg["hooks"].(map[string]interface{}); ok {
			for event, raw := range hooks {
				list, _ := raw.([]interface{})
				remaining := slices.DeleteFunc(slices.Clone(list), func(item interface{}) bool {
					if scope != nil {
						return scope.runsOwnCommand(item)
					}
					return kiroV2EntryOwned(item, hookScript)
				})
				if len(remaining) == 0 {
					delete(hooks, event)
				} else {
					hooks[event] = remaining
				}
			}
			if len(hooks) == 0 {
				delete(cfg, "hooks")
			}
		}
		if kiroV2AgentIsDefenseClawOverlay(cfg) {
			_ = os.Remove(backup)
		}
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
// (GAP-0907) or that is a copy named by a Windows path, on every OS
// (GAP-1942).
func removeKiroOwnedV2Hooks(raw interface{}, hookScript string) []interface{} {
	list, _ := raw.([]interface{})
	out := make([]interface{}, 0, len(list))
	for _, item := range list {
		if kiroV2EntryOwned(item, hookScript) || editedDefenseClawHookEntry(item, kiroHookScriptName) {
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
	return kiroAgentFileHoldsCommand(path, kiroOwnedHookCommands(hookScript))
}

// kiroV3FileHoldsCommand reports whether the v3 hook file at path has an
// entry whose decoded action.command is exactly one of commands. Unlike
// kiroV3FileReferencesHook it does not take the name prefix defenseclaw-* or
// the script's base name as proof: a file shared with another install's
// entries is not this install's.
func kiroV3FileHoldsCommand(path string, commands []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cfg, err := kiroDecodeJSONObject(data)
	if err != nil {
		return false, fmt.Errorf("parse kiro hooks %s: %w", path, err)
	}
	hooks, _ := cfg["hooks"].([]interface{})
	for _, item := range hooks {
		obj, _ := item.(map[string]interface{})
		action, _ := obj["action"].(map[string]interface{})
		command, _ := action["command"].(string)
		if command = strings.TrimSpace(command); command != "" && slices.Contains(commands, command) {
			return true, nil
		}
	}
	return false, nil
}

// kiroAgentFileHoldsCommand reports whether the CLI 2.x agent file at path has
// a hook entry that runs exactly one of commands, in any form of the file.
func kiroAgentFileHoldsCommand(path string, commands []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	cfg, err := kiroDecodeJSONObject(data)
	if err != nil {
		return false, fmt.Errorf("parse kiro agent %s: %w", path, err)
	}
	return containsHookScript(cfg, commands...), nil
}

// kiroUTF8BOM is the byte order mark a Windows editor (Windows PowerShell
// 5.1's Set-Content -Encoding UTF8, Notepad) puts before a UTF-8 file.
var kiroUTF8BOM = []byte{0xEF, 0xBB, 0xBF}

// kiroDecodeJSONObject decodes a Kiro hook or agent file as the ownership
// checks read it: a leading UTF-8 BOM is skipped and an empty file holds no
// entry. A BOM failed the parse, and one such file a backup record named
// failed the whole reclaim and prune on every boot.
func kiroDecodeJSONObject(data []byte) (map[string]interface{}, error) {
	data = bytes.TrimPrefix(data, kiroUTF8BOM)
	cfg := map[string]interface{}{}
	if len(bytes.TrimSpace(data)) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	if cfg == nil {
		cfg = map[string]interface{}{}
	}
	return cfg, nil
}

// kiroReadJSONObject is readJSONObject for a Kiro hook or agent file whose
// DefenseClaw entries come out: it skips a leading UTF-8 BOM, as the
// ownership checks do (kiroDecodeJSONObject), so a file they find holding
// this install's entries can also be cleaned. The file is written back
// without the BOM.
func kiroReadJSONObject(path string) (map[string]interface{}, error) {
	data, err := readHookConfigFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return map[string]interface{}{}, nil
		}
		return nil, err
	}
	return decodeJSONObject(path, bytes.TrimPrefix(data, kiroUTF8BOM))
}

// kiroFileUnparsable reports whether path is a file the ownership checks
// cannot read as a JSON object (kiroDecodeJSONObject). An absent file, or one
// that cannot be opened, is not: those keep their own handling.
func kiroFileUnparsable(path string) bool {
	data, err := os.ReadFile(path)
	if err != nil {
		return false
	}
	_, err = kiroDecodeJSONObject(data)
	return err != nil
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

func removeStaleKiroDefaultOverlay(hookScript string, scope *kiroReclaimScope) error {
	return removeKiroV2AgentHooksKeeping(kiroBuiltInDefaultAgentPath(), hookScript, false, scope)
}

// kiroCommandOwned reports whether a v3 hook command is DefenseClaw's by its
// text: it runs the current hook command, carries the native launcher's
// hook --connector kiro arguments, or is a Windows bridge Setup wrote. A
// command that only names kiro-hook.sh is not: a user's own hook of that name
// (C:\Users\me\hooks\kiro-hook.sh, /home/me/bin/kiro-hook.sh --flag) was
// removed by the v3 repair and uninstall (GAP-1932). DefenseClaw's script in
// another data directory, or a copy, is claimed by its .defenseclaw shape or
// its binding (editedDefenseClawHookCommandByAnyPath), as in the other
// connectors, and every entry Setup writes is named defenseclaw-*.
func kiroCommandOwned(command, hookScript string) bool {
	command = strings.TrimSpace(command)
	hookScript = strings.TrimSpace(hookScript)
	if command == "" {
		return false
	}
	if hookScript != "" && (command == hookScript || strings.Contains(command, hookScript)) {
		return true
	}
	if strings.Contains(command, "hook --connector kiro") {
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
