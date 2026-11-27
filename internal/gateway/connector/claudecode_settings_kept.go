// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"path"
	"strings"
	"sync"
)

// claudeCodeSettingsRequiredGroups are the hook groups every registered
// Claude Code hook contract installs (the events all contracts share), with
// Setup's matcher, timeout and async flag. Sandboxes run Linux.
var claudeCodeSettingsRequiredGroups = sync.OnceValue(func() []claudeCodeHookGroup {
	registry := make(map[string]claudeCodeHookGroup, len(claudeCodeAllHookGroups))
	for _, group := range claudeCodeAllHookGroups {
		registry[group.eventType] = group
	}
	counts := map[string]int{}
	contracts := hookContractsForOS("claudecode", "linux")
	for _, contract := range contracts {
		seen := map[string]bool{}
		for _, event := range contract.Events {
			if !seen[event] {
				seen[event] = true
				counts[event]++
			}
		}
	}
	var out []claudeCodeHookGroup
	for _, group := range claudeCodeAllHookGroups {
		if len(contracts) > 0 && counts[group.eventType] == len(contracts) {
			out = append(out, registry[group.eventType])
		}
	}
	return out
})

// ClaudeCodeSettingsKeepsHooks names the first Claude Code hook event the
// "hooks" member of a settings document no longer serves with DefenseClaw's
// per-user hook, "" when it serves every event every supported Claude Code
// hook contract installs. A gateway judges a complete settings replacement
// with it when it cannot compare the replacement with the file it
// overwrites (a sandbox call that sent no settings snapshot): the laptop
// compares the two documents and blocks a replacement that drops any entry
// Setup installed, so such a replacement must still carry what Setup
// installs, on every event: an entry whose matcher covers Setup's, holding
// a synchronous, unconditional command handler that runs the hook script of
// the DefenseClaw data directory of one of homes ("~" or an absolute home)
// exactly as Setup renders it, with no shorter timeout than Setup's
// (substrate-1 GAP-0615, GAP-0619). A hand-written command, another
// script, extra arguments or an edited guard clause are not DefenseClaw's
// hook.
func ClaudeCodeSettingsKeepsHooks(hooks any, homes []string) string {
	commands := map[string]bool{}
	for _, home := range homes {
		home = strings.TrimSpace(home)
		var word string
		switch {
		case home == "~":
			word = "~/.defenseclaw/hooks/claude-code-hook.sh"
		case path.IsAbs(home) && path.Clean(home) == home && home != "/":
			word = posixHookCommandWord(home + "/.defenseclaw/hooks/claude-code-hook.sh")
		default:
			continue
		}
		commands[word] = true
		commands[claudeCodeMissingHookGuard(word)] = true
		commands[claudeCodeMissingHookGuardWith(word, claudeCodeManagedMissingHookGuardMessage)] = true
	}
	member, _ := hooks.(map[string]any)
	for _, group := range claudeCodeSettingsRequiredGroups() {
		if !claudeCodeSettingsEventServed(member[group.eventType], group, commands) {
			return group.eventType
		}
	}
	return ""
}

func claudeCodeSettingsEventServed(raw any, group claudeCodeHookGroup, commands map[string]bool) bool {
	entries, _ := raw.([]any)
	for _, rawEntry := range entries {
		entry, ok := rawEntry.(map[string]any)
		if !ok || !claudeCodeMatcherCovers(group.eventType, entry["matcher"], group.matcher) {
			continue
		}
		handlers, _ := entry["hooks"].([]any)
		for _, rawHandler := range handlers {
			if handler, ok := rawHandler.(map[string]any); ok && claudeCodeSettingsHandlerServes(handler, group, commands) {
				return true
			}
		}
	}
	return false
}

func claudeCodeSettingsHandlerServes(handler map[string]any, group claudeCodeHookGroup, commands map[string]bool) bool {
	for key := range handler {
		switch key {
		case "type", "command", "timeout", "async", "asyncRewake", "async_rewake", "if":
		default:
			return false
		}
	}
	if kind, _ := handler["type"].(string); kind != "command" {
		return false
	}
	if command, _ := handler["command"].(string); !commands[command] {
		return false
	}
	if asynchronous, err := claudeCodeHandlerAsync(handler); err != nil || asynchronous != group.async {
		return false
	}
	if condition, present := handler["if"]; present {
		if text, ok := condition.(string); !ok || text != "" {
			return false
		}
	}
	if raw, present := handler["timeout"]; present {
		if number, ok := raw.(json.Number); ok {
			value, err := number.Int64()
			if err != nil {
				return false
			}
			raw = value
		}
		seconds, ok := claudeCodeHookInteger(raw)
		if !ok || seconds < group.timeout {
			return false
		}
	}
	return true
}
