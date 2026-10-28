// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// removeWindowsManagedClaudeCommands removes only handlers whose executable
// is the exact per-user DefenseClaw launcher, run directly (0.8.x, managed)
// or through the cmd.exe launcher guard 1.0.0-1.0.3 per-user Setup wrote
// (GAP-0587). It preserves other handlers in a shared matcher group and
// leaves all unrelated settings intact.
func removeWindowsManagedClaudeCommands(raw []byte, executable string) ([]byte, int, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil || settings == nil {
		return nil, 0, fmt.Errorf("the Claude settings must be a JSON object: %v", err)
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(settings["hooks"], &events); err != nil {
		if len(settings["hooks"]) == 0 {
			return raw, 0, nil
		}
		return nil, 0, fmt.Errorf("the Claude hooks must be a JSON object: %w", err)
	}
	removed := 0
	for event, value := range events {
		eventRemoved := 0
		var groups []json.RawMessage
		if err := json.Unmarshal(value, &groups); err != nil {
			return nil, 0, fmt.Errorf("the Claude hooks.%s must be an array: %w", event, err)
		}
		keptGroups := make([]json.RawMessage, 0, len(groups))
		for _, group := range groups {
			var entry map[string]json.RawMessage
			if err := json.Unmarshal(group, &entry); err != nil || entry == nil {
				return nil, 0, fmt.Errorf("the Claude hooks.%s contains an invalid matcher", event)
			}
			var handlers []json.RawMessage
			if err := json.Unmarshal(entry["hooks"], &handlers); err != nil {
				return nil, 0, fmt.Errorf("the Claude hooks.%s contains invalid handlers: %w", event, err)
			}
			kept := make([]json.RawMessage, 0, len(handlers))
			for _, handler := range handlers {
				var hook struct {
					Command string `json:"command"`
				}
				if err := json.Unmarshal(handler, &hook); err != nil {
					return nil, 0, fmt.Errorf("the Claude hooks.%s contains an invalid handler: %w", event, err)
				}
				if windowsManagedHookCommandIs(hook.Command, executable) || windowsManagedClaudeLauncherGuardIs(handler, executable) {
					removed++
					eventRemoved++
				} else {
					kept = append(kept, handler)
				}
			}
			if len(kept) == 0 && len(handlers) != 0 {
				continue
			}
			if len(kept) != len(handlers) {
				entry["hooks"], _ = json.Marshal(kept)
				group, _ = json.Marshal(entry)
			}
			keptGroups = append(keptGroups, group)
		}
		if eventRemoved != 0 && len(keptGroups) == 0 {
			delete(events, event)
		} else if eventRemoved != 0 {
			events[event], _ = json.Marshal(keptGroups)
		}
	}
	if removed == 0 {
		return raw, 0, nil
	}
	if len(events) == 0 {
		delete(settings, "hooks")
	} else {
		settings["hooks"], _ = json.Marshal(events)
	}
	out, err := json.MarshalIndent(settings, "", "  ")
	return append(out, '\n'), removed, err
}

// windowsClaudeHooksNamingDefenseClaw describes, in a stable order, each
// hook command in Claude Code settings that names a DefenseClaw launcher or
// binary (defenseclaw-hook, defenseclaw-gateway, defenseclaw.exe), whatever
// its shape, as "<event>: a hook command naming <launcher> (arguments not
// shown)" (#1286). It never returns the command: a hand-written command can
// carry credentials or other private arguments, and the description goes
// into the uninstall result and the lifecycle log. Settings that are not a
// JSON object are an error, so a caller never reports "none" for a file it
// could not inspect.
func windowsClaudeHooksNamingDefenseClaw(raw []byte) ([]string, error) {
	var settings map[string]any
	if err := json.Unmarshal(raw, &settings); err != nil || settings == nil {
		return nil, errors.New("the Claude settings must be a JSON object")
	}
	events, _ := settings["hooks"].(map[string]any)
	names := make([]string, 0, len(events))
	for event := range events {
		names = append(names, event)
	}
	sort.Strings(names)
	var found []string
	for _, event := range names {
		label := windowsClaudeHookEventLabel(event)
		for _, launcher := range windowsClaudeHookLaunchers(events[event], nil) {
			found = append(found, label+": a hook command naming "+launcher+" (arguments not shown)")
		}
	}
	return found, nil
}

// windowsClaudeHookEventNamePattern is the shape of a Claude Code hook event
// name. Another key is user text and is not repeated.
var windowsClaudeHookEventNamePattern = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9_-]{0,63}$`)

func windowsClaudeHookEventLabel(event string) string {
	if windowsClaudeHookEventNamePattern.MatchString(event) {
		return event
	}
	return "an unrecognized hook event"
}

// windowsClaudeHookLaunchers walks one hook event's value and appends, in
// file order (object keys sorted), the DefenseClaw launcher each "command"
// string names.
func windowsClaudeHookLaunchers(value any, found []string) []string {
	switch typed := value.(type) {
	case []any:
		for _, item := range typed {
			found = windowsClaudeHookLaunchers(item, found)
		}
	case map[string]any:
		if command, ok := typed["command"].(string); ok {
			launcher := windowsDefenseClawLauncherNamed(command)
			if args, ok := typed["args"].([]any); ok && launcher == "" {
				// A launcher guard names the launcher in its arguments.
				for _, arg := range args {
					if arg, ok := arg.(string); ok && launcher == "" {
						launcher = windowsDefenseClawLauncherNamed(arg)
					}
				}
			}
			if launcher != "" {
				found = append(found, launcher)
			}
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			if key != "command" {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			found = windowsClaudeHookLaunchers(typed[key], found)
		}
	}
	return found
}

// windowsDefenseClawLauncherNamed returns the DefenseClaw launcher or binary
// a command names, "" for none.
func windowsDefenseClawLauncherNamed(command string) string {
	lower := strings.ToLower(command)
	for _, name := range []string{"defenseclaw-hook", "defenseclaw-gateway", "defenseclaw.exe"} {
		if strings.Contains(lower, name) {
			return name
		}
	}
	return ""
}

// windowsManagedClaudeLauncherGuardIs reports whether handler is the exact
// generated launcher guard running executable's Claude Code hook.
func windowsManagedClaudeLauncherGuardIs(handler json.RawMessage, executable string) bool {
	var hook map[string]interface{}
	if err := json.Unmarshal(handler, &hook); err != nil {
		return false
	}
	launcher, hookArgs, ok := connector.ClaudeCodeLauncherGuardTarget(hook)
	return ok && strings.Join(hookArgs, " ") == "hook --connector claudecode" &&
		strings.EqualFold(strings.ReplaceAll(launcher, "/", `\`), strings.ReplaceAll(executable, "/", `\`))
}

func windowsManagedHookCommandIs(command, executable string) bool {
	command = strings.TrimSpace(command)
	if strings.HasPrefix(command, "& ") {
		command = strings.TrimSpace(command[2:])
	}
	if strings.HasPrefix(command, `"`) || strings.HasPrefix(command, `'`) {
		quote := command[:1]
		end := strings.Index(command[1:], quote)
		if end < 0 {
			return false
		}
		return strings.EqualFold(strings.ReplaceAll(command[1:end+1], "/", `\`), strings.ReplaceAll(executable, "/", `\`)) &&
			(len(command) == end+2 || command[end+2] == ' ')
	}
	command = strings.ReplaceAll(command, "/", `\`)
	executable = strings.ReplaceAll(executable, "/", `\`)
	return strings.EqualFold(command, executable) ||
		(len(command) > len(executable) && strings.EqualFold(command[:len(executable)], executable) && command[len(executable)] == ' ')
}
