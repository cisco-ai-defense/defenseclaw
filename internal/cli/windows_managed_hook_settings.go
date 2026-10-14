// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"fmt"
	"strings"
)

// removeWindowsManagedClaudeCommands removes only handlers whose executable
// is the exact per-user DefenseClaw launcher. It preserves other handlers in
// a shared matcher group and leaves all unrelated settings intact.
func removeWindowsManagedClaudeCommands(raw []byte, executable string) ([]byte, int, error) {
	var settings map[string]json.RawMessage
	if err := json.Unmarshal(raw, &settings); err != nil || settings == nil {
		return nil, 0, fmt.Errorf("Claude settings must be a JSON object: %v", err)
	}
	var events map[string]json.RawMessage
	if err := json.Unmarshal(settings["hooks"], &events); err != nil {
		if len(settings["hooks"]) == 0 {
			return raw, 0, nil
		}
		return nil, 0, fmt.Errorf("Claude hooks must be a JSON object: %w", err)
	}
	removed := 0
	for event, value := range events {
		eventRemoved := 0
		var groups []json.RawMessage
		if err := json.Unmarshal(value, &groups); err != nil {
			return nil, 0, fmt.Errorf("Claude hooks.%s must be an array: %w", event, err)
		}
		keptGroups := make([]json.RawMessage, 0, len(groups))
		for _, group := range groups {
			var entry map[string]json.RawMessage
			if err := json.Unmarshal(group, &entry); err != nil || entry == nil {
				return nil, 0, fmt.Errorf("Claude hooks.%s contains an invalid matcher", event)
			}
			var handlers []json.RawMessage
			if err := json.Unmarshal(entry["hooks"], &handlers); err != nil {
				return nil, 0, fmt.Errorf("Claude hooks.%s contains invalid handlers: %w", event, err)
			}
			kept := make([]json.RawMessage, 0, len(handlers))
			for _, handler := range handlers {
				var hook struct {
					Command string `json:"command"`
				}
				if err := json.Unmarshal(handler, &hook); err != nil {
					return nil, 0, fmt.Errorf("Claude hooks.%s contains an invalid handler: %w", event, err)
				}
				if windowsManagedHookCommandIs(hook.Command, executable) {
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
