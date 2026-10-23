// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "strings"

var neutralLifecycleSets = map[string][]string{
	"claudecode": {"Stop", "SubagentStop", "TeammateIdle", "StopFailure", "SessionEnd"},
	"codex":      {"Stop", "SubagentStop", "SessionEnd"},
	"cursor":     {"stop", "subagentStop", "sessionEnd"},
	"devin":      {"Stop", "SessionEnd"},
	"copilot":    {"agentStop", "subagentStop", "sessionEnd", "Stop", "SubagentStop"},
	"kiro":       {"Stop"},
	"opencode":   {"session.created", "session.updated", "session.status", "session.idle", "session.compacted", "session.error", "session.deleted"},
}

// NeutralLifecycleEvents is the exact event set whose denial would prolong a
// stopped session or cannot stop a tool. Kiro PostToolUse and OpenCode
// tool.execute.after report tool results, so they are outside this stop set.
// The set is shared by the foreign-hook guard, standalone hook failures, and
// gateway failures other than recovered panics. A closed recovered panic
// blocks these events too.
func NeutralLifecycleEvents(connector string) []string {
	return append([]string(nil), neutralLifecycleSets[connector]...)
}

// NeutralLifecycleEvent matches only the named lifecycle events. Cursor's
// event names are case insensitive in its native hook contract.
func NeutralLifecycleEvent(connector, event string) bool {
	event = strings.TrimSpace(event)
	for _, candidate := range neutralLifecycleSets[connector] {
		if connector == "cursor" && strings.EqualFold(event, candidate) || event == candidate {
			return true
		}
	}
	return false
}
