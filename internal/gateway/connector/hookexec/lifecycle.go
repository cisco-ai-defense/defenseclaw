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

// loopingStopEvents are stop events outside the neutral set whose only native
// veto re-enters the agent loop. Antigravity's Stop decision "continue" starts
// another turn; DefenseClaw renders allow for every Stop verdict there, so its
// native runners need no neutral failure rule for it.
var loopingStopEvents = map[string][]string{
	"antigravity": {"Stop"},
}

// NeutralLifecycleEvents is the exact event set whose denial would prolong a
// stopped session or cannot stop a tool. Kiro PostToolUse and OpenCode
// tool.execute.after report tool results, so they are outside this stop set.
// The set is shared by the foreign-hook guard, standalone hook failures, and
// the gateway's failed checks, recovered evaluator panics included
// (LifecycleEvent).
func NeutralLifecycleEvents(connector string) []string {
	return append([]string(nil), neutralLifecycleSets[connector]...)
}

// LifecycleEvent reports an event whose denial keeps the agent running and
// repeats the hook instead of stopping a tool call: a neutral lifecycle event
// or a looping stop event. The gateway never answers a failed check on one
// with a retrying block, a recovered evaluator panic included.
func LifecycleEvent(connector, event string) bool {
	if NeutralLifecycleEvent(connector, event) {
		return true
	}
	for _, candidate := range loopingStopEvents[connector] {
		if strings.TrimSpace(event) == candidate {
			return true
		}
	}
	return false
}

// LifecycleEvents lists every LifecycleEvent of connector: the neutral set
// followed by the looping stop events.
func LifecycleEvents(connector string) []string {
	return append(NeutralLifecycleEvents(connector), loopingStopEvents[connector]...)
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
