// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"strings"
)

// codexBlockAnswer reports an answer Codex reads as a block of event: one
// event-shaped JSON object on stdout and exit 0, as the native hook gives it
// (emitCodexBlock). Codex runs a prompt whose hook exits 2: it reads a
// non-zero UserPromptSubmit status as a hook failure, not a block.
func codexBlockAnswer(event string, code int, stdout string) bool {
	if code != 0 {
		return false
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 1 {
		return false
	}
	var answer map[string]any
	if json.Unmarshal([]byte(lines[0]), &answer) != nil {
		return false
	}
	nested, _ := answer["hookSpecificOutput"].(map[string]any)
	switch event {
	case "PreToolUse":
		return nested["hookEventName"] == "PreToolUse" && nested["permissionDecision"] == "deny"
	case "PermissionRequest":
		decision, _ := nested["decision"].(map[string]any)
		return nested["hookEventName"] == "PermissionRequest" && decision["behavior"] == "deny"
	case "SessionStart", "PreCompact", "PostCompact":
		return answer["continue"] == false
	}
	return answer["decision"] == "block"
}
