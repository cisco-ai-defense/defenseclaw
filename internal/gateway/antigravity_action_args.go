// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"strings"
)

const antigravityRunCommandMetadataMaxBytes = 4096

// antigravityRunCommandMetadata lists the arguments Antigravity's run_command
// carries beside CommandLine and Cwd. They are scheduling and UI annotations
// (how long to wait before backgrounding, the model's own safety claim, the
// status-line text), never command text, and each has one expected type.
var antigravityRunCommandMetadata = map[string]func(any) bool{
	"WaitMsBeforeAsync": antigravityNonNegativeNumber,
	"SafeToAutoRun":     antigravityBoolean,
	"Blocking":          antigravityBoolean,
	"toolAction":        antigravityBoundedText,
	"toolSummary":       antigravityBoundedText,
}

func antigravityNonNegativeNumber(value any) bool {
	number, ok := value.(json.Number)
	if !ok {
		return false
	}
	parsed, err := number.Float64()
	return err == nil && parsed >= 0
}

func antigravityBoolean(value any) bool {
	_, ok := value.(bool)
	return ok
}

func antigravityBoundedText(value any) bool {
	text, ok := value.(string)
	return ok && len(text) <= antigravityRunCommandMetadataMaxBytes && !strings.ContainsRune(text, 0)
}

// agentHookTrustedActionArgs returns the tool arguments ActionFacts analyzes
// for one hook call. Antigravity's run_command sends its metadata keys beside
// CommandLine and Cwd; ActionFacts treats every unknown key as an unparsed
// operand, so a real Antigravity command never produced complete command
// facts and no command-fact rule could match it. When the arguments are
// exactly CommandLine, Cwd and those keys with their expected value types,
// the metadata is dropped from the analyzed copy; any other shape is
// returned unchanged and keeps its conservative parse. The audited
// and inspected arguments are not changed. Kiro's shell tools get the same
// treatment (kiroShellActionArgs).
func agentHookTrustedActionArgs(connectorName, toolName string, args json.RawMessage) json.RawMessage {
	if strings.EqualFold(strings.TrimSpace(connectorName), "kiro") {
		return kiroShellActionArgs(toolName, args)
	}
	if strings.EqualFold(strings.TrimSpace(connectorName), "amp") {
		return ampShellActionArgs(toolName, args)
	}
	if !strings.EqualFold(strings.TrimSpace(connectorName), "antigravity") ||
		!strings.EqualFold(strings.TrimSpace(toolName), "run_command") {
		return args
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(args, &object); err != nil || object == nil {
		return args
	}
	projected := make(map[string]json.RawMessage, len(object))
	dropped := false
	for key, raw := range object {
		valid, metadata := antigravityRunCommandMetadata[key]
		if !metadata {
			if key != "CommandLine" && key != "Cwd" {
				// Not the reviewed run_command schema: analyze it as sent.
				return args
			}
			projected[key] = raw
			continue
		}
		decoder := json.NewDecoder(bytes.NewReader(raw))
		decoder.UseNumber()
		var value any
		if err := decoder.Decode(&value); err != nil || !valid(value) {
			return args
		}
		dropped = true
	}
	if !dropped {
		return args
	}
	out, err := json.Marshal(projected)
	if err != nil {
		return args
	}
	return out
}

// kiroShellActionArgs drops what Kiro's shell tools send beside the closed
// shell schema ActionFacts accepts: the CLI 2.x `shell` tool's
// __tool_use_purpose note, and the unset cwd, description and timeout (JSON
// null) of the v3 `execute_bash` tool. Neither carries command text, but as sent every real
// Kiro command parsed as partial, so a command-fact rule matched only as text
// (CRITICAL, allow). Any other key, or a note of another type, is kept, so an
// unreviewed shape keeps its conservative parse.
func kiroShellActionArgs(toolName string, args json.RawMessage) json.RawMessage {
	switch strings.ToLower(strings.TrimSpace(toolName)) {
	case "shell", "execute_bash":
	default:
		return args
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(args, &object); err != nil || object == nil || !jsonObjectKeysUnique(args) {
		return args
	}
	projected := make(map[string]json.RawMessage, len(object))
	dropped := false
	for key, raw := range object {
		switch key {
		case "__tool_use_purpose":
			var value any
			if err := json.Unmarshal(raw, &value); err != nil || !antigravityBoundedText(value) {
				return args
			}
			dropped = true
		case "cwd", "description", "timeout":
			if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
				dropped = true
				continue
			}
			projected[key] = raw
		default:
			projected[key] = raw
		}
	}
	if !dropped {
		return args
	}
	out, err := json.Marshal(projected)
	if err != nil {
		return args
	}
	return out
}

// ampShellActionArgs gives Amp's Bash tool arguments, {"cmd": ..., "cwd": ...},
// the "command" key of the shell schema ActionFacts reads. Under "cmd"
// ActionFacts found no command at all, so every Amp command stayed on the
// fallback lane: a rule whose match needs command facts, such as a CRITICAL
// match with a runtime-expanded redirect target ("> ~/out.txt"), was only
// detected while Claude Code and Codex blocked it. Any other shape, including
// an unknown key or a "command" key beside "cmd", is returned unchanged.
func ampShellActionArgs(toolName string, args json.RawMessage) json.RawMessage {
	if !strings.EqualFold(strings.TrimSpace(toolName), "bash") {
		return args
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(args, &object); err != nil || object == nil || !jsonObjectKeysUnique(args) {
		return args
	}
	if _, ok := object["cmd"]; !ok {
		return args
	}
	projected := make(map[string]json.RawMessage, len(object))
	for key, raw := range object {
		switch key {
		case "cmd":
			projected["command"] = raw
		case "cwd":
			projected[key] = raw
		default:
			return args
		}
	}
	out, err := json.Marshal(projected)
	if err != nil {
		return args
	}
	return out
}

// jsonObjectKeysUnique reports whether raw is one JSON object whose top-level
// keys are all distinct. A projection must not hide a duplicate key that the
// unprojected parse would report as ambiguous.
func jsonObjectKeysUnique(raw json.RawMessage) bool {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	if token, err := decoder.Token(); err != nil || token != json.Delim('{') {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] {
			return false
		}
		seen[key] = true
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return false
		}
	}
	return true
}
