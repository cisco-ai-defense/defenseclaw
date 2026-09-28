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
// and inspected arguments are not changed.
func agentHookTrustedActionArgs(connectorName, toolName string, args json.RawMessage) json.RawMessage {
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
