// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

// Package antigravityargs reads Google Antigravity (agy) hook calls: the
// toolCall envelope of a PreToolUse body and the run_command projection the
// trusted-action parser proves. The gateway's agy hook profile and the hook
// client (hookpaths.ResolveConnector) both read a call through it, so the
// client describes the same tool, arguments and working directory the
// gateway judges. The client read only the Claude Code shaped
// tool_name/tool_input, so it listed no write targets for an agy call and a
// managed (hook-socket peer) gateway, which cannot open the home, had no
// placement for a write only those targets show (rel-1-0-10:GAP-1132).
package antigravityargs

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// MaxJSONNestingDepth is the deepest JSON nesting ValidateUniqueJSON accepts.
const MaxJSONNestingDepth = 64

// ToolCall returns the tool name and the literal toolCall.args JSON object of
// an authenticated agy hook body. It rejects malformed JSON, duplicate JSON
// object keys, alias collisions, a blank name and non-object args (ok false),
// so ambiguous input never acquires structured authority.
func ToolCall(rawPayload []byte) (name string, args json.RawMessage, ok bool) {
	if ValidateUniqueJSON(rawPayload) != nil {
		return "", nil, false
	}
	var payload map[string]json.RawMessage
	if json.Unmarshal(rawPayload, &payload) != nil {
		return "", nil, false
	}
	toolCallRaw, ok := uniqueRawField(payload, "toolCall", "tool_call")
	if !ok || !rawJSONObject(toolCallRaw) {
		return "", nil, false
	}
	var toolCall map[string]json.RawMessage
	if json.Unmarshal(toolCallRaw, &toolCall) != nil {
		return "", nil, false
	}
	nameRaw, ok := uniqueRawField(toolCall, "name", "tool_name", "toolName")
	if !ok || json.Unmarshal(nameRaw, &name) != nil || strings.TrimSpace(name) == "" {
		return "", nil, false
	}
	argsRaw, ok := uniqueRawField(toolCall, "args", "arguments", "tool_input", "toolInput")
	if !ok || !rawJSONObject(argsRaw) {
		return "", nil, false
	}
	return name, append(json.RawMessage(nil), argsRaw...), true
}

// TrustedShellArgs projects the arguments of an agy run_command call onto
// the {"CommandLine": ...} shape the trusted-action parser proves, and
// returns the call's Cwd separately as the command's working directory.
//
// agy 1.2's run_command schema requires WaitMsBeforeAsync, toolSummary and
// toolAction next to CommandLine and Cwd, and offers IsDaemon, RunPersistent,
// RequestedTerminalID and BypassSandbox (run outside agy's own sandbox).
// With those left in, every real call parsed only partially. Cwd is where
// agy runs the command; left in the arguments, any
// Cwd other than the session's workspace (a subdirectory, /tmp, or the
// sandbox path of a mounted workspace, which the gateway sees under its host
// path) conflicted with the request's working directory and the parse was
// ambiguous. Either way no command rule could close its trusted-action proof
// and a CRITICAL finding stayed an allowed candidate.
//
// Every one of those fields still runs CommandLine in a shell, so the
// projection keeps only the command. It is exact or refused (ok false,
// arguments unchanged): every key must be unique and known, CommandLine a
// string, Cwd an absolute path, WaitMsBeforeAsync a number, IsDaemon,
// RunPersistent and BypassSandbox booleans, and the model's labels and the
// terminal ID strings; each optional field may also be null.
//
// send_command_input (text written to the stdin of a command run_command
// started: CommandId, Input, WaitMs, Terminate and the model's labels) is
// projected onto {"CommandLine": Input}, so the input is judged as a shell
// command: the running command is often a shell, and unprojected the call
// had no command facts at all, so a CRITICAL command rule allowed it. Only
// Input is read; the other fields never change what reaches the process, so
// the projection judges the input whatever else the call carries (keys must
// still be unique). A call without input text (Terminate alone) is left
// alone.
func TrustedShellArgs(toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	if strings.TrimSpace(toolName) == "send_command_input" {
		out, ok := commandInputArgs(args)
		return out, "", ok
	}
	if strings.TrimSpace(toolName) != "run_command" || ValidateUniqueJSON(args) != nil {
		return args, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, "", false
	}
	var command *string
	for key, raw := range fields {
		switch key {
		case "CommandLine":
			if json.Unmarshal(raw, &command) != nil || command == nil {
				return args, "", false
			}
		case "Cwd":
			var dir *string
			if json.Unmarshal(raw, &dir) != nil {
				return args, "", false
			}
			if dir != nil {
				if !filepath.IsAbs(*dir) {
					return args, "", false
				}
				cwd = *dir
			}
		case "WaitMsBeforeAsync":
			var ms *float64
			if json.Unmarshal(raw, &ms) != nil {
				return args, "", false
			}
		case "IsDaemon", "RunPersistent", "BypassSandbox":
			var flag *bool
			if json.Unmarshal(raw, &flag) != nil {
				return args, "", false
			}
		case "toolSummary", "toolAction", "RequestedTerminalID":
			var label *string
			if json.Unmarshal(raw, &label) != nil {
				return args, "", false
			}
		default:
			return args, "", false
		}
	}
	if command == nil {
		return args, "", false
	}
	out, err := encodeCommandLine(*command)
	if err != nil {
		return args, "", false
	}
	return out, cwd, true
}

func commandInputArgs(args json.RawMessage) (json.RawMessage, bool) {
	if ValidateUniqueJSON(args) != nil {
		return args, false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, false
	}
	var input string
	if raw, ok := fields["Input"]; !ok || json.Unmarshal(raw, &input) != nil || strings.TrimSpace(input) == "" {
		return args, false
	}
	out, err := encodeCommandLine(input)
	if err != nil {
		return args, false
	}
	return out, true
}

// encodeCommandLine is {"CommandLine": command} without HTML escaping, so
// the text fallback reads the same text the call carried.
func encodeCommandLine(command string) (json.RawMessage, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]string{"CommandLine": command}); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

func uniqueRawField(parent map[string]json.RawMessage, keys ...string) (json.RawMessage, bool) {
	var found json.RawMessage
	for _, key := range keys {
		value, ok := parent[key]
		if !ok {
			continue
		}
		if found != nil {
			return nil, false
		}
		found = value
	}
	return found, found != nil
}

func rawJSONObject(raw json.RawMessage) bool {
	trimmed := bytes.TrimSpace(raw)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}

// ValidateUniqueJSON reports an error for raw that is not exactly one JSON
// value, repeats a key in any object, or nests past MaxJSONNestingDepth.
func ValidateUniqueJSON(raw []byte) error {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := consumeUniqueJSONValue(dec, 0); err != nil {
		return err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("multiple JSON values")
		}
		return err
	}
	return nil
}

func consumeUniqueJSONValue(dec *json.Decoder, depth int) error {
	token, err := dec.Token()
	if err != nil {
		return err
	}
	delim, ok := token.(json.Delim)
	if !ok {
		return nil
	}
	if depth >= MaxJSONNestingDepth {
		return fmt.Errorf("JSON nesting exceeds maximum depth of %d", MaxJSONNestingDepth)
	}
	switch delim {
	case '{':
		seen := make(map[string]struct{})
		for dec.More() {
			keyToken, err := dec.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return fmt.Errorf("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate JSON field %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return fmt.Errorf("invalid JSON object terminator")
		}
	case '[':
		for dec.More() {
			if err := consumeUniqueJSONValue(dec, depth+1); err != nil {
				return err
			}
		}
		end, err := dec.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return fmt.Errorf("invalid JSON array terminator")
		}
	default:
		return fmt.Errorf("unexpected JSON delimiter %q", delim)
	}
	return nil
}
