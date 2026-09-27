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

package connector

import (
	"encoding/json"
	"path/filepath"
	"strings"
)

// AntigravityTrustedShellArgs projects the arguments of an agy run_command
// call onto the {"CommandLine": ...} shape the trusted-action parser proves,
// and returns the call's Cwd separately as the command's working directory.
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
func AntigravityTrustedShellArgs(toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	if strings.TrimSpace(toolName) == "send_command_input" {
		out, ok := antigravityCommandInputArgs(args)
		return out, "", ok
	}
	if strings.TrimSpace(toolName) != "run_command" || antigravityValidateUniqueJSON(args) != nil {
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
	out, err := encodeTrustedShellArgs(map[string]string{"CommandLine": *command})
	if err != nil {
		return args, "", false
	}
	return out, cwd, true
}

// antigravityCommandInputArgs projects an agy send_command_input call (text
// written to the stdin of a command run_command started: CommandId, Input,
// WaitMs, Terminate and the model's labels) onto {"CommandLine": Input}, so
// the input is judged as a shell command: the running command is often a
// shell, and unprojected the call had no command facts at all, so a
// CRITICAL command rule allowed it. Only Input is read; the other fields
// never change what reaches the process, so the projection judges the
// input whatever else the call carries (keys must still be unique). A call
// without input text (Terminate alone) is left alone.
func antigravityCommandInputArgs(args json.RawMessage) (json.RawMessage, bool) {
	if antigravityValidateUniqueJSON(args) != nil {
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
	out, err := encodeTrustedShellArgs(map[string]string{"CommandLine": input})
	if err != nil {
		return args, false
	}
	return out, true
}
