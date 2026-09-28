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
	"bytes"
	"encoding/json"
	"strings"
)

// trustedShellArg is how TrustedShellArgs handles a shell tool argument it
// knows, and the JSON value the argument must have (null is always
// accepted).
type trustedShellArg uint8

const (
	// trustedShellWorkdir is the command's working directory, a string.
	trustedShellWorkdir trustedShellArg = iota + 1
	// The others change neither what runs nor where: the model's labels
	// (a string), timeouts and waits (a number), background, detach, PTY
	// and notification switches (a boolean), watch patterns (a list of
	// strings), and Hermes' notify (a boolean or a list of strings).
	trustedShellLabel
	trustedShellNumber
	trustedShellFlag
	trustedShellStrings
	trustedShellNotify
)

// copilotShellArgs are the control arguments of Copilot CLI 1.0.8x's bash
// and powershell tools. shellId is not among them: a reused shell keeps the
// directory it was created in, which the call does not name.
var copilotShellArgs = map[string]trustedShellArg{
	"description": trustedShellLabel, "mode": trustedShellLabel,
	"initial_wait": trustedShellNumber, "detach": trustedShellFlag,
}

// trustedShellTools lists, per connector and shell tool (as the tool is
// named to hooks), the arguments TrustedShellArgs takes out, from the
// installed harnesses' tool schemas:
//
//   - OpenCode 1.18 bash: workdir, absolute or relative to the project
//     (timeout is part of the shell shape the parser proves).
//   - Hermes 0.21 terminal: workdir; background, timeout, pty, notify, and
//     the legacy notify_on_complete and watch_patterns.
//   - Amp shell_command: workdir; timeout_ms.
//   - Cursor Agent preToolUse Shell: cwd, the call's working_directory
//     (timeout is part of the shell shape).
//   - Devin 3000.10 exec: workdir, absolute; timeout, tty.
//   - Kiro CLI 2.24 shell: working_dir and the __tool_use_purpose note;
//     execute_bash (also --v3): also summary, and cwd, description and
//     timeout, which v3 sends unset (null).
//   - Copilot CLI 1.0.8x bash and powershell: copilotShellArgs.
//
// Arguments that change where or how the command runs are left for the
// parser, which does not prove them: Devin's env, shell_flavor and shell_id,
// and Copilot's shellId. Claude Code's and Codex's shell calls take their
// own hook paths (Codex passes its hooks only the command); OpenHands'
// terminal, agy's run_command and Hermes' process have their own
// projections, and OmniGent's sys_os_shell has only the command.
var trustedShellTools = map[string]map[string]map[string]trustedShellArg{
	"opencode": {"bash": {"workdir": trustedShellWorkdir}},
	"hermes": {"terminal": {
		"workdir": trustedShellWorkdir, "background": trustedShellFlag, "timeout": trustedShellNumber,
		"pty": trustedShellFlag, "notify": trustedShellNotify,
		"notify_on_complete": trustedShellFlag, "watch_patterns": trustedShellStrings,
	}},
	"amp":    {"shell_command": {"workdir": trustedShellWorkdir, "timeout_ms": trustedShellNumber}},
	"cursor": {"Shell": {"cwd": trustedShellWorkdir}},
	"devin":  {"exec": {"workdir": trustedShellWorkdir, "timeout": trustedShellNumber, "tty": trustedShellFlag}},
	"kiro": {
		"shell": {"working_dir": trustedShellWorkdir, "__tool_use_purpose": trustedShellLabel},
		"execute_bash": {
			"working_dir": trustedShellWorkdir, "summary": trustedShellLabel,
			"cwd": trustedShellWorkdir, "description": trustedShellLabel, "timeout": trustedShellNumber,
		},
	},
	"copilot": {"bash": copilotShellArgs, "powershell": copilotShellArgs},
}

// TrustedShellArgs takes the arguments trustedShellTools lists out of a
// shell tool call and returns the working directory the call names
// separately, as the command's working directory; "" when it names none
// (the directory is absent, null or empty), so the command runs in the
// session's directory.
//
// Left in the arguments, the directory was a second working directory next
// to the request's. Whenever the two differed (the model named a
// subdirectory or another directory, the request's was symlink-resolved on
// the host, or a sandbox's was mapped to the host directory it is mounted
// from) the trusted-action parse was ambiguous. A directory key the parser
// does not read as one (Kiro's working_dir), and any control argument it
// does not know, left it partial. Either way no command rule could close
// its trusted-action proof and a CRITICAL finding stayed an allowed
// candidate.
//
// The other arguments are passed on unchanged for the parser to judge.
// Refused (ok false, arguments unchanged) when the call has none of the
// listed arguments, or unless the arguments are a JSON object whose keys
// are unique and every listed argument has its JSON value.
func TrustedShellArgs(connectorName, toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	known := trustedShellTools[strings.ToLower(strings.TrimSpace(connectorName))][strings.TrimSpace(toolName)]
	if len(known) == 0 || antigravityValidateUniqueJSON(args) != nil {
		return args, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, "", false
	}
	taken := false
	for key, raw := range fields {
		kind, listed := known[key]
		if !listed {
			continue
		}
		if !trustedShellArgValue(kind, raw) {
			return args, "", false
		}
		if kind == trustedShellWorkdir {
			var dir *string
			_ = json.Unmarshal(raw, &dir)
			if dir != nil {
				cwd = *dir
			}
		}
		delete(fields, key)
		taken = true
	}
	if !taken {
		return args, "", false
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return args, "", false
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), cwd, true
}

func trustedShellArgValue(kind trustedShellArg, raw json.RawMessage) bool {
	switch kind {
	case trustedShellWorkdir, trustedShellLabel:
		var text *string
		return json.Unmarshal(raw, &text) == nil
	case trustedShellNumber:
		var number *float64
		return json.Unmarshal(raw, &number) == nil
	case trustedShellFlag:
		var flag *bool
		return json.Unmarshal(raw, &flag) == nil
	case trustedShellStrings:
		var list []string
		return json.Unmarshal(raw, &list) == nil
	case trustedShellNotify:
		var flag *bool
		var list []string
		return json.Unmarshal(raw, &flag) == nil || json.Unmarshal(raw, &list) == nil
	}
	return false
}

// shellCommandKeys names, per connector and shell tool (as the tool is
// named to hooks), the argument that holds the command: the tools
// trustedShellTools lists, OpenHands' terminal, agy's run_command,
// OmniGent's sys_os_shell, and Claude Code's and Codex's Bash.
var shellCommandKeys = map[string]map[string]string{
	"opencode":    {"bash": "command"},
	"hermes":      {"terminal": "command"},
	"amp":         {"shell_command": "command"},
	"cursor":      {"Shell": "command"},
	"devin":       {"exec": "command"},
	"kiro":        {"shell": "command", "execute_bash": "command"},
	"copilot":     {"bash": "command", "powershell": "command"},
	"openhands":   {"terminal": "command"},
	"antigravity": {"run_command": "CommandLine"},
	"omnigent":    {"sys_os_shell": "command"},
	"claudecode":  {"Bash": "command"},
	"codex":       {"Bash": "command"},
}

// ShellCommandArgs reduces a shell tool call to its command, in the shell
// shape the trusted-action parser proves ({"command": ...}, or agy's
// {"CommandLine": ...}), whatever else the call carries.
//
// The trusted-action projections (TrustedShellArgs and the connectors' own)
// take out only the arguments they know, with the JSON values they expect.
// An argument they do not list, or a listed one with another value, stays
// next to the command, and the parse is only partial: no command rule can
// close its trusted-action proof, and a CRITICAL command finding is an
// allowed candidate. For a sandbox, whose hooks are the only gate on its
// tool calls, the gateway also judges the command alone (see
// inspectSandboxShellToolPolicyCtx), so one extra argument cannot turn a
// block into an allow. The reduced shape is only ever used to add a
// verdict, never to lift one: the arguments it drops may change how the
// command runs.
//
// The command is a non-blank string, or a non-empty list of strings (an
// argv). When the key repeats, the last value is the command, as JSON
// decoders in the harnesses read it. Refused (ok false) for any other tool,
// or unless the arguments are a JSON object with such a command.
func ShellCommandArgs(connectorName, toolName string, args json.RawMessage) (json.RawMessage, bool) {
	key := shellCommandKeys[strings.ToLower(strings.TrimSpace(connectorName))][strings.TrimSpace(toolName)]
	if key == "" {
		return nil, false
	}
	return shellCommandOnly(key, args)
}

// CursorShellCommandArgs reduces a Cursor beforeShellExecution payload to
// its command in the {"command": ...} shape, whatever else it carries (see
// ShellCommandArgs); CursorTrustedShellArgs refuses one whose cwd is
// neither a string nor null. Refused (ok false) for any other event, or
// unless the payload is a JSON object with a command.
func CursorShellCommandArgs(event string, payload json.RawMessage) (json.RawMessage, bool) {
	if canonicalHookEvent(event) != "beforeshellexecution" {
		return nil, false
	}
	return shellCommandOnly("command", payload)
}

func shellCommandOnly(key string, args json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return nil, false
	}
	var command interface{}
	var text string
	var argv []string
	switch raw := fields[key]; {
	case json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != "":
		command = text
	case json.Unmarshal(raw, &argv) == nil && len(argv) > 0:
		command = argv
	default:
		return nil, false
	}
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(map[string]interface{}{key: command}); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), true
}

// CursorTrustedShellArgs projects a Cursor beforeShellExecution payload onto
// the {"command": ...} shell shape and returns its cwd, the command's
// working directory. The event names no tool and has no tool_input: the
// payload is the call, its command and cwd next to Cursor's hook metadata
// (conversation, generation, model, version, workspace roots, user,
// transcript, sandbox). Taken as tool arguments, the whole payload parsed
// as an unknown tool's with unknown fields and a second working directory,
// so no command rule ever closed its trusted-action proof on this event.
//
// Refused (ok false, payload unchanged) for any other event, or unless the
// payload is a JSON object with unique keys, a non-blank string command and
// a string or null cwd.
func CursorTrustedShellArgs(event string, payload json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	if canonicalHookEvent(event) != "beforeshellexecution" || antigravityValidateUniqueJSON(payload) != nil {
		return payload, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(payload, &fields); err != nil || fields == nil {
		return payload, "", false
	}
	var command string
	if raw, present := fields["command"]; !present || json.Unmarshal(raw, &command) != nil || strings.TrimSpace(command) == "" {
		return payload, "", false
	}
	if raw, present := fields["cwd"]; present {
		var dir *string
		if json.Unmarshal(raw, &dir) != nil {
			return payload, "", false
		}
		if dir != nil {
			cwd = *dir
		}
	}
	out, err := encodeTrustedShellArgs(map[string]string{"command": command})
	if err != nil {
		return payload, "", false
	}
	return out, cwd, true
}
