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

// encodeTrustedShellArgs is shared by the supported shell-tool adapters.
func encodeTrustedShellArgs(fields map[string]string) (json.RawMessage, error) {
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return nil, err
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), nil
}

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
//   - OpenCode V2 shell: workdir, absolute or relative to the project,
//     and background (timeout is part of the shell shape the parser proves).
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
//   - OpenClaw 2026.3 exec (judged through /api/v1/inspect/tool): workdir;
//     yieldMs, background, timeout, pty, and OpenClaw's own approval modes
//     ask and security.
//
// Arguments that change where or how the command runs are left for the
// parser, which does not prove them: Devin's env, shell_flavor and shell_id,
// Copilot's shellId, and OpenClaw's env, elevated, host and node. Claude Code's
// and Codex's shell calls take their own hook paths; the Codex exec_command
// hook resolves its workdir before proving the command. Agy's run_command
// and Hermes' process have their own projections.
var trustedShellTools = map[string]map[string]map[string]trustedShellArg{
	"opencode": {"shell": {"workdir": trustedShellWorkdir, "background": trustedShellFlag}},
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
	"openclaw": {"exec": {
		"workdir": trustedShellWorkdir, "yieldMs": trustedShellNumber, "background": trustedShellFlag,
		"timeout": trustedShellNumber, "pty": trustedShellFlag,
		"ask": trustedShellLabel, "security": trustedShellLabel,
	}},
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
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	toolName = strings.TrimSpace(toolName)
	known := trustedShellTools[connectorName][toolName]
	if len(known) == 0 || antigravityValidateUniqueJSON(args) != nil {
		return args, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, "", false
	}
	if connectorName == "opencode" && toolName == "shell" {
		// Preserve case-twin control fields for the conflicting-arguments
		// check. Projecting one away can otherwise make a V2 shell call look
		// complete even though its original directory/control key was ambiguous.
		seen := make(map[string]string, len(fields))
		for key := range fields {
			folded := strings.ToLower(key)
			if previous, exists := seen[folded]; exists {
				_, previousKnown := known[previous]
				_, currentKnown := known[key]
				if previousKnown || currentKnown {
					return args, "", false
				}
			}
			seen[folded] = key
		}
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
// trustedShellTools lists, agy's run_command, Claude Code's Bash, Codex's
// Bash and exec_command, and Amp's Bash ("cmd"). Any connector's bash,
// powershell or shell tool that is not listed here has its command under
// "command" (shellCommandTool).
var shellCommandKeys = map[string]map[string]string{
	"opencode":    {"shell": "command"},
	"hermes":      {"terminal": "command"},
	"amp":         {"shell_command": "command", "Bash": "cmd"},
	"cursor":      {"Shell": "command"},
	"devin":       {"exec": "command"},
	"kiro":        {"shell": "command", "execute_bash": "command"},
	"copilot":     {"bash": "command", "powershell": "command"},
	"antigravity": {"run_command": "CommandLine"},
	"claudecode":  {"Bash": "command"},
	"codex":       {"Bash": "command", "exec_command": "cmd"},
	"openclaw":    {"exec": "command"},
}

// shellCommandWorkdirKeys names the working-directory argument of the shell
// tools whose projection is not TrustedShellArgs (Amp's Bash, agy's
// run_command), and of the bash, powershell and shell tools no projection
// lists (the exact shell schema reads cwd or workdir).
var shellCommandWorkdirKeys = map[string]map[string][]string{
	"amp":         {"Bash": {"cwd"}},
	"antigravity": {"run_command": {"Cwd"}},
}

// shellCommandTool returns the argument that holds the command of the
// connector's shell tool toolName, and the key of the reduced shape the
// trusted-action parser proves; "" for a tool that is no shell tool.
//
// The exact shell schema (bash, powershell, and shell with its closed
// arguments) leaves any argument it does not know partial. A connector's
// tool of those names that the table did not list (Amp's Bash, which
// Amp also reports as bash; OpenCode's and Devin's bash; Claude Code's
// PowerShell) was therefore never judged on its command alone, and one
// extra argument turned a block into a detection-only allow (GAP-0694).
// Amp's Bash holds its command under cmd; the reduced shape names it
// command, as AmpBashTrustedShellArgs does.
func shellCommandTool(connectorName, toolName string) (key, out string) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	toolName = strings.TrimSpace(toolName)
	if key = shellCommandKeys[connectorName][toolName]; key != "" {
		if connectorName == "amp" && toolName == "Bash" {
			return key, "command"
		}
		return key, key
	}
	if connectorName == "amp" && strings.EqualFold(toolName, "bash") {
		return "cmd", "command"
	}
	switch strings.ToLower(toolName) {
	case "bash", "powershell", "shell":
		return "command", "command"
	}
	return "", ""
}

// ShellCommandArgs reduces a shell tool call to its command, in the shell
// shape the trusted-action parser proves ({"command": ...}, Codex
// exec_command's {"cmd": ...}, or agy's {"CommandLine": ...}), whatever else
// the call carries.
//
// The trusted-action projections (TrustedShellArgs and the connectors' own)
// take out only the arguments they know, with the JSON values they expect.
// An argument they do not list, or a listed one with another value, stays
// next to the command, and the parse is only partial: no command rule can
// close its trusted-action proof, and a CRITICAL command finding is an
// allowed candidate. The gateway also judges the command alone (see
// inspectSandboxShellToolPolicyCtx), so one extra argument cannot turn a
// block into an allow. The reduced shape is only ever used to add a
// verdict, never to lift one: the arguments it drops may change how the
// command runs.
//
// The command is a non-blank string, or a non-empty list of strings (an
// argv), under the tool's command key, or, when that key is absent, under
// the other of cmd and command (GAP-0694: Amp's Bash called with command
// and an extra key reached no rule). When both are present they must hold
// the same command; two different commands are refused, so the call is
// judged as unverified. When the key repeats, the last value is the command,
// as JSON decoders in the harnesses read it. A key that differs from the
// command key only in letter case (Command next to command) stays next to
// the command with its value: it names the same argument to a reader that
// folds case, so the gateway judges the call as conflicting arguments
// (GAP-0678, GAP-0686); a reduced shape whose key is not the call's refuses
// such a twin instead. Refused (ok false) for any other tool, or unless the
// arguments are a JSON object with such a command.
func ShellCommandArgs(connectorName, toolName string, args json.RawMessage) (json.RawMessage, bool) {
	key, out := shellCommandTool(connectorName, toolName)
	if key == "" {
		return nil, false
	}
	return shellCommandOnly(key, out, args)
}

// IsShellTool reports whether toolName is the connector's shell tool, as
// the tool is named to hooks (the tools ShellCommandArgs reduces).
func IsShellTool(connectorName, toolName string) bool {
	key, _ := shellCommandTool(connectorName, toolName)
	return key != ""
}

// ShellCommandCWD returns the working directory a shell tool call names
// under its tool's working-directory argument (shellCommandWorkdirKeys,
// the TrustedShellArgs working directories, cwd or workdir for the tools
// shellCommandTool reads by name), or "" when it names none or more than one.
// It is for a call whose projection was refused: the command judged on its
// own still runs there (GAP-0694: Amp's Bash and agy's run_command with an
// extra key were judged in the session's directory).
func ShellCommandCWD(connectorName, toolName string, args json.RawMessage) string {
	if !IsShellTool(connectorName, toolName) {
		return ""
	}
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	toolName = strings.TrimSpace(toolName)
	keys := shellCommandWorkdirKeys[connectorName][toolName]
	if connectorName == "amp" && strings.EqualFold(toolName, "bash") {
		keys = []string{"cwd"}
	}
	for key, kind := range trustedShellTools[connectorName][toolName] {
		if kind == trustedShellWorkdir {
			keys = append(keys, key)
		}
	}
	if len(keys) == 0 && shellCommandKeys[connectorName][toolName] == "" {
		keys = []string{"cwd", "workdir"}
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return ""
	}
	cwd := ""
	for _, key := range keys {
		var dir string
		if raw, ok := fields[key]; !ok || json.Unmarshal(raw, &dir) != nil || strings.TrimSpace(dir) == "" {
			continue
		}
		if cwd != "" && cwd != dir {
			return ""
		}
		cwd = dir
	}
	return cwd
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
	return shellCommandOnly("command", "command", payload)
}

func shellCommandOnly(key, out string, args json.RawMessage) (json.RawMessage, bool) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return nil, false
	}
	alias := map[string]string{"cmd": "command", "command": "cmd"}[key]
	used := key
	if _, present := fields[key]; !present && alias != "" {
		used = alias
	}
	command, ok := shellCommandValue(fields[used])
	if !ok {
		return nil, false
	}
	if other, present := fields[alias]; present && alias != "" && used != alias {
		// Both cmd and command: one command, or the call is unverified.
		if again, ok := shellCommandValue(other); !ok || !shellCommandsEqual(command, again) {
			return nil, false
		}
	}
	reduced := map[string]interface{}{out: command}
	for name, raw := range fields {
		if name != used && name != alias && (strings.EqualFold(name, used) || strings.EqualFold(name, out)) {
			if used != out {
				// The reduced shape renames the command key: a case
				// twin cannot be kept next to it as the call named it.
				return nil, false
			}
			reduced[name] = raw
		}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(reduced); err != nil {
		return nil, false
	}
	return bytes.TrimSuffix(buf.Bytes(), []byte("\n")), true
}

// shellCommandValue reads a shell command: a non-blank string, or a
// non-empty list of strings (an argv).
func shellCommandValue(raw json.RawMessage) (interface{}, bool) {
	var text string
	var argv []string
	switch {
	case json.Unmarshal(raw, &text) == nil && strings.TrimSpace(text) != "":
		return text, true
	case json.Unmarshal(raw, &argv) == nil && len(argv) > 0:
		return argv, true
	}
	return nil, false
}

func shellCommandsEqual(a, b interface{}) bool {
	left, _ := json.Marshal(a)
	right, _ := json.Marshal(b)
	return bytes.Equal(left, right)
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

// AmpBashTrustedShellArgs projects Amp's Bash tool call, {"cmd": ...,
// "cwd": ...}, onto the {"command": ...} shell shape and returns its cwd, the
// command's working directory. The trusted-action parser reads a shell
// command only under "command", so under "cmd" an Amp command had no command
// facts and was judged by the text-pattern fallback alone: a rule whose
// decision needs those facts only detected a command that Claude Code and
// Codex blocked.
//
// Refused (ok false, arguments unchanged) for any other tool, or unless the
// arguments are a JSON object with unique keys, only cmd and cwd, a
// non-blank string cmd and a string or null cwd.
func AmpBashTrustedShellArgs(toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(toolName), "bash") || antigravityValidateUniqueJSON(args) != nil {
		return args, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, "", false
	}
	var command string
	if raw, present := fields["cmd"]; !present || json.Unmarshal(raw, &command) != nil || strings.TrimSpace(command) == "" {
		return args, "", false
	}
	for key, raw := range fields {
		switch key {
		case "cmd":
		case "cwd":
			var dir *string
			if json.Unmarshal(raw, &dir) != nil {
				return args, "", false
			}
			if dir != nil {
				cwd = *dir
			}
		default:
			return args, "", false
		}
	}
	out, err := encodeTrustedShellArgs(map[string]string{"command": command})
	if err != nil {
		return args, "", false
	}
	return out, cwd, true
}
