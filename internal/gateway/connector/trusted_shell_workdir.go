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

// trustedShellWorkdirKeys names, per connector and shell tool (as the tool
// is named to hooks), the argument that sets the command's working
// directory:
//
//   - OpenCode 1.18 bash: workdir, absolute or relative to the project.
//   - Hermes 0.21 terminal: workdir.
//   - Amp shell_command: workdir.
//   - Cursor Agent preToolUse Shell: cwd, the call's working_directory.
//   - Devin 3000.10 exec: workdir, absolute.
//   - Kiro CLI 2.24 shell and execute_bash: working_dir.
//
// Claude Code's Bash and PowerShell, Codex's hook input (it passes only the
// command), Copilot's bash and powershell, OpenHands' terminal and OmniGent's
// sys_os_shell name no working directory. agy's run_command Cwd is split
// out by AntigravityTrustedShellArgs.
var trustedShellWorkdirKeys = map[string]map[string]string{
	"opencode": {"bash": "workdir"},
	"hermes":   {"terminal": "workdir"},
	"amp":      {"shell_command": "workdir"},
	"cursor":   {"Shell": "cwd"},
	"devin":    {"exec": "workdir"},
	"kiro":     {"shell": "working_dir", "execute_bash": "working_dir"},
}

// TrustedShellWorkdirArgs takes the working directory a shell tool call
// names out of its arguments and returns it separately, as the command's
// working directory; "" when the call names none (the key is null or
// empty), so the command runs in the session's directory.
//
// Left in the arguments, the directory was a second working directory next
// to the request's. Whenever the two differed (the model named a
// subdirectory or another directory, the request's was symlink-resolved on
// the host, or a sandbox's was mapped to the host directory it is mounted
// from) the trusted-action parse was ambiguous, and a key the parser does
// not read as a directory (Kiro's working_dir) left it partial. Either
// way no command rule could close its trusted-action proof and a CRITICAL
// finding stayed an allowed candidate.
//
// Only the directory moves; the other arguments are passed on unchanged for
// the parser to judge. Refused (ok false, arguments unchanged) unless the
// arguments are a JSON object whose keys are unique and the directory is a
// string or null.
func TrustedShellWorkdirArgs(connectorName, toolName string, args json.RawMessage) (projected json.RawMessage, cwd string, ok bool) {
	key := trustedShellWorkdirKeys[strings.ToLower(strings.TrimSpace(connectorName))][strings.TrimSpace(toolName)]
	if key == "" || antigravityValidateUniqueJSON(args) != nil {
		return args, "", false
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(args, &fields); err != nil || fields == nil {
		return args, "", false
	}
	raw, present := fields[key]
	if !present {
		return args, "", false
	}
	var dir *string
	if json.Unmarshal(raw, &dir) != nil {
		return args, "", false
	}
	delete(fields, key)
	var out bytes.Buffer
	enc := json.NewEncoder(&out)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(fields); err != nil {
		return args, "", false
	}
	if dir != nil {
		cwd = *dir
	}
	return bytes.TrimSuffix(out.Bytes(), []byte("\n")), cwd, true
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
