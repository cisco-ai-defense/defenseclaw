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

package actionfacts

import (
	"strings"
	"unicode"
)

// PowerShellProfileWrapperReduction returns a complete view of a partial
// action that starts with a `pwsh -Command "<body>"` or `powershell -Command
// "<body>"` call without -NoProfile, such as
// `pwsh -Command "echo marker > C:/x.txt"` (GAP-1639), the same call with a
// redirect outside the quotes, or the call followed by more list members
// (`...; echo done`, GAP-1868). facts must be Analyze(input).
//
// The wrapper is unwrapped only with -NoProfile because a profile runs
// commands before the body. Those commands come first and the body still
// runs, so the action has at least the commands and facts of the same call
// with -NoProfile. The view is the complete analysis of that twin, with the
// wrapper's argv and arguments restored to the call's. A caller may count a
// semantic match on it only for an expression whose match more commands,
// redirects, paths, network facts and data flows cannot undo
// (semantic.Program.StaticCommandSubsetSafe); a non-match proves nothing.
//
// A redirect on the call also takes the profile's output, and the commands
// after it run as they do after the twin, so neither can undo the body's
// match. The view is unavailable unless the call is the action's first
// top-level command, a PowerShell process with a static argv and certain
// control flow, the only parse issue is the unsupported wrapper, and the
// twin is complete (so every other command and redirect target is too).
func PowerShellProfileWrapperReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status != StatusPartial || len(facts.Commands) == 0 ||
		len(facts.Parse.Issues) != 1 || facts.Parse.Issues[0] != IssueUnsupportedConstruct ||
		(facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectPowerShell) {
		return Facts{}, false
	}
	wrapper := facts.Commands[0]
	switch strings.ToLower(wrapper.Program) {
	case "pwsh", "powershell", "pwsh.exe", "powershell.exe":
	default:
		return Facts{}, false
	}
	if wrapper.ParentCommandID != 0 || !staticCertainPOSIXOrPowerShellProcess(wrapper) ||
		len(wrapper.Argv) < 3 {
		return Facts{}, false
	}
	for _, option := range wrapper.Argv[1:] {
		if strings.EqualFold(option, "-noprofile") {
			return Facts{}, false
		}
	}
	_, capture := analyzeWithRedirectTargets(input, "")
	source := strings.TrimSpace(capture.source)
	program := wrapper.Argv[0]
	if !strings.HasPrefix(source, program) || len(source) == len(program) ||
		!unicode.IsSpace(rune(source[len(program)])) {
		return Facts{}, false
	}
	twin, _ := analyzeWithRedirectTargets(input, program+" -NoProfile"+source[len(program):])
	if !twin.Authoritative() || len(twin.Parse.Issues) != 0 || len(twin.Commands) < 2 ||
		twin.Commands[0].ID != wrapper.ID || len(twin.Commands[0].Argv) != len(wrapper.Argv)+1 {
		return Facts{}, false
	}
	commands := cloneCommands(twin.Commands)
	commands[0].Argv = cloneSlice(wrapper.Argv)
	commands[0].Arguments = append([]ArgumentFact(nil), wrapper.Arguments...)
	twin.Commands = commands
	return twin, true
}

// staticCertainPOSIXOrPowerShellProcess is staticCertainPOSIXProcess for a
// command parsed as POSIX or PowerShell.
func staticCertainPOSIXOrPowerShellProcess(command CommandFact) bool {
	if command.Dialect == DialectPowerShell {
		command.Dialect = DialectPOSIX
	}
	return staticCertainPOSIXProcess(command)
}
