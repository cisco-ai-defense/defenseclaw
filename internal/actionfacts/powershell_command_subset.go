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
	"encoding/base64"
	"encoding/binary"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

// PowerShellCommandSubsetReduction projects statically supplied commands of
// a PowerShell -Command or -EncodedCommand body. The original action remains
// partial: profiles, outer shell operators, and some body operators cannot be
// represented as a complete action. The view contains the action's static
// top-level commands (outer redirects dropped) and the independently parsed
// inner commands of each exact body. A caller may use a match only for a
// monotone argv subset rule, as an extra pass next to any other view of the
// action; a non-match proves nothing about the original action.
func PowerShellCommandSubsetReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Status == StatusPartial && facts.Parse.Dialect == DialectPowerShell {
		return rawPowerShellStatementSubset(input, facts)
	}
	if facts.Parse.Status != StatusPartial ||
		(facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectMixed) ||
		len(facts.Commands) == 0 {
		return Facts{}, false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueUnsupportedConstruct && issue != IssueDynamicWord {
			return Facts{}, false
		}
	}
	_, capture := analyzeWithRedirectTargets(input, "")
	if definesFunction(capture.source) {
		return Facts{}, false
	}
	view = Facts{
		Tool:       facts.Tool,
		CWD:        facts.CWD,
		ActiveHome: facts.ActiveHome,
		Parse:      ParseResult{Status: StatusComplete, Dialect: DialectMixed},
	}
	inner := 0
	for _, outer := range facts.Commands {
		if outer.ParentCommandID != 0 {
			continue
		}
		if !staticCertainPOSIXProcess(outer) {
			return Facts{}, false
		}
		if shellStateBuiltins[strings.ToLower(outer.Program)] {
			return Facts{}, false
		}
		// Every top-level command is static and certain (or a plain list
		// member, judged as if it runs), so it stays in the view: a benign
		// wrapper must not hide a matching command next to it.
		if len(view.Commands)+1 > maxCommands {
			return Facts{}, false
		}
		kept := outer
		kept.ID = int64(len(view.Commands) + 1)
		kept.ParentCommandID = 0
		kept.PipelineID = 0
		kept.ControlFlowUncertain = false
		kept.ControlFlowOperator = ControlFlowOperatorNone
		kept.Redirects = nil
		view.Commands = append(view.Commands, kept)
		switch strings.ToLower(outer.Program) {
		case "pwsh", "pwsh.exe", "powershell", "powershell.exe":
		default:
			continue
		}
		body, valid := exactPowerShellCommandBody(outer.Argv)
		if !valid {
			continue
		}
		commands := powerShellBodyCommands(input, body)
		if len(commands) == 0 || len(view.Commands)+len(commands) > maxCommands {
			continue
		}
		inner += appendPowerShellBodyCommands(&view, commands)
	}
	if inner == 0 {
		return Facts{}, false
	}
	return view, true
}

// rawPowerShellStatementSubset is the reduction of a raw PowerShell action,
// such as a Codex shell call on Windows, where the action is a body itself
// (GAP-0175). An exit after a static command, or a cmdlet with no operand
// grammar next to it, leaves the whole action partial, so without the view a
// monotone argv rule could not count its match on `Write-Output marker;
// exit 0` or `Get-Location; Write-Output marker`.
func rawPowerShellStatementSubset(input Input, facts Facts) (Facts, bool) {
	extracted := extractArgsForTool(input.Args, input.Tool)
	if len(input.Argv) != 0 || len(extracted.argv) != 0 {
		return Facts{}, false
	}
	body := input.Command
	if body == "" {
		body = extracted.command
	}
	if body == "" || len(body) > maxCommandBytes {
		return Facts{}, false
	}
	commands := powerShellBodyCommands(input, body)
	if len(commands) == 0 || len(commands) > maxCommands {
		return Facts{}, false
	}
	view := Facts{
		Tool:       facts.Tool,
		CWD:        facts.CWD,
		ActiveHome: facts.ActiveHome,
		Parse:      ParseResult{Status: StatusComplete, Dialect: DialectPowerShell},
	}
	appendPowerShellBodyCommands(&view, commands)
	return view, true
}

// powerShellBodyCommands parses the static segments of an exact PowerShell
// body in order, and stops at the first it cannot prove or after a command
// that may change what the next one runs.
func powerShellBodyCommands(input Input, body string) []CommandFact {
	segments, valid := staticPowerShellSegments(body, 0)
	if !valid {
		return nil
	}
	var commands []CommandFact
	for _, segment := range segments {
		if len(commands) != 0 && !powerShellCommandPreservesNext(commands[len(commands)-1]) {
			break
		}
		command, valid := exactPowerShellSegmentCommand(input, segment)
		if !valid {
			break
		}
		commands = append(commands, command)
	}
	return commands
}

// appendPowerShellBodyCommands adds a body's commands to view as top-level
// commands that run, and reports how many it added.
func appendPowerShellBodyCommands(view *Facts, commands []CommandFact) int {
	for _, command := range commands {
		command.ID = int64(len(view.Commands) + 1)
		command.ParentCommandID = 0
		command.PipelineID = 0
		command.ControlFlowUncertain = false
		command.ControlFlowOperator = ControlFlowOperatorNone
		command.Wrappers = nil
		view.Commands = append(view.Commands, command)
	}
	return len(commands)
}

// Only these output/read commands can precede another statement in the
// reduced body. Other commands may exit, alter aliases, or change the
// process state that determines the next command's identity.
func powerShellCommandPreservesNext(command CommandFact) bool {
	switch command.Program {
	case "echo", "write-output", "write-host", "out-null", "get-date", "get-location", "pwd",
		"get-content", "gc", "cat", "type":
		return true
	default:
		return false
	}
}

// exactPowerShellCommandBody accepts only startup switches whose argument
// boundaries are fixed. PowerShell joins words after -Command with spaces;
// -EncodedCommand is one UTF-16LE script, with no trailing arguments.
func exactPowerShellCommandBody(argv []string) (string, bool) {
	if len(argv) < 3 {
		return "", false
	}
	profile, interactive, policy := false, false, false
	for i := 1; i < len(argv); i++ {
		switch strings.ToLower(argv[i]) {
		case "-noprofile":
			if profile {
				return "", false
			}
			profile = true
		case "-noninteractive":
			if interactive {
				return "", false
			}
			interactive = true
		case "-nologo":
		case "-executionpolicy":
			if policy || i+1 >= len(argv) || !exactPowerShellExecutionPolicy(argv[i+1]) {
				return "", false
			}
			policy = true
			i++
		case "-command", "-c":
			if i+1 >= len(argv) || argv[i+1] == "-" {
				return "", false
			}
			for _, word := range argv[i+1:] {
				if word == "" {
					return "", false
				}
			}
			body := strings.Join(argv[i+1:], " ")
			return body, len(body) <= maxCommandBytes
		case "-encodedcommand":
			if i+2 != len(argv) {
				return "", false
			}
			return decodePowerShellCommand(argv[i+1])
		default:
			return "", false
		}
	}
	return "", false
}

func exactPowerShellExecutionPolicy(value string) bool {
	switch strings.ToLower(value) {
	case "allsigned", "bypass", "default", "remotesigned", "restricted", "undefined", "unrestricted":
		return true
	default:
		return false
	}
}

func decodePowerShellCommand(value string) (string, bool) {
	if value == "" || len(value) > 2*maxCommandBytes {
		return "", false
	}
	encoded, err := base64.StdEncoding.Strict().DecodeString(value)
	if err != nil || len(encoded) == 0 || len(encoded)%2 != 0 || len(encoded) > 2*maxCommandBytes {
		return "", false
	}
	units := make([]uint16, len(encoded)/2)
	for i := range units {
		units[i] = binary.LittleEndian.Uint16(encoded[2*i:])
		if units[i] == 0 {
			return "", false
		}
	}
	for i, unit := range units {
		if unit >= 0xdc00 && unit <= 0xdfff && (i == 0 || units[i-1] < 0xd800 || units[i-1] > 0xdbff) ||
			unit >= 0xd800 && unit <= 0xdbff && (i+1 == len(units) || units[i+1] < 0xdc00 || units[i+1] > 0xdfff) {
			return "", false
		}
	}
	body := string(utf16.Decode(units))
	return body, body != "" && utf8.ValidString(body) && len(body) <= maxCommandBytes
}

// staticPowerShellSegments accepts unconditional statement lists and pipeline
// stages. Descriptor duplication has no file target. An all-stream redirect
// contributes a stdout redirect, so it is represented as > in the view.
// Both transformations omit information; the subset rule must be monotone.
func staticPowerShellSegments(source string, depth int) ([]string, bool) {
	if depth > maxWrapperDepth || len(source) > maxCommandBytes {
		return nil, false
	}
	source = strings.TrimSpace(source)
	if inner, ok := exactPowerShellScriptBlock(source); ok {
		return staticPowerShellSegments(inner, depth+1)
	}
	runes := []rune(source)
	var part strings.Builder
	segments := make([]string, 0, 2)
	quote := rune(0)
	flush := func() bool {
		segment := strings.TrimSpace(part.String())
		part.Reset()
		if segment == "" || len(segments) >= maxCommands {
			return false
		}
		segments = append(segments, segment)
		return true
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		delimiter := windowsPowerShellQuoteDelimiter(r)
		if quote != 0 {
			if quote == '"' && r == '`' {
				return nil, false
			}
			part.WriteRune(r)
			if delimiter == quote {
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == quote {
					i++
					part.WriteRune(runes[i])
				} else {
					quote = 0
				}
			}
			continue
		}
		switch {
		case delimiter != 0:
			quote = delimiter
			part.WriteRune(r)
		case r == '`' || r == '#' || r == '&':
			return nil, false
		case r == '2' && i+3 < len(runes) && string(runes[i:i+4]) == "2>&1" &&
			(i == 0 || unicode.IsSpace(runes[i-1])) &&
			(i+4 == len(runes) || unicode.IsSpace(runes[i+4]) || runes[i+4] == ';' || runes[i+4] == '|'):
			i += 3
		case r == '*' && i+1 < len(runes) && runes[i+1] == '>' &&
			(i == 0 || unicode.IsSpace(runes[i-1])):
			part.WriteRune('>')
			i++
		case r == ';' || r == '|' || r == '\n' || r == '\r':
			if r == '|' && i+1 < len(runes) && (runes[i+1] == '|' || runes[i+1] == '&') ||
				i+1 < len(runes) && runes[i+1] == r && r == ';' {
				return nil, false
			}
			if !flush() {
				return nil, false
			}
			if r == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
		case r == '\x00':
			return nil, false
		default:
			part.WriteRune(r)
		}
	}
	if quote != 0 || !flush() {
		return nil, false
	}
	return segments, true
}

// exactPowerShellScriptBlock accepts only a directly invoked, whole script
// block. Braces inside quoted strings do not end it.
func exactPowerShellScriptBlock(source string) (string, bool) {
	runes := []rune(source)
	if len(runes) < 4 || runes[0] != '&' {
		return "", false
	}
	i := 1
	for i < len(runes) && unicode.IsSpace(runes[i]) {
		i++
	}
	if i >= len(runes) || runes[i] != '{' || runes[len(runes)-1] != '}' {
		return "", false
	}
	start := i + 1
	quote := rune(0)
	for i++; i < len(runes); i++ {
		r := runes[i]
		delimiter := windowsPowerShellQuoteDelimiter(r)
		if quote != 0 {
			if quote == '"' && r == '`' {
				return "", false
			}
			if delimiter == quote {
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == quote {
					i++
				} else {
					quote = 0
				}
			}
			continue
		}
		if delimiter != 0 {
			quote = delimiter
		} else if r == '`' || r == '#' || r == '{' || r == '}' && i != len(runes)-1 {
			return "", false
		}
	}
	if quote != 0 {
		return "", false
	}
	return string(runes[start : len(runes)-1]), true
}

func exactPowerShellSegmentCommand(input Input, segment string) (CommandFact, bool) {
	segmentInput := input
	segmentInput.Args = nil
	segmentInput.Argv = nil
	segmentInput.Command = segment
	segmentInput.DialectHint = DialectPowerShell
	parsed := Analyze(segmentInput)
	if len(parsed.Commands) != 1 || parsed.Commands[0].ParentCommandID != 0 ||
		!parsed.Commands[0].ArgvComplete {
		return CommandFact{}, false
	}
	command := parsed.Commands[0]
	if command.Program != "cmd" && command.Program != "cmd.exe" {
		if parsed.EnforcementEligible() {
			return command, true
		}
		if parsed.Parse.Status == StatusPartial && len(parsed.Parse.Issues) == 1 &&
			parsed.Parse.Issues[0] == IssueUnknownOperandGrammar &&
			command.Effect == EffectExecute {
			// The invocation's literal argv is known, but its operands have no
			// reviewed effect grammar. The caller may only use an argv-safe
			// positive match on this subset.
			command.Operations = nil
			command.Redirects = nil
			return command, true
		}
		return CommandFact{}, false
	}
	if command.Effect != EffectExecute ||
		(parsed.Parse.Status != StatusComplete &&
			(parsed.Parse.Status != StatusPartial || len(parsed.Parse.Issues) != 1 ||
				parsed.Parse.Issues[0] != IssueUnsupportedConstruct)) {
		return CommandFact{}, false
	}
	cmdBody, ok := exactCMDCommandBody(command.Argv)
	if !ok {
		return CommandFact{}, false
	}
	segmentInput.Command = cmdBody
	segmentInput.DialectHint = DialectCMD
	parsed = Analyze(segmentInput)
	if !parsed.EnforcementEligible() || len(parsed.Commands) != 1 ||
		parsed.Commands[0].ParentCommandID != 0 || !parsed.Commands[0].ArgvComplete {
		return CommandFact{}, false
	}
	return parsed.Commands[0], true
}

func exactCMDCommandBody(argv []string) (string, bool) {
	i := 1
	if i < len(argv) && strings.EqualFold(argv[i], "/d") {
		i++
	}
	if len(argv) != i+2 || !strings.EqualFold(argv[i], "/c") ||
		strings.TrimSpace(argv[i+1]) == "" || len(argv[i+1]) > maxCommandBytes {
		return "", false
	}
	return argv[i+1], true
}
