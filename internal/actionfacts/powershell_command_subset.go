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

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// POSIXPowerShellCommandFacts analyzes the literal body of a PowerShell
// -Command invocation carried by a POSIX shell tool. The shell projection
// loses single backslashes in unquoted Windows paths, so those words are
// recovered from the same parsed shell call before the PowerShell analysis.
// Only one unconditional invocation with a statically named executable and
// a -Command or -c body is eligible.
func POSIXPowerShellCommandFacts(input Input, facts Facts) []Facts {
	if input.Command == "" || len(facts.Commands) == 0 ||
		(facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectMixed) ||
		len(input.Command) > maxCommandBytes {
		return nil
	}
	outer := facts.Commands[0]
	if outer.ParentCommandID != 0 || len(outer.Argv) < 3 {
		return nil
	}
	switch strings.ToLower(outer.Program) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
	default:
		return nil
	}
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(input.Command), "")
	if err != nil || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 ||
		file.Stmts[0].Background || file.Stmts[0].Negated {
		return nil
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != len(outer.Argv) {
		return nil
	}
	argv := append([]string(nil), outer.Argv...)
	commandSwitch := false
	for _, argument := range argv[1:] {
		if strings.EqualFold(argument, "-Command") || strings.EqualFold(argument, "-c") {
			commandSwitch = true
		}
	}
	if !commandSwitch {
		return nil
	}
	for index, word := range call.Args {
		if index == 0 {
			continue
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start < 0 || end <= start || end > len(input.Command) {
			return nil
		}
		raw := input.Command[start:end]
		if strings.Contains(raw, `\`) && !strings.ContainsAny(raw, `"'`+"`"+`$`) {
			argv[index] = raw
		} else if index >= 2 && !outer.ArgvComplete &&
			strings.HasPrefix(raw, `"`) && strings.HasSuffix(raw, `"`) {
			body := raw[1 : len(raw)-1]
			body = strings.ReplaceAll(body, `\"`, `"`)
			body = strings.ReplaceAll(body, `\$`, `$`)
			argv[index] = body
		}
	}
	body, ok := exactPowerShellCommandBody(argv)
	if !ok {
		return nil
	}
	segments, ok := staticPowerShellSegments(body, 0)
	if !ok {
		return nil
	}
	var result []Facts
	for _, segment := range segments {
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Tool = "powershell"
		inner.Command = segment
		inner.DialectHint = DialectPowerShell
		parsed := Analyze(inner)
		if parsed.EnforcementEligible() || parsed.Parse.Status == StatusPartial {
			result = append(result, parsed)
		}
	}
	return result
}

// PowerShellCommandSubsetReduction projects statically supplied commands of
// a PowerShell -Command or -EncodedCommand body. The original action remains
// partial: profiles, outer shell operators, and some body operators cannot be
// represented as a complete action. The view contains the action's static
// top-level commands (outer redirects dropped) and the independently parsed
// inner commands of each exact body. A caller may use a match only for a
// monotone argv subset rule, as an extra pass next to any other view of the
// action; a non-match proves nothing about the original action.
//
// An action that is itself a PowerShell script, as a Windows shell tool sends
// it (Codex runs every shell call through PowerShell), is read as such a body:
// the view holds the commands of its leading statements and pipeline stages
// (GAP-1415).
func PowerShellCommandSubsetReduction(input Input, facts Facts) (view Facts, ok bool) {
	defer func() {
		if recover() != nil {
			view, ok = Facts{}, false
		}
	}()
	if facts.Parse.Dialect == DialectPowerShell {
		return powerShellScriptSubset(input, facts)
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
		segments, valid := staticPowerShellSegments(body, 0)
		if !valid {
			continue
		}
		commands := staticPowerShellSegmentCommands(input, segments)
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

// powerShellScriptSubset is the view of a partial PowerShell action read as a
// -Command body: the commands of its leading statements and pipeline stages
// that staticPowerShellStatements keeps. The first statement runs before
// anything later in the script can change what it is, and the first stage of
// a pipeline runs whatever the later stages are, so each kept command runs as
// the view has it (GAP-1415: "New-Item -Name marker.txt | Out-Null").
//
// What follows the kept statements never takes one out of the view: the
// script is read up to its first construct the segments do not model (a
// comment, a call operator, an escape, a pipeline chain), and a compound
// statement (if/else, foreach, try) only ends the kept commands. A kept
// statement that no pipeline feeds also brings the paths and hosts of its
// own complete analysis, so a rule that matches the statement alone (a path
// that holds a literal) matches it here too (GAP-1415: "New-Item -Path
// <file> -Force | Out-Null; if (Test-Path ...) { ... } else { ... }").
func powerShellScriptSubset(input Input, facts Facts) (Facts, bool) {
	if facts.Parse.Status != StatusPartial || len(input.Argv) != 0 {
		return Facts{}, false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != IssueUnsupportedConstruct && issue != IssueDynamicWord &&
			issue != IssueUnknownOperandGrammar {
			return Facts{}, false
		}
	}
	source := input.Command
	if source == "" {
		extracted := extractArgsForTool(input.Args, input.Tool)
		if len(extracted.issues) != 0 || extracted.status != StatusComplete || len(extracted.argv) != 0 {
			return Facts{}, false
		}
		source = extracted.command
	}
	segments, ok := scanPowerShellSegments(source, 0, true)
	if !ok {
		return Facts{}, false
	}
	statements := staticPowerShellStatements(input, segments)
	if len(statements) == 0 || len(statements) > maxCommands {
		return Facts{}, false
	}
	view := Facts{
		Tool:       facts.Tool,
		CWD:        facts.CWD,
		ActiveHome: facts.ActiveHome,
		Parse:      ParseResult{Status: StatusComplete, Dialect: DialectPowerShell},
	}
	for _, statement := range statements {
		command := statement.command
		own := command.ID
		command.ID = int64(len(view.Commands) + 1)
		command.ParentCommandID = 0
		command.PipelineID = 0
		command.ControlFlowUncertain = false
		command.ControlFlowOperator = ControlFlowOperatorNone
		command.Wrappers = nil
		view.Commands = append(view.Commands, command)
		if statement.piped {
			// Pipeline input may bind to its parameters.
			continue
		}
		for _, path := range statement.paths {
			if path.CommandID == own {
				path.CommandID = command.ID
				view.Paths = append(view.Paths, path)
			}
		}
		for _, network := range statement.network {
			if network.CommandID == own {
				network.CommandID = command.ID
				view.Network = append(view.Network, network)
			}
		}
	}
	return view, true
}

// powerShellSegment is one statement or pipeline stage of a PowerShell body.
type powerShellSegment struct {
	text string
	// piped is set on a pipeline stage after the first.
	piped bool
}

// powerShellStatement is the exact command of a segment, with the path and
// network facts of the segment's own complete analysis.
type powerShellStatement struct {
	command CommandFact
	paths   []PathFact
	network []NetworkFact
	piped   bool
}

// staticPowerShellSegmentCommands returns the commands of
// staticPowerShellStatements.
func staticPowerShellSegmentCommands(input Input, segments []string) []CommandFact {
	scanned := make([]powerShellSegment, len(segments))
	for i, segment := range segments {
		scanned[i] = powerShellSegment{text: segment}
	}
	statements := staticPowerShellStatements(input, scanned)
	commands := make([]CommandFact, 0, len(statements))
	for _, statement := range statements {
		commands = append(commands, statement.command)
	}
	return commands
}

// staticPowerShellStatements returns the exact statements of the leading
// segments of a PowerShell body: the first one, and each next one only while
// the command before it cannot change what the next command is. A segment
// "$null = <command>" runs <command> and drops its output.
func staticPowerShellStatements(input Input, segments []powerShellSegment) []powerShellStatement {
	var statements []powerShellStatement
	for _, segment := range segments {
		if len(statements) != 0 && !powerShellCommandPreservesNext(statements[len(statements)-1].command) {
			break
		}
		statement, valid := exactPowerShellStatement(input, powerShellNullAssignmentCommand(segment.text))
		if !valid {
			break
		}
		statement.piped = segment.piped
		statements = append(statements, statement)
	}
	return statements
}

// powerShellNullAssignmentCommand returns the command of "$null = <command>",
// or segment unchanged.
func powerShellNullAssignmentCommand(segment string) string {
	if len(segment) < 6 || !strings.EqualFold(segment[:5], "$null") {
		return segment
	}
	rest := strings.TrimLeft(segment[5:], " \t")
	if !strings.HasPrefix(rest, "=") || strings.HasPrefix(rest, "==") {
		return segment
	}
	if command := strings.TrimSpace(rest[1:]); command != "" {
		return command
	}
	return segment
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
// PowerShellCommandBodyActions returns the complete analysis of the exact
// -Command or -EncodedCommand body of each static top-level pwsh or
// powershell call of a partial action, such as `pwsh -Command "<body>"`
// without -NoProfile (a profile runs before the body) or the same call with a
// runtime-expanded redirect target. facts must be Analyze(input).
//
// The body runs as written whatever made the whole action partial: a profile
// only runs commands before it, an outer redirect only takes its output, and a
// list is judged as if every member runs. A caller may count a match on a
// body only for a rule whose proof reads the body's own commands and the data
// flow between them; a non-match proves nothing about the action.
func PowerShellCommandBodyActions(input Input, facts Facts) (bodies []Facts) {
	defer func() {
		if recover() != nil {
			bodies = nil
		}
	}()
	if facts.Parse.Status != StatusPartial {
		return nil
	}
	for _, outer := range facts.Commands {
		if outer.ParentCommandID != 0 {
			continue
		}
		switch strings.ToLower(outer.Program) {
		case "pwsh", "pwsh.exe", "powershell", "powershell.exe":
		default:
			continue
		}
		if !staticCertainPOSIXOrPowerShellProcess(outer) {
			continue
		}
		body, ok := exactPowerShellCommandBody(outer.Argv)
		if !ok {
			continue
		}
		inner := input
		inner.Args, inner.Argv = nil, nil
		inner.Tool = "powershell"
		inner.Command = body
		inner.DialectHint = DialectPowerShell
		parsed := Analyze(inner)
		if parsed.Authoritative() && parsed.Parse.Status == StatusComplete {
			bodies = append(bodies, parsed)
		}
	}
	return bodies
}

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
	scanned, ok := scanPowerShellSegments(source, depth, false)
	if !ok {
		return nil, false
	}
	segments := make([]string, len(scanned))
	for i, segment := range scanned {
		segments[i] = segment.text
	}
	return segments, true
}

// scanPowerShellSegments splits source as staticPowerShellSegments does. With
// leading set, a construct it does not model ends the scan instead of failing
// it, and the statements and stages before that construct are returned: each
// is complete, and nothing after it changes it.
func scanPowerShellSegments(source string, depth int, leading bool) ([]powerShellSegment, bool) {
	if depth > maxWrapperDepth || len(source) > maxCommandBytes {
		return nil, false
	}
	source = strings.TrimSpace(source)
	if inner, ok := exactPowerShellScriptBlock(source); ok {
		return scanPowerShellSegments(inner, depth+1, leading)
	}
	runes := []rune(source)
	var part strings.Builder
	segments := make([]powerShellSegment, 0, 2)
	quote := rune(0)
	piped := false
	stop := func() ([]powerShellSegment, bool) {
		if !leading || len(segments) == 0 {
			return nil, false
		}
		return segments, true
	}
	flush := func() bool {
		segment := strings.TrimSpace(part.String())
		part.Reset()
		if segment == "" || len(segments) >= maxCommands {
			return false
		}
		segments = append(segments, powerShellSegment{text: segment, piped: piped})
		return true
	}
	for i := 0; i < len(runes); i++ {
		r := runes[i]
		delimiter := windowsPowerShellQuoteDelimiter(r)
		if quote != 0 {
			if quote == '"' && r == '`' {
				return stop()
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
			return stop()
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
				return stop()
			}
			if !flush() {
				return stop()
			}
			piped = r == '|'
			if r == '\r' && i+1 < len(runes) && runes[i+1] == '\n' {
				i++
			}
		case r == '\x00':
			return stop()
		default:
			part.WriteRune(r)
		}
	}
	if quote != 0 || !flush() {
		return stop()
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

// exactPowerShellStatement is the exact command of segment, with the path and
// network facts of its complete analysis (none when its operands have no
// reviewed effect grammar).
func exactPowerShellStatement(input Input, segment string) (powerShellStatement, bool) {
	segmentInput := input
	segmentInput.Args = nil
	segmentInput.Argv = nil
	segmentInput.Command = segment
	segmentInput.DialectHint = DialectPowerShell
	parsed := Analyze(segmentInput)
	if len(parsed.Commands) != 1 || parsed.Commands[0].ParentCommandID != 0 ||
		!parsed.Commands[0].ArgvComplete {
		return powerShellStatement{}, false
	}
	command := parsed.Commands[0]
	if command.Program != "cmd" && command.Program != "cmd.exe" {
		if parsed.EnforcementEligible() {
			return powerShellStatement{command: command, paths: parsed.Paths, network: parsed.Network}, true
		}
		if parsed.Parse.Status == StatusPartial && len(parsed.Parse.Issues) == 1 &&
			parsed.Parse.Issues[0] == IssueUnknownOperandGrammar &&
			command.Effect == EffectExecute {
			// The invocation's literal argv is known, but its operands have no
			// reviewed effect grammar. The caller may only use an argv-safe
			// positive match on this subset.
			command.Operations = nil
			command.Redirects = nil
			return powerShellStatement{command: command}, true
		}
		return powerShellStatement{}, false
	}
	if command.Effect != EffectExecute ||
		(parsed.Parse.Status != StatusComplete &&
			(parsed.Parse.Status != StatusPartial || len(parsed.Parse.Issues) != 1 ||
				parsed.Parse.Issues[0] != IssueUnsupportedConstruct)) {
		return powerShellStatement{}, false
	}
	cmdBody, ok := exactCMDCommandBody(command.Argv)
	if !ok {
		return powerShellStatement{}, false
	}
	segmentInput.Command = cmdBody
	segmentInput.DialectHint = DialectCMD
	parsed = Analyze(segmentInput)
	if !parsed.EnforcementEligible() || len(parsed.Commands) != 1 ||
		parsed.Commands[0].ParentCommandID != 0 || !parsed.Commands[0].ArgvComplete {
		return powerShellStatement{}, false
	}
	return powerShellStatement{command: parsed.Commands[0], paths: parsed.Paths, network: parsed.Network}, true
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
