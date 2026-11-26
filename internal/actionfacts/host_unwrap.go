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
	"encoding/json"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// Host unwrapping: the one place the PowerShell parser (internal/psparse)
// feeds ActionFacts, and it only ever ADDS.
//
// A call such as `powershell -Command "<script>"`, `pwsh -EncodedCommand
// <base64>`, `cmd /c "<line>"`, `& { <script> }`, `Invoke-Expression '<script>'`
// or Git Bash running powershell.exe runs the same statements as the bare
// script, and the rules judge the action, not its spelling. psparse
// (ExtractNestedScripts) says what the launcher runs; HostScriptTwin hands that
// script back as a second reading of the call, in its own grammar, recursively
// to the wrapper depth and size budget.
//
// The facts of the call as written (Analyze) are never touched by this file:
// the launcher stays the command the tokenizer saw, with the status and issues
// the tokenizer gave it. A caller judges the script reading separately and may
// only add its findings to those of the call as written. So a psparse result
// that is wrong (a Static text that differs from what runs) can add a false
// alert, which the precision gate measures, and can never hide an attack or
// turn an unknown call into a clean one. Anything psparse cannot resolve to one
// static script (a variable, a sub-expression, a stdin read, a child argv, a
// stop-parse tail, quotes the legacy argument passing rewrites, an empty or
// colon-glued word) has no reading at all. A launcher's -WorkingDirectory is
// read as a Set-Location to its value before the script
// (launcherWorkingDirectory), so the script's relative paths are read from the
// folder it runs in.

// withoutUnreachableStatements cuts a PowerShell script after its first
// top-level exit or return: the statements after it never run, so a rule must
// not judge them (the tokenizer's own wrapper reading does the same,
// POSIXPowerShellCommandFacts).
func withoutUnreachableStatements(source string) string {
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 {
		return source
	}
	for _, statement := range script.Statements {
		flow, isFlow := statement.(*psparse.Block)
		if !isFlow || (flow.Keyword != "exit" && flow.Keyword != "return") {
			continue
		}
		if _, end := flow.Span(); end > 0 && end <= len(source) {
			return source[:end]
		}
		return source
	}
	return source
}

// mayHoldHostScript is the cheap screen of HostScriptTwin: a text with none of
// the words a launcher, an Invoke-Expression or a call block needs has no
// script reading. It never rejects a text that has one.
func mayHoldHostScript(source string) bool {
	if source == "" || len(source) > maxCommandBytes {
		return false
	}
	lower := strings.ToLower(source)
	for _, word := range []string{"powershell", "pwsh", "cmd", "iex", "invoke-expression", "{", "start-process", "saps", "--%"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	// The start alias of Start-Process, as a word (powerShellChildArgvCall).
	for index := strings.Index(lower, "start"); index >= 0; {
		end := index + len("start")
		if (index == 0 || strings.ContainsRune(" \t;|&(", rune(lower[index-1]))) &&
			end < len(lower) && (lower[end] == ' ' || lower[end] == '\t') {
			return true
		}
		next := strings.Index(lower[end:], "start")
		if next < 0 {
			break
		}
		index = end + next
	}
	return false
}

// hostUnwrap is the result of unwrapping the static host wrappers of one source.
type hostUnwrap struct {
	source  string
	dialect Dialect
	// layers is the number of launchers unwrapped.
	layers int
	// limit: another wrapper layer was left because a bound ended the reading
	// (the wrapper depth, the nested size budget, a mid-list body past its
	// size); caps names the bound (internal/guardrail/bounded).
	limit bool
	caps  bounded.CapSet
	// floorRaiseOnly: a layer unwrapped is a blank-decoded -EncodedCommand
	// body (psparse.NestedScript.BlankDecoded; Input.FloorRaiseOnly).
	floorRaiseOnly bool
}

// maxHostMidListBody bounds the script text substituted into the middle of a
// statement list; whole-call replacement is bounded by the nested size budget.
const maxHostMidListBody = 4 << 10

// The bounds of the script reading, for the cross-lane bound test
// (internal/gateway bounded_lanes_test.go registers each as a lane cap).
const (
	MaxWrapperDepth    = maxWrapperDepth
	MaxHostMidListBody = maxHostMidListBody
	MaxListReadings    = maxListReadings
)

// psparseBoundCaps names the psparse bounds a parse hit: its nesting depth
// (ps_depth_limit) and its input size (ps_truncated). A script psparse stopped
// reading at a bound is not left unread: the reading is truncated and the
// call is judged at the unknown tier of the pack at least (rel-1-0-10:GAP-0478).
// Any other diagnostic (an unbalanced or dynamic construct) is psparse not
// resolving the script, which leaves the call as the tokenizer read it.
func psparseBoundCaps(script *psparse.Script) bounded.CapSet {
	var caps bounded.CapSet
	if script == nil {
		return caps
	}
	for _, diagnostic := range script.Diagnostics {
		switch diagnostic.Reason {
		case psparse.ReasonDepthLimit:
			caps = caps.Union(bounded.Of(bounded.Depth))
		case psparse.ReasonTruncated:
			caps = caps.Union(bounded.Of(bounded.Bytes))
		}
	}
	return caps
}

// unwrapHostSource unwraps source (PowerShell or cmd.exe grammar) until no
// static host wrapper is left, at most maxWrapperDepth layers. ok is false when
// source holds no static wrapper.
func unwrapHostSource(source string, dialect Dialect, depth int) (hostUnwrap, bool) {
	result := hostUnwrap{source: source, dialect: dialect}
	for layer := 0; ; layer++ {
		var next string
		var nextDialect Dialect
		var ok, blanked bool
		switch result.dialect {
		case DialectPowerShell:
			var caps bounded.CapSet
			next, nextDialect, ok, caps, blanked = unwrapPowerShellOnce(result.source)
			result.caps = result.caps.Union(caps)
			result.limit = result.limit || caps.Any()
		case DialectCMD:
			next, nextDialect, ok, blanked = unwrapCMDOnce(result.source)
		}
		if !ok || strings.TrimSpace(next) == "" {
			break
		}
		if len(next)*(depth+layer+2) > maxNestedCommandBytes {
			result.limit, result.caps = true, result.caps.Union(bounded.Of(bounded.Bytes))
			break
		}
		if depth+layer >= maxWrapperDepth {
			result.limit, result.caps = true, result.caps.Union(bounded.Of(bounded.Depth))
			break
		}
		result.source, result.dialect = next, nextDialect
		result.floorRaiseOnly = result.floorRaiseOnly || blanked
		result.layers++
	}
	return result, result.layers > 0 || result.limit
}

// raiseReadable reports whether a host script reading (a twin, which only adds
// findings to the call) may read a parse: one with only lexical diagnostics
// (an unterminated string, here-string or block comment) is read as psparse
// read it at 1.0.10. Such a text is often a statement of a POSIX reading of a
// Windows-host call, cut at a ; that PowerShell reads inside a string
// (rel-1-0-10:GAP-1919): the statement reading before the open token is exact
// and must keep its findings. Readers that cut a script or call it safe keep
// requiring a clean parse.
func raiseReadable(script *psparse.Script) bool {
	return script != nil && script.OnlyLexicalDiagnostics()
}

// unwrapPowerShellOnce replaces the static host wrappers among the top-level
// statements of a PowerShell source. A source that is one wrapper statement is
// replaced whole (and may change grammar to cmd.exe's); wrappers among other
// statements are replaced in place when their script is one simple line.
// blanked is a replaced script that is a blank-decoded -EncodedCommand body
// (psparse.NestedScript.BlankDecoded).
func unwrapPowerShellOnce(source string) (string, Dialect, bool, bounded.CapSet, bool) {
	var caps bounded.CapSet
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if !raiseReadable(script) || len(script.Statements) == 0 {
		return "", DialectNone, false, psparseBoundCaps(script), false
	}
	type edit struct {
		start, end int
		body       string
	}
	var edits []edit
	whole := len(script.Statements) == 1
	var wholeDialect Dialect
	blanked := false
	for _, statement := range script.Statements {
		body, dialect, start, end, moves, ok, bodyBlanked := powerShellStatementWrapper(source, script, statement, whole)
		if !ok || moves && !whole {
			// A launcher that starts its script in another folder is read
			// in place only as the whole call: its Set-Location would move
			// the statements after it too. The statement reading
			// (powerShellNestedTexts) reads it alone.
			continue
		}
		if !whole && len(body) > maxHostMidListBody {
			// A body past the size a statement list takes in place is not read
			// there: the reading is truncated, not skipped.
			caps = caps.Union(bounded.Of(bounded.Bytes))
			continue
		}
		if !whole && (dialect != DialectPowerShell || !simpleHostBody(body)) {
			continue
		}
		edits = append(edits, edit{start: start, end: end, body: body})
		wholeDialect = dialect
		blanked = blanked || bodyBlanked
	}
	if len(edits) == 0 {
		return "", DialectNone, false, caps, false
	}
	if whole {
		return edits[0].body, wholeDialect, true, caps, blanked
	}
	next := source
	for i := len(edits) - 1; i >= 0; i-- {
		next = next[:edits[i].start] + edits[i].body + next[edits[i].end:]
	}
	return next, DialectPowerShell, true, caps, blanked
}

// simpleHostBody reports a script that can stand between other statements of
// a line without changing what follows it: no comment, newline, escape or
// here-string that could swallow or reshape the neighbours.
func simpleHostBody(body string) bool {
	if len(body) > maxHostMidListBody || strings.TrimSpace(body) == "" {
		return false
	}
	return !strings.ContainsAny(body, "#\r\n`\x00") && !strings.Contains(body, "@'") &&
		!strings.Contains(body, `@"`)
}

// powerShellStatementWrapper recognizes one top-level statement that only runs
// a static nested script and returns that script, its grammar and the source
// range of the statement; moves is a script that starts with the launcher's
// move to its working directory; blanked is a blank-decoded -EncodedCommand
// body (psparse.NestedScript.BlankDecoded).
func powerShellStatementWrapper(
	source string,
	script *psparse.Script,
	statement psparse.Statement,
	whole bool,
) (body string, dialect Dialect, start, end int, moves, ok, blanked bool) {
	pipeline, isPipeline := statement.(*psparse.Pipeline)
	if !isPipeline || pipeline.ChainRHS != nil || pipeline.ChainOp != "" ||
		pipeline.Background || len(pipeline.Redirs) != 0 || len(pipeline.Elements) != 1 {
		return
	}
	command, isCommand := pipeline.Elements[0].(*psparse.Command)
	if !isCommand || len(command.Redirs) != 0 || command.StopParsing != "" {
		return
	}
	start, end = pipeline.Span()
	if start < 0 || end > len(source) || start >= end {
		return
	}
	if block, isBlock := command.Name.(*psparse.ScriptBlockExpr); isBlock &&
		(command.InvokeOp == "&" || command.InvokeOp == ".") && len(command.Elements) == 0 {
		blockStart, blockEnd := block.Span()
		if len(block.Params) != 0 || blockStart < 0 || blockEnd > len(source) ||
			blockEnd-blockStart < 2 || source[blockStart] != '{' || source[blockEnd-1] != '}' {
			return
		}
		body = source[blockStart+1 : blockEnd-1]
		return body, DialectPowerShell, start, end, false, true, false
	}
	name, named := psparse.LiteralString(command.Name)
	if !named {
		return
	}
	// A launcher between other statements keeps psparse's own reading: its
	// statement is read whole as a statement of the list
	// (HostScriptReadings), so its payload as written is read there, once,
	// not pasted into the list a second time (launcherNestedScripts).
	extract := psparse.ExtractNestedScripts
	if whole {
		extract = launcherNestedScripts
	}
	nested := extract(&psparse.Script{
		Statements: []psparse.Statement{statement},
		Dialect:    script.Dialect,
	})
	var found *psparse.NestedScript
	for i := range nested {
		if nested[i].Source != psparse.Node(command) {
			continue
		}
		if found != nil {
			return
		}
		found = &nested[i]
	}
	if found == nil || !found.Static || found.Text == "" {
		return
	}
	switch found.Kind {
	case psparse.KindPowerShellCommand, psparse.KindEncodedCommand:
		if !hostLauncherIdentity(name, "powershell") && !hostLauncherIdentity(name, "pwsh") ||
			commandHasEmptyWord(command) || !launcherWordsArePlain(command) {
			return
		}
		location, readable := launcherWorkingDirectory(source, command)
		if !readable {
			return
		}
		found.Text, moves = location+found.Text, location != ""
		dialect = DialectPowerShell
	case psparse.KindIEXLiteral:
		dialect = DialectPowerShell
	case psparse.KindCmdC:
		if !hostLauncherIdentity(name, "cmd") {
			return
		}
		// psparse joins every word after /c with a blank; the line cmd.exe
		// receives re-quotes the words that hold blanks, so the payload is
		// rebuilt from the words.
		payload, isPayload := cmdCommandPayload(command)
		if !isPayload {
			return
		}
		found.Text = payload
		dialect = DialectCMD
	default:
		return
	}
	return found.Text, dialect, start, end, moves, true, found.BlankDecoded
}

// launcherWorkingDirectory is the move a powershell or pwsh launcher call makes
// before its script: -WorkingDirectory (-wd, or an abbreviation) starts the
// script in that folder, so the reading of the script starts with
// `Set-Location -LiteralPath <value>; ` and its relative paths are read from
// there, not from the caller's folder (rel-1-0-10:GAP-0198). The value is the
// launcher's own argument as written, so the reading evaluates it as the
// caller's shell does. location is empty for a call with no such switch; ok is
// false when the switch is not one switch with one value before the script (a
// colon form, a quoted switch, no value, twice, or after -Command): that
// launcher stays unread, as before.
func launcherWorkingDirectory(source string, command *psparse.Command) (location string, ok bool) {
	value, started := -1, false
	for index, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Parameter:
			if !workingDirectoryWord("-" + typed.Name) {
				started = started || hostScriptSwitch(typed.Name)
				continue
			}
			if started || value >= 0 || typed.HasColon || typed.Colon != nil || index+1 >= len(command.Elements) {
				return "", false
			}
			if _, isArg := command.Elements[index+1].(*psparse.Arg); !isArg {
				return "", false
			}
			value = index + 1
		case *psparse.Arg:
			if text, static := psparse.LiteralString(typed.Value); static && workingDirectoryWord(text) {
				return "", false
			}
		}
	}
	if value < 0 {
		return "", true
	}
	start, end := command.Elements[value].(*psparse.Arg).Span()
	if start < 0 || end > len(source) || start >= end {
		return "", false
	}
	return "Set-Location -LiteralPath " + source[start:end] + "; ", true
}

// hostScriptSwitch reports a host switch (without its dash) that starts the
// script: -Command, -EncodedCommand or -File, or an abbreviation of one. A
// word after it belongs to the script, not to the host.
func hostScriptSwitch(name string) bool {
	name = strings.ToLower(name)
	return name != "" && (strings.HasPrefix("command", name) || strings.HasPrefix("encodedcommand", name) ||
		strings.HasPrefix("file", name))
}

// cmdCommandPayload is the line a `cmd /c <words>` call hands to cmd.exe: the
// static words after /c, with the words that hold blanks quoted. /k and a
// payload with a quote of its own are not modeled.
func cmdCommandPayload(command *psparse.Command) (string, bool) {
	var words []string
	seen := false
	for _, element := range command.Elements {
		argument, isArg := element.(*psparse.Arg)
		if !isArg {
			if seen {
				return "", false
			}
			continue
		}
		text, static := psparse.LiteralString(argument.Value)
		if !static {
			if seen {
				return "", false
			}
			continue
		}
		if !seen {
			switch strings.ToLower(text) {
			case "/c":
				seen = true
			case "/k", "/r":
				return "", false
			}
			continue
		}
		if text == "--%" {
			continue
		}
		words = append(words, text)
	}
	if !seen {
		return "", false
	}
	return cmdJoinPayload(words)
}

// cmdJoinPayload joins launcher words into the line cmd.exe runs. A single
// word is the line as written.
func cmdJoinPayload(words []string) (string, bool) {
	switch len(words) {
	case 0:
		return "", false
	case 1:
		return words[0], strings.TrimSpace(words[0]) != ""
	}
	parts := make([]string, len(words))
	for index, word := range words {
		if word == "" || strings.ContainsAny(word, "\"\r\n") {
			return "", false
		}
		parts[index] = word
		if strings.ContainsAny(word, " \t") {
			parts[index] = `"` + word + `"`
		}
	}
	return strings.Join(parts, " "), true
}

// launcherWordsArePlain reports a launcher call whose words are switches and
// string words only. A colon-glued switch value, a number literal or any other
// expression is not reproduced as the native argv the launcher receives, so such
// a call is not unwrapped. One variable is: the value of -WorkingDirectory
// ($env:X, psparse.FolderValueWord), which the caller's shell expands to the
// one folder word the launcher receives. The reading moves to it as written
// (launcherWorkingDirectory: Set-Location -LiteralPath $env:X), a folder the
// gateway cannot know, so the script's relative paths keep the hook folder's
// reading and are marked as in an unresolved folder; that launcher had no
// reading at all before (rel-1-0-10:GAP-1556).
func launcherWordsArePlain(command *psparse.Command) bool {
	for index, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Parameter:
			if typed.HasColon || typed.Colon != nil {
				return false
			}
		case *psparse.Arg:
			if _, isString := typed.Value.(*psparse.StringLit); !isString && !launcherWorkingDirectoryVariable(command, index) {
				return false
			}
		case *psparse.StringLit:
		default:
			return false
		}
	}
	return true
}

// launcherWorkingDirectoryVariable reports a launcher word that is a variable
// a folder word may be ($env:X, $HOME: psparse.FolderValueWord) given as the
// value of a -WorkingDirectory switch (-wd or an abbreviation) right before it.
func launcherWorkingDirectoryVariable(command *psparse.Command, index int) bool {
	if index == 0 {
		return false
	}
	switchWord, isParameter := command.Elements[index-1].(*psparse.Parameter)
	if !isParameter || !workingDirectoryWord("-"+switchWord.Name) {
		return false
	}
	variable, isVariable := command.Elements[index].(*psparse.Arg).Value.(*psparse.Variable)
	return isVariable && psparse.FolderValueWord(variable)
}

// launcherNestedScripts is psparse.ExtractNestedScripts of script, with the
// script of a launcher whose payload psparse leaves unread for legacy quoting
// alone (ps_legacy_quoting: a double quote, a blank word ending in a
// backslash, an empty word) read as written. Windows PowerShell 5.1 may drop
// or change that quote when it hands the word over, but pwsh 7 and any caller
// that hands over the argv as is run the payload
// as written, so it is one way the call runs. The reading only adds: the call
// as written is judged as before, and before this the payload had no reading
// at all, so an eventvwr handler chain in a quoted -Command body was allowed
// with no finding in every tier while the same chain sent plainly alerted
// (rel-1-0-10:GAP-1638). Only the legacy-quoting gate depends on the dialect
// (every word was resolved by the parse already), so no other payload is
// read differently, and a call without such a payload pays no second pass.
func launcherNestedScripts(script *psparse.Script) []psparse.NestedScript {
	nested := psparse.ExtractNestedScripts(script)
	for _, candidate := range nested {
		if candidate.Reason == psparse.ReasonLegacyQuoting {
			asWritten := *script
			asWritten.Dialect = psparse.DialectPwsh7
			return psparse.ExtractNestedScripts(&asWritten)
		}
	}
	return nested
}

// commandHasEmptyWord reports an empty static word among the words of a
// launcher call: PowerShell versions pass it differently, so the script stays
// opaque.
func commandHasEmptyWord(command *psparse.Command) bool {
	for _, element := range command.Elements {
		if argument, isArg := element.(*psparse.Arg); isArg {
			if text, static := psparse.LiteralString(argument.Value); static && text == "" {
				return true
			}
		}
	}
	return false
}

// unwrapCMDOnce unwraps a cmd.exe source that is one host launcher call. The
// last result is a blank-decoded -EncodedCommand body (hostScript).
func unwrapCMDOnce(source string) (string, Dialect, bool, bool) {
	argv, ok := soleCMDHostCall(source)
	if !ok {
		return "", DialectNone, false, false
	}
	program := commandProgramForDialect(argv[0], DialectCMD)
	script, ok := hostFromArgv(program, argv)
	if !ok {
		return "", DialectNone, false, false
	}
	return script.body, script.dialect, true, script.floorRaiseOnly
}

// soleCMDHostCall returns the argv of a cmd.exe source that is exactly one
// powershell, pwsh or cmd launcher call with static words and no pipe or
// redirect.
//
// A %NAME% reference in the line is read as written: the launched cmd.exe
// inherits the environment and expands it to the same value, so
// cmd /c "copy %USERPROFILE%\.git-credentials x" runs the copy its author
// wrote (rel-1-0-10:GAP-0998). Any other expansion keeps the line unread.
func soleCMDHostCall(source string) ([]string, bool) {
	source, names := maskedCMDVariables(source)
	probe := newParseOutput(DialectCMD, 1)
	lexemes, ok := windowsLex(source, windowsCMD, &probe)
	if !ok || probe.status != StatusComplete {
		return nil, false
	}
	commands, edges, ok := windowsBuildCommands(lexemes, &probe)
	if !ok || len(commands) != 1 || len(edges) != 0 || len(commands[0].redirects) != 0 {
		return nil, false
	}
	words := commands[0].words
	if len(words) < 2 || windowsNativeArgvUncertain(words[0], words[1:]) {
		return nil, false
	}
	for _, word := range words {
		if word.expands || word.wildcard {
			return nil, false
		}
	}
	values := windowsWordValues(words)
	for i := range values {
		values[i] = names.Replace(values[i])
	}
	return values, true
}

// maskedCMDVariables is source with each %NAME% reference (a name of
// letters, digits and _) replaced by a private-use marker the cmd lexer reads
// as a literal, and the replacer that writes the references back. A source
// that already holds the marker rune is returned as it is.
func maskedCMDVariables(source string) (string, *strings.Replacer) {
	const openMark, closeMark = '\ue000', '\ue001'
	if !strings.Contains(source, "%") || strings.ContainsRune(source, openMark) {
		return source, strings.NewReplacer()
	}
	var masked strings.Builder
	var pairs []string
	for i := 0; i < len(source); i++ {
		if source[i] == '%' {
			end := strings.IndexByte(source[i+1:], '%')
			name := ""
			if end > 0 {
				name = source[i+1 : i+1+end]
			}
			if name != "" && strings.IndexFunc(name, isNotCMDVariableNameRune) < 0 {
				marker := string(openMark) + strconv.Itoa(len(pairs)/2) + string(closeMark)
				pairs = append(pairs, marker, source[i:i+end+2])
				masked.WriteString(marker)
				i += end + 1
				continue
			}
		}
		masked.WriteByte(source[i])
	}
	return masked.String(), strings.NewReplacer(pairs...)
}

// isNotCMDVariableNameRune reports whether r falls outside the ASCII letters,
// digits and underscore of a %NAME% reference maskedCMDVariables keeps.
func isNotCMDVariableNameRune(r rune) bool {
	return r != '_' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z')
}

// hostLauncherIdentity reports that name is the Windows launcher family
// (powershell, pwsh or cmd) itself: a bare name, or a path under the system
// directories. A launcher of the same name in any other directory is an
// arbitrary program and is never unwrapped.
func hostLauncherIdentity(name, family string) bool {
	return windowsExactNativeExecutableIdentity(name, family) ||
		windowsExactNativeExecutableIdentity(name, family+".exe")
}

// hostFromArgv resolves the script a powershell, pwsh or cmd launcher argv
// runs. ok is false for any launcher form that does not name one static script:
// the caller then treats the launcher as an opaque command.
func hostFromArgv(program string, argv []string) (hostScript, bool) {
	if len(argv) == 0 || !hostLauncherIdentity(argv[0], strings.TrimSuffix(program, ".exe")) {
		return hostScript{}, false
	}
	switch program {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		body, dialect, ok, blanked := powerShellHostBody(argv)
		return hostScript{body: body, dialect: dialect, floorRaiseOnly: blanked}, ok
	case "cmd", "cmd.exe":
		body, dialect, ok := cmdHostBody(argv)
		return hostScript{body: body, dialect: dialect}, ok
	}
	return hostScript{}, false
}

// hostScript is the script a launcher argv runs. floorRaiseOnly: it is a
// blank-decoded -EncodedCommand body (psparse.NestedScript.BlankDecoded;
// Input.FloorRaiseOnly).
type hostScript struct {
	body           string
	dialect        Dialect
	floorRaiseOnly bool
}

// powerShellHostBody asks psparse what a powershell/pwsh argv runs. The argv
// is spelled as one call of single-quoted literals, so the verdict is the host
// command-line rules of psparse (parameter abbreviations, -Command joins,
// -EncodedCommand decoding, stdin and stop-parse reads, legacy quoting) and
// nothing else. The last result is a blank-decoded -EncodedCommand body
// (psparse.NestedScript.BlankDecoded).
func powerShellHostBody(argv []string) (string, Dialect, bool, bool) {
	for _, word := range argv {
		if word == "" {
			// An empty argument is passed differently across PowerShell
			// versions, so the script it belongs to stays opaque.
			return "", DialectNone, false, false
		}
	}
	location, readable := argvWorkingDirectory(argv)
	if !readable {
		return "", DialectNone, false, false
	}
	// The call is rendered by the one PowerShell renderer (the launcher as a
	// literal behind the call operator, then each word as an inert literal),
	// never quoted by hand (rel-1-0-10:GAP-0607). It is only read by psparse.
	var builder strings.Builder
	builder.WriteString(managed.WindowsCommandLine(argv[0]))
	for _, word := range argv[1:] {
		builder.WriteByte(' ')
		builder.WriteString(managed.PowerShellLiteral(word))
	}
	script, _ := psparse.Parse(builder.String(), psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 {
		return "", DialectNone, false, false
	}
	var found *psparse.NestedScript
	nested := launcherNestedScripts(script)
	for i := range nested {
		if nested[i].Kind != psparse.KindPowerShellCommand &&
			nested[i].Kind != psparse.KindEncodedCommand {
			continue
		}
		if found != nil {
			return "", DialectNone, false, false
		}
		found = &nested[i]
	}
	if found == nil || !found.Static || strings.TrimSpace(found.Text) == "" {
		return "", DialectNone, false, false
	}
	return location + found.Text, DialectPowerShell, true, found.BlankDecoded
}

// argvWorkingDirectory is launcherWorkingDirectory for a launcher argv: the
// script is read after `Set-Location -LiteralPath '<value>'; ` when the host
// words carry one -WorkingDirectory (or -wd, or an abbreviation) with one
// value before the script; ok is false for any other spelling of it.
func argvWorkingDirectory(argv []string) (location string, ok bool) {
	location, started := "", false
	for i := 1; i < len(argv); i++ {
		word := strings.TrimSpace(argv[i])
		if !workingDirectoryWord(word) {
			if strings.HasPrefix(word, "-") || strings.HasPrefix(word, "/") {
				started = started || hostScriptSwitch(strings.TrimLeft(word, "-/"))
			}
			continue
		}
		move, readable := workingDirectoryMove(argv, i)
		if started || location != "" || !readable {
			return "", false
		}
		location = move
		i++
	}
	return location, true
}

// workingDirectoryMove is the move the -WorkingDirectory word argv[i] makes,
// `Set-Location -LiteralPath '<value>'; `: ok is false for the colon form, no
// value, a blank value or a value that is a switch.
func workingDirectoryMove(argv []string, i int) (string, bool) {
	if strings.Contains(argv[i], ":") || i+1 >= len(argv) {
		return "", false
	}
	if value := strings.TrimSpace(argv[i+1]); value == "" || strings.HasPrefix(value, "-") {
		return "", false
	}
	return "Set-Location -LiteralPath " + managed.PowerShellLiteral(argv[i+1]) + "; ", true
}

func workingDirectoryWord(word string) bool {
	name := strings.ToLower(strings.TrimSpace(word))
	if !strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "/") {
		return false
	}
	name = strings.TrimLeft(name, "-/")
	if colon := strings.IndexByte(name, ':'); colon >= 0 {
		name = name[:colon]
	}
	return name == "wd" || len(name) >= 2 && strings.HasPrefix("workingdirectory", name)
}

// cmdHostBody resolves the line `cmd /c <words>` runs. A single word is the
// line as written; several words are joined as the launcher passes them, each
// word with blanks re-quoted. Any other cmd.exe switch before /c, and /k, are
// not modeled: the call stays opaque.
func cmdHostBody(argv []string) (string, Dialect, bool) {
	for i := 1; i < len(argv); i++ {
		switch strings.TrimPrefix(strings.ToLower(argv[i]), "/") {
		case "c":
			body, ok := cmdJoinPayload(argv[i+1:])
			return body, DialectCMD, ok
		case "d", "q", "s", "a", "u":
		default:
			return "", DialectNone, false
		}
	}
	return "", DialectNone, false
}

// soleHostCall recognizes a POSIX parse whose one top-level command is an
// unconditional launcher call (powershell, pwsh or cmd with a static script) and
// returns the script it runs. Commands nested under it (the tokenizer's own
// reading of an exact launcher) are ignored: the script is read again from the
// launcher's argv.
func soleHostCall(out *parseOutput) (hostScript, bool) {
	var top []CommandFact
	for _, command := range out.commands {
		if command.ParentCommandID == 0 {
			top = append(top, command)
		}
	}
	if len(top) != 1 {
		return hostScript{}, false
	}
	command := top[0]
	if command.PipelineID != 0 || command.ControlFlowUncertain || command.Background ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		!command.ArgvComplete || len(command.Argv) < 2 || len(command.Arguments) != len(command.Argv) {
		return hostScript{}, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return hostScript{}, false
		}
	}
	return hostFromArgv(commandProgram(command.Executable), command.Argv)
}

// posixSoleHostCallSource is the script text of a POSIX source that is one
// static launcher call; blanked is a blank-decoded -EncodedCommand body
// (hostScript).
func posixSoleHostCallSource(source string) (body string, dialect Dialect, ok, blanked bool) {
	lower := strings.ToLower(source)
	if !strings.Contains(lower, "powershell") && !strings.Contains(lower, "pwsh") &&
		!strings.Contains(lower, "cmd") {
		return "", DialectNone, false, false
	}
	out := parsePOSIX(source, 1, 0)
	script, ok := soleHostCall(&out)
	if !ok {
		return "", DialectNone, false, false
	}
	return script.body, script.dialect, true, script.floorRaiseOnly
}

// powerShellVerbNoun is a cmdlet name in the approved-verb form
// (Get-ChildItem, Set-Location, Invoke-WebRequest) that opens the text or its
// call block. No POSIX program is named so; the text is PowerShell whatever
// tool label it arrived under, because connector tool labels do not identify
// the host shell on Windows (chooseRawCommandDialect). A cmdlet name further in
// (inside a quoted -Command body, after a POSIX && or here-document) does not
// make the text PowerShell: a mixed text read whole as PowerShell resolves its
// POSIX paths and redirects wrongly.
var powerShellVerbNoun = lazyMustCompile(`(?i)^\s*(?:&\s*\{\s*)?(?:get|set|new|remove|add|invoke|start|stop|out|write|copy|move|test|select|where|foreach|clear|import|export|enable|disable|register|unregister|update|restart|resolve|read|rename|expand|compress|format|measure|sort|join|split|convert|find|install|uninstall|grant|revoke|send|wait|push|pop|reset)-[a-z][a-z0-9]*\b`)

// powerShellOnlyGrammar reports a text, read by the tokenizer as a POSIX or
// unlabeled command, that opens with PowerShell-only grammar: a call block (& {
// ... }) or a verb-noun cmdlet. HostScriptTwin then
// reads the same text a second time as PowerShell; the reading only adds.
func powerShellOnlyGrammar(source string) bool {
	trimmed := strings.TrimSpace(source)
	if strings.HasPrefix(trimmed, "& {") {
		return true
	}
	if powerShellVerbNoun.MatchString(source) {
		return true
	}
	first := strings.ToLower(trimmed)
	if end := strings.IndexAny(first, " \t\r\n;|"); end > 0 {
		first = first[:end]
	}
	return powerShellOnlyAliases[first] || powerShellVariableAssignment.MatchString(trimmed)
}

// plainHostLauncherLine reports a text that is one powershell or pwsh
// launcher call of plain words only (letters, digits, blanks and - + / = . _ :):
// a POSIX shell, cmd.exe and PowerShell split it into the same words, so the
// text read as PowerShell is the call whatever tool label it came under. It is
// how an -EncodedCommand launcher a POSIX tool runs gets the reading the
// PowerShell-tool spelling gets when the POSIX reading stops at its word limit
// (rel-1-0-10:GAP-0345). One pass over the text, no parse.
func plainHostLauncherLine(source string) bool {
	text := strings.TrimSpace(source)
	end := strings.IndexAny(text, " \t")
	if end <= 0 {
		return false
	}
	if first := text[:end]; !hostLauncherIdentity(first, "powershell") && !hostLauncherIdentity(first, "pwsh") {
		return false
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case 'a' <= c && c <= 'z', 'A' <= c && c <= 'Z', '0' <= c && c <= '9':
		case c == ' ' || c == '\t' || c == '-' || c == '+' || c == '/' || c == '=' || c == '.' || c == '_' || c == ':':
		default:
			return false
		}
	}
	return true
}

// TruncatedHostCall reports a call the tokenizer stopped reading at its input
// bound that holds a Windows host script the script reading would have read:
// a call that names a powershell, pwsh or cmd launcher in any shape and under
// any tool label (hostLauncherMention: beside other statements, behind a cmd
// /c wrapper, by a quoted or path launcher, in an argv, in a JSON array
// command), or a PowerShell or cmd call (by its tool label or dialect hint)
// that names a call block or Invoke-Expression (overSizeHostScriptMention).
// The text is read from the arguments as given, up to their size limit. Such
// a call is judged as truncated, never a clean allow (rel-1-0-10:GAP-0345,
// GAP-0608); one long ordinary statement past the bound stays as the readers
// left it (GAP-0318). The caller asks only for a call past the input bound.
func TruncatedHostCall(input Input) bool {
	if len(input.Argv) != 0 {
		for _, word := range input.Argv {
			if hostLauncherWord(word) {
				return true
			}
		}
		return hostLauncherArgv(input.Argv, 0)
	}
	windows := input.DialectHint == DialectPowerShell || input.DialectHint == DialectCMD
	switch strings.ToLower(input.Tool) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe":
		windows = true
	}
	text := input.Command
	if text == "" {
		if len(input.Args) == 0 || !argsExecutionTool(input.Tool) {
			return false
		}
		if len(input.Args) > maxTruncatedHostCallArgsBytes {
			// Too large to screen: a Windows call is truncated unread.
			return windows
		}
		var args struct {
			Command string `json:"command"`
		}
		if json.Unmarshal(input.Args, &args) == nil {
			text = args.Command
		} else {
			// A command that is an array of words: its words are joined.
			var words struct {
				Command []any `json:"command"`
			}
			if json.Unmarshal(input.Args, &words) != nil {
				return false
			}
			parts := make([]string, 0, len(words.Command))
			for _, word := range words.Command {
				if text, ok := word.(string); ok {
					parts = append(parts, text)
				}
			}
			if hostLauncherArgv(parts, 0) {
				return true
			}
			text = strings.Join(parts, " ")
		}
	}
	return hostLauncherMention(text) || windows && overSizeHostScriptMention(text)
}

// hostLauncherWord reports an argv word whose program is powershell, pwsh or
// cmd, by its last path element.
func hostLauncherWord(word string) bool {
	base := strings.ToLower(word[strings.LastIndexAny(word, `/\`)+1:])
	switch strings.TrimSuffix(base, ".exe") {
	case "powershell", "pwsh", "cmd":
		return true
	}
	return false
}

// hostLauncherMention reports a text that runs a powershell, pwsh or cmd
// launcher: by the shell's own reading of the text (hostLauncherStatements:
// a launcher as the command of a statement, behind a wrapper and its options,
// in a local shell -c, eval or backtick script, quoted or by a path), or by
// the pattern screen, which also sees the text the reading steps over (a
// here-document body) and the text it cannot follow (an unterminated quote).
// The launcher word of another command's quoted argument (an ssh remote
// command, a message) is data and names nothing (rel-1-0-10:GAP-0608,
// GAP-0740).
func hostLauncherMention(text string) bool {
	return hostLauncherStatements(text, 0) || hostLauncherPatternMention(text)
}

// hostLauncherPatternMention reports a text with a powershell, pwsh or cmd
// launcher at a command position: at the start, after a statement separator
// (; & | && || ( ) { } or a line break), behind sudo, env, exec, nohup,
// command, time or start, by name or by a path, quoted or bare. A launcher
// word inside an open quoted string (an odd count of quote characters before
// it) is a word of another command. Past maxLauncherMentionMatches
// candidates the text counts as naming one, so the screen is bounded. One
// pass of a regular expression; no parse.
func hostLauncherPatternMention(text string) bool {
	matches := hostLauncherAtCommand.FindAllStringIndex(text, maxLauncherMentionMatches+1)
	if len(matches) > maxLauncherMentionMatches {
		return true
	}
	for _, match := range matches {
		before := text[:match[0]]
		if strings.Count(before, "'")%2 == 0 && strings.Count(before, `"`)%2 == 0 {
			return true
		}
	}
	return false
}

// maxLauncherMentionMatches bounds the candidates hostLauncherPatternMention checks.
const maxLauncherMentionMatches = 64

// hostLauncherAtCommand is a launcher word at a command position
// (hostLauncherPatternMention).
var hostLauncherAtCommand = lazyMustCompile(`(?i)(?:^|[;&|(){}\n]|&&|\|\|)[ \t]*(?:(?:sudo|env|exec|nohup|command|time|start)[ \t]+)*["'\x60]?(?:[a-z]:)?(?:[^\s;&|"'\x60()]*[/\\])?(?:powershell|pwsh|cmd)(?:\.exe)?["'\x60]?(?:[ \t]|$)`)

// maxTruncatedHostCallArgsBytes bounds the arguments TruncatedHostCall
// screens (four times the analysis bound, the hook body size).
const maxTruncatedHostCallArgsBytes = 4 * maxArgsJSONBytes

// overSizeHostScriptMention reports a text that names what the script
// reading reads: a powershell or pwsh launcher, a call block or
// Invoke-Expression (its iex alias as a word). One pass, no parse.
func overSizeHostScriptMention(text string) bool {
	lower := strings.ToLower(text)
	for _, word := range []string{"powershell", "pwsh", "invoke-expression", "& {", "&{"} {
		if strings.Contains(lower, word) {
			return true
		}
	}
	for index := strings.Index(lower, "iex"); index >= 0; {
		before := index == 0 || !isWordByte(lower[index-1])
		after := index+3 >= len(lower) || !isWordByte(lower[index+3])
		if before && after {
			return true
		}
		next := strings.Index(lower[index+3:], "iex")
		if next < 0 {
			break
		}
		index += 3 + next
	}
	return false
}

func isWordByte(c byte) bool {
	return 'a' <= c && c <= 'z' || '0' <= c && c <= '9' || c == '_' || c == '-'
}

// powerShellVariableAssignment is a statement that starts with $name = ...:
// no POSIX shell has that, and cmd.exe does not expand it.
var powerShellVariableAssignment = lazyMustCompile(`^\$[A-Za-z_][A-Za-z0-9_:]*\s*[-+*/]?=`)

// powerShellOnlyAliases are PowerShell aliases that no POSIX or cmd.exe
// program is called: a text that opens with one is PowerShell.
var powerShellOnlyAliases = map[string]bool{
	"iwr": true, "irm": true, "iex": true, "gci": true, "sls": true, "saps": true,
	"cpi": true, "ii": true,
}

// rawCMDLauncherLine is the line a `cmd /c <line>` call written in a POSIX
// shell hands to cmd.exe when the text after /c is read as cmd.exe reads it, not
// as the POSIX shell would split it: a POSIX word turns every backslash into an
// escape and drops it, which destroys the registry and file paths the line
// names, while the author of the call (and cmd.exe, given the text) means them
// as written. One pair of quotes around the whole line is removed (cmd.exe
// removes it too). Only the leading cmd launcher is read; anything before it is
// no cmd call at all.
func rawCMDLauncherLine(source string) (string, Dialect, bool) {
	text := strings.TrimSpace(source)
	word := func() string {
		end := strings.IndexAny(text, " \t")
		if end < 0 {
			end = len(text)
		}
		first := text[:end]
		text = strings.TrimLeft(text[end:], " \t")
		return first
	}
	if launcher := strings.Trim(word(), `"`); !hostLauncherIdentity(launcher, "cmd") {
		return "", DialectNone, false
	}
	for text != "" {
		switchWord := strings.ToLower(word())
		if strings.HasPrefix(switchWord, "//") {
			// Git Bash (MSYS) hands a //c switch to cmd.exe as /c.
			switchWord = switchWord[1:]
		}
		switch switchWord {
		case "/c", "/r":
			// /r is /c. /k (the shell stays open) is not modeled: the call
			// stays partial, as the Windows marker tests pin (GAP-0364).
			line := text
			if len(line) >= 2 && (line[0] == '"' && line[len(line)-1] == '"' ||
				line[0] == '\'' && line[len(line)-1] == '\'') {
				line = line[1 : len(line)-1]
			}
			line = strings.TrimSpace(line)
			return line, DialectCMD, line != ""
		case "/d", "/q", "/s", "/a", "/u":
		default:
			return "", DialectNone, false
		}
	}
	return "", DialectNone, false
}

// powerShellCmdLauncherLine is the line a PowerShell call that is a cmd
// launcher (cmd, cmd.exe or the system's cmd.exe, bare or after the &
// call operator) hands to cmd.exe, read as its author wrote it
// (rawCMDLauncherLine). PowerShell's own reading of the words may differ: an
// unquoted & or | is its own operator, and Windows PowerShell 5.1 re-quotes a
// native argv, so psparse leaves the line non-static; the author means the
// line as cmd.exe reads it, and the Bash tool's spelling of the same call is
// read that way. It is a second reading beside the call as written: it only
// adds (rel-1-0-10:GAP-0552).
func powerShellCmdLauncherLine(source string) (string, bool) {
	text := strings.TrimSpace(source)
	if rest, ok := strings.CutPrefix(text, "&"); ok {
		text = strings.TrimSpace(rest)
	}
	line, dialect, ok := rawCMDLauncherLine(text)
	return line, ok && dialect == DialectCMD
}

// posixLauncherRequotedBody is the -Command script of a POSIX call to a
// PowerShell host whose words psparse will not resolve to one script because
// a word holds a blank: PowerShell joins the words after -Command with single
// blanks, so `-Command Add-Content -Path "C:\Users\a b\f" -Value x` runs with
// the path split in two, or, as its author meant it and as PowerShell 7 reads
// a quoted argument, with the path whole. This reading is the author's: each
// word with a blank is quoted again. It is a second reading beside the call as
// written, so it only adds what that spelling does.
func posixLauncherRequotedBody(source string) (string, Dialect, bool) {
	lower := strings.ToLower(source)
	if !strings.Contains(lower, "powershell") && !strings.Contains(lower, "pwsh") {
		return "", DialectNone, false
	}
	out := parsePOSIX(source, 1, 0)
	var top []CommandFact
	for _, command := range out.commands {
		if command.ParentCommandID == 0 {
			top = append(top, command)
		}
	}
	if len(top) != 1 {
		return "", DialectNone, false
	}
	command := top[0]
	if command.PipelineID != 0 || command.ControlFlowUncertain || command.Background ||
		len(command.Redirects) != 0 || len(command.Wrappers) != 0 || !command.ArgvComplete ||
		len(command.Argv) < 3 || len(command.Arguments) != len(command.Argv) {
		return "", DialectNone, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return "", DialectNone, false
		}
	}
	program := commandProgram(command.Executable)
	if !hostLauncherIdentity(command.Argv[0], strings.TrimSuffix(program, ".exe")) ||
		!slices.Contains([]string{"powershell", "powershell.exe", "pwsh", "pwsh.exe"}, program) {
		return "", DialectNone, false
	}
	argv := command.Argv
	index := 1
	for ; index < len(argv); index++ {
		word := strings.ToLower(argv[index])
		switch {
		case len(word) >= 2 && word[0] == '-' && strings.HasPrefix("command", word[1:]):
			index++
			goto found
		case word == "-executionpolicy" || word == "-ep" || word == "-windowstyle" || word == "-w":
			index++
		case word == "-noprofile" || word == "-nop" || word == "-noninteractive" || word == "-noni" ||
			word == "-nologo" || word == "-nol":
		default:
			return "", DialectNone, false
		}
	}
	return "", DialectNone, false
found:
	if len(argv)-index < 2 {
		// One word is the script itself, not words PowerShell joins.
		return "", DialectNone, false
	}
	parts := make([]string, 0, len(argv)-index)
	spaced := false
	for _, word := range argv[index:] {
		switch {
		case word == "" || strings.ContainsAny(word, "\"'`$\r\n"):
			return "", DialectNone, false
		case strings.ContainsAny(word, " \t"):
			spaced = true
			parts = append(parts, `"`+word+`"`)
		default:
			parts = append(parts, word)
		}
	}
	if !spaced {
		// No blank to preserve: psparse's own reading of the call is the one.
		return "", DialectNone, false
	}
	return strings.Join(parts, " "), DialectPowerShell, true
}

// posixOnlySyntax reports a text that holds a here-document operator (<<): no
// PowerShell statement has one, so the text is a POSIX script whose body lines
// (a note, a README, a script it writes) are not PowerShell statements and are
// not read as a list of them.
func posixOnlySyntax(source string) bool {
	return strings.Contains(source, "<<")
}

// maxListReadings is the number of statements of one list that are read one by
// one (a work bound of the extra readings; the call's own statement budget
// decides a longer list).
const maxListReadings = 32

// HostScriptReading is what HostScriptReadings returns: the readings of the
// script a call runs, to be judged beside the call as written, and the bounds
// that cut the reading short.
type HostScriptReading struct {
	// Twins are the second readings: the script of a static launcher, call
	// block or Invoke-Expression literal, or the statements of a PowerShell
	// list one by one. Each is judged on its own; their findings are only
	// ever added to those of the call as written.
	Twins []Input
	// Depth is the number of wrapper layers used so far, including the ones
	// this reading unwrapped. A twin is read again with it as its depth, so
	// one call has one wrapper budget however its twins nest.
	Depth int
	// Listed[i] marks twin i as a statement (or an edge-trimmed run of
	// statements) of a list: it is never split into statements again.
	Listed []bool
	// Caps is the set of bounds the reading hit: the wrapper depth, the
	// nested size budget, a body past the in-list size, more nested scripts
	// than maxListReadings. A truncated reading is judged at the unknown tier of
	// the pack at least (internal/guardrail/bounded).
	Caps bounded.CapSet
}

// HostScriptTwin is HostScriptReadings at depth 0: the first twin, which is the
// script of a launcher, for callers that want that one script.
func HostScriptTwin(input Input, facts Facts) (Input, bool) {
	reading := HostScriptReadings(input, facts, 0, false)
	if len(reading.Twins) == 0 {
		return Input{}, false
	}
	return reading.Twins[0], true
}

// HostScriptReadings (listed: the input is itself a statement or a run of
// statements of a list, so it is not split again) is the second reading of a call that runs a static
// powershell, pwsh or cmd launcher, a call block or an Invoke-Expression of a
// literal, or that is a list of PowerShell statements: the same call written
// as the script it runs, in the script's own grammar (psparse decides what the
// launcher runs: ExtractNestedScripts), a statement at a time for a list.
//
// The reading is ADDITIVE. The call is analyzed as written, exactly as before,
// and its facts are never changed by the launcher; a caller judges each twin
// as a separate reading and may only add the findings it raises to those of
// the call as written (the gateway does, through withOverLimitTwinFindings). A
// psparse result therefore cannot hide, replace or soften anything the
// tokenizer saw, and a launcher psparse cannot resolve to one static script has
// no reading at all (the call stays as unknown as it was). A bound of the
// reading itself is not silent: it comes back in Caps.
func HostScriptReadings(input Input, facts Facts, depth int, listed bool) HostScriptReading {
	reading := HostScriptReading{Depth: depth}
	if facts.Parse.Status == StatusLimitExceeded && len(input.Argv) == 0 &&
		len(shellCommandText(input)) > maxCommandBytes {
		return reading
	}
	if depth >= 2*maxWrapperDepth {
		// A twin of a twin of a twin: one call never reads past twice the
		// wrapper depth, whatever its shape (a list of lists of lists).
		reading.Caps = bounded.Of(bounded.Depth)
		return reading
	}
	source := shellCommandText(input)
	// Hook calls run this on every tool call: most have no launcher, call
	// block, Invoke-Expression or statement list, and a substring screen says
	// so before any parse.
	if len(input.Argv) == 0 && !mayHoldHostScript(source) && !strings.ContainsAny(source, ";\r\n") {
		return reading
	}
	var dialect Dialect
	layers := 0 // launchers already resolved from the argv or the POSIX call
	// blanked: a launcher resolved here runs a blank-decoded -EncodedCommand
	// body (Input.FloorRaiseOnly).
	blanked := false
	switch {
	case len(input.Argv) != 0:
		program := commandProgramForDialect(input.Argv[0], DialectPowerShell)
		script, ok := hostFromArgv(program, input.Argv)
		if !ok {
			return reading
		}
		source, dialect, layers, blanked = script.body, script.dialect, 1, script.floorRaiseOnly
	case source == "" || len(source) > maxCommandBytes:
		return reading
	default:
		dialect, _ = chooseRawCommandDialect(input.Tool, input.DialectHint, source)
		if dialect == DialectPOSIX || dialect == DialectNone || dialect == DialectMixed {
			body, bodyDialect, ok := rawCMDLauncherLine(source)
			if !ok {
				body, bodyDialect, ok, blanked = posixSoleHostCallSource(source)
			}
			if !ok {
				// The home the shell expands in the launcher's words
				// (pwsh -Command "... $HOME/f ..."), spelled out.
				if homed, spelled := posixLauncherHomeSource(source, input.ActiveHome); spelled {
					body, bodyDialect, ok, blanked = posixSoleHostCallSource(homed)
				}
			}
			if !ok {
				body, bodyDialect, ok = posixLauncherRequotedBody(source)
			}
			if !ok && (powerShellOnlyGrammar(source) || plainHostLauncherLine(source)) {
				body, bodyDialect, ok = source, DialectPowerShell, true
			}
			if !ok {
				return reading
			}
			source, dialect = body, bodyDialect
			if body != shellCommandText(input) {
				layers = 1
			}
		}
	}
	if dialect != DialectPowerShell && dialect != DialectCMD {
		return reading
	}
	unwrapped, _ := unwrapHostSource(source, dialect, depth+layers)
	reading.Caps = unwrapped.caps
	reading.Depth = depth + layers + unwrapped.layers
	// A PowerShell call that is a cmd launcher is also read as the cmd.exe
	// line its author wrote (powerShellCmdLauncherLine).
	var cmdLine *Input
	if dialect == DialectPowerShell {
		if line, ok := powerShellCmdLauncherLine(source); ok && (unwrapped.layers <= 0 || unwrapped.source != line) {
			twin := input
			twin.Args, twin.Argv = nil, nil
			twin.Command, twin.DialectHint = line, DialectCMD
			cmdLine = &twin
			if reading.Depth == depth+layers {
				reading.Depth++
			}
		}
	}
	if unwrapped.layers > 0 || layers > 0 {
		twin := input
		twin.Args, twin.Argv = nil, nil
		twin.Command = unwrapped.source
		if unwrapped.dialect == DialectPowerShell {
			twin.Command = withoutUnreachableStatements(unwrapped.source)
		}
		twin.DialectHint = unwrapped.dialect
		twin.FloorRaiseOnly = twin.FloorRaiseOnly || blanked || unwrapped.floorRaiseOnly
		// The twin is the script a launcher runs.
		twin.PowerShellLauncherBody = true
		reading.Twins = append(reading.Twins, twin)
		// A launcher word that holds a blank has two readings: the words
		// joined as PowerShell 5.1 joins them (psparse's), and quoted as its
		// author wrote them. The second is judged too.
		if len(input.Argv) == 0 && layers == 1 && unwrapped.layers == 0 {
			if requoted, requotedDialect, ok := posixLauncherRequotedBody(shellCommandText(input)); ok &&
				requoted != unwrapped.source {
				second := twin
				second.Command, second.DialectHint = requoted, requotedDialect
				reading.Twins = append(reading.Twins, second)
			}
		}
		if cmdLine != nil {
			reading.Twins = append(reading.Twins, *cmdLine)
		}
		// The twin is a script: its own list of statements is read when the
		// twin is read in turn, with the depth carried.
		return reading
	}
	if cmdLine != nil {
		reading.Twins = append(reading.Twins, *cmdLine)
		reading.Listed = append(reading.Listed, false)
	}
	if dialect != DialectPowerShell || listed {
		return reading
	}
	statements, caps := powerShellStatementTexts(source)
	reading.Caps = reading.Caps.Union(caps)
	for _, text := range statements {
		twin := input
		twin.Args, twin.Argv = nil, nil
		twin.Command = text
		twin.DialectHint = DialectPowerShell
		reading.Twins = append(reading.Twins, twin)
		reading.Listed = append(reading.Listed, true)
	}
	reading.Depth = depth + 1
	// Launchers, call blocks and evaluated literals anywhere in the tree (in a
	// branch, a loop, a try, a function, a pipeline stage, an assignment or a
	// sub-expression), each read as the script it runs.
	nested, nestedCaps := powerShellNestedTexts(source)
	reading.Caps = reading.Caps.Union(nestedCaps)
	for _, item := range nested {
		if slices.ContainsFunc(reading.Twins, func(have Input) bool { return have.Command == item.text }) {
			continue
		}
		twin := input
		twin.Args, twin.Argv = nil, nil
		twin.Command = item.text
		twin.DialectHint = item.dialect
		twin.FloorRaiseOnly = twin.FloorRaiseOnly || item.floorRaiseOnly
		reading.Twins = append(reading.Twins, twin)
		reading.Listed = append(reading.Listed, false)
	}
	return reading
}

// nonStaticNestedText is the script of a launcher spelling psparse reports as
// not static but whose text is written out: powershell -Command { block },
// powershell -Command "<script>" that expands only $HOME and $env:NAME
// (psparse.HostCommandChildText, rel-1-0-10:GAP-1226), and Start-Process
// powershell -ArgumentList <literal words with -Command> or <one literal
// command line> (startProcessCommandLine).
func nonStaticNestedText(source string, nested psparse.NestedScript) (string, bool) {
	command, ok := nested.Source.(*psparse.Command)
	if !ok {
		return "", false
	}
	name, named := psparse.LiteralString(command.Name)
	if !named {
		return "", false
	}
	switch nested.Reason {
	case psparse.ReasonNonLiteral:
		if !hostLauncherIdentity(name, "powershell") && !hostLauncherIdentity(name, "pwsh") ||
			commandHasEmptyWord(command) {
			return "", false
		}
		if _, readable := launcherWorkingDirectory(source, command); !readable {
			// The caller adds the move to the working directory.
			return "", false
		}
		var block *psparse.ScriptBlockExpr
		for _, element := range command.Elements {
			if argument, isArg := element.(*psparse.Arg); isArg {
				if candidate, isBlock := argument.Value.(*psparse.ScriptBlockExpr); isBlock {
					if block != nil {
						return "", false
					}
					block = candidate
				}
			}
		}
		if block == nil {
			return psparse.HostCommandChildText(command)
		}
		if len(block.Params) != 0 {
			return "", false
		}
		start, end := block.Span()
		if start < 0 || end > len(source) || end-start < 2 || source[start] != '{' || source[end-1] != '}' {
			return "", false
		}
		return source[start+1 : end-1], true
	case psparse.ReasonChildArgv:
		switch strings.ToLower(name) {
		case "start-process", "saps", "start":
		default:
			return "", false
		}
		words := cradleWords(command)
		var host string
		var list psparse.Expr
		for index := 0; index < len(words); index++ {
			word := words[index]
			switch {
			case word.param && len(word.text) >= 1 && strings.HasPrefix("argumentlist", word.text):
				list = word.value
				if list == nil && index+1 < len(words) {
					// The value word is the list, never the program.
					index++
					list = words[index].value
				}
			case !word.param && host == "" && word.text != "":
				host = word.text
			}
		}
		if !hostLauncherIdentity(host, "powershell") && !hostLauncherIdentity(host, "pwsh") {
			return "", false
		}
		if line, isLine := list.(*psparse.StringLit); isLine {
			return startProcessCommandLine(host, line)
		}
		array, isArray := list.(*psparse.ArrayLit)
		if !isArray {
			return "", false
		}
		var rest []string
		seen := false
		for _, element := range array.Elements {
			// A word with a double quote is read as written, as a launcher
			// body that holds one is (launcherNestedScripts,
			// rel-1-0-10:GAP-1638).
			text, static := psparse.LiteralString(element)
			if !static {
				return "", false
			}
			if seen {
				rest = append(rest, text)
			} else if lower := strings.ToLower(text); lower != "" && lower[0] == '-' &&
				len(lower) >= 2 && strings.HasPrefix("command", lower[1:]) {
				seen = true
			}
		}
		if !seen || len(rest) == 0 {
			return "", false
		}
		// Start-Process joins the words with blanks into the child's command
		// line, so a body word written "<chain>" is the chain
		// (rel-1-0-10:GAP-1655).
		return commandLineBody(strings.Join(rest, " ")), true
	}
	return "", false
}

// startProcessCommandLine is the script of Start-Process <host>
// -ArgumentList '<line>': the child host gets line as its command line, which
// it splits at blanks into its words, so the words are read by the launcher
// argv reading (powerShellLauncherBody: the host switches, then -Command or
// the first word that is not a switch, to the end). A line with a double quote
// is read as written: Windows PowerShell 5.1 may drop the quote when it splits
// the line, but the script as written is one way the call runs, and before
// this the line had no reading at all, so an eventvwr handler chain given as
// the line was allowed with no finding in every tier while the same chain sent
// plainly alerted (rel-1-0-10:GAP-1638). Newlines stay inside their word, as
// the host splits at spaces and tabs only. A body that is one double-quoted
// word (-Command "<chain>") is the chain: the host splits its command line
// with the CommandLineToArgvW rules, which take off that pair of quotes and
// turn \" into ", so the body is read with one level of quotes taken off
// (commandLineQuotedWord); as written it is a string expression that runs
// nothing (rel-1-0-10:GAP-1655).
func startProcessCommandLine(host string, line *psparse.StringLit) (string, bool) {
	text, static := psparse.LiteralString(line)
	if !static {
		return "", false
	}
	words := strings.FieldsFunc(text, func(r rune) bool { return r == ' ' || r == '\t' })
	body, ok := powerShellLauncherBody(append([]string{host}, words...))
	if !ok {
		return "", false
	}
	return commandLineBody(body), true
}

// commandLineBody is the script of a -Command body of a child command line.
// A body that starts with a double quote is, as written, a string expression
// that runs nothing; the child host splits its command line into words with
// the CommandLineToArgvW rules (commandLineWords) and joins the words after
// -Command with blanks, so that body is read as the join: -Command "a b" is
// a b (rel-1-0-10:GAP-1655), and so are -Command "a" "b", "a" ; "b" and
// "a""b" (a"b), which were read as written (rel-1-0-10:GAP-1660). A body
// whose first word is not quoted is read as written (rel-1-0-10:GAP-1638),
// and so is one whose words are all empty.
func commandLineBody(body string) string {
	if !strings.HasPrefix(body, `"`) {
		return body
	}
	joined := strings.Join(commandLineWords(body), " ")
	if strings.TrimSpace(joined) == "" {
		return body
	}
	return joined
}

// commandLineWords splits a Windows command line into the words a child
// process gets, with the CommandLineToArgvW rules: blanks (space, tab) end a
// word outside quotes; 2n backslashes before a double quote give n and the
// quote opens or closes a quoted part, 2n+1 give n and a literal quote;
// backslashes elsewhere are literal; within quotes a run of three quotes
// gives one literal quote and leaves the quoted part (so "a""b" is a"b); an
// open quoted part runs to the end of the line.
func commandLineWords(text string) []string {
	var words []string
	var word strings.Builder
	inWord, quotes, backslashes := false, 0, 0
	for i := 0; i < len(text); {
		c := text[i]
		switch {
		case (c == ' ' || c == '\t') && quotes == 0:
			if inWord {
				words = append(words, word.String())
				word.Reset()
				inWord = false
			}
			backslashes = 0
			i++
		case c == '\\':
			word.WriteByte(c)
			backslashes++
			inWord = true
			i++
		case c == '"':
			inWord = true
			kept := word.String()
			kept = kept[:len(kept)-backslashes/2]
			word.Reset()
			word.WriteString(kept)
			if backslashes%2 == 1 {
				// The last backslash escapes the quote.
				kept = word.String()
				word.Reset()
				word.WriteString(kept[:len(kept)-1])
				word.WriteByte('"')
			} else {
				quotes++
			}
			backslashes = 0
			i++
			for i < len(text) && text[i] == '"' {
				if quotes++; quotes == 3 {
					word.WriteByte('"')
					quotes = 0
				}
				i++
			}
			if quotes == 2 {
				quotes = 0
			}
		default:
			word.WriteByte(c)
			backslashes = 0
			inWord = true
			i++
		}
	}
	if inWord {
		words = append(words, word.String())
	}
	return words
}

type nestedText struct {
	text    string
	dialect Dialect
	// floorRaiseOnly: a blank-decoded -EncodedCommand body
	// (psparse.NestedScript.BlankDecoded; Input.FloorRaiseOnly).
	floorRaiseOnly bool
}

// powerShellNestedTexts is every static script embedded anywhere in a
// PowerShell script that psparse reads in full (psparse.ExtractNestedScripts
// walks the whole tree): a -Command or -EncodedCommand body of a PowerShell
// host, an Invoke-Expression literal, a script block built from a literal, a
// Start-Process -ArgumentList to a host, and a cmd /c line. Only the
// launchers' own identity is checked here (a program called powershell that
// is not the system's is not read as one). A script past the in-list size, or
// more of them than maxListReadings, is truncated.
func powerShellNestedTexts(source string) ([]nestedText, bounded.CapSet) {
	var caps bounded.CapSet
	if posixOnlySyntax(source) {
		return nil, caps
	}
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if !raiseReadable(script) {
		if script != nil && onlyStopParsingDiagnostics(script) {
			// A --% remainder is the one part psparse leaves unread: the
			// argv it hands the program is read all the same.
			return powerShellChildArgvTexts(script, nil, caps)
		}
		return nil, psparseBoundCaps(script)
	}
	var out []nestedText
	for _, nested := range psparse.ExtractNestedScripts(script) {
		if !nested.Static {
			// psparse leaves two launcher spellings open that are static
			// text all the same: a script block given as the -Command value,
			// and the words of a Start-Process -ArgumentList to a host.
			text, ok := nonStaticNestedText(source, nested)
			if !ok {
				continue
			}
			nested.Text, nested.Dialect, nested.Static = text, "powershell", true
		}
		if strings.TrimSpace(nested.Text) == "" {
			continue
		}
		if command, ok := nested.Source.(*psparse.Command); ok {
			name, named := psparse.LiteralString(command.Name)
			switch nested.Kind {
			case psparse.KindPowerShellCommand, psparse.KindEncodedCommand:
				if !named || !hostLauncherIdentity(name, "powershell") && !hostLauncherIdentity(name, "pwsh") ||
					commandHasEmptyWord(command) || !launcherWordsArePlain(command) {
					continue
				}
				location, readable := launcherWorkingDirectory(source, command)
				if !readable {
					continue
				}
				nested.Text = location + nested.Text
			case psparse.KindCmdC:
				if !named || !hostLauncherIdentity(name, "cmd") {
					continue
				}
			}
		}
		if len(nested.Text) > maxHostMidListBody {
			caps = caps.Union(bounded.Of(bounded.Bytes))
			continue
		}
		if len(out) >= maxListReadings {
			caps = caps.Union(bounded.Of(bounded.Items))
			break
		}
		dialect := DialectPowerShell
		if nested.Dialect == "cmd" {
			dialect = DialectCMD
		}
		out = append(out, nestedText{text: strings.TrimSpace(nested.Text), dialect: dialect, floorRaiseOnly: nested.BlankDecoded})
	}
	return powerShellChildArgvTexts(script, out, caps)
}

// powerShellInertCommands are commands that change nothing a later statement
// depends on but the working folder or the terminal: a directory change or a
// print. They are the benign neighbours an attack can be put between.
var powerShellInertCommands = map[string]bool{
	"set-location": true, "sl": true, "cd": true, "chdir": true, "push-location": true, "pushd": true,
	"pop-location": true, "popd": true, "write-output": true, "write-host": true, "echo": true,
	"get-date": true, "clear-host": true, "cls": true,
}

// powerShellInertStatement reports a top-level statement that is one inert
// command (powerShellInertCommands).
func powerShellInertStatement(statement psparse.Statement) bool {
	pipeline, ok := statement.(*psparse.Pipeline)
	if !ok || pipeline.ChainRHS != nil || pipeline.Background || len(pipeline.Redirs) != 0 || len(pipeline.Elements) != 1 {
		return false
	}
	command, ok := pipeline.Elements[0].(*psparse.Command)
	if !ok || command.InvokeOp != "" || len(command.Redirs) != 0 {
		return false
	}
	name, ok := psparse.LiteralString(command.Name)
	return ok && powerShellInertCommands[strings.ToLower(name)]
}

// powerShellStatementTexts reads a PowerShell script psparse reads in full as
// the readings an attack inside it needs: the script without its inert
// statements at either edge (a directory change before it, a print after it),
// which keeps every binding and branch of what is left, and each statement
// that stands on its own (no variable, block or flow construct: nothing a
// neighbour could bind or guard). A script of one statement, or one psparse
// does not read in full, has none. A list longer than maxListReadings is
// truncated.
func powerShellStatementTexts(source string) ([]string, bounded.CapSet) {
	var caps bounded.CapSet
	if posixOnlySyntax(source) {
		return nil, caps
	}
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if !raiseReadable(script) || len(script.Statements) < 2 {
		return nil, psparseBoundCaps(script)
	}
	statements := script.Statements
	if len(statements) > maxListReadings {
		// Past the work bound the list is read as far as it goes. This is not
		// a truncation of the call: the readings of a list are extra readings
		// beside the call as written, whose own statement budget decides a
		// long script (an ordinary 130-statement script stays allowed,
		// TestGAP0331PowerShellPrefixDoesNotHideTheBudget).
		statements = statements[:maxListReadings]
	}
	span := func(index int) (int, int, bool) {
		start, end := statements[index].Span()
		return start, end, start >= 0 && end <= len(source) && start < end
	}
	var texts []string
	first, last := 0, len(statements)-1
	for first <= last && powerShellInertStatement(statements[first]) {
		first++
	}
	for last >= first && powerShellInertStatement(statements[last]) {
		last--
	}
	if (first > 0 || last < len(statements)-1) && first <= last {
		start, _, ok1 := span(first)
		_, end, ok2 := span(last)
		if ok1 && ok2 {
			texts = append(texts, strings.TrimSpace(source[start:end]))
		}
	}
	for index := first; index <= last; index++ {
		start, end, ok := span(index)
		if !ok {
			continue
		}
		text := strings.TrimSpace(source[start:end])
		if strings.ContainsAny(text, "${") || powerShellInertStatement(statements[index]) || slices.Contains(texts, text) {
			continue
		}
		texts = append(texts, text)
	}
	return texts, caps
}
