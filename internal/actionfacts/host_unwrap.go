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
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
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
// stop-parse tail, quotes the legacy argument passing rewrites, a working
// directory, an empty or colon-glued word) has no reading at all.

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
	for _, word := range []string{"powershell", "pwsh", "cmd", "iex", "invoke-expression", "{"} {
		if strings.Contains(lower, word) {
			return true
		}
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

// unwrapHostSource unwraps source (PowerShell or cmd.exe grammar) until no
// static host wrapper is left, at most maxWrapperDepth layers. ok is false when
// source holds no static wrapper.
func unwrapHostSource(source string, dialect Dialect, depth int) (hostUnwrap, bool) {
	result := hostUnwrap{source: source, dialect: dialect}
	for layer := 0; ; layer++ {
		var next string
		var nextDialect Dialect
		var ok bool
		switch result.dialect {
		case DialectPowerShell:
			var caps bounded.CapSet
			next, nextDialect, ok, caps = unwrapPowerShellOnce(result.source)
			result.caps = result.caps.Union(caps)
			result.limit = result.limit || caps.Any()
		case DialectCMD:
			next, nextDialect, ok = unwrapCMDOnce(result.source)
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
		result.layers++
	}
	return result, result.layers > 0 || result.limit
}

// unwrapPowerShellOnce replaces the static host wrappers among the top-level
// statements of a PowerShell source. A source that is one wrapper statement is
// replaced whole (and may change grammar to cmd.exe's); wrappers among other
// statements are replaced in place when their script is one simple line.
func unwrapPowerShellOnce(source string) (string, Dialect, bool, bounded.CapSet) {
	var caps bounded.CapSet
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 || len(script.Statements) == 0 {
		return "", DialectNone, false, caps
	}
	type edit struct {
		start, end int
		body       string
	}
	var edits []edit
	whole := len(script.Statements) == 1
	var wholeDialect Dialect
	for _, statement := range script.Statements {
		body, dialect, start, end, ok := powerShellStatementWrapper(source, script, statement)
		if !ok {
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
	}
	if len(edits) == 0 {
		return "", DialectNone, false, caps
	}
	if whole {
		return edits[0].body, wholeDialect, true, caps
	}
	next := source
	for i := len(edits) - 1; i >= 0; i-- {
		next = next[:edits[i].start] + edits[i].body + next[edits[i].end:]
	}
	return next, DialectPowerShell, true, caps
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
// range of the statement.
func powerShellStatementWrapper(
	source string,
	script *psparse.Script,
	statement psparse.Statement,
) (body string, dialect Dialect, start, end int, ok bool) {
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
		return body, DialectPowerShell, start, end, true
	}
	name, named := psparse.LiteralString(command.Name)
	if !named {
		return
	}
	nested := psparse.ExtractNestedScripts(&psparse.Script{
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
			commandHasWorkingDirectoryOption(command) || commandHasEmptyWord(command) ||
			!launcherWordsArePlain(command) {
			return
		}
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
	return found.Text, dialect, start, end, true
}

// commandHasWorkingDirectoryOption reports a -WorkingDirectory switch (or an
// abbreviation of it) among the words of a launcher call.
func commandHasWorkingDirectoryOption(command *psparse.Command) bool {
	for _, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Parameter:
			if workingDirectoryWord("-" + typed.Name) {
				return true
			}
		case *psparse.Arg:
			if text, static := psparse.LiteralString(typed.Value); static && workingDirectoryWord(text) {
				return true
			}
		}
	}
	return false
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
// a call is not unwrapped.
func launcherWordsArePlain(command *psparse.Command) bool {
	for _, element := range command.Elements {
		switch typed := element.(type) {
		case *psparse.Parameter:
			if typed.HasColon || typed.Colon != nil {
				return false
			}
		case *psparse.Arg:
			if _, isString := typed.Value.(*psparse.StringLit); !isString {
				return false
			}
		case *psparse.StringLit:
		default:
			return false
		}
	}
	return true
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

// unwrapCMDOnce unwraps a cmd.exe source that is one host launcher call.
func unwrapCMDOnce(source string) (string, Dialect, bool) {
	argv, ok := soleCMDHostCall(source)
	if !ok {
		return "", DialectNone, false
	}
	program := commandProgramForDialect(argv[0], DialectCMD)
	script, ok := hostFromArgv(program, argv)
	if !ok {
		return "", DialectNone, false
	}
	return script.body, script.dialect, true
}

// soleCMDHostCall returns the argv of a cmd.exe source that is exactly one
// powershell, pwsh or cmd launcher call with static words and no pipe or
// redirect.
func soleCMDHostCall(source string) ([]string, bool) {
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
	return windowsWordValues(words), true
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
		body, dialect, ok := powerShellHostBody(argv)
		return hostScript{body: body, dialect: dialect}, ok
	case "cmd", "cmd.exe":
		body, dialect, ok := cmdHostBody(argv)
		return hostScript{body: body, dialect: dialect}, ok
	}
	return hostScript{}, false
}

// hostScript is the script a launcher argv runs.
type hostScript struct {
	body    string
	dialect Dialect
}

// powerShellHostBody asks psparse what a powershell/pwsh argv runs. The argv
// is spelled as one call of single-quoted literals, so the verdict is the host
// command-line rules of psparse (parameter abbreviations, -Command joins,
// -EncodedCommand decoding, stdin and stop-parse reads, legacy quoting) and
// nothing else.
func powerShellHostBody(argv []string) (string, Dialect, bool) {
	for _, word := range argv {
		if word == "" {
			// An empty argument is passed differently across PowerShell
			// versions, so the script it belongs to stays opaque.
			return "", DialectNone, false
		}
	}
	if powerShellWorkingDirectoryOption(argv) {
		// -WorkingDirectory moves the cwd the script's relative paths resolve
		// against; Facts has no wrapper-local cwd, so the script is not
		// analyzed against the wrong directory.
		return "", DialectNone, false
	}
	var builder strings.Builder
	builder.WriteString("& ")
	for i, word := range argv {
		if i > 0 {
			builder.WriteByte(' ')
		}
		builder.WriteString(powerShellSingleQuote(word))
	}
	script, _ := psparse.Parse(builder.String(), psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 {
		return "", DialectNone, false
	}
	var found *psparse.NestedScript
	nested := psparse.ExtractNestedScripts(script)
	for i := range nested {
		if nested[i].Kind != psparse.KindPowerShellCommand &&
			nested[i].Kind != psparse.KindEncodedCommand {
			continue
		}
		if found != nil {
			return "", DialectNone, false
		}
		found = &nested[i]
	}
	if found == nil || !found.Static || strings.TrimSpace(found.Text) == "" {
		return "", DialectNone, false
	}
	return found.Text, DialectPowerShell, true
}

// powerShellWorkingDirectoryOption reports a -WorkingDirectory switch (or an
// abbreviation of it, -wo and longer) among the host words.
func powerShellWorkingDirectoryOption(argv []string) bool {
	for _, word := range argv[1:] {
		if workingDirectoryWord(word) {
			return true
		}
	}
	return false
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

func powerShellSingleQuote(word string) string {
	return "'" + strings.ReplaceAll(word, "'", "''") + "'"
}

// cmdHostBody resolves the line `cmd /c <words>` runs. A single word is the
// line as written; several words are joined as the launcher passes them, each
// word with blanks re-quoted. Any other cmd.exe switch before /c, and /k, are
// not modeled: the call stays opaque.
func cmdHostBody(argv []string) (string, Dialect, bool) {
	for i := 1; i < len(argv); i++ {
		switch strings.ToLower(argv[i]) {
		case "/c", "/k":
			body, ok := cmdJoinPayload(argv[i+1:])
			return body, DialectCMD, ok
		case "/d", "/q", "/s", "/a", "/u":
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
// static launcher call.
func posixSoleHostCallSource(source string) (string, Dialect, bool) {
	lower := strings.ToLower(source)
	if !strings.Contains(lower, "powershell") && !strings.Contains(lower, "pwsh") &&
		!strings.Contains(lower, "cmd") {
		return "", DialectNone, false
	}
	out := parsePOSIX(source, 1, 0)
	script, ok := soleHostCall(&out)
	if !ok {
		return "", DialectNone, false
	}
	return script.body, script.dialect, true
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
	switch strings.ToLower(word()) {
	case "cmd", "cmd.exe":
	default:
		return "", DialectNone, false
	}
	for text != "" {
		switch switchWord := strings.ToLower(word()); switchWord {
		case "/c", "/k":
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

// maxListReadings is the number of statements of one list that are read one by
// one; a longer list is truncated (the bound rule), not read in part silently.
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
	// Listed marks twins that are statements (or edge-trimmed runs of
	// statements) of a list: they are never split into statements again.
	Listed bool
	// Caps is the set of bounds the reading hit: the wrapper depth, the
	// nested size budget, a body past the in-list size, a list past
	// maxListReadings. A truncated reading is judged at the unknown tier of
	// the pack at least (internal/guardrail/bounded).
	Caps bounded.CapSet
}

// HostScriptTwin is HostScriptReadings for one reading at depth 0: the one
// twin when the call has exactly one, for callers that want the script of a
// launcher.
func HostScriptTwin(input Input, facts Facts) (Input, bool) {
	reading := HostScriptReadings(input, facts, 0, false)
	if len(reading.Twins) != 1 {
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
	switch {
	case len(input.Argv) != 0:
		program := commandProgramForDialect(input.Argv[0], DialectPowerShell)
		script, ok := hostFromArgv(program, input.Argv)
		if !ok {
			return reading
		}
		source, dialect, layers = script.body, script.dialect, 1
	case source == "" || len(source) > maxCommandBytes:
		return reading
	default:
		dialect, _ = chooseRawCommandDialect(input.Tool, input.DialectHint, source)
		if dialect == DialectPOSIX || dialect == DialectNone || dialect == DialectMixed {
			body, bodyDialect, ok := rawCMDLauncherLine(source)
			if !ok {
				body, bodyDialect, ok = posixSoleHostCallSource(source)
			}
			if !ok && powerShellOnlyGrammar(source) {
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
	if unwrapped.layers > 0 || layers > 0 {
		twin := input
		twin.Args, twin.Argv = nil, nil
		twin.Command = unwrapped.source
		if unwrapped.dialect == DialectPowerShell {
			twin.Command = withoutUnreachableStatements(unwrapped.source)
		}
		twin.DialectHint = unwrapped.dialect
		reading.Twins = append(reading.Twins, twin)
		// The twin is a script: its own list of statements is read when the
		// twin is read in turn, with the depth carried.
		return reading
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
	}
	reading.Depth = depth + 1
	reading.Listed = len(reading.Twins) != 0
	return reading
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
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 || len(script.Statements) < 2 {
		return nil, caps
	}
	statements := script.Statements
	if len(statements) > maxListReadings {
		caps = caps.Union(bounded.Of(bounded.Items))
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
