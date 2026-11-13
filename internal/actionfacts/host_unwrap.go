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

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// Host unwrapping: the one place the PowerShell parser (internal/psparse)
// feeds ActionFacts.
//
// A call such as `powershell -Command "<script>"`, `pwsh -EncodedCommand
// <base64>`, `cmd /c "<line>"`, `& { <script> }`, `Invoke-Expression '<script>'`
// or Git Bash running powershell.exe runs the same statements as the bare
// script. The rules judge the action, not its spelling, so the facts of a
// static wrapper are the facts of the script it runs: this file replaces the
// wrapper by that script (recursively, to the POSIX wrapper depth and size
// budget) before the shell grammar of the script is parsed, and records the
// launcher only as Facts.HostWrappers evidence. Wrappers is left to the
// launchers that change the execution context (sudo, env, chroot, nsenter,
// find -exec), which the exact rules must keep refusing.
//
// What the wrapper script is comes from psparse (ExtractNestedScripts): a
// payload psparse cannot resolve to one static string (a variable, a
// sub-expression, a stdin read, a child argv, a stop-parse tail, quotes the
// legacy argument passing rewrites) is never unwrapped. The call then keeps the
// launcher as an ordinary command whose operands are unknown, exactly as before.
// The launcher's ambient startup (a PowerShell profile, a cmd.exe AutoRun
// entry) is the same ambient state any other call in the session runs under;
// it is not part of what the call text says, so it no longer keeps a static
// wrapper out of the rules.

// A recorded launcher is value-free: its executable as typed, never its
// switches or its script.

// hostUnwrap is the result of unwrapping the static host wrappers of one source.
type hostUnwrap struct {
	source   string
	dialect  Dialect
	wrappers []WrapperFact
	// keepOpen: a launcher left its host running after the script (cmd /k,
	// powershell -NoExit); what the host reads next is not in the call.
	keepOpen bool
	// limit: another wrapper layer was left because the wrapper depth is spent.
	limit bool
}

// maxHostMidListBody bounds the script text substituted into the middle of a
// statement list; whole-call replacement is bounded by the nested size budget.
const maxHostMidListBody = 4 << 10

// unwrapHostSource unwraps source (PowerShell or cmd.exe grammar) until no
// static host wrapper is left, at most maxWrapperDepth layers. ok is false when
// source holds no static wrapper.
func unwrapHostSource(source string, dialect Dialect, depth int) (hostUnwrap, bool) {
	result := hostUnwrap{source: source, dialect: dialect}
	for layer := 0; ; layer++ {
		var next string
		var nextDialect Dialect
		var wrapper WrapperFact
		var keepOpen, ok bool
		switch result.dialect {
		case DialectPowerShell:
			next, nextDialect, wrapper, ok = unwrapPowerShellOnce(result.source)
		case DialectCMD:
			next, nextDialect, wrapper, keepOpen, ok = unwrapCMDOnce(result.source)
		}
		if !ok || strings.TrimSpace(next) == "" ||
			len(next)*(depth+layer+2) > maxNestedCommandBytes {
			break
		}
		if depth+layer >= maxWrapperDepth {
			result.limit = true
			break
		}
		result.source, result.dialect = next, nextDialect
		result.wrappers = append(result.wrappers, wrapper)
		result.keepOpen = result.keepOpen || keepOpen
	}
	return result, len(result.wrappers) > 0 || result.limit
}

// unwrapPowerShellOnce replaces the static host wrappers among the top-level
// statements of a PowerShell source. A source that is one wrapper statement is
// replaced whole (and may change grammar to cmd.exe's); wrappers among other
// statements are replaced in place when their script is one simple line.
func unwrapPowerShellOnce(source string) (string, Dialect, WrapperFact, bool) {
	script, _ := psparse.Parse(source, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) != 0 || len(script.Statements) == 0 {
		return "", DialectNone, WrapperFact{}, false
	}
	type edit struct {
		start, end int
		body       string
	}
	var edits []edit
	var first WrapperFact
	whole := len(script.Statements) == 1
	var wholeDialect Dialect
	for _, statement := range script.Statements {
		body, dialect, wrapper, start, end, ok := powerShellStatementWrapper(source, script, statement)
		if !ok {
			continue
		}
		if !whole && (dialect != DialectPowerShell || !simpleHostBody(body)) {
			continue
		}
		if len(edits) == 0 {
			first = wrapper
		}
		edits = append(edits, edit{start: start, end: end, body: body})
		wholeDialect = dialect
	}
	if len(edits) == 0 {
		return "", DialectNone, WrapperFact{}, false
	}
	if whole {
		return edits[0].body, wholeDialect, first, true
	}
	next := source
	for i := len(edits) - 1; i >= 0; i-- {
		next = next[:edits[i].start] + edits[i].body + next[edits[i].end:]
	}
	return next, DialectPowerShell, first, true
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
) (body string, dialect Dialect, wrapper WrapperFact, start, end int, ok bool) {
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
		return body, DialectPowerShell, WrapperFact{Executable: command.InvokeOp}, start, end, true
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
			commandHasWorkingDirectoryOption(command) {
			return
		}
		dialect = DialectPowerShell
	case psparse.KindIEXLiteral:
		dialect = DialectPowerShell
	case psparse.KindCmdC:
		if !hostLauncherIdentity(name, "cmd") {
			return
		}
		// psparse joins every word after /c; only the single-word form is the
		// line cmd.exe runs as written (several words are re-quoted by the
		// launcher in ways the join does not show).
		if !soleCMDPayloadWord(command) {
			return
		}
		dialect = DialectCMD
	default:
		return
	}
	return found.Text, dialect, WrapperFact{Executable: name}, start, end, true
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

// soleCMDPayloadWord reports a cmd invocation with exactly one word after its
// /c run switch.
func soleCMDPayloadWord(command *psparse.Command) bool {
	for i, element := range command.Elements {
		argument, isArg := element.(*psparse.Arg)
		if !isArg {
			continue
		}
		text, static := psparse.LiteralString(argument.Value)
		if !static {
			continue
		}
		switch strings.ToLower(text) {
		case "/c":
			return i+2 == len(command.Elements)
		case "/k", "/r":
			return false
		}
	}
	return false
}

// unwrapCMDOnce unwraps a cmd.exe source that is one host launcher call.
func unwrapCMDOnce(source string) (string, Dialect, WrapperFact, bool, bool) {
	argv, ok := soleCMDHostCall(source)
	if !ok {
		return "", DialectNone, WrapperFact{}, false, false
	}
	program := commandProgramForDialect(argv[0], DialectCMD)
	script, ok := hostFromArgv(program, argv)
	if !ok {
		return "", DialectNone, WrapperFact{}, false, false
	}
	return script.body, script.dialect, WrapperFact{Executable: argv[0]}, script.keepOpen, true
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

// hostLauncherProgram reports a program that launches a PowerShell or cmd.exe
// script from its argv.
func hostLauncherProgram(program string) bool {
	switch program {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe":
		return true
	}
	return false
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
		return hostScript{body: body, dialect: dialect, keepOpen: powerShellKeepsHostOpen(argv)}, ok
	case "cmd", "cmd.exe":
		body, dialect, keepOpen, ok := cmdHostBody(argv)
		return hostScript{body: body, dialect: dialect, keepOpen: keepOpen}, ok
	}
	return hostScript{}, false
}

// hostScript is the script a launcher argv runs.
type hostScript struct {
	body     string
	dialect  Dialect
	keepOpen bool
}

// powerShellKeepsHostOpen reports -NoExit (or an abbreviation of it).
func powerShellKeepsHostOpen(argv []string) bool {
	for _, word := range argv[1:] {
		name := strings.ToLower(strings.TrimSpace(word))
		if !strings.HasPrefix(name, "-") && !strings.HasPrefix(name, "/") {
			continue
		}
		name = strings.TrimLeft(name, "-/")
		if len(name) >= 3 && strings.HasPrefix("noexit", name) {
			return true
		}
	}
	return false
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
	return len(name) >= 2 && strings.HasPrefix("workingdirectory", name)
}

func powerShellSingleQuote(word string) string {
	return "'" + strings.ReplaceAll(word, "'", "''") + "'"
}

// cmdHostBody resolves the line `cmd /c <words>` runs. A single word is the
// line as written; several words are joined as the launcher passes them, each
// word with blanks re-quoted. Any other cmd.exe switch before /c, and /k, are
// not modeled: the call stays opaque.
func cmdHostBody(argv []string) (string, Dialect, bool, bool) {
	for i := 1; i < len(argv); i++ {
		lower := strings.ToLower(argv[i])
		switch lower {
		case "/c", "/k":
			keepOpen := lower == "/k"
			payload := argv[i+1:]
			if len(payload) == 0 {
				return "", DialectNone, false, false
			}
			if len(payload) == 1 {
				return payload[0], DialectCMD, keepOpen, strings.TrimSpace(payload[0]) != ""
			}
			parts := make([]string, len(payload))
			for j, word := range payload {
				if word == "" || strings.ContainsAny(word, "\"\r\n") {
					return "", DialectNone, false, false
				}
				parts[j] = word
				if strings.ContainsAny(word, " \t") {
					parts[j] = `"` + word + `"`
				}
			}
			return strings.Join(parts, " "), DialectCMD, keepOpen, true
		case "/d", "/q", "/s", "/a", "/u":
		default:
			return "", DialectNone, false, false
		}
	}
	return "", DialectNone, false, false
}

// soleHostCallReduction replaces a POSIX parse that is one launcher call (Git
// Bash or a generic shell running powershell/pwsh/cmd with a static script) by
// the parse of the script, in the script's own grammar.
func soleHostCallReduction(out *parseOutput, wrapperDepth int) (parseOutput, bool) {
	if out.status != StatusComplete || len(out.commands) != 1 || wrapperDepth >= maxWrapperDepth {
		return parseOutput{}, false
	}
	command := out.commands[0]
	if command.ParentCommandID != 0 || command.PipelineID != 0 || command.ControlFlowUncertain ||
		command.Background || len(command.Redirects) != 0 || len(command.Wrappers) != 0 ||
		!command.ArgvComplete || len(command.Argv) < 2 || len(command.Arguments) != len(command.Argv) {
		return parseOutput{}, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return parseOutput{}, false
		}
	}
	program := commandProgram(command.Executable)
	script, ok := hostFromArgv(program, command.Argv)
	if !ok {
		return parseOutput{}, false
	}
	wrapper := WrapperFact{Executable: command.Executable}
	child := parseCommandAs(script.body, script.dialect, command.ID, wrapperDepth+1)
	child.hostWrappers = append([]WrapperFact{wrapper}, child.hostWrappers...)
	if script.keepOpen {
		child.markPartial(IssueUnsupportedConstruct)
	}
	return child, true
}
