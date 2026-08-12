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
//
// This file contains modifications of Apache-2.0-licensed source.

package actionfacts

import (
	"strconv"
	"strings"
	"unicode/utf8"

	"mvdan.cc/sh/v3/syntax"
)

func parsePOSIX(source string, startID int64, wrapperDepth int) parseOutput {
	out := newParseOutput(DialectPOSIX, startID)
	if len(source) > maxCommandBytes ||
		len(source)*(wrapperDepth+1) > maxNestedCommandBytes {
		out.markLimit(IssueInputLimit)
		return out
	}
	if !utf8.ValidString(source) {
		out.markInvalid(IssueInvalidUTF8)
		return out
	}
	if strings.TrimSpace(source) == "" {
		out.markInvalid(IssueInvalidSyntax)
		return out
	}
	if wrapperDepth > maxWrapperDepth {
		out.markLimit(IssueWrapperLimit)
		return out
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangPOSIX))
	file, err := parser.Parse(strings.NewReader(source), "")
	if err != nil {
		out.markInvalid(IssueInvalidSyntax)
		return out
	}
	if !checkPOSIXBounds(file, &out) {
		return out
	}

	pipelines := posixPipelineRelations(file)
	statementIDs := make(map[*syntax.Stmt]int64)
	var stack []syntax.Node
	syntax.Walk(file, func(node syntax.Node) bool {
		if node == nil {
			if len(stack) > 0 {
				stack = stack[:len(stack)-1]
			}
			return true
		}
		if out.status == StatusLimitExceeded {
			return false
		}

		switch typed := node.(type) {
		case *syntax.FuncDecl:
			// A definition is inert until invoked. Do not project its body as
			// an executed action.
			out.markPartial(IssueUnsupportedConstruct)
			return false
		case *syntax.ForClause, *syntax.CaseClause:
			// Retain statically visible body actions, but never claim that a
			// loop iteration or case arm is reachable.
			out.markPartial(IssueUnsupportedConstruct)
		case *syntax.IfClause, *syntax.WhileClause:
			// Branches and loop bodies are intentionally retained as positive
			// facts, but their runtime reachability is not authoritative.
			out.markPartial(IssueUnsupportedConstruct)
		case *syntax.BinaryCmd:
			if typed.Op == syntax.AndStmt || typed.Op == syntax.OrStmt ||
				typed.Op == syntax.PipeAll {
				// Short-circuit reachability and stderr-inclusive pipelines
				// cannot be represented by the current fact contract.
				out.markPartial(IssueUnsupportedConstruct)
			}
		case *syntax.Stmt:
			command, ok := projectPOSIXStatement(typed, pipelines[typed], stack, statementIDs, &out)
			if ok {
				statementIDs[typed] = command.ID
				out.appendCommand(command)
			}
		}
		stack = append(stack, node)
		return true
	})

	addPOSIXStructuralFlows(&out)
	expandStaticPOSIXWrappers(&out, wrapperDepth)
	if len(out.commands) == 0 && out.status == StatusComplete {
		out.markUnsupported(IssueUnsupportedConstruct)
	}
	return out
}

func checkPOSIXBounds(root syntax.Node, out *parseOutput) bool {
	nodes := 0
	depth := 0
	valid := true
	syntax.Walk(root, func(node syntax.Node) bool {
		if node == nil {
			if depth > 0 {
				depth--
			}
			return true
		}
		if !valid {
			return false
		}
		nodes++
		if nodes > maxPOSIXNodes {
			out.markLimit(IssueNodeLimit)
			valid = false
			return false
		}
		depth++
		if depth > maxPOSIXDepth {
			out.markLimit(IssueDepthLimit)
			// syntax.Walk does not emit the matching nil callback when a
			// node callback returns false, so undo this node's increment.
			depth--
			valid = false
			return false
		}
		return true
	})
	return valid
}

func projectPOSIXStatement(
	stmt *syntax.Stmt,
	pipelineID int64,
	stack []syntax.Node,
	statementIDs map[*syntax.Stmt]int64,
	out *parseOutput,
) (CommandFact, bool) {
	if stmt == nil {
		return CommandFact{}, false
	}
	if stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		out.markPartial(IssueUnsupportedConstruct)
	}
	parentID := enclosingPOSIXCommand(stack, statementIDs)

	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		if stmt.Cmd == nil && len(stmt.Redirs) > 0 {
			command := CommandFact{
				ID:              out.nextCommandID(),
				ParentCommandID: parentID,
				PipelineID:      pipelineID,
				Dialect:         DialectPOSIX,
				Effect:          EffectUncertain,
				ArgvComplete:    false,
			}
			projectPOSIXRedirects(stmt.Redirs, &command, out)
			out.markPartial(IssueUnsupportedConstruct)
			return command, true
		}
		switch stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			return CommandFact{}, false
		case *syntax.Subshell, *syntax.Block:
			// Grouping changes execution and pipeline scope in ways the
			// current flat command graph cannot represent exactly. Retain
			// visible child commands for detection, but fail closed.
			out.markPartial(IssueUnsupportedConstruct)
			return CommandFact{}, false
		default:
			if stmt.Cmd != nil {
				out.markPartial(IssueUnsupportedConstruct)
			}
			return CommandFact{}, false
		}
	}

	command := CommandFact{
		ID:              out.nextCommandID(),
		ParentCommandID: parentID,
		PipelineID:      pipelineID,
		Dialect:         DialectPOSIX,
		Effect:          EffectExecute,
		ArgvComplete:    true,
	}
	if len(call.Assigns) > 0 {
		// Prefix assignments can change executable lookup and runtime startup
		// behavior (for example PATH, ENV, or BASH_ENV). Keep the outer command
		// visible, but do not treat its argv as a self-contained envelope that
		// can safely publish facts from a nested shell or wrapper.
		command.ArgvComplete = false
		out.markPartial(IssueUnsupportedConstruct)
	}
	for index, word := range call.Args {
		argument := projectPOSIXWord(word)
		if !argument.Expands && len(argument.Value) > maxScalarBytes {
			out.markLimit(IssueInputLimit)
			return CommandFact{}, false
		}
		command.Arguments = append(command.Arguments, argument)
		if argument.Expands {
			command.Effect = EffectUncertain
			command.ArgvComplete = false
			command.Argv = append(command.Argv, "")
			out.markPartial(IssueDynamicWord)
			continue
		}
		command.Argv = append(command.Argv, argument.Value)
		if index == 0 {
			command.Executable = argument.Value
			command.Program = commandProgram(argument.Value)
		}
	}
	if len(call.Args) == 0 {
		command.Effect = EffectUncertain
		command.ArgvComplete = false
		out.markPartial(IssueUnsupportedConstruct)
	} else if command.Argv[0] == "" {
		command.Executable = ""
		command.Program = ""
		command.Effect = EffectUncertain
		command.ArgvComplete = false
		out.markPartial(IssueDynamicWord)
	}
	projectPOSIXRedirects(stmt.Redirs, &command, out)
	return command, true
}

func projectPOSIXWord(word *syntax.Word) ArgumentFact {
	if word == nil {
		return ArgumentFact{Expands: true}
	}
	var value strings.Builder
	quote := QuoteNone
	expands := false
	sawQuoted := false
	sawUnquoted := false
	unquotedExpansion := false
	for _, part := range word.Parts {
		rawUnquotedExpansion := posixUnquotedExpansion(part, value.Len() == 0)
		partValue, partQuote, partExpands := projectPOSIXWordPart(part)
		if partExpands {
			expands = true
		} else {
			if partQuote == QuoteNone {
				sawUnquoted = true
				if rawUnquotedExpansion {
					unquotedExpansion = true
				}
			} else {
				sawQuoted = true
			}
			value.WriteString(partValue)
		}
		quote = mergeQuote(quote, partQuote)
	}
	if sawQuoted && sawUnquoted {
		quote = QuoteMixed
	} else if quote == "" {
		quote = QuoteNone
	}
	result := ArgumentFact{
		Value:   value.String(),
		Quote:   quote,
		Expands: expands || unquotedExpansion,
	}
	if result.Expands {
		result.Value = ""
	}
	return result
}

func posixUnquotedExpansion(part syntax.WordPart, atWordStart bool) bool {
	literal, ok := part.(*syntax.Lit)
	if !ok {
		return false
	}
	return (atWordStart && strings.HasPrefix(literal.Value, "~")) ||
		hasUnescapedPOSIXPattern(literal.Value)
}

func hasUnescapedPOSIXPattern(value string) bool {
	escaped := false
	runes := []rune(value)
	for index, char := range runes {
		if escaped {
			escaped = false
			continue
		}
		if char == '\\' {
			escaped = true
			continue
		}
		if char == '*' || char == '?' {
			return true
		}
		if char != '[' {
			continue
		}
		// An unmatched or empty '[' is literal in POSIX shell words. Treat
		// only a bracket expression with a later unescaped ']' as a glob.
		// A first ']' is a literal bracket member, including after a leading
		// '!', so a second ']' is required to close the expression. Do not
		// extend the negation handling to '^': shells disagree about it.
		closeStart := index + 1
		if closeStart < len(runes) && runes[closeStart] == '!' {
			closeStart++
		}
		if closeStart < len(runes) && runes[closeStart] == ']' {
			closeStart++
		}
		bracketEscaped := false
		for closeIndex := closeStart; closeIndex < len(runes); closeIndex++ {
			switch {
			case bracketEscaped:
				bracketEscaped = false
			case runes[closeIndex] == '\\':
				bracketEscaped = true
			case runes[closeIndex] == ']':
				return true
			}
		}
	}
	return false
}

func projectPOSIXWordPart(part syntax.WordPart) (string, QuoteKind, bool) {
	switch part := part.(type) {
	case *syntax.Lit:
		return unquotePOSIXLiteral(part.Value, false), QuoteNone, false
	case *syntax.SglQuoted:
		return part.Value, QuoteSingle, part.Dollar
	case *syntax.DblQuoted:
		var value strings.Builder
		for _, nested := range part.Parts {
			nestedValue, expands := projectPOSIXDoubleQuotedPart(nested)
			if expands {
				return "", QuoteDouble, true
			}
			value.WriteString(nestedValue)
		}
		return value.String(), QuoteDouble, part.Dollar
	case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
		*syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
		return "", QuoteNone, true
	default:
		return "", QuoteNone, true
	}
}

func projectPOSIXDoubleQuotedPart(part syntax.WordPart) (string, bool) {
	switch part := part.(type) {
	case *syntax.Lit:
		return unquotePOSIXLiteral(part.Value, true), false
	case *syntax.ParamExp, *syntax.CmdSubst, *syntax.ArithmExp,
		*syntax.ProcSubst, *syntax.ExtGlob, *syntax.BraceExp:
		return "", true
	default:
		return "", true
	}
}

func unquotePOSIXLiteral(value string, doubleQuoted bool) string {
	if !strings.Contains(value, `\`) {
		return value
	}
	var result strings.Builder
	result.Grow(len(value))
	for i := 0; i < len(value); i++ {
		if value[i] != '\\' || i+1 >= len(value) {
			result.WriteByte(value[i])
			continue
		}
		next := value[i+1]
		if next == '\n' {
			i++
			continue
		}
		if doubleQuoted && next != '$' && next != '`' &&
			next != '"' && next != '\\' {
			result.WriteByte('\\')
		}
		result.WriteByte(next)
		i++
	}
	return result.String()
}

func mergeQuote(current, next QuoteKind) QuoteKind {
	if next == "" || next == QuoteNone {
		if current == "" {
			return QuoteNone
		}
		return current
	}
	if current == "" || current == QuoteNone {
		return next
	}
	if current == next {
		return current
	}
	return QuoteMixed
}

func projectPOSIXRedirects(redirections []*syntax.Redirect, command *CommandFact, out *parseOutput) {
	for _, redirection := range redirections {
		if redirection == nil || redirection.Word == nil {
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		if redirection.Op == syntax.DplIn || redirection.Op == syntax.DplOut {
			fd := int64(0)
			access := PathAccessRead
			if redirection.Op == syntax.DplOut {
				fd = 1
				access = PathAccessWrite
			}
			if redirection.N != nil {
				parsed, err := strconv.ParseInt(redirection.N.Value, 10, 64)
				if err != nil {
					out.markPartial(IssueDynamicWord)
					continue
				}
				fd = parsed
			}
			// Descriptor duplication changes structural stdin/stdout ownership,
			// but its operand is another descriptor rather than a path. Retain
			// only the affected descriptor so flow projection fails closed.
			if !out.appendRedirects(command, RedirectFact{
				FD:     fd,
				Access: access,
			}) {
				return
			}
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		access, ok := posixRedirectAccess(redirection.Op)
		if !ok {
			out.markPartial(IssueUnsupportedConstruct)
			continue
		}
		fd := posixRedirectFD(redirection.Op)
		if redirection.N != nil {
			parsed, err := strconv.ParseInt(redirection.N.Value, 10, 64)
			if err != nil {
				out.markPartial(IssueDynamicWord)
				continue
			}
			fd = parsed
		}
		target := projectPOSIXWord(redirection.Word)
		if !target.Expands && len(target.Value) > maxScalarBytes {
			out.markLimit(IssueInputLimit)
			return
		}
		redirect := RedirectFact{
			FD:      fd,
			Access:  access,
			Target:  target.Value,
			Expands: target.Expands,
		}
		if redirection.Op == syntax.RdrInOut {
			readRedirect := redirect
			readRedirect.Access = PathAccessRead
			if !out.appendRedirects(command, redirect, readRedirect) {
				return
			}
		} else if !out.appendRedirects(command, redirect) {
			return
		}
		if target.Expands {
			command.ArgvComplete = false
			out.markPartial(IssueDynamicWord)
		}
		if redirection.Hdoc != nil {
			out.markPartial(IssueUnsupportedConstruct)
		}
	}
}

func posixRedirectAccess(operator syntax.RedirOperator) (PathAccess, bool) {
	switch operator {
	case syntax.RdrIn:
		return PathAccessRead, true
	case syntax.RdrOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob:
		return PathAccessWrite, true
	case syntax.AppOut, syntax.AppClob, syntax.AppAll, syntax.AppAllClob:
		return PathAccessAppend, true
	case syntax.RdrInOut:
		return PathAccessWrite, true
	default:
		return "", false
	}
}

func posixRedirectFD(operator syntax.RedirOperator) int64 {
	switch operator {
	case syntax.RdrIn, syntax.RdrInOut:
		return 0
	case syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return -1
	default:
		return 1
	}
}

func posixPipelineRelations(root syntax.Node) map[*syntax.Stmt]int64 {
	relations := make(map[*syntax.Stmt]int64)
	var counter int64
	syntax.Walk(root, func(node syntax.Node) bool {
		binary, ok := node.(*syntax.BinaryCmd)
		if !ok || binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
			return true
		}
		var statements []*syntax.Stmt
		collectPOSIXPipelineStatements(binary.X, &statements)
		collectPOSIXPipelineStatements(binary.Y, &statements)
		pipelineID := int64(0)
		for _, statement := range statements {
			if relations[statement] != 0 {
				pipelineID = relations[statement]
				break
			}
		}
		if pipelineID == 0 {
			counter++
			pipelineID = counter
		}
		for _, statement := range statements {
			relations[statement] = pipelineID
		}
		return true
	})
	return relations
}

func collectPOSIXPipelineStatements(stmt *syntax.Stmt, statements *[]*syntax.Stmt) {
	if stmt == nil {
		return
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok &&
		(binary.Op == syntax.Pipe || binary.Op == syntax.PipeAll) {
		collectPOSIXPipelineStatements(binary.X, statements)
		collectPOSIXPipelineStatements(binary.Y, statements)
		return
	}
	*statements = append(*statements, stmt)
}

func enclosingPOSIXCommand(stack []syntax.Node, statementIDs map[*syntax.Stmt]int64) int64 {
	insideSubcommand := false
	for i := len(stack) - 1; i >= 0; i-- {
		switch node := stack[i].(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			insideSubcommand = true
		case *syntax.Stmt:
			if insideSubcommand {
				return statementIDs[node]
			}
		}
	}
	return 0
}

func addPOSIXStructuralFlows(out *parseOutput) {
	lastByPipeline := make(map[int64]CommandFact)
	for _, command := range out.commands {
		if command.PipelineID != 0 {
			if previous := lastByPipeline[command.PipelineID]; previous.ID != 0 &&
				posixDescriptorIsUnredirected(previous, 1) &&
				posixDescriptorIsUnredirected(command, 0) {
				out.appendDataFlow(DataFlowFact{
					FromCommandID: previous.ID,
					ToCommandID:   command.ID,
					From:          DataStdout,
					To:            DataStdin,
				})
			}
			lastByPipeline[command.PipelineID] = command
		}
		if command.ParentCommandID != 0 &&
			posixDescriptorIsUnredirected(command, 1) {
			out.appendDataFlow(DataFlowFact{
				FromCommandID: command.ID,
				ToCommandID:   command.ParentCommandID,
				From:          DataStdout,
				To:            DataProcess,
			})
		}
	}
}

func posixDescriptorIsUnredirected(command CommandFact, fd int64) bool {
	for _, redirect := range command.Redirects {
		if redirect.FD == fd || fd == 1 && redirect.FD == -1 {
			return false
		}
	}
	return true
}

func expandStaticPOSIXWrappers(out *parseOutput, wrapperDepth int) {
	outerCommands := cloneCommands(out.commands)
	for _, command := range outerCommands {
		if !command.ArgvComplete || len(command.Argv) < 2 {
			continue
		}
		program := commandProgram(command.Executable)
		var child parseOutput
		switch program {
		case "bash", "sh", "zsh", "dash", "ksh", "mksh":
			if structuralPOSIXPipelineStdinInterpreter(out, &command) ||
				exactPOSIXShellPreviewInvocation(&command) {
				continue
			}
			invocation := parsePOSIXShellInvocation(program, command.Argv)
			if !invocation.valid {
				out.markPartial(IssueUnsupportedConstruct)
				continue
			}
			if invocation.mode != posixShellModeCommand {
				continue
			}
			if invocation.noExec {
				if !provesIsolatedPOSIXNoExecPreview(
					out,
					&command,
					invocation,
					posixShellModeCommand,
				) {
					// A pipeline or redirect can route shell parser output into
					// another action. Retain an opaque executing carrier for fallback.
					out.markPartial(IssueUnsupportedConstruct)
				}
				continue
			}
			if wrapperDepth >= maxWrapperDepth {
				out.markLimit(IssueWrapperLimit)
				return
			}
			child = parsePOSIX(
				command.Argv[invocation.commandIndex],
				out.nextID,
				wrapperDepth+1,
			)
		case "eval":
			if wrapperDepth >= maxWrapperDepth {
				out.markLimit(IssueWrapperLimit)
				return
			}
			child = parsePOSIX(strings.Join(command.Argv[1:], " "), out.nextID, wrapperDepth+1)
		case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe":
			nested, dialect, ok, unsafe := nestedCommand(command.Argv, program)
			if unsafe {
				out.markPartial(IssueUnsupportedConstruct)
				continue
			}
			if !ok {
				continue
			}
			if wrapperDepth >= maxWrapperDepth {
				out.markLimit(IssueWrapperLimit)
				return
			}
			child = parseCommandAs(nested, dialect, out.nextID, wrapperDepth+1)
		case "sudo", "exec", "env", "command", "nsenter", "chroot":
			nestedArgv, ok, uncertain := staticPOSIXWrapperArgv(command.Argv, program)
			if uncertain {
				out.markPartial(IssueUnsupportedConstruct)
			}
			if !ok {
				continue
			}
			if wrapperDepth >= maxWrapperDepth {
				out.markLimit(IssueWrapperLimit)
				return
			}
			child = analyzeStructuredArgv(
				nestedArgv,
				out.nextID,
				wrapperDepth+1,
				DialectPOSIX,
			)
			// The argv was projected exactly by the surrounding POSIX parser;
			// it does not introduce a second action dialect.
			child.dialect = DialectPOSIX
		default:
			continue
		}
		for i := range child.commands {
			if child.commands[i].ParentCommandID == 0 {
				child.commands[i].ParentCommandID = command.ID
				if posixDescriptorIsUnredirected(child.commands[i], 1) {
					child.appendDataFlow(DataFlowFact{
						FromCommandID: child.commands[i].ID,
						ToCommandID:   command.ID,
						From:          DataStdout,
						To:            DataProcess,
					})
				}
			}
			child.commands[i].Wrappers = append(
				[]WrapperFact{{Executable: command.Executable, Argv: cloneSlice(command.Argv)}},
				child.commands[i].Wrappers...,
			)
		}
		out.mergeNested(child)
	}
}

var (
	posixEnvWrapperValueOptions = map[string]struct{}{
		"-u": {}, "--unset": {},
	}
	posixEnvWrapperSwitchOptions = map[string]struct{}{
		"-i": {}, "--ignore-environment": {}, "-0": {}, "--null": {},
		"-v": {}, "--debug": {},
	}
	posixSudoWrapperValueOptions = map[string]struct{}{
		"-u": {}, "--user": {}, "-g": {}, "--group": {},
		"-h": {}, "--host": {}, "-p": {}, "--prompt": {},
		"-C": {}, "--close-from": {}, "-T": {}, "--command-timeout": {},
		"-r": {}, "--role": {}, "-t": {}, "--type": {},
	}
	posixSudoWrapperSwitchOptions = map[string]struct{}{
		"-n": {}, "--non-interactive": {}, "-E": {}, "--preserve-env": {},
		"-H": {}, "--set-home": {}, "-S": {}, "--stdin": {},
		"-k": {}, "--reset-timestamp": {}, "-K": {}, "--remove-timestamp": {},
		"-b": {}, "--background": {},
	}
)

func staticPOSIXWrapperArgv(argv []string, program string) ([]string, bool, bool) {
	if len(argv) < 2 {
		return nil, false, false
	}
	switch program {
	case "exec":
		for i := 1; i < len(argv); i++ {
			arg := argv[i]
			if posixExecLoginOption(arg) || arg == "-a" {
				return nil, false, true
			}
			switch arg {
			case "--":
				if i+1 < len(argv) {
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			case "-c":
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return nil, false, true
			}
			return cloneSlice(argv[i:]), true, false
		}

	case "env":
		for i := 1; i < len(argv); i++ {
			arg := argv[i]
			if arg == "--" {
				if i+1 < len(argv) {
					if isStaticEnvironmentAssignment(argv[i+1]) {
						return nil, false, true
					}
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			}
			if arg == "-S" || arg == "--split-string" ||
				strings.HasPrefix(arg, "--split-string=") {
				return nil, false, true
			}
			if posixEnvChangesDirectory(arg) {
				return nil, false, true
			}
			if _, ok := posixEnvWrapperValueOptions[arg]; ok {
				i++
				if i >= len(argv) {
					return nil, false, true
				}
				continue
			}
			if _, ok := posixEnvWrapperSwitchOptions[arg]; ok {
				continue
			}
			if strings.HasPrefix(arg, "--unset=") {
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return nil, false, true
			}
			if isStaticEnvironmentAssignment(arg) {
				return nil, false, true
			}
			return cloneSlice(argv[i:]), true, false
		}

	case "sudo":
		for i := 1; i < len(argv); i++ {
			arg := argv[i]
			if arg == "--" {
				if i+1 < len(argv) {
					if isStaticEnvironmentAssignment(argv[i+1]) {
						return nil, false, true
					}
					if posixShellProgram(commandProgram(argv[i+1])) {
						if terminalPOSIXShellArgv(argv[i+1:]) {
							return nil, false, false
						}
						return nil, false, true
					}
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			}
			switch arg {
			case "-i", "--login", "-s", "--shell", "-l", "-ll", "--list":
				if i+1 == len(argv) {
					return nil, false, false
				}
				return nil, false, true
			case "-e", "--edit":
				return nil, false, true
			case "-v", "--validate", "-V", "--version":
				if i+1 == len(argv) {
					return nil, false, false
				}
				return nil, false, true
			}
			if posixSudoChangesExecutionRoot(arg) {
				return nil, false, true
			}
			if _, ok := posixSudoWrapperValueOptions[arg]; ok {
				i++
				if i >= len(argv) {
					return nil, false, true
				}
				continue
			}
			if _, ok := posixSudoWrapperSwitchOptions[arg]; ok {
				continue
			}
			if strings.HasPrefix(arg, "--user=") || strings.HasPrefix(arg, "--group=") ||
				strings.HasPrefix(arg, "--host=") || strings.HasPrefix(arg, "--prompt=") ||
				strings.HasPrefix(arg, "--command-timeout=") {
				continue
			}
			if strings.HasPrefix(arg, "--preserve-env=") {
				if strings.TrimPrefix(arg, "--preserve-env=") == "" {
					return nil, false, true
				}
				continue
			}
			if strings.HasPrefix(arg, "-") {
				return nil, false, true
			}
			if isStaticEnvironmentAssignment(arg) {
				return nil, false, true
			}
			if posixShellProgram(commandProgram(argv[i])) {
				if terminalPOSIXShellArgv(argv[i:]) {
					return nil, false, false
				}
				return nil, false, true
			}
			return cloneSlice(argv[i:]), true, false
		}

	case "command":
		for i := 1; i < len(argv); i++ {
			switch argv[i] {
			case "--":
				if i+1 < len(argv) {
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			case "-p":
				continue
			case "-v", "-V":
				return nil, false, false
			}
			if strings.HasPrefix(argv[i], "-") {
				return nil, false, true
			}
			return cloneSlice(argv[i:]), true, false
		}

	case "nsenter":
		parsed := parseNSEnterInvocation(argv)
		if parsed.preview {
			return nil, false, false
		}
		if !parsed.complete || parsed.childIndex < 0 {
			return nil, false, true
		}
		// The child executes inside one or more selected namespaces. Until
		// facts carry that execution context, projecting its paths or network
		// targets as if they belonged to the caller would be misleading.
		return nil, false, true

	case "chroot":
		parsed := parseChrootInvocation(argv)
		if parsed.preview {
			return nil, false, false
		}
		if !parsed.complete || parsed.childIndex < 0 {
			return nil, false, true
		}
		// Absolute child paths are relative to the new root, not the caller's
		// filesystem. Keep the wrapper facts but leave the child to fallback
		// evaluation until root-aware path facts are available.
		return nil, false, true
	}
	return nil, false, false
}

func posixExecLoginOption(arg string) bool {
	return len(arg) > 1 && arg[0] == '-' && arg[1] != '-' &&
		strings.ContainsRune(arg[1:], 'l')
}

func posixEnvChangesDirectory(arg string) bool {
	return arg == "-C" ||
		len(arg) > len("-C") && strings.HasPrefix(arg, "-C") ||
		arg == "--chdir" ||
		strings.HasPrefix(arg, "--chdir=")
}

func posixSudoChangesExecutionRoot(arg string) bool {
	return arg == "-D" || arg == "-R" ||
		len(arg) > 2 &&
			(strings.HasPrefix(arg, "-D") || strings.HasPrefix(arg, "-R")) ||
		arg == "--chdir" || arg == "--chroot" ||
		strings.HasPrefix(arg, "--chdir=") ||
		strings.HasPrefix(arg, "--chroot=")
}

func terminalPOSIXShellArgv(argv []string) bool {
	if len(argv) != 1 {
		return false
	}
	return posixShellProgram(commandProgram(argv[0]))
}

func posixShellProgram(program string) bool {
	switch program {
	case "bash", "sh", "zsh", "dash", "ksh", "mksh", "fish":
		return true
	default:
		return false
	}
}

func isStaticEnvironmentAssignment(value string) bool {
	name, _, ok := strings.Cut(value, "=")
	return ok && name != ""
}
