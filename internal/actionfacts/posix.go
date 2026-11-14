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
	"slices"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
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
	parsedSource := source
	file, err := parser.Parse(shellparse.Reader(source), "")
	if err != nil {
		normalized, valid := normalizePOSIXAggregateRedirects(source, true)
		if !valid {
			out.markInvalid(IssueInvalidSyntax)
			return out
		}
		parsedSource = normalized
		parser = syntax.NewParser(syntax.Variant(syntax.LangPOSIX))
		file, err = parser.Parse(shellparse.Reader(normalized), "")
		if err != nil {
			out.markInvalid(IssueInvalidSyntax)
			return out
		}
	}
	if !checkPOSIXBounds(file, &out) {
		return out
	}

	pipelines := posixPipelineRelations(file)
	representedFallbacks := exactStandalonePOSIXAbsoluteCDFallbacks(file)
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
				if _, represented := representedFallbacks[typed]; represented {
					break
				}
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
	if posixMayRebindHome(parsedSource) {
		for i := range out.commands {
			for j := range out.commands[i].Arguments {
				out.commands[i].Arguments[j].homeSpelling = ""
			}
		}
	}
	if len(out.commands) == 0 && out.status == StatusComplete {
		out.markUnsupported(IssueUnsupportedConstruct)
	}
	if wrapperDepth == 0 {
		out.redirectTargets.source = parsedSource
	} else {
		out.redirectTargets = redirectTargetCapture{}
	}
	return out
}

// exactStandalonePOSIXAbsoluteCDFallbacks returns every OR node in one closed
// top-level fallback list such as `cd /tmp || cd /var/run || cd /`. The
// individual attempts remain ControlFlowUncertain; this proof only establishes
// that the complete static list is represented. Requiring the list to consume
// the entire file prevents an unresolved selected directory from affecting the
// interpretation of later relative paths.
func exactStandalonePOSIXAbsoluteCDFallbacks(
	file *syntax.File,
) map[*syntax.BinaryCmd]struct{} {
	represented := make(map[*syntax.BinaryCmd]struct{})
	if file == nil || len(file.Stmts) != 1 ||
		posixStatementHasUnsupportedControl(file.Stmts[0]) {
		return represented
	}
	if _, ok := file.Stmts[0].Cmd.(*syntax.BinaryCmd); !ok ||
		!collectExactPOSIXAbsoluteCDFallback(file.Stmts[0], represented) {
		return map[*syntax.BinaryCmd]struct{}{}
	}
	return represented
}

func collectExactPOSIXAbsoluteCDFallback(
	stmt *syntax.Stmt,
	represented map[*syntax.BinaryCmd]struct{},
) bool {
	if stmt == nil || posixStatementHasUnsupportedControl(stmt) ||
		len(stmt.Redirs) != 0 {
		return false
	}
	if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
		if binary.Op != syntax.OrStmt ||
			!collectExactPOSIXAbsoluteCDFallback(binary.X, represented) ||
			!collectExactPOSIXAbsoluteCDFallback(binary.Y, represented) {
			return false
		}
		represented[binary] = struct{}{}
		return true
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return false
	}
	program := projectPOSIXWord(call.Args[0])
	target := projectPOSIXWord(call.Args[1])
	return !program.Expands && program.Value == "cd" &&
		!target.Expands && strings.HasPrefix(target.Value, "/")
}

// normalizePOSIXAggregateRedirects rewrites the Bash and zsh redirects of
// stdout and stderr to one file (&> f, &>> f, &>| f, and >& f with a file
// word) into separate stdout and stderr redirects of the same word (> f 2> f,
// >> f 2>> f); the rest of the source is kept byte for byte, so Bash-only
// syntax elsewhere stays invalid.
//
// nullOnly is the parse of a command the POSIX grammar rejects: only an
// exact, nonexpanding &>/dev/null (or its append/clobber sibling) is
// represented there, so every other all-output redirect fails closed.
// Without nullOnly (BashAggregateRedirectsAsPOSIX) any static target is
// kept. A target with a command, process or arithmetic substitution, a >&
// word that may be a descriptor and a >& with a descriptor number are never
// rewritten.
func normalizePOSIXAggregateRedirects(source string, nullOnly bool) (string, bool) {
	parser := syntax.NewParser(syntax.Variant(syntax.LangBash))
	file, err := parser.Parse(shellparse.Reader(source), "")
	if err != nil {
		return "", false
	}
	type replacement struct {
		start int
		end   int
		value string
	}
	var replacements []replacement
	valid := true
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok {
			return valid
		}
		stderr := " 2>"
		switch redirect.Op {
		case syntax.RdrAll, syntax.RdrAllClob:
		case syntax.AppAll, syntax.AppAllClob:
			stderr = " 2>>"
		case syntax.DplOut:
			// A word with a literal / names a file whatever it expands to;
			// another expanding word may still be a descriptor number.
			// "1>&word" is ">&word" (GAP-2143); the / may sit in quotes.
			target := projectPOSIXWord(redirect.Word)
			slash := false
			syntax.Walk(redirect.Word, func(inner syntax.Node) bool {
				switch typed := inner.(type) {
				case *syntax.Lit:
					slash = slash || strings.Contains(typed.Value, "/")
				case *syntax.SglQuoted:
					slash = slash || strings.Contains(typed.Value, "/")
				}
				return true
			})
			if nullOnly || redirect.N != nil && redirect.N.Value != "1" || target.Expands && !slash ||
				!target.Expands && (target.Value == "-" || strings.Trim(target.Value, "0123456789") == "") {
				return valid // a descriptor copy or close
			}
		default:
			return valid
		}
		target := projectPOSIXWord(redirect.Word)
		if nullOnly && (target.Expands || target.Value != "/dev/null") {
			valid = false
			return false
		}
		substituted := false
		syntax.Walk(redirect.Word, func(inner syntax.Node) bool {
			switch inner.(type) {
			case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp:
				substituted = true
			}
			return !substituted
		})
		start := int(redirect.OpPos.Offset())
		wordStart := int(redirect.Word.Pos().Offset())
		end := int(redirect.End().Offset())
		if substituted || start < 0 || wordStart <= start || end <= wordStart || end > len(source) {
			valid = false
			return false
		}
		operator := source[start:wordStart]
		switch {
		case strings.HasPrefix(operator, "&"):
			operator = operator[1:]
		case strings.HasPrefix(operator, ">&"):
			operator = ">" + operator[2:]
		default:
			valid = false
			return false
		}
		word := source[wordStart:end]
		replacements = append(replacements, replacement{
			start: start,
			end:   end,
			value: operator + word + stderr + word,
		})
		return valid
	})
	if !valid || len(replacements) == 0 {
		return "", false
	}
	sort.Slice(replacements, func(i, j int) bool {
		return replacements[i].start > replacements[j].start
	})
	result := source
	for _, edit := range replacements {
		result = result[:edit.start] + edit.value + result[edit.end:]
	}
	return result, true
}

// BashAggregateRedirectsAsPOSIX returns the command with its Bash and zsh
// all-output redirects (&> f, &>> f, >& f) spelled as the POSIX redirects
// of the same file (> f 2> f), and false when it has none. POSIX sh reads
// "cmd &> f" as "cmd &" and "> f", so the facts of the command as sent do
// not tie the write of f to it; a write owner that must judge the file a
// Bash shell writes analyzes this spelling as well (GAP-2143).
func BashAggregateRedirectsAsPOSIX(command string) (string, bool) {
	return normalizePOSIXAggregateRedirects(command, false)
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
		if stmt.Cmd == nil && len(stmt.Redirs) > 0 && posixOutputRedirectsOnly(stmt.Redirs) {
			// A command-less redirect (`> f`, `>> f`) opens its targets and
			// runs nothing: it is the ":" builtin with the same redirects, so
			// its targets are write path facts like any other (GAP-2076).
			command := CommandFact{
				ID:                   out.nextCommandID(),
				ParentCommandID:      parentID,
				PipelineID:           pipelineID,
				ControlFlowUncertain: posixControlFlowUncertain(stmt, stack),
				ControlFlowOperator:  posixControlFlowOperator(stmt, stack),
				Background:           stmt.Background,
				Dialect:              DialectPOSIX,
				Effect:               EffectExecute,
				ArgvComplete:         true,
				Executable:           ":",
				Program:              ":",
				Argv:                 []string{":"},
				Arguments:            []ArgumentFact{{Value: ":", Quote: QuoteNone}},
			}
			projectPOSIXRedirects(stmt.Redirs, &command, out)
			return command, true
		}
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
		ID:                   out.nextCommandID(),
		ParentCommandID:      parentID,
		PipelineID:           pipelineID,
		ControlFlowUncertain: posixControlFlowUncertain(stmt, stack),
		ControlFlowOperator:  posixControlFlowOperator(stmt, stack),
		Background:           stmt.Background,
		ShortCircuitListID:   out.shortCircuitListID(stack),
		Dialect:              DialectPOSIX,
		Effect:               EffectExecute,
		ArgvComplete:         true,
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
			command.Program = commandProgramForDialect(argument.Value, DialectPOSIX)
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
	if command.Program == "exec" && command.ParentCommandID == 0 {
		if len(command.Argv) != 1 || command.ControlFlowUncertain ||
			command.PipelineID != 0 || command.Background {
			clear(out.posixOpenFDs)
		} else {
			for _, redirect := range command.Redirects {
				if redirect.FD < 3 {
					continue
				}
				if !redirect.Expands && strings.HasPrefix(redirect.Target, "/dev/tcp/") {
					if out.posixOpenFDs == nil {
						out.posixOpenFDs = make(map[int64]string)
					}
					out.posixOpenFDs[redirect.FD] = redirect.Target
				} else {
					delete(out.posixOpenFDs, redirect.FD)
				}
			}
		}
	}
	classifyPOSIXGitConfigEnvironmentOutput(out, &command, call.Assigns)
	return command, true
}

// posixOutputRedirectsOnly reports redirects that only open files for
// output (>, >>, >|); a command-less heredoc or input redirect keeps its
// partial reading.
func posixOutputRedirectsOnly(redirects []*syntax.Redirect) bool {
	for _, redirect := range redirects {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob:
		default:
			return false
		}
	}
	return true
}

// Git uses GIT_CONFIG_GLOBAL as the output file for a command-local
// `git config --global` mutation. Prefix assignments make the entire call
// partial because they can also change executable lookup, but this static
// destination remains positive evidence of a possible write.
func classifyPOSIXGitConfigEnvironmentOutput(out *parseOutput, command *CommandFact, assignments []*syntax.Assign) {
	if command.Program != "git" || command.Effect != EffectExecute ||
		len(command.Argv) < 3 || command.Argv[1] != "config" ||
		!gitConfigMutates(command.Argv[2:]) {
		return
	}
	global := false
	for _, arg := range command.Argv[2:] {
		if arg == "--global" {
			global = true
		}
		if arg == "-f" || strings.HasPrefix(arg, "-f") && len(arg) > 2 ||
			arg == "--file" || strings.HasPrefix(arg, "--file=") {
			// An explicit file option selects the destination instead.
			return
		}
	}
	if !global {
		return
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return
		}
	}
	for _, assignment := range assignments {
		if assignment == nil || assignment.Name == nil ||
			assignment.Name.Value != "GIT_CONFIG_GLOBAL" ||
			assignment.Append || assignment.Naked || assignment.Index != nil ||
			assignment.Array != nil {
			continue
		}
		target := projectPOSIXWord(assignment.Value)
		if target.Expands || target.Value == "" {
			continue
		}
		addOperation(command, OperationWrite)
		appendCommandPath(out, command, PathAccessWrite, target.Value)
	}
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
	staticValue := value.String()
	result := ArgumentFact{
		Value:   staticValue,
		Quote:   quote,
		Expands: expands || unquotedExpansion,
	}
	if expands {
		result.homeSpelling = posixHomeSpelling(word)
	}
	if result.Expands {
		if !expands && unquotedExpansion && quote == QuoteNone {
			result.StaticGlob = staticValue
		}
		result.Value = ""
	} else {
		result.literalTilde = strings.HasPrefix(staticValue, "~")
	}
	return result
}

// carryPOSIXLiteralTildes keeps the parser's quoted-tilde mark on the argv a
// wrapper (sudo, env, command, exec) passes on: each child command whose
// argv is a suffix of the parent's takes the mark of the aligned word.
func carryPOSIXLiteralTildes(child *parseOutput, parent CommandFact) {
	if len(parent.Arguments) != len(parent.Argv) {
		return
	}
	for i := range child.commands {
		command := &child.commands[i]
		offset := len(parent.Argv) - len(command.Argv)
		if offset <= 0 || len(command.Arguments) != len(command.Argv) ||
			!slices.Equal(command.Argv, parent.Argv[offset:]) {
			continue
		}
		for j := range command.Arguments {
			if parent.Arguments[offset+j].literalTilde {
				command.Arguments[j].literalTilde = true
			}
		}
	}
}

func posixControlFlowUncertain(stmt *syntax.Stmt, stack []syntax.Node) bool {
	if stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown {
		return true
	}
	for _, ancestor := range stack {
		switch typed := ancestor.(type) {
		case *syntax.FuncDecl, *syntax.ForClause, *syntax.CaseClause,
			*syntax.IfClause, *syntax.WhileClause, *syntax.Subshell:
			return true
		case *syntax.BinaryCmd:
			switch typed.Op {
			case syntax.AndStmt, syntax.OrStmt, syntax.PipeAll:
				return true
			}
		}
	}
	return false
}

func posixControlFlowOperator(
	stmt *syntax.Stmt,
	stack []syntax.Node,
) CommandControlFlowOperator {
	if stmt == nil || posixStatementHasUnsupportedControl(stmt) {
		return ControlFlowOperatorMixedOrUnsupported
	}
	operator := ControlFlowOperatorNone
	merge := func(candidate CommandControlFlowOperator) {
		if operator == ControlFlowOperatorMixedOrUnsupported ||
			candidate == ControlFlowOperatorNone {
			return
		}
		if candidate == ControlFlowOperatorMixedOrUnsupported ||
			operator != ControlFlowOperatorNone && operator != candidate {
			operator = ControlFlowOperatorMixedOrUnsupported
			return
		}
		operator = candidate
	}
	for _, ancestor := range stack {
		switch typed := ancestor.(type) {
		case *syntax.Stmt:
			if posixStatementHasUnsupportedControl(typed) {
				merge(ControlFlowOperatorMixedOrUnsupported)
			}
		case *syntax.FuncDecl, *syntax.ForClause, *syntax.CaseClause,
			*syntax.IfClause, *syntax.WhileClause, *syntax.Subshell,
			*syntax.Block:
			merge(ControlFlowOperatorMixedOrUnsupported)
		case *syntax.BinaryCmd:
			switch typed.Op {
			case syntax.AndStmt:
				merge(ControlFlowOperatorAnd)
			case syntax.OrStmt:
				merge(ControlFlowOperatorOr)
			case syntax.PipeAll:
				merge(ControlFlowOperatorMixedOrUnsupported)
			}
		}
	}
	return operator
}

func posixStatementHasUnsupportedControl(stmt *syntax.Stmt) bool {
	return stmt == nil || stmt.Negated || stmt.Background || stmt.Coprocess || stmt.Disown
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
		if redirection.Op == syntax.Hdoc || redirection.Op == syntax.DashHdoc {
			projectPOSIXLiteralHeredoc(redirection, command, out)
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
			if fd == 0 {
				posixLiteralStdinReplaced(command, out)
			}
			target := projectPOSIXWord(redirection.Word)
			targetFD, targetFDErr := strconv.ParseInt(target.Value, 10, 64)
			if !target.Expands && targetFDErr == nil &&
				target.Value == strconv.FormatInt(targetFD, 10) &&
				command.ParentCommandID == 0 && !command.ControlFlowUncertain {
				if path := out.posixOpenFDs[targetFD]; path != "" {
					if !out.appendRedirects(command, RedirectFact{FD: fd, Access: access, Target: path}) {
						return
					}
					continue
				}
			}
			if redirection.Op == syntax.DplOut && !target.Expands &&
				targetFDErr == nil &&
				target.Value == strconv.FormatInt(targetFD, 10) &&
				(fd == 2 && targetFD == 1 || fd == 1 && targetFD == 2) &&
				posixDescriptorAlreadyRedirectedToNull(
					command.Redirects,
					targetFD,
				) {
				// Resolve only an ordered descriptor copy whose source descriptor
				// already names a static null sink. This covers the deterministic
				// `>/dev/null 2>&1`, `&>/dev/null 2>&1`, and
				// `2>/dev/null 1>&2` forms. Every other descriptor duplication
				// remains non-authoritative below.
				if !out.appendRedirects(command, RedirectFact{
					FD: fd, Access: access, Target: "/dev/null",
				}) {
					return
				}
				continue
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
			if fd != 0 || command.Program != "apply_patch" {
				out.markPartial(IssueUnsupportedConstruct)
			}
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
		if fd == 0 {
			posixLiteralStdinReplaced(command, out)
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
			out.redirectTargets.record(redirection.Word)
		}
	}
}

// posixLiteralStdinReplaced drops the here-document text a command holds when a
// later input redirect of descriptor 0 (a file, a descriptor copy, a here-string
// or a close) takes over its stdin. The shell opens the redirects in order and
// the last one wins, so the earlier document is no stdin of the command, in
// whole or in the text it shows (LiteralStdinView).
func posixLiteralStdinReplaced(command *CommandFact, out *parseOutput) {
	if !command.LiteralStdinComplete && command.LiteralStdinView == "" {
		return
	}
	command.LiteralStdin = ""
	command.LiteralStdinView = ""
	command.LiteralStdinComplete = false
	command.LiteralStdinAmbiguous = true
	if command.Program != "apply_patch" {
		// An apply_patch call without a document reading is partial anyway
		// (classifyPOSIXApplyPatchStdin), and a later here-document may
		// still be its stdin, so the call is not marked partial here.
		out.markPartial(IssueUnsupportedConstruct)
	}
}

func projectPOSIXLiteralHeredoc(
	redirection *syntax.Redirect,
	command *CommandFact,
	out *parseOutput,
) {
	if redirection == nil || command == nil || redirection.Hdoc == nil ||
		redirection.Op != syntax.Hdoc &&
			(redirection.Op != syntax.DashHdoc || command.Program != "apply_patch") {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	patch := command.Program == "apply_patch"
	if !patch && (command.LiteralStdinComplete || command.LiteralStdinAmbiguous) {
		command.LiteralStdin = ""
		command.LiteralStdinView = ""
		command.LiteralStdinComplete = false
		command.LiteralStdinAmbiguous = true
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	if redirection.N != nil {
		parsed, err := strconv.ParseInt(redirection.N.Value, 10, 64)
		if err == nil && parsed != 0 && patch {
			// A document on another descriptor is no stdin of the patch
			// call: the stdin stays what the other redirects left.
			return
		}
		if err != nil || parsed != 0 {
			out.markPartial(IssueUnsupportedConstruct)
			return
		}
	}
	if patch {
		// The shell opens the redirects in order and the last input redirect
		// of descriptor 0 is the stdin: a here-document after an earlier
		// input redirect or an earlier here-document is the stdin the
		// command reads, and replaces whatever the earlier ones showed.
		command.LiteralStdin = ""
		command.LiteralStdinView = ""
		command.LiteralStdinComplete = false
		command.LiteralStdinAmbiguous = false
		projectPOSIXPatchHeredoc(redirection, command, out)
		if !command.LiteralStdinComplete && command.LiteralStdinView == "" {
			command.LiteralStdinAmbiguous = true
		}
		return
	}
	if posixDescriptorIsRedirected(command, 0) {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	delimiter := projectPOSIXWord(redirection.Word)
	if !delimiter.Expands && delimiter.Value != "" && delimiter.Quote != QuoteSingle &&
		posixHeredocBodyRunsNothing(redirection.Hdoc) {
		// An expanding body whose only expansions are parameters runs no
		// command: the command and its redirect targets are as certain as
		// with a quoted body, only the stdin text is unknown. The parse
		// stays complete, so a proven write target (cat > /etc/sudoers
		// <<X) is judged by the integrity owners (rel-1-0-6:GAP-0399).
		command.LiteralStdin = ""
		command.LiteralStdinComplete = false
		command.LiteralStdinAmbiguous = true
		return
	}
	body, exact := literalPOSIXHeredocBody(redirection.Hdoc)
	if delimiter.Expands || delimiter.Quote != QuoteSingle ||
		delimiter.Value == "" || !exact || len(body) > maxScalarBytes ||
		strings.ContainsRune(body, '\x00') {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	command.LiteralStdin = body
	command.LiteralStdinComplete = true
}

// A quoted delimiter leaves the here-document body byte-for-byte literal.
// The generic word projection treats '*' as a pathname pattern, which is
// correct for command operands but not for a patch's *** directive lines.
func literalPOSIXHeredocBody(word *syntax.Word) (string, bool) {
	if word == nil {
		return "", false
	}
	var text strings.Builder
	for _, part := range word.Parts {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			return "", false
		}
		text.WriteString(literal.Value)
	}
	return text.String(), true
}

// projectPOSIXPatchHeredoc reads the here-document of an apply_patch command
// in every delimiter spelling (unquoted, double-quoted, quoted by a
// backslash, single-quoted, each also with <<-). The spelling decides only
// whether the shell expands the body (any quoting of the delimiter word
// prevents it); <<- only strips the leading tabs of the lines. A body that
// reaches the command byte for byte is the literal stdin in every spelling.
func projectPOSIXPatchHeredoc(
	redirection *syntax.Redirect,
	command *CommandFact,
	out *parseOutput,
) {
	delimiter := projectPOSIXWord(redirection.Word)
	if delimiter.Expands || delimiter.Value == "" {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	body, dynamic, readable := posixHeredocText(
		redirection.Hdoc, posixHeredocDelimiterQuoted(redirection.Word),
		redirection.Op == syntax.DashHdoc,
	)
	// Patch envelopes can contain ordinary file content beyond the scalar
	// operand bound; the shell command itself remains bounded.
	if !readable || len(body) > maxCommandBytes || strings.ContainsRune(body, '\x00') {
		out.markPartial(IssueUnsupportedConstruct)
		return
	}
	if !dynamic {
		command.LiteralStdin = body
		command.LiteralStdinComplete = true
		return
	}
	// The shell expands this body, so its bytes are not known. The patch keeps
	// the text it shows, each expansion replaced by one "$", for the readers of
	// its envelope (applyPatchStdinText). A substitution in the body is a
	// command of its own in the facts, judged by its own facts; the patch stays
	// as certain as with a quoted body, only the text of the lines that hold an
	// expansion is unknown.
	command.LiteralStdinView = body
	command.LiteralStdinAmbiguous = true
}

// posixHeredocDelimiterQuoted reports a here-document delimiter with any part
// quoted, in single or double quotes or by a backslash: the shell then leaves
// the body unexpanded.
func posixHeredocDelimiterQuoted(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	for _, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		case *syntax.Lit:
			if strings.Contains(typed.Value, "\\") {
				return true
			}
		}
	}
	return false
}

// posixHeredocText is the text of a here-document body as the shell hands it
// to the command, less the expansions: for <<- the leading tabs of every line
// are dropped. dynamic is set for a body the shell expands: a substitution or
// parameter expansion, or a backslash before $, a backquote, another backslash
// or a line end. The text then holds one "$" for each expansion and keeps the
// backslashes as written. readable is false for a quoted body that is not one
// literal.
func posixHeredocText(
	body *syntax.Word, quoted, stripTabs bool,
) (text string, dynamic, readable bool) {
	var out strings.Builder
	lineStart := true
	for _, part := range body.Parts {
		literal, ok := part.(*syntax.Lit)
		if !ok {
			if quoted {
				return "", false, false
			}
			out.WriteByte('$')
			lineStart = false
			dynamic = true
			continue
		}
		for index := 0; index < len(literal.Value); index++ {
			char := literal.Value[index]
			if lineStart && stripTabs && char == '\t' {
				continue
			}
			out.WriteByte(char)
			lineStart = char == '\n'
		}
		if !quoted && posixHeredocLiteralEscapes(literal.Value) {
			dynamic = true
		}
	}
	return out.String(), dynamic, true
}

// posixHeredocLiteralEscapes reports text of an unquoted here-document body
// the shell may expand: a $ or backquote the parser left in a literal, or a
// backslash before $, a backquote, a backslash or a line end. Any other
// backslash stays two ordinary characters.
func posixHeredocLiteralEscapes(text string) bool {
	for index := 0; index < len(text); index++ {
		if text[index] == '$' || text[index] == '`' {
			return true
		}
		if text[index] != '\\' {
			continue
		}
		if index+1 == len(text) {
			return true
		}
		switch text[index+1] {
		case '$', '`', '\\', '\n':
			return true
		}
		index++
	}
	return false
}

// posixHeredocBodyRunsNothing reports an unquoted heredoc body that expands
// only parameters: no command, arithmetic or process substitution anywhere
// in it, so reading it runs nothing.
func posixHeredocBodyRunsNothing(body *syntax.Word) bool {
	if body == nil {
		return true
	}
	runs := false
	// The POSIX grammar keeps the legacy $[expr] arithmetic as text (split
	// into adjacent literals), but bash evaluates it, and a subscript in a
	// variable value it names can run a command (rel-1-0-6:GAP-0419).
	var text strings.Builder
	syntax.Walk(body, func(node syntax.Node) bool {
		switch typed := node.(type) {
		case *syntax.CmdSubst, *syntax.ArithmExp, *syntax.ProcSubst:
			runs = true
		case *syntax.Lit:
			text.WriteString(typed.Value)
		case *syntax.Word:
		case nil:
		default:
			text.WriteByte(0)
		}
		return !runs
	})
	return !runs && !strings.Contains(text.String(), "$[")
}

func posixDescriptorIsRedirected(command *CommandFact, fd int64) bool {
	if command == nil {
		return false
	}
	for _, redirect := range command.Redirects {
		if redirect.FD == fd || fd == 1 && redirect.FD == -1 {
			return true
		}
	}
	return false
}

// StaticPOSIXCatLiteralStdinOutput returns the exact stdout bytes of a direct
// cat invocation fed by the bounded quoted-heredoc projection. Cat options,
// file operands, wrappers, and competing stdin redirects are excluded.
func StaticPOSIXCatLiteralStdinOutput(command CommandFact) (string, bool) {
	if command.Dialect != DialectPOSIX || command.Effect != EffectExecute ||
		command.Program != "cat" || !command.ArgvComplete ||
		len(command.Argv) != 1 || len(command.Arguments) != 1 ||
		len(command.Wrappers) != 0 || !command.LiteralStdinComplete ||
		command.LiteralStdinAmbiguous {
		return "", false
	}
	for _, redirect := range command.Redirects {
		if redirect.FD == 0 {
			return "", false
		}
	}
	return command.LiteralStdin, true
}

func posixDescriptorAlreadyRedirectedToNull(
	redirects []RedirectFact,
	fd int64,
) bool {
	for index := len(redirects) - 1; index >= 0; index-- {
		redirect := redirects[index]
		if redirect.FD != fd && redirect.FD != -1 {
			continue
		}
		return !redirect.Expands &&
			redirect.Target == "/dev/null" &&
			(redirect.Access == PathAccessWrite ||
				redirect.Access == PathAccessAppend)
	}
	return false
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
		switch posixStaticWrapperSwitchKey(program) {
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
				// Defer the all-or-nothing preview decision until classifyOutput
				// has established the final status of every non-noexec command.
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
		case "su":
			nested, ok := exactRootSuCommand(command)
			if !ok {
				continue
			}
			if wrapperDepth >= maxWrapperDepth {
				out.markLimit(IssueWrapperLimit)
				return
			}
			child = parsePOSIX(nested, out.nextID, wrapperDepth+1)
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
		case posixStaticWrapperKey:
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
			carryPOSIXLiteralTildes(&child, command)
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

func exactRootSuCommand(command CommandFact) (string, bool) {
	if command.Program != "su" || !command.ArgvComplete ||
		len(command.Argv) != 3 || command.Argv[1] != "-c" ||
		strings.TrimSpace(command.Argv[2]) == "" ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	return command.Argv[2], true
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

// staticPOSIXWrapperPrograms are the programs staticPOSIXWrapperArgv unwraps:
// the one list of the pass-through wrappers, read by both places that
// expand them (expandStaticPOSIXWrappers and analyzeStructuredArgv) through
// posixStaticWrapperSwitchKey.
var staticPOSIXWrapperPrograms = map[string]struct{}{
	"env": {}, "sudo": {}, "command": {}, "builtin": {}, "exec": {},
	"nsenter": {}, "chroot": {}, "nice": {}, "time": {}, "timeout": {}, "nohup": {},
}

// posixStaticWrapperKey is the switch key of a program in
// staticPOSIXWrapperPrograms.
const posixStaticWrapperKey = "\x00static-posix-wrapper"

// posixStaticWrapperSwitchKey maps a pass-through wrapper to
// posixStaticWrapperKey and any other program to itself.
func posixStaticWrapperSwitchKey(program string) string {
	if _, ok := staticPOSIXWrapperPrograms[program]; ok {
		return posixStaticWrapperKey
	}
	return program
}

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

	case "nice":
		for i := 1; i < len(argv); i++ {
			arg := argv[i]
			switch {
			case arg == "--":
				if i+1 < len(argv) {
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			case arg == "--help" || arg == "--version":
				return nil, false, false
			case arg == "-n" || arg == "--adjustment":
				i++
				if i >= len(argv) {
					return nil, false, true
				}
			case strings.HasPrefix(arg, "--adjustment="):
			case strings.HasPrefix(arg, "-n") && posixSignedDecimal(arg[2:]):
			case strings.HasPrefix(arg, "-") && posixSignedDecimal(strings.TrimLeft(arg, "-")):
				// The historical -N and --N spellings of -n N.
			case strings.HasPrefix(arg, "-"):
				return nil, false, true
			default:
				return cloneSlice(argv[i:]), true, false
			}
		}

	case "time":
		// The external time program (the shell keyword is parsed as syntax).
		for i := 1; i < len(argv); i++ {
			arg := argv[i]
			switch {
			case arg == "--":
				if i+1 < len(argv) {
					return cloneSlice(argv[i+1:]), true, false
				}
				return nil, false, false
			case arg == "-p" || arg == "-v" || arg == "-a" || arg == "-q" ||
				arg == "--portability" || arg == "--verbose" || arg == "--append" ||
				arg == "--quiet":
			case arg == "-f" || arg == "--format":
				i++
				if i >= len(argv) {
					return nil, false, true
				}
			case strings.HasPrefix(arg, "--format="):
			case strings.HasPrefix(arg, "-f") && len(arg) > 2:
			case strings.HasPrefix(arg, "-"):
				// -o FILE writes a report file; --help, --version and the
				// rest are not a plain pass-through.
				return nil, false, true
			default:
				return cloneSlice(argv[i:]), true, false
			}
		}

	case "timeout":
		i := 1
	timeoutOptions:
		for ; i < len(argv); i++ {
			arg := argv[i]
			switch {
			case arg == "--":
				i++
				break timeoutOptions
			case arg == "--preserve-status" || arg == "--foreground" ||
				arg == "-v" || arg == "--verbose":
			case arg == "-s" || arg == "--signal" || arg == "-k" || arg == "--kill-after":
				i++
				if i >= len(argv) {
					return nil, false, true
				}
			case strings.HasPrefix(arg, "--signal=") || strings.HasPrefix(arg, "--kill-after="):
			case (strings.HasPrefix(arg, "-s") || strings.HasPrefix(arg, "-k")) && len(arg) > 2:
			case strings.HasPrefix(arg, "-"):
				return nil, false, true
			default:
				break timeoutOptions
			}
		}
		if i >= len(argv) {
			return nil, false, false
		}
		if !posixTimeoutDuration(argv[i]) {
			return nil, false, true
		}
		if i+1 < len(argv) {
			return cloneSlice(argv[i+1:]), true, false
		}
		return nil, false, false

	case "nohup":
		// nohup takes no options but --help, --version and the -- end
		// marker: its first word decides (staticcheck SA4008, the loop
		// this replaces never passed its first word).
		if len(argv) > 1 {
			switch arg := argv[1]; {
			case arg == "--":
				if len(argv) > 2 {
					return cloneSlice(argv[2:]), true, false
				}
				return nil, false, false
			case arg == "--help" || arg == "--version":
				return nil, false, false
			case strings.HasPrefix(arg, "-"):
				return nil, false, true
			default:
				return cloneSlice(argv[1:]), true, false
			}
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
						if sudoStdinPOSIXShellArgv(argv[i+1:]) {
							return nil, false, false
						}
						if !staticPOSIXShellCommandArgv(argv[i+1:]) {
							return nil, false, true
						}
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
				if sudoStdinPOSIXShellArgv(argv[i:]) {
					return nil, false, false
				}
				if !staticPOSIXShellCommandArgv(argv[i:]) {
					return nil, false, true
				}
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

	case "builtin":
		// builtin NAME runs the shell builtin NAME in the caller shell with the
		// caller descriptors, so a redirect on it is a redirect of the NAME it
		// runs, as for command. The shell accepts a leading --.
		for i := 1; i < len(argv); i++ {
			switch {
			case argv[i] == "--":
				continue
			case strings.HasPrefix(argv[i], "-"):
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

func staticPOSIXShellCommandArgv(argv []string) bool {
	program := commandProgram(argv[0])
	if program != "sh" && program != "bash" {
		return false
	}
	invocation := parsePOSIXShellInvocation(program, argv)
	return invocation.valid && !invocation.noExec &&
		invocation.mode == posixShellModeCommand &&
		invocation.commandIndex < len(argv) &&
		strings.TrimSpace(argv[invocation.commandIndex]) != ""
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

// sudoStdinPOSIXShellArgv reports whether a shell that sudo starts reads its
// commands from stdin and names no command of its own: a bare shell (`sudo
// bash`) or one with an explicit stdin operand (`sudo bash -`, `sudo sh -s`).
// Like the bare shell, it has no nested command to analyze, so the action
// stays authoritative (rel-1-0-6 GAP-0221).
func sudoStdinPOSIXShellArgv(argv []string) bool {
	if terminalPOSIXShellArgv(argv) {
		return true
	}
	program := commandProgram(argv[0])
	switch program {
	case "sh", "bash", "zsh", "dash", "ksh":
		return exactPOSIXShellStdinArguments(program, argv)
	default:
		return false
	}
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

// posixSignedDecimal reports an optionally signed decimal number.
func posixSignedDecimal(value string) bool {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "+"), "-")
	if value == "" {
		return false
	}
	for _, character := range value {
		if character < '0' || character > '9' {
			return false
		}
	}
	return true
}

// posixTimeoutDuration reports a timeout(1) DURATION: a number with an
// optional s, m, h or d suffix.
func posixTimeoutDuration(value string) bool {
	if value != "" && strings.ContainsRune("smhd", rune(value[len(value)-1])) {
		value = value[:len(value)-1]
	}
	digits := 0
	dots := 0
	for _, character := range value {
		switch {
		case character >= '0' && character <= '9':
			digits++
		case character == '.':
			dots++
		default:
			return false
		}
	}
	return digits > 0 && dots <= 1
}
