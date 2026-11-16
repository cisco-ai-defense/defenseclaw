// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"regexp"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// ShellStatementsOverBudget reports whether a POSIX shell command has more
// statements than one action evaluates (maxStatementsAlone, 128), counted
// as SimpleCommands splits it: list members, pipeline stages and the
// commands of bodies. SimpleCommands reports such a command as a "limit"
// failure while the analysis keeps its text; a command whose analysis
// stopped earlier, at the node or input bound, is over the same budget, so
// the limit is the same at every size up to the hook payload cap (GAP-0146,
// GAP-0568). A command that does not parse is not counted here.
func ShellStatementsOverBudget(command string) bool {
	if command == "" {
		return false
	}
	statements, _, ok := sequenceStatementDetails(command, true, true, false, true)
	if ok {
		if len(statements) > maxStatementsAlone {
			// The semantic splitter also accepts Bash-only syntax. The
			// analyzer counts POSIX syntax, so a Bash-only split is not a
			// statement-budget result for this reading.
			_, parsed := budgetPOSIXParse(command)
			return parsed
		}
		// The flattened outer call can be short while a static shell -c
		// or eval body in it exceeds the same budget.
		if !strings.Contains(command, " -c") && !strings.Contains(command, " --command") &&
			!strings.Contains(command, "eval ") && !strings.Contains(command, "trap ") {
			return false
		}
	}
	// The evaluator can decline a dynamic function invocation (for
	// example run() { "$@"; }). That does not make the surrounding
	// statements disappear. Count their syntax without resolving the
	// function's dynamic command name.
	return posixStructuralStatementsOverBudget(command)
}

// posixStructuralStatementsOverBudget is the count-only fallback when the
// evaluator cannot flatten a valid POSIX call. Function definitions are
// inert; their bodies count when an earlier definition is invoked. Compound
// statements are replaced by their children, as in SimpleCommands.
func posixStructuralStatementsOverBudget(command string) bool {
	file, ok := budgetPOSIXParse(command)
	if !ok {
		return false
	}
	functions := make(map[string]*syntax.Stmt)
	variables := make(map[string]string)
	var forwardedArgs []*syntax.Word
	count := 0
	var statements func([]*syntax.Stmt, int)
	var statement func(*syntax.Stmt, int)
	statements = func(list []*syntax.Stmt, depth int) {
		for _, stmt := range list {
			if count > maxStatementsAlone {
				return
			}
			statement(stmt, depth)
		}
	}
	statement = func(stmt *syntax.Stmt, depth int) {
		if stmt == nil || count > maxStatementsAlone {
			return
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.FuncDecl:
			if cmd.Name != nil && cmd.Body != nil {
				functions[cmd.Name.Value] = cmd.Body
			}
			return
		case *syntax.BinaryCmd:
			statement(cmd.X, depth)
			statement(cmd.Y, depth)
			return
		case *syntax.Subshell:
			statements(cmd.Stmts, depth)
			return
		case *syntax.Block:
			statements(cmd.Stmts, depth)
			return
		case *syntax.IfClause:
			for clause := cmd; clause != nil; clause = clause.Else {
				statements(clause.Cond, depth)
				statements(clause.Then, depth)
			}
			return
		case *syntax.WhileClause:
			statements(cmd.Cond, depth)
			statements(cmd.Do, depth)
			return
		case *syntax.ForClause:
			statements(cmd.Do, depth)
			return
		case *syntax.CaseClause:
			for _, item := range cmd.Items {
				statements(item.Stmts, depth)
			}
			return
		case *syntax.TimeClause:
			statement(cmd.Stmt, depth)
			return
		case *syntax.CallExpr:
			count++
			if len(cmd.Args) == 0 {
				for _, assign := range cmd.Assigns {
					if assign.Name == nil {
						continue
					}
					value, known := simpleStaticWord(assign.Value, variables)
					if known {
						variables[assign.Name.Value] = value
					} else {
						delete(variables, assign.Name.Value)
					}
				}
			}
			syntax.Walk(cmd, func(node syntax.Node) bool {
				switch nested := node.(type) {
				case *syntax.CmdSubst:
					statements(nested.Stmts, depth)
					return false
				case *syntax.ProcSubst:
					statements(nested.Stmts, depth)
					return false
				}
				return count <= maxStatementsAlone
			})
			if len(cmd.Args) > 0 {
				forwardedCall := budgetForwardedArgv(cmd.Args[0]) && len(cmd.Args) == 1
				if len(cmd.Args) == 2 && budgetForwardedArgv(cmd.Args[1]) {
					forwardedCall = cmd.Args[0].Lit() == "command" || cmd.Args[0].Lit() == "exec"
				}
				if forwardedCall && len(forwardedArgs) > 0 && depth < 8 {
					if script, _, nested, static := simpleNestedScriptArgs(forwardedArgs, variables, 0, nil, nil); nested && static {
						if child, parsed := budgetPOSIXParse(script); parsed {
							prior := forwardedArgs
							forwardedArgs = nil
							statements(child.Stmts, depth+1)
							forwardedArgs = prior
						}
					}
				}
				name, known := simpleFunctionCallName(cmd)
				if !known {
					name, known = simpleStaticWord(cmd.Args[0], variables)
				}
				if known && depth < 8 {
					if body := functions[name]; body != nil {
						prior := forwardedArgs
						forwardedArgs = cmd.Args[1:]
						if len(cmd.Args) == 2 && budgetForwardedArgv(cmd.Args[1]) {
							forwardedArgs = prior
						}
						statement(body, depth+1)
						forwardedArgs = prior
					}
				}
			}
			if depth < 8 {
				if script, _, nested, static := simpleNestedScript(cmd, nil, nil, nil); nested && static {
					if child, ok := budgetPOSIXParse(script); ok {
						prior := forwardedArgs
						forwardedArgs = nil
						statements(child.Stmts, depth+1)
						forwardedArgs = prior
					}
				}
			}
		default:
			count++
		}
	}
	statements(file.Stmts, 0)
	return count > maxStatementsAlone
}

// budgetForwardedArgv recognizes the unchanged argv used by a function
// wrapper. An unquoted $@ is not an unchanged argv because it can split.
func budgetForwardedArgv(word *syntax.Word) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	return ok && param.Param != nil && param.Param.Value == "@"
}

func budgetPOSIXParse(command string) (*syntax.File, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(command), "")
	if err == nil {
		return file, true
	}
	// Match the analyzer's narrow normalization for aggregate redirects.
	// Other Bash syntax remains invalid in a POSIX reading.
	normalized, valid := normalizePOSIXAggregateRedirects(command, true)
	if !valid {
		return nil, false
	}
	file, err = syntax.NewParser(syntax.Variant(syntax.LangPOSIX)).Parse(shellparse.Reader(normalized), "")
	return file, err == nil
}

// ShellStatementTexts returns the statements of a POSIX command as the
// statement budget counts them (ShellStatementsOverBudget), in order; ok is
// false when the command does not parse.
func ShellStatementTexts(command string) ([]string, bool) {
	texts, _, ok := ShellStatementTextsWithOffsets(command)
	return texts, ok
}

// ShellStatementTextsWithOffsets also reports each statement's start in
// command. A function body can be read after its source position, so callers
// use the offsets only for top-level statements executed in source order.
func ShellStatementTextsWithOffsets(command string) ([]string, []int, bool) {
	statements, _, ok := sequenceStatementDetails(command, true, true, false, true)
	if !ok {
		return nil, nil, false
	}
	texts := make([]string, len(statements))
	offsets := make([]int, len(statements))
	for i, statement := range statements {
		texts[i] = statement.text
		offsets[i] = statement.sourceStart
	}
	return texts, offsets, true
}

// PowerShellStatementsOverBudget reports whether a command has more
// statements than one action evaluates (maxStatementsAlone) as PowerShell
// splits it: list members (;, &&, ||, line ends) and pipeline stages, at
// every depth of a subexpression ($( ), @( ), ( )) and a script block
// ({ }). It is the budget of a call that PowerShell may run but that no
// analysis read to its end, such as a Codex call on Windows past the 64 KiB
// input bound (rel-1-0-6:GAP-0318).
//
// It reads the command with its own scanner, not the Windows lexer: the
// lexer used to stop at the first subexpression, array, hashtable, braced
// variable or here-string, so a single $(Get-Date) in front hid later
// statements from the count (rel-1-0-6:GAP-0331). Text in quotes,
// here-strings and comments is not counted, nor are the entries of a
// hashtable (@{ a = 1; b = 2 }); an
// opening bracket or brace starts a new statement count inside it, and a
// closing one continues the statement around it, so a block never counts
// more statements than it holds.
func PowerShellStatementsOverBudget(command string) bool {
	statements, _ := powerShellStatements(command, maxStatementsAlone+1)
	return statements > maxStatementsAlone
}

// PowerShellReadingStopsEarly reports a command with a construct that can
// leave a partial Windows lexer reading: a subexpression $( ), an array @( ),
// a hashtable @{ }, a braced variable ${ }, a here-string, the stop-parsing
// token --% or an & call. The separate budget scanner counts past these
// constructs (rel-1-0-6:GAP-0331).
func PowerShellReadingStopsEarly(command string) bool {
	_, opaque := powerShellStatements(command, len(command)+1)
	return opaque
}

// powerShellStatements counts the statements of command, stopping at limit,
// and reports whether it met an opaque construct.
func powerShellStatements(command string, limit int) (int, bool) {
	const (
		frameCode = iota
		frameHashtable
		frameDouble
		frameVariable
		// frameParen is a bare ( ): one expression or pipeline, so a line
		// end inside it continues the statement (a multi-line param( )).
		frameParen
	)
	runes := []rune(command)
	frames := []int{frameCode}
	argumentMode := []bool{false}
	statementStart := []bool{true}
	push := func(frame int) {
		frames = append(frames, frame)
		argumentMode = append(argumentMode, false)
		statementStart = append(statementStart, frame != frameHashtable)
	}
	pop := func() {
		frames = frames[:len(frames)-1]
		argumentMode = argumentMode[:len(argumentMode)-1]
		statementStart = statementStart[:len(statementStart)-1]
	}
	statements := 0
	inStatement := false
	opaque := false
	// lastSignificant is the last non-blank character of code before i: a
	// line end right after a comma continues the statement (a multi-line
	// array). Comment text never sets it (commentEnd).
	lastSignificant := rune(0)
	lastSignificantAt := -1
	commentEnd := -1
	// stmtStart is where the current statement's text begins: an & after
	// an = is the call operator only when the text from here to the = is
	// an assignment target (powerShellAssignmentTarget).
	stmtStart := 0
	boundary := func() {
		if inStatement {
			statements++
			inStatement = false
		}
	}
	// lineStart reports that i begins a line (for a here-string end).
	lineStart := func(i int) bool { return i == 0 || runes[i-1] == '\n' || runes[i-1] == '\r' }
	for i := 0; i < len(runes) && statements < limit; i++ {
		r := runes[i]
		top := frames[len(frames)-1]
		switch top {
		case frameDouble:
			switch {
			case r == '`':
				i++
			case windowsPowerShellQuoteDelimiter(r) == '"':
				if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == '"' {
					i++ // a doubled quote is one quote character
				} else {
					pop()
				}
			case r == '$' && i+1 < len(runes) && runes[i+1] == '(':
				push(frameCode)
				i++
			}
			continue
		case frameVariable:
			switch r {
			case '`':
				i++
			case '}':
				pop()
			}
			continue
		}
		// Code, paren and hashtable frames.
		next := rune(0)
		if i+1 < len(runes) {
			next = runes[i+1]
		}
		comment := (r == '#' || r == '<' && next == '#') &&
			windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1])
		if statementStart[len(statementStart)-1] && windowsPowerShellStatementCommandWord(runes, i) {
			argumentMode[len(argumentMode)-1] = true
		}
		if statementStart[len(statementStart)-1] && !unicode.IsSpace(r) && r != '&' && !comment {
			statementStart[len(statementStart)-1] = false
		}
		if r == '&' && (i == 0 || runes[i-1] != '>') {
			argumentMode[len(argumentMode)-1] = false
			statementStart[len(statementStart)-1] = true
		}
		if i > 0 && i-1 != commentEnd && !unicode.IsSpace(runes[i-1]) {
			lastSignificant, lastSignificantAt = runes[i-1], i-1
		}
		switch {
		case r == '#' && windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1]):
			// A line comment: the line goes on as the code before it ends.
			// A comma inside the comment does not continue the line
			// (review r3 finding 1: `Write-Output 1 # note,` lines hid
			// their statements from the count).
			lastSignificant, lastSignificantAt = 0, -1
			for j := i - 1; j >= 0 && runes[j] != '\n' && runes[j] != '\r'; j-- {
				if !unicode.IsSpace(runes[j]) {
					lastSignificant, lastSignificantAt = runes[j], j
					break
				}
			}
			for i+1 < len(runes) && runes[i+1] != '\n' && runes[i+1] != '\r' {
				i++
			}
			commentEnd = i
		case r == '<' && next == '#' && windowsPowerShellCommentStarts(runes, i, !argumentMode[len(argumentMode)-1]):
			end, ok := windowsPowerShellBlockCommentEnd(runes, i)
			if !ok {
				return statements, opaque
			}
			// The comment's text never sets lastSignificant: the code
			// before the comment decides what an & or a line end after it
			// means (review r4 finding 1: `cmd <#c#> & cmd`).
			i = end
			commentEnd = end
		case r == '-' && next == '-' && i+2 < len(runes) && runes[i+2] == '%' &&
			(i+3 == len(runes) || unicode.IsSpace(runes[i+3])) && windowsPowerShellTokenStart(runes, i):
			// The stop-parsing arguments end at an unquoted pipe, &&, or line end.
			opaque, inStatement = true, true
			i = windowsPowerShellStopParsingEnd(runes, i+3) - 1
		case r == '`':
			// An escaped character, or a line continuation.
			inStatement = true
			i++
		case r == '@' && windowsPowerShellQuoteDelimiter(next) != 0 && powerShellHereStringOpens(runes, i+2):
			quote := windowsPowerShellQuoteDelimiter(next)
			inStatement = true
			j := i + 2
			for ; j+1 < len(runes); j++ {
				if lineStart(j) && windowsPowerShellQuoteDelimiter(runes[j]) == quote && runes[j+1] == '@' {
					break
				}
			}
			if j+1 >= len(runes) {
				return statements, opaque
			}
			opaque = true
			i = j + 1
		case windowsPowerShellQuoteDelimiter(r) == '\'':
			inStatement = true
			for i++; i < len(runes); i++ {
				if windowsPowerShellQuoteDelimiter(runes[i]) == '\'' {
					if i+1 < len(runes) && windowsPowerShellQuoteDelimiter(runes[i+1]) == '\'' {
						i++
						continue
					}
					break
				}
			}
		case windowsPowerShellQuoteDelimiter(r) == '"':
			inStatement = true
			push(frameDouble)
		case r == '$' && next == '{':
			inStatement, opaque = true, true
			push(frameVariable)
			i++
		case r == '@' && next == '{':
			inStatement, opaque = true, true
			push(frameHashtable)
			i++
		case (r == '$' || r == '@') && next == '(':
			push(frameCode)
			inStatement, opaque = false, true
			i++
			stmtStart = i + 1
		case r == '(':
			push(frameParen)
			inStatement = false
			stmtStart = i + 1
		case r == '{':
			push(frameCode)
			inStatement = false
			stmtStart = i + 1
		case r == ')' || r == '}':
			// The statement around the bracket goes on; the last statement
			// inside it is counted with it.
			if len(frames) > 1 {
				pop()
			}
			inStatement = true
		case top == frameHashtable && (r == ';' || r == '\n' || r == '\r'):
			// Entry separators of a hashtable, not statements.
			argumentMode[len(argumentMode)-1] = false
			statementStart[len(statementStart)-1] = false
		case (r == '\n' || r == '\r') && (top == frameParen || lastSignificant == ','):
			// A line end inside a bare ( ) or after a trailing comma
			// continues the statement.
		case r == ';' || r == '|' || r == '\n' || r == '\r':
			boundary()
			argumentMode[len(argumentMode)-1] = false
			statementStart[len(statementStart)-1] = true
			stmtStart = i + 1
		case r == '&' && next == '&':
			boundary()
			statementStart[len(statementStart)-1] = true
			i++
			stmtStart = i + 1
		case r == '&' && (i == 0 || runes[i-1] != '>'):
			// At a statement start, or right after an assignment operator
			// ($x = & git ..., $x += & f, $a[0]= & f, ${x}= & f, a
			// hashtable value), the call operator, which ends nothing
			// (review r3 finding 2). After anything else the PowerShell 7
			// background operator ends the command: a bare argument ending
			// in * / % - + ! < > (review r4 finding 1), and an = or a comma
			// in or at the end of a bare word (Write-Output key=, a base64
			// value ending in ==), which command mode reads as part of the
			// argument (rel-1-0-6:GAP-0412). A comma before & is a
			// PowerShell parse error (MissingExpression) in every mode, so it
			// never makes a call. The Windows lexer stops at a call whose
			// target is not quoted.
			opaque = true
			call := !inStatement || lastSignificant == '=' && lastSignificantAt >= stmtStart &&
				(top == frameHashtable || powerShellAssignmentTarget(runes[stmtStart:lastSignificantAt]))
			if call {
				inStatement = true
			} else {
				boundary()
				stmtStart = i + 1
			}
		case !unicode.IsSpace(r):
			inStatement = true
		}
	}
	if inStatement {
		statements++
	}
	return statements, opaque
}

// powerShellAssignable matches the targets of a PowerShell assignment with
// an optional compound operator before its =: $x, $env:X, ${x}, $a[0],
// $o.p, [int]$n, [string[]]$s and [List[string]]$l (one level of nested
// type brackets), $a, $b (multiple assignment), $x = $y (a chain), and
// $x + (for +=), $x ?? (for ??=). Review r6 finding 5: the nested types,
// the list and the chain counted two statements a line.
var powerShellAssignable = func() *regexp.Regexp {
	target := `(\[(?:[^\[\]]|\[[^\[\]]*\])+\]\s*)*(\$\{[^}]+\}|\$[A-Za-z_][\w:]*)(\[[^\]]*\]|\.[A-Za-z_]\w*)*`
	list := target + `(\s*,\s*` + target + `)*`
	return regexp.MustCompile(`^(` + list + `\s*=\s*)*` + list + `\s*(\?\?|[-+*/%])?$`)
}()

var powerShellBlockComment = regexp.MustCompile(`<#[\s\S]*?#>`)

// powerShellAssignmentTarget reports that target, the text of a statement
// before an =, is an assignable expression, so the = is the assignment
// operator. A statement that begins with a bare word is in command mode,
// where = is part of an argument (Write-Output key=, Write-Output =). A
// target is short: past 256 characters it is not one, which keeps the count
// linear.
func powerShellAssignmentTarget(target []rune) bool {
	if len(target) > 256 {
		return false
	}
	text := strings.TrimSpace(powerShellBlockComment.ReplaceAllString(string(target), " "))
	return powerShellAssignable.MatchString(text)
}

// powerShellHereStringOpens reports that only blanks follow position i up to
// the end of its line: @' and @" open a here-string only at a line end.
func powerShellHereStringOpens(runes []rune, i int) bool {
	for ; i < len(runes); i++ {
		switch runes[i] {
		case '\n', '\r':
			return true
		case ' ', '\t':
		default:
			return false
		}
	}
	return false
}
