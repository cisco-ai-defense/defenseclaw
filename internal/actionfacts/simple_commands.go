// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"maps"
	"path/filepath"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// SimpleCommand is one command of a shell action, with the directory in
// which it runs. Its text is independently suitable for Analyze.
type SimpleCommand struct {
	Text string
	CWD  string
	// ZshHistoryBuiltin marks a history command in an explicitly invoked zsh
	// body. Zsh history is fc -l, so Bash's history -c clear grammar does not
	// apply to this child.
	ZshHistoryBuiltin bool
	// UnresolvedBoundVariable means a parameter in Text is bound elsewhere
	// in the action but this walk could not carry its value into Text. The
	// original action decides the protected-write class for that value.
	UnresolvedBoundVariable bool
	// EvaluationFailure is "limit" or "parse" when no complete per-command
	// view can be produced. A parse gap is not an action refusal.
	EvaluationFailure string
}

type simpleShellState struct {
	cwd        string
	cwdUnknown bool
	dirStack   []string
	vars       map[string]string
}

const (
	maxSimpleStates      = 32
	maxSimpleEvaluations = 512
)

func (s simpleShellState) clone() simpleShellState {
	copy := simpleShellState{cwd: s.cwd, cwdUnknown: s.cwdUnknown,
		dirStack: slices.Clone(s.dirStack), vars: make(map[string]string, len(s.vars))}
	for name, value := range s.vars {
		copy.vars[name] = value
	}
	return copy
}

// SimpleCommands flattens an action with the full parser used by the hook
// command class rule. Every returned command is judged on its own, in
// addition to the original action. A plain single command needs no second
// pass. Ordinary assignments and known home or local variable expansions
// are resolved; a subshell or pipeline stage has its own shell state.
func SimpleCommands(input Input, facts Facts) []SimpleCommand {
	return simpleCommands(input, facts, 0, "")
}

func simpleCommands(input Input, facts Facts, depth int, interpreter string) []SimpleCommand {
	if facts.Parse.Dialect == DialectPowerShell || facts.Parse.Dialect == DialectCMD {
		return windowsSimpleCommands(input, facts)
	}
	if facts.Parse.Dialect != DialectPOSIX {
		return nil
	}
	if depth >= 8 {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	source := input.Command
	if source == "" {
		_, capture := analyzeWithRedirectTargets(input, "")
		source = capture.source
	}
	if len(source) > maxCommandBytes {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if source == "" {
		return nil
	}
	if !strings.ContainsAny(source, ";&|(){}<>\n`$=!") &&
		!strings.Contains(source, "eval") && !strings.Contains(source, "trap") &&
		!strings.Contains(source, " -") {
		return nil
	}
	parts, reduced, ok := sequenceStatementDetails(source, true, true)
	if !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	var bound map[string]bool
	if strings.ContainsRune(source, '$') {
		file, _ := shellparse.Parse(source)
		bound = simpleBoundVariables(file)
	}
	if len(parts) == 0 {
		return nil
	}
	if len(parts) > maxStatementsAlone {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	if !reduced && len(parts) == 1 {
		file, parsed := shellparse.Parse(parts[0].text)
		if !parsed || len(file.Stmts) != 1 {
			return nil
		}
		stmt := file.Stmts[0]
		call, _ := stmt.Cmd.(*syntax.CallExpr)
		prefix := call != nil && len(call.Assigns) != 0 && len(call.Args) != 0
		duplication := slices.ContainsFunc(stmt.Redirs, func(redirect *syntax.Redirect) bool {
			return redirect.Op == syntax.DplIn || redirect.Op == syntax.DplOut
		})
		_, _, nested, _ := simpleNestedScript(call, nil, nil, nil)
		if !prefix && !duplication && !nested {
			return nil
		}
	}
	home, _ := normalizeActiveHome(input.ActiveHome)
	initialVars := map[string]string{"HOME": home}
	if filepath.IsAbs(input.CWD) {
		initialVars["PWD"] = filepath.Clean(input.CWD)
	}
	states := map[string][]simpleShellState{
		"0": {{cwd: input.CWD, vars: initialVars}},
	}
	result := make([]SimpleCommand, 0, len(parts))
	changed := reduced || len(parts) != 1
	unproven := false
	previousScope := "0"
	for _, part := range parts {
		// A conditional or loop body runs in its parent's shell when selected.
		// Keep both its resulting state and the path that skipped the body.
		for previousScope != part.scope && !strings.HasPrefix(part.scope, previousScope+"/") {
			index := strings.LastIndexByte(previousScope, '/')
			if index < 0 {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
			}
			parent := previousScope[:index]
			if previousScope[index+1] == 'c' {
				states[parent] = uniqueSimpleStates(append(states[parent], states[previousScope]...))
				if len(states[parent]) > maxSimpleStates {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			previousScope = parent
		}
		previousScope = part.scope
		variants, present := states[part.scope]
		if !present {
			parent := part.scope
			for {
				index := strings.LastIndexByte(parent, '/')
				if index < 0 {
					return []SimpleCommand{{EvaluationFailure: "parse"}}
				}
				parent = parent[:index]
				if inherited, ok := states[parent]; ok {
					for _, state := range inherited {
						variants = append(variants, state.clone())
					}
					break
				}
			}
		}
		file, parsed := shellparse.Parse(part.text)
		if !parsed || len(file.Stmts) != 1 {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		stmt := file.Stmts[0]
		nextVariants := make([]simpleShellState, 0, len(variants))
		emitted := make(map[SimpleCommand]bool)
		for _, prior := range variants {
			state := prior.clone()
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) == 0 && len(call.Assigns) != 0 && len(stmt.Redirs) == 0 {
				updateSimpleVariables(state.vars, call.Assigns)
				changed = true
				nextVariants = append(nextVariants, state)
				continue
			}
			text := part.text
			effective := state.vars
			if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Assigns) != 0 && len(call.Args) != 0 {
				effective = state.clone().vars
				updateSimpleVariables(effective, call.Assigns)
				// The policy facts are the command's argv. Keep prefixes
				// that can change executable resolution: dropping PATH from
				// `PATH=/missing $'rm' -rf /` would invent a runnable rm.
				if !simplePrefixChangesResolution(call.Assigns) {
					start := int(call.Args[0].Pos().Offset())
					end := int(call.Pos().Offset())
					if start <= end || start > len(text) {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					text = text[start:]
					changed = true
				}
			}
			if resolved, ok := simpleResolvedVariables(text, effective); ok {
				text = resolved
				changed = true
			}
			if stripped, ok := withoutDescriptorDuplications(text); ok {
				text = stripped
				changed = true
			}
			if strings.TrimSpace(text) == "" {
				return []SimpleCommand{{EvaluationFailure: "parse"}}
			}
			if state.cwdUnknown && simpleRelativePathOperand(text) {
				unproven = true
			}
			call, _ := stmt.Cmd.(*syntax.CallExpr)
			command := SimpleCommand{Text: text, CWD: state.cwd,
				ZshHistoryBuiltin:       simpleZshHistoryCall(call, effective, interpreter),
				UnresolvedBoundVariable: simpleUnresolvedBoundVariable(text, effective, bound)}
			if !emitted[command] {
				result = append(result, command)
				emitted[command] = true
				if len(result) > maxSimpleEvaluations {
					return []SimpleCommand{{EvaluationFailure: "limit"}}
				}
			}
			if call != nil {
				var innerCWDUnknown bool
				var innerInterpreter string
				script, shared, nested, static := simpleNestedScript(call, effective, &innerCWDUnknown, &innerInterpreter)
				if nested {
					if !static || len(script) > maxCommandBytes {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					innerInput := input
					innerInput.Command, innerInput.Args, innerInput.Argv = script, nil, nil
					innerInput.CWD = state.cwd
					if innerCWDUnknown {
						innerInput.CWD = ""
					}
					if shared {
						if resolved, ok := simpleResolvedVariables(script, effective); ok {
							innerInput.Command = resolved
						}
					}
					if _, ok := shellparse.Parse(innerInput.Command); !ok {
						return []SimpleCommand{{EvaluationFailure: "parse"}}
					}
					innerFacts := Analyze(innerInput)
					if innerInterpreter == "" {
						innerInterpreter = interpreter
					}
					inner := simpleCommands(innerInput, innerFacts, depth+1, innerInterpreter)
					if len(inner) == 0 && strings.TrimSpace(innerInput.Command) != "" {
						zshHistory := innerInterpreter == "zsh" && len(innerFacts.Commands) == 1 &&
							innerFacts.Commands[0].Executable == "history"
						inner = []SimpleCommand{{Text: innerInput.Command, CWD: innerInput.CWD,
							ZshHistoryBuiltin: zshHistory}}
					}
					changed = changed || len(inner) != 0
					for _, child := range inner {
						if child.EvaluationFailure != "" {
							unproven = true
							continue
						}
						child.UnresolvedBoundVariable = child.UnresolvedBoundVariable ||
							simpleUnresolvedBoundVariable(child.Text, effective, bound)
						result = append(result, child)
						if len(result) > maxSimpleEvaluations {
							return []SimpleCommand{{EvaluationFailure: "limit"}}
						}
					}
					if shared {
						for _, innerCommand := range innerFacts.Commands {
							if ChangesShellDirectory(innerCommand) {
								state.cwd, state.cwdUnknown = "", true
								delete(state.vars, "PWD")
								break
							}
						}
					}
				}
			}
			nextCWD, changedDirectory := simpleCommandNextCWD(text, &state, effective)
			if !changedDirectory {
				// An unmodeled shell builtin or dynamic program may move the
				// caller's directory. Later relative operands cannot use the
				// original hook directory as an authoritative base.
				if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) != 0 {
					program, known := simpleStaticProgramWord(call.Args[0], effective)
					if !known || program != "trap" &&
						ChangesShellDirectory(CommandFact{Dialect: DialectPOSIX, Program: program}) {
						nextCWD, changedDirectory = "", true
					}
				}
			}
			if changedDirectory {
				if state.cwd != "" {
					state.vars["OLDPWD"] = state.cwd
				} else {
					delete(state.vars, "OLDPWD")
				}
				if nextCWD != "" {
					state.vars["PWD"] = nextCWD
				} else {
					delete(state.vars, "PWD")
				}
			}
			state.cwd = nextCWD
			if changedDirectory {
				state.cwdUnknown = nextCWD == ""
			}
			nextVariants = append(nextVariants, state)
		}
		states[part.scope] = uniqueSimpleStates(nextVariants)
		if len(states[part.scope]) > maxSimpleStates {
			return []SimpleCommand{{EvaluationFailure: "limit"}}
		}
	}
	if !changed {
		return nil
	}
	if unproven {
		return append(result, SimpleCommand{EvaluationFailure: "parse"})
	}
	return result
}

// windowsSimpleCommands uses the same lexer as Analyze to find statement and
// pipeline boundaries. The source slices preserve quotes, escaping and path
// spelling for each standalone policy evaluation.
func windowsSimpleCommands(input Input, facts Facts) []SimpleCommand {
	source := input.Command
	if source == "" && argsExecutionTool(input.Tool) {
		source = extractArgsForTool(input.Args, input.Tool).command
	}
	if source == "" {
		return nil
	}
	if len(source) > maxCommandBytes {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	dialect := windowsPowerShell
	if facts.Parse.Dialect == DialectCMD {
		dialect = windowsCMD
	}
	if !strings.ContainsAny(source, ";&|\n\r") && !windowsSimplePotentialGroup(source, dialect) {
		return nil
	}
	var groupEvents []windowsSimpleGroupEvent
	source, groupEvents, ok := windowsSimpleGroupSource(source, dialect)
	if !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	out := newParseOutput(facts.Parse.Dialect, 1)
	lexemes, ok := windowsLex(source, dialect, &out)
	if !ok || out.status == StatusInvalid {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	if out.status == StatusLimitExceeded {
		return []SimpleCommand{{EvaluationFailure: "limit"}}
	}
	lexemes = windowsSimpleContinuedLexemes(lexemes)
	if _, _, ok = windowsBuildCommands(lexemes, &out); !ok {
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	if len(groupEvents) != 0 && strings.TrimSpace(source) == "" {
		return nil
	}
	runes := []rune(source)
	begin := 0
	result := make([]SimpleCommand, 0, 2)
	variables := make(map[string]string)
	state := simpleWindowsState{cwd: input.CWD}
	failed := false
	groupIndex := 0
	var groups []simpleWindowsGroupSnapshot
	processGroupEvents := func(before int) {
		for groupIndex < len(groupEvents) && groupEvents[groupIndex].offset < before {
			if groupEvents[groupIndex].open {
				groups = append(groups, state.groupSnapshot(variables))
			} else if len(groups) == 0 {
				failed = true
			} else {
				state.mergeGroup(groups[len(groups)-1], variables)
				groups = groups[:len(groups)-1]
			}
			groupIndex++
		}
	}
	appendPart := func(part string, start, end int) {
		childStart := start
		for childStart < end && unicode.IsSpace(runes[childStart]) {
			childStart++
		}
		processGroupEvents(childStart)
		childInput := input
		childInput.CWD = state.cwd
		text := part
		if dialect == windowsPowerShell {
			if !windowsSimpleAssignment(part, childInput, variables) {
				text = windowsSimpleResolvedVariables(part, variables)
			}
		}
		state.forgetKnownVariables(variables)
		if state.referencesUncertainVariable(part) {
			failed = true
		}
		if state.cwdUnknown && windowsSimpleRelativePathOperand(text, facts.Parse.Dialect) {
			failed = true
		}
		result = append(result, SimpleCommand{Text: text, CWD: state.cwd})
		state.next(part, dialect, childInput, variables)
		processGroupEvents(end)
	}
	for _, lexeme := range lexemes {
		if lexeme.kind != windowsSeparatorLexeme && lexeme.kind != windowsPipeLexeme {
			continue
		}
		if lexeme.start < begin || lexeme.end > len(runes) {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		part := strings.TrimSpace(string(runes[begin:lexeme.start]))
		if part == "" {
			return []SimpleCommand{{EvaluationFailure: "parse"}}
		}
		appendPart(part, begin, lexeme.start)
		begin = lexeme.end
		if lexeme.kind == windowsPipeLexeme || lexeme.operator == "&&" || lexeme.operator == "||" {
			// A pipeline stage has a separate scope; conditional assignments
			// may not have run. Do not carry either into a later command.
			clear(variables)
		}
		if len(result) >= maxStatementsAlone {
			return []SimpleCommand{{EvaluationFailure: "limit"}}
		}
	}
	if len(result) == 0 && len(groupEvents) == 0 {
		return nil
	}
	last := strings.TrimSpace(string(runes[begin:]))
	if last == "" {
		if dialect == windowsPowerShell && len(lexemes) != 0 &&
			lexemes[len(lexemes)-1].kind == windowsSeparatorLexeme &&
			lexemes[len(lexemes)-1].operator == ";" {
			if failed {
				return append(result, SimpleCommand{EvaluationFailure: "parse"})
			}
			return result
		}
		return []SimpleCommand{{EvaluationFailure: "parse"}}
	}
	appendPart(last, begin, len(runes))
	if failed {
		return append(result, SimpleCommand{EvaluationFailure: "parse"})
	}
	return result
}

// Recognize only bounded PowerShell path assignments. An unresolved value is
// left dynamic, so its later use keeps the ordinary fail-closed path proof.
func windowsSimpleAssignment(part string, input Input, variables map[string]string) bool {
	out := newParseOutput(DialectPowerShell, 1)
	lexemes, ok := windowsLex(part, windowsPowerShell, &out)
	if !ok || len(lexemes) < 3 {
		return false
	}
	words := make([]windowsWord, 0, len(lexemes))
	for _, lexeme := range lexemes {
		if lexeme.kind != windowsWordLexeme {
			return false
		}
		words = append(words, lexeme.word)
	}
	name := strings.ToLower(words[0].value)
	if words[0].quote != QuoteNone || !windowsSimpleVariableName(name) || words[1].value != "=" {
		return false
	}
	delete(variables, name)
	var value string
	switch {
	case len(words) == 3:
		value, ok = windowsSimplePathValue(words[2], input, variables)
	case len(words) == 5 && strings.EqualFold(words[2].value, "Join-Path"):
		var base string
		base, ok = windowsSimplePathValue(words[3], input, variables)
		child := words[4]
		if !ok || child.expands || child.wildcard || child.value == "" ||
			strings.ContainsAny(child.value, "$%`*?[]\r\n") ||
			strings.HasPrefix(child.value, "/") || strings.HasPrefix(child.value, `\`) ||
			strings.Contains(child.value, ":") {
			ok = false
			break
		}
		for _, component := range strings.Split(strings.ReplaceAll(child.value, `\`, "/"), "/") {
			if component == ".." || strings.Contains(component, "~") {
				ok = false
				break
			}
		}
		if ok {
			_, _, value = deriveWindowsPathWithPolicy(joinWindowsPath(base, child.value),
				input.CWD, input.ActiveHome, pathExpansionPolicy{expandTilde: true})
			ok = value != ""
		}
	default:
		ok = false
	}
	if ok {
		variables[name] = value
	}
	return true
}

func windowsSimplePathValue(word windowsWord, input Input, variables map[string]string) (string, bool) {
	if word.quote != QuoteSingle && windowsSimpleVariableName(strings.ToLower(word.value)) {
		if value, ok := variables[strings.ToLower(word.value)]; ok {
			return value, true
		}
		if strings.EqualFold(word.value, "$HOME") {
			_, _, value := deriveWindowsPathWithPolicy(input.ActiveHome, input.CWD,
				input.ActiveHome, pathExpansionPolicy{expandTilde: true})
			return value, value != ""
		}
	}
	if word.expands || word.wildcard || strings.ContainsAny(word.value, "$%`*?[]\r\n") {
		return "", false
	}
	_, _, value := deriveWindowsPathWithPolicy(word.value, input.CWD, input.ActiveHome,
		pathExpansionPolicy{expandTilde: true})
	return value, value != ""
}

func windowsSimpleVariableName(value string) bool {
	if len(value) < 2 || value[0] != '$' ||
		!windowsSimpleVariableLetter(rune(value[1])) {
		return false
	}
	for _, char := range value[2:] {
		if !windowsSimpleVariableLetter(char) && (char < '0' || char > '9') {
			return false
		}
	}
	return true
}

func windowsSimpleVariableLetter(char rune) bool {
	return char >= 'a' && char <= 'z' || char == '_'
}

func windowsSimpleResolvedVariables(source string, variables map[string]string) string {
	if len(variables) == 0 {
		return source
	}
	runes := []rune(source)
	var result strings.Builder
	var quote rune
	writePath := func(value string) {
		result.WriteByte('\'')
		result.WriteString(strings.ReplaceAll(value, "'", "''"))
		result.WriteByte('\'')
	}
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		if char == '`' && quote != '\'' && index+1 < len(runes) {
			result.WriteRune(char)
			index++
			result.WriteRune(runes[index])
			continue
		}
		if char == '"' && quote == 0 {
			end := index + 1
			for end < len(runes) && runes[end] != '"' && runes[end] != '`' {
				end++
			}
			if end < len(runes) && runes[end] == '"' {
				name := strings.ToLower(string(runes[index+1 : end]))
				if windowsSimpleVariableName(name) {
					if value, ok := variables[name]; ok {
						writePath(value)
						index = end
						continue
					}
				}
			}
		}
		if char == '\'' || char == '"' {
			switch quote {
			case 0:
				quote = char
			case char:
				quote = 0
			}
			result.WriteRune(char)
			continue
		}
		if char == '$' && quote == 0 && index+1 < len(runes) &&
			(unicode.IsLetter(runes[index+1]) || runes[index+1] == '_') {
			end := index + 2
			for end < len(runes) && (unicode.IsLetter(runes[end]) || unicode.IsDigit(runes[end]) || runes[end] == '_') {
				end++
			}
			if end == len(runes) || runes[end] != ':' {
				if value, ok := variables[strings.ToLower(string(runes[index:end]))]; ok {
					writePath(value)
					index = end - 1
					continue
				}
			}
		}
		result.WriteRune(char)
	}
	return result.String()
}

func simplePrefixChangesResolution(assigns []*syntax.Assign) bool {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil {
			continue
		}
		switch assign.Name.Value {
		case "PATH", "IFS", "CDPATH", "ENV", "BASH_ENV", "SHELLOPTS", "BASHOPTS":
			return true
		}
		if strings.HasPrefix(assign.Name.Value, "LD_") ||
			strings.HasPrefix(assign.Name.Value, "DYLD_") {
			return true
		}
	}
	return false
}

func uniqueSimpleStates(states []simpleShellState) []simpleShellState {
	result := make([]simpleShellState, 0, len(states))
	for _, state := range states {
		if !slices.ContainsFunc(result, func(previous simpleShellState) bool {
			return previous.cwd == state.cwd && previous.cwdUnknown == state.cwdUnknown &&
				slices.Equal(previous.dirStack, state.dirStack) && maps.Equal(previous.vars, state.vars)
		}) {
			result = append(result, state)
		}
	}
	return result
}

func updateSimpleVariables(vars map[string]string, assigns []*syntax.Assign) {
	for _, assign := range assigns {
		if assign == nil || assign.Name == nil || assign.Index != nil || assign.Array != nil {
			continue
		}
		name := assign.Name.Value
		if assign.Value == nil {
			vars[name] = ""
		} else if value, known := simpleStaticWord(assign.Value, vars); known {
			vars[name] = value
		} else {
			delete(vars, name)
		}
	}
}

// The full action may bind a value that the simple-command walk cannot
// resolve. Record only shell bindings, using the shared shell parser.
func simpleBoundVariables(file *syntax.File) map[string]bool {
	bound := make(map[string]bool)
	if file == nil {
		return bound
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch part := node.(type) {
		case *syntax.Assign:
			if part.Name != nil {
				bound[part.Name.Value] = true
			}
		case *syntax.WordIter:
			if part.Name != nil {
				bound[part.Name.Value] = true
			}
		case *syntax.FuncDecl:
			for i := '1'; i <= '9'; i++ {
				bound[string(i)] = true
			}
		case *syntax.CallExpr:
			if len(part.Args) == 0 {
				break
			}
			program, known := simpleStaticWord(part.Args[0], nil)
			if !known {
				break
			}
			switch program {
			case "printf":
				if len(part.Args) >= 3 && part.Args[1].Lit() == "-v" {
					if name, known := simpleStaticWord(part.Args[2], nil); known && simpleVariableName(name) {
						bound[name] = true
					}
				}
			case "read", "mapfile", "readarray":
				for _, arg := range part.Args[1:] {
					name, known := simpleStaticWord(arg, nil)
					if !known {
						break
					}
					if strings.HasPrefix(name, "-") {
						continue
					}
					if simpleVariableName(name) {
						bound[name] = true
					}
					break
				}
			}
		}
		return true
	})
	return bound
}

func simpleVariableName(name string) bool {
	if name == "" {
		return false
	}
	for index, char := range name {
		if char == '_' || char >= 'A' && char <= 'Z' || char >= 'a' && char <= 'z' ||
			index > 0 && char >= '0' && char <= '9' {
			continue
		}
		return false
	}
	return true
}

func simpleUnresolvedBoundVariable(source string, vars map[string]string, bound map[string]bool) bool {
	if len(bound) == 0 || !strings.ContainsRune(source, '$') {
		return false
	}
	file, ok := shellparse.Parse(source)
	if !ok {
		return false
	}
	unresolved := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil &&
			bound[param.Param.Value] {
			if _, known := vars[param.Param.Value]; !known {
				unresolved = true
				return false
			}
		}
		return !unresolved
	})
	return unresolved
}

func simpleStaticWord(word *syntax.Word, vars map[string]string) (string, bool) {
	return simpleStaticWordWithNewline(word, vars, false)
}

// '[' is a literal test builtin. The ordinary word resolver rejects its
// unmatched glob opener, but it cannot change the shell's directory.
func simpleStaticProgramWord(word *syntax.Word, vars map[string]string) (string, bool) {
	if word != nil && word.Lit() == "[" {
		return "[", true
	}
	return simpleStaticWord(word, vars)
}

func simpleZshHistoryCall(call *syntax.CallExpr, vars map[string]string, interpreter string) bool {
	if interpreter != "zsh" || call == nil || len(call.Args) == 0 {
		return false
	}
	program, known := simpleStaticProgramWord(call.Args[0], vars)
	return known && program == "history"
}

// A quoted -c or trap action can contain physical lines. Other shell words
// still require one line so they cannot silently become a different command.
func simpleStaticScriptWord(word *syntax.Word, vars map[string]string) (string, bool) {
	return simpleStaticWordWithNewline(word, vars, true)
}

func simpleStaticWordWithNewline(word *syntax.Word, vars map[string]string, allowNewline bool) (string, bool) {
	if word == nil {
		return "", false
	}
	safe := true
	syntax.Walk(word, func(node syntax.Node) bool {
		switch part := node.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				safe = false
			}
		case *syntax.ParamExp:
			if part.Param == nil {
				safe = false
				return false
			}
			_, known := vars[part.Param.Value]
			if !known || part.Excl || part.Length || part.Width || part.IsSet || part.Index != nil ||
				part.Slice != nil || part.Repl != nil || part.Names != 0 || part.Exp != nil ||
				part.Flags != nil || part.NestedParam != nil || len(part.Modifiers) != 0 {
				safe = false
			}
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
			safe = false
		}
		return safe
	})
	if !safe {
		return "", false
	}
	names := make([]string, 0, len(vars))
	for name := range vars {
		names = append(names, name)
	}
	slices.Sort(names)
	env := make([]string, 0, len(names))
	for _, name := range names {
		env = append(env, name+"="+vars[name])
	}
	fields, err := expand.Fields(&expand.Config{Env: expand.ListEnviron(env...)}, word)
	if err != nil || len(fields) != 1 || strings.ContainsRune(fields[0], 0) ||
		!allowNewline && strings.ContainsAny(fields[0], "\r\n") {
		return "", false
	}
	return fields[0], true
}

func simpleResolvedVariables(source string, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed {
		return "", false
	}
	type replacement struct {
		start, end int
		text       string
	}
	var replacements []replacement
	syntax.Walk(file, func(node syntax.Node) bool {
		if redirect, ok := node.(*syntax.Redirect); ok &&
			(redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc) {
			return false
		}
		word, ok := node.(*syntax.Word)
		if !ok {
			return true
		}
		hasParam := false
		hasTilde := false
		if len(word.Parts) != 0 {
			if lit, ok := word.Parts[0].(*syntax.Lit); ok {
				hasTilde = lit.Value == "~" || strings.HasPrefix(lit.Value, "~/")
			}
		}
		syntax.Walk(word, func(part syntax.Node) bool {
			if _, ok := part.(*syntax.ParamExp); ok {
				hasParam = true
			}
			return true
		})
		if !hasParam && !hasTilde {
			return false
		}
		value, known := simpleStaticWord(word, vars)
		if !known {
			return false
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start >= 0 && end > start && end <= len(source) {
			replacements = append(replacements, replacement{start, end,
				"'" + strings.ReplaceAll(value, "'", "'\\''") + "'"})
		}
		return false
	})
	if len(replacements) == 0 {
		return "", false
	}
	for i := len(replacements) - 1; i >= 0; i-- {
		r := replacements[i]
		source = source[:r.start] + r.text + source[r.end:]
	}
	return source, true
}

// simpleNestedScript returns a static shell -c or eval body. eval shares the
// caller's variables and directory; a -c shell starts a child shell.
func simpleNestedScript(call *syntax.CallExpr, vars map[string]string, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false, false, false
	}
	return simpleNestedScriptArgs(call.Args, vars, 0, cwdUnknown, interpreter)
}

func simpleNestedScriptArgs(args []*syntax.Word, vars map[string]string, depth int, cwdUnknown *bool, interpreter *string) (script string, shared, nested, static bool) {
	if depth >= 8 || len(args) == 0 {
		return "", false, true, false
	}
	program, ok := simpleStaticWord(args[0], vars)
	if !ok {
		return "", false, false, false
	}
	if program == "eval" {
		words := make([]string, 0, len(args)-1)
		for _, arg := range args[1:] {
			value, known := simpleStaticScriptWord(arg, vars)
			if !known {
				// The command substitution itself is exposed by the outer
				// statement walk. Runtime eval text has no static child to
				// compare with a standalone command.
				return "", true, false, false
			}
			words = append(words, value)
		}
		if len(words) == 0 {
			return "", true, false, false
		}
		return strings.Join(words, " "), true, true, true
	}
	if program == "trap" {
		// The handler executes later, after intervening commands may cd.
		if cwdUnknown != nil {
			*cwdUnknown = true
		}
		index := 1
		if index < len(args) && args[index].Lit() == "--" {
			index++
		}
		if index >= len(args) || args[index].Lit() == "-p" {
			return "", true, false, false
		}
		value, known := simpleStaticScriptWord(args[index], vars)
		return value, true, true, known
	}
	if program == "su" && simplePotentialShellScript(args) {
		// The target account can change both startup files and directory.
		return "", false, true, false
	}
	wrapper := filepath.Base(program)
	if simpleNestedWrapper(wrapper) {
		argv := make([]string, len(args))
		for index, arg := range args {
			value, known := simpleStaticScriptWord(arg, vars)
			if !known {
				if simplePotentialShellScript(args) {
					return "", false, true, false
				}
				return "", false, false, false
			}
			argv[index] = value
		}
		childIndex, found, uncertain := simpleWrapperChild(argv, wrapper)
		if uncertain {
			if simplePotentialShellScript(args) {
				return "", false, true, false
			}
			return "", false, false, false
		}
		if !found {
			return "", false, false, false
		}
		if childIndex <= 0 || childIndex >= len(args) {
			return "", false, true, false
		}
		return simpleNestedScriptArgs(args[childIndex:], vars, depth+1, cwdUnknown, interpreter)
	}
	shellProgram := filepath.Base(program)
	switch shellProgram {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash":
	default:
		return "", false, false, false
	}
	if simpleShellNoExec(args, vars, shellProgram) {
		// Syntax-check mode does not execute the -c body. Use the same
		// invocation grammar as Analyze so option order and +n are honored.
		return "", false, false, false
	}
	for index := 1; index < len(args); index++ {
		option := args[index].Lit()
		if option == "--" {
			continue
		}
		if option == "-o" || option == "+o" {
			index++
			if index >= len(args) {
				return "", false, true, false
			}
			name, known := simpleStaticWord(args[index], vars)
			if !known || name == "" {
				return "", false, true, false
			}
			continue
		}
		if !simpleShellSafeOption(option) {
			if simplePotentialShellScript(args) {
				return "", false, true, false
			}
			return "", false, false, false
		}
		if cwdUnknown != nil && strings.ContainsAny(option[1:], "il") {
			// Login and interactive startup files may change directory
			// before the static -c body runs.
			*cwdUnknown = true
		}
		if simpleShellCOption(option) {
			if index+1 == len(args) {
				return "", false, true, false
			}
			value, known := simpleStaticScriptWord(args[index+1], vars)
			if known && interpreter != nil {
				*interpreter = shellProgram
			}
			return value, false, true, known
		}
	}
	return "", false, false, false
}

// simpleWrapperChild returns the index of the command that a static wrapper
// argv runs. found is false when it runs none; uncertain when an option of
// the wrapper is not understood.
func simpleWrapperChild(argv []string, wrapper string) (index int, found, uncertain bool) {
	switch wrapper {
	case "nohup":
		index = 1
		if len(argv) > 1 && argv[1] == "--" {
			index++
		}
	case "timeout":
		index = simpleTimeoutChildIndex(argv)
	case "env":
		index = simpleEnvChildIndex(argv)
	default:
		child, found, uncertain := staticPOSIXWrapperArgv(argv, wrapper)
		if uncertain || !found {
			return 0, found, uncertain
		}
		index = len(argv) - len(child)
	}
	return index, true, false
}

func simpleShellNoExec(args []*syntax.Word, vars map[string]string, program string) bool {
	argv := make([]string, len(args))
	for index, arg := range args {
		value, known := simpleStaticScriptWord(arg, vars)
		if !known {
			return false
		}
		argv[index] = value
	}
	return parsePOSIXShellInvocation(program, argv).noExec
}

func simpleNestedWrapper(program string) bool {
	switch program {
	case "env", "sudo", "exec", "command", "nohup", "timeout", "nsenter", "chroot":
		return true
	default:
		return false
	}
}

// An env assignment changes the child's environment but leaves a following
// static shell -c body executable. Directory changes are accepted here only
// when they preserve the caller's directory; other forms stay whole-action
// only until the simple-command walker can carry their new CWD.
func simpleEnvChildIndex(argv []string) int {
	for index := 1; index < len(argv); index++ {
		arg := argv[index]
		switch {
		case arg == "--":
			if index+1 < len(argv) {
				return index + 1
			}
			return -1
		case arg == "-i" || arg == "--ignore-environment" ||
			arg == "-0" || arg == "--null" || arg == "-v" || arg == "--debug":
			continue
		case arg == "-u" || arg == "--unset":
			index++
			if index >= len(argv) {
				return -1
			}
		case strings.HasPrefix(arg, "--unset="):
			continue
		case arg == "--chdir=." || arg == "-C.":
			continue
		case arg == "--chdir" || arg == "-C":
			index++
			if index >= len(argv) || argv[index] != "." {
				return -1
			}
		case strings.HasPrefix(arg, "-"):
			return -1
		case isStaticEnvironmentAssignment(arg):
			continue
		default:
			return index
		}
	}
	return -1
}

func simplePotentialShellScript(args []*syntax.Word) bool {
	for _, arg := range args {
		option := arg.Lit()
		if option == "-c" || len(option) > 2 && strings.HasPrefix(option, "-") && option[1] != '-' &&
			strings.ContainsRune(option[1:], 'c') {
			return true
		}
	}
	return false
}

func simpleTimeoutChildIndex(argv []string) int {
	index := 1
	for index < len(argv) && strings.HasPrefix(argv[index], "-") {
		if argv[index] == "--" {
			index++
			break
		}
		switch argv[index] {
		case "-s", "--signal", "-k", "--kill-after":
			index += 2
		case "--preserve-status", "--foreground":
			index++
		default:
			return -1
		}
	}
	if index >= len(argv) || !boundedTimeoutDuration(argv[index]) {
		return -1
	}
	return index + 1
}

func simpleShellCOption(option string) bool {
	return strings.Contains(option, "c") && simpleShellSafeOption(option)
}

func simpleShellSafeOption(option string) bool {
	if len(option) < 2 || len(option) > 5 || option[0] != '-' {
		return false
	}
	for _, flag := range option[1:] {
		// A login or interactive shell may run startup code too, but a
		// statically supplied -c body still runs and adds policy findings.
		if !strings.ContainsRune("cefiluvx", flag) {
			return false
		}
	}
	return true
}

// Once the directory is unknown, a relative path cannot be judged with the
// same facts as a standalone command in its actual directory.
func simpleRelativePathOperand(source string) bool {
	file, ok := shellparse.Parse(source)
	if !ok || len(file.Stmts) != 1 {
		return true
	}
	for _, redirect := range file.Stmts[0].Redirs {
		value, known := simpleStaticWord(redirect.Word, nil)
		if !known || !filepath.IsAbs(value) {
			return true
		}
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return false
	}
	for _, arg := range call.Args[1:] {
		value, known := simpleStaticWord(arg, nil)
		if !known {
			return true
		}
		if value == "." || value == ".." || strings.HasPrefix(value, "./") ||
			strings.HasPrefix(value, "../") || strings.Contains(value, "/") &&
			!filepath.IsAbs(value) && !strings.Contains(value, "://") {
			return true
		}
	}
	// Reviewed command grammars also identify bare file operands such as
	// `cat id_rsa`, which have no slash to recognize lexically.
	facts := Analyze(Input{Tool: "shell", Command: source, DialectHint: DialectPOSIX})
	for _, path := range facts.Paths {
		if path.Flavor == PathFlavorPOSIX && !path.Absolute {
			return true
		}
	}
	return false
}

func simpleCommandNextCWD(source string, state *simpleShellState, vars map[string]string) (string, bool) {
	file, parsed := shellparse.Parse(source)
	if !parsed || len(file.Stmts) != 1 {
		return state.cwd, false
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return state.cwd, false
	}
	program, known := simpleStaticProgramWord(call.Args[0], vars)
	if !known {
		return state.cwd, false
	}
	argStart := 1
	if program == "builtin" || program == "command" {
		if program == "command" && argStart < len(call.Args) && call.Args[argStart].Lit() == "-p" {
			argStart++
		}
		if argStart < len(call.Args) && call.Args[argStart].Lit() == "--" {
			argStart++
		}
		if argStart >= len(call.Args) {
			return state.cwd, false
		}
		program, known = simpleStaticWord(call.Args[argStart], vars)
		if !known {
			return "", true
		}
		argStart++
	}
	if program == "popd" {
		if len(call.Args) != argStart || len(state.dirStack) == 0 {
			return "", true
		}
		dir := state.dirStack[len(state.dirStack)-1]
		state.dirStack = state.dirStack[:len(state.dirStack)-1]
		return dir, true
	}
	if program != "cd" && program != "pushd" {
		return state.cwd, false
	}
	arg := argStart
	if program == "cd" {
		for arg < len(call.Args) {
			option := call.Args[arg].Lit()
			if option == "--" {
				arg++
				break
			}
			if len(option) < 2 || option[0] != '-' || option == "-" {
				break
			}
			for _, flag := range option[1:] {
				if !strings.ContainsRune("eLP", flag) {
					return "", true
				}
			}
			arg++
		}
	} else if arg < len(call.Args) && call.Args[arg].Lit() == "--" {
		arg++
	}
	if arg == len(call.Args) {
		if program == "pushd" {
			if len(state.dirStack) == 0 {
				return "", true
			}
			dir := state.dirStack[len(state.dirStack)-1]
			state.dirStack[len(state.dirStack)-1] = state.cwd
			return dir, true
		}
		return vars["HOME"], true
	}
	if arg+1 != len(call.Args) {
		return "", true
	}
	dir, known := simpleStaticWord(call.Args[arg], vars)
	if !known || dir == "" {
		return "", true
	}
	if dir == "-" {
		return vars["OLDPWD"], true
	}
	if program == "pushd" {
		state.dirStack = append(state.dirStack, state.cwd)
	}
	if filepath.IsAbs(dir) {
		return filepath.Clean(dir), true
	}
	if program == "cd" && vars["CDPATH"] != "" &&
		!strings.HasPrefix(dir, "./") && !strings.HasPrefix(dir, "../") {
		return "", true
	}
	if state.cwd == "" {
		return "", true
	}
	return filepath.Clean(filepath.Join(state.cwd, dir)), true
}
