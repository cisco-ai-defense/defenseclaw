// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"maps"
	"slices"
	"strings"
	"unicode"
)

type windowsSimpleGroupEvent struct {
	offset int
	open   bool
	// possible marks a body that runs only when a condition this walk does
	// not decide holds (GAP-0935): if, elseif, while, for or foreach with a
	// header that is not a literal, and an else after such a branch.
	possible bool
}

func windowsSimplePotentialGroup(source string, dialect windowsDialect) bool {
	trimmed := strings.TrimSpace(source)
	if trimmed == "" {
		return false
	}
	if dialect == windowsCMD {
		return trimmed[0] == '(' || strings.HasPrefix(strings.ToLower(trimmed), "if ")
	}
	// A statement that is only a bare { } is a scriptblock value; it runs
	// nothing, so it needs no second pass.
	if len(trimmed) > 1 && (trimmed[0] == '&' || trimmed[0] == '.') &&
		strings.HasPrefix(strings.TrimLeft(trimmed[1:], " \t"), "{") {
		return true
	}
	for _, keyword := range []string{"if", "elseif", "else", "while", "foreach", "for", "switch"} {
		if windowsSimpleKeyword([]rune(trimmed), 0, keyword) {
			return true
		}
	}
	return false
}

// Replace only recognized control syntax with spaces, preserving rune offsets
// for windowsLex. Unrecognized or unbalanced groups cannot yield partial
// children: the caller refuses the entire compound action.
func windowsSimpleGroupSource(source string, dialect windowsDialect) (string, []windowsSimpleGroupEvent, bool) {
	runes := []rune(source)
	clean := []rune(source)
	var stack []rune
	var possibleStack []bool
	// chainPossible is set when the group just closed was a possible branch:
	// an else or elseif after it depends on the same condition.
	chainPossible := false
	var events []windowsSimpleGroupEvent
	atStart := true
	var quote rune
	blank := func(start, end int) {
		for i := start; i < end; i++ {
			if clean[i] != '\r' && clean[i] != '\n' {
				clean[i] = ' '
			}
		}
	}
	for i := 0; i < len(runes); i++ {
		char := runes[i]
		if quote != 0 {
			if char == quote {
				if dialect == windowsPowerShell && i+1 < len(runes) && runes[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			} else if dialect == windowsPowerShell && quote == '"' && char == '`' && i+1 < len(runes) {
				i++
			}
			continue
		}
		if dialect == windowsPowerShell && char == '`' || dialect == windowsCMD && char == '^' {
			if i+1 >= len(runes) {
				return "", nil, false
			}
			i++
			atStart = false
			continue
		}
		if char == '"' || dialect == windowsPowerShell && char == '\'' {
			quote = char
			atStart = false
			continue
		}
		if unicode.IsSpace(char) {
			if char == '\r' || char == '\n' {
				atStart = true
			}
			continue
		}
		if atStart && dialect == windowsPowerShell && char == '{' {
			// A bare { } that is a whole statement is a scriptblock value:
			// PowerShell writes it out and runs nothing in it, and so do the
			// inert consumers of a pipeline (| Out-Null). Keep it as an inert
			// string of the same length. A block followed by member access,
			// an argument or another consumer may be invoked; it stays a group.
			end := windowsSimpleScriptBlockEnd(runes, i)
			if end < 0 {
				return "", nil, false
			}
			if windowsSimpleStatementEnds(runes, end+1) || windowsSimpleInertPipeline(runes, end+1) {
				for j := i + 1; j < end; j++ {
					clean[j] = ' '
				}
				clean[i], clean[end] = '\'', '\''
				i = end
				atStart = false
				continue
			}
		}
		if atStart {
			if opener, end, recognized, valid, possible := windowsSimpleGroupOpening(runes, i, dialect); recognized {
				if !valid || len(stack) >= 32 {
					return "", nil, false
				}
				if chainPossible && (windowsSimpleKeyword(runes, i, "else") || windowsSimpleKeyword(runes, i, "elseif")) {
					possible = true
				}
				chainPossible = false
				blank(i, end)
				stack = append(stack, opener)
				possibleStack = append(possibleStack, possible)
				events = append(events, windowsSimpleGroupEvent{offset: i, open: true, possible: possible})
				i = end - 1
				continue
			}
			chainPossible = false
		}
		if dialect == windowsCMD && (char == '{' || char == '}') {
			// cmd treats braces as argument text (for example bcdedit
			// selectors), not as command groups.
			atStart = false
			continue
		}
		if char == ')' || char == '}' {
			if len(stack) == 0 || stack[len(stack)-1] != char {
				return "", nil, false
			}
			stack = stack[:len(stack)-1]
			chainPossible = possibleStack[len(possibleStack)-1]
			possibleStack = possibleStack[:len(possibleStack)-1]
			blank(i, i+1)
			// Adjacent branches have no shell list operator in their source.
			// Preserve their command boundary in the policy view.
			if windowsSimpleNeedsBoundary(runes, i+1) {
				if dialect == windowsPowerShell {
					clean[i] = ';'
				} else {
					clean[i] = '&'
				}
			}
			events = append(events, windowsSimpleGroupEvent{offset: i, possible: chainPossible})
			atStart = true
			continue
		}
		if char == '(' || char == '{' {
			return "", nil, false
		}
		if char == ';' || char == '|' || char == '&' {
			atStart = true
			continue
		}
		atStart = false
	}
	if quote != 0 || len(stack) != 0 {
		return "", nil, false
	}
	return string(clean), events, true
}

// windowsSimpleScriptBlockEnd returns the index of the } that closes the
// PowerShell scriptblock opened at open, or -1.
func windowsSimpleScriptBlockEnd(runes []rune, open int) int {
	depth := 0
	var quote rune
	for i := open; i < len(runes); i++ {
		char := runes[i]
		switch {
		case quote != 0:
			if char == quote {
				if i+1 < len(runes) && runes[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			} else if quote == '"' && char == '`' {
				i++
			}
		case char == '`':
			i++
		case char == '\'' || char == '"':
			quote = char
		case char == '{':
			depth++
		case char == '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

// windowsSimpleStatementEnds reports whether the PowerShell statement ends at
// from: end of input, a statement separator, a pipeline chain operator, the
// } of an enclosing block, or a comment.
func windowsSimpleStatementEnds(runes []rune, from int) bool {
	for from < len(runes) && (runes[from] == ' ' || runes[from] == '\t') {
		from++
	}
	if from >= len(runes) || strings.ContainsRune(";\r\n}#", runes[from]) {
		return true
	}
	return from+1 < len(runes) && (runes[from] == '&' && runes[from+1] == '&' ||
		runes[from] == '|' && runes[from+1] == '|')
}

// windowsSimpleInertConsumers take a pipeline value without invoking it:
// they discard, write, format, measure or convert it. A sink (false) binds
// its arguments as data, such as a path, an encoding or a width, so a
// variable, subexpression, splat or parenthesized value in them cannot run
// the input. A property consumer (true) also evaluates a property expression
// that such a value may carry, as a calculated property @{e={...}} in $p does
// with the input as $_; there only quoted text and bare words are data.
var windowsSimpleInertConsumers = map[string]bool{
	"out-null": false, "out-string": false, "out-host": false, "out-default": false,
	"out-file": false, "write-output": false, "echo": false, "write": false,
	"write-host": false, "get-member": false, "gm": false, "convertto-json": false,
	"convertto-xml": false, "convertto-csv": false,
	"measure-object": true, "measure": true, "format-list": true, "fl": true,
	"format-table": true, "ft": true, "format-wide": true, "fw": true,
	"convertto-html": true,
}

// windowsSimpleInertPipeline reports whether the PowerShell value that ends
// at from flows only into inert consumers until its statement ends. A quoted
// string is data, also with a variable or subexpression in it. A scriptblock
// argument, which PowerShell may bind to the input and run, makes a stage
// not inert, and so does a computed value for a property consumer.
func windowsSimpleInertPipeline(runes []rune, from int) bool {
	stages := 0
	for {
		for from < len(runes) && (runes[from] == ' ' || runes[from] == '\t') {
			from++
		}
		if from >= len(runes) || runes[from] != '|' || from+1 < len(runes) && runes[from+1] == '|' {
			return stages != 0 && windowsSimpleStatementEnds(runes, from)
		}
		start := from + 1
		var quote rune
		depth, computed := 0, false
		for from = start; from < len(runes); from++ {
			char := runes[from]
			if quote == 0 && depth == 0 && strings.ContainsRune("|;\r\n}#&", char) {
				break
			}
			if quote == '\'' {
				if char == quote {
					quote = 0
				}
				continue
			}
			if quote == '"' {
				switch char {
				case '`':
					from++
				case quote:
					quote = 0
				}
				continue
			}
			switch char {
			case '`':
				from++
			case '\'', '"':
				quote = char
			case '{', '}', '<':
				return false
			case '(':
				depth++
				computed = true
			case ')':
				if depth == 0 {
					return false
				}
				depth--
			case '$', '[', ']':
				computed = true
			case '@':
				if from == start || !windowsSimpleWordRune(runes[from-1]) {
					computed = true // a splat or an array, not @ inside report@2026.txt
				}
			}
		}
		if quote != 0 || depth != 0 {
			return false
		}
		fields := strings.Fields(string(runes[start:from]))
		if len(fields) == 0 {
			return false
		}
		evaluates, known := windowsSimpleInertConsumers[strings.ToLower(fields[0])]
		if !known || evaluates && computed {
			return false
		}
		stages++
	}
}

// windowsSimpleWordRune reports a letter, digit or one of ._- that
// continues a bare PowerShell word.
func windowsSimpleWordRune(char rune) bool {
	return unicode.IsLetter(char) || unicode.IsDigit(char) || strings.ContainsRune("._-", char)
}

func windowsSimpleNeedsBoundary(runes []rune, from int) bool {
	for from < len(runes) && (runes[from] == ' ' || runes[from] == '\t') {
		from++
	}
	return from < len(runes) && !strings.ContainsRune(";&|\r\n)}", runes[from])
}

// windowsSimpleGroupOpening recognizes a group opening at start. possible is
// set for a control body whose header is not a literal: the body may run,
// and its matches are strict-tier findings (SimpleCommand.Possible).
func windowsSimpleGroupOpening(runes []rune, start int, dialect windowsDialect) (opener rune, end int, recognized, valid, possible bool) {
	if dialect == windowsCMD {
		if runes[start] == '(' {
			return ')', start + 1, true, true, false
		}
		if !windowsSimpleKeyword(runes, start, "if") {
			return 0, 0, false, false, false
		}
		end := start + 2
		for end < len(runes) && runes[end] != '(' && runes[end] != '\r' && runes[end] != '\n' {
			end++
		}
		if end >= len(runes) || runes[end] != '(' ||
			!windowsSimpleCMDIfHeader(string(runes[start:end])) {
			return 0, 0, true, false, false
		}
		return ')', end + 1, true, true, false
	}
	if runes[start] == '{' {
		return '}', start + 1, true, true, false
	}
	if runes[start] == '&' || runes[start] == '.' {
		end := start + 1
		for end < len(runes) && (runes[end] == ' ' || runes[end] == '\t') {
			end++
		}
		if end < len(runes) && runes[end] == '{' {
			return '}', end + 1, true, true, false
		}
	}
	for _, keyword := range []string{"if", "elseif", "while", "foreach", "for", "switch"} {
		if !windowsSimpleKeyword(runes, start, keyword) {
			continue
		}
		index := start + len(keyword)
		for index < len(runes) && (runes[index] == ' ' || runes[index] == '\t') {
			index++
		}
		if index >= len(runes) || runes[index] != '(' {
			return 0, 0, true, false, false
		}
		close := windowsSimpleCloseParen(runes, index)
		if close < 0 {
			return 0, 0, true, false, false
		}
		header := string(runes[index+1 : close])
		if !windowsSimpleInertHeader(keyword, header) {
			// A condition that is not a literal decides at run time whether
			// the body runs (GAP-0935). switch bodies hold case labels and
			// stay unflattened.
			if keyword == "switch" || !windowsSimplePossibleHeader(header) {
				return 0, 0, true, false, false
			}
			possible = true
		}
		end := close + 1
		for end < len(runes) && (runes[end] == ' ' || runes[end] == '\t') {
			end++
		}
		if end >= len(runes) || runes[end] != '{' {
			return 0, 0, true, false, false
		}
		return '}', end + 1, true, true, possible
	}
	if windowsSimpleKeyword(runes, start, "else") {
		end := start + 4
		for end < len(runes) && (runes[end] == ' ' || runes[end] == '\t') {
			end++
		}
		if end >= len(runes) || runes[end] != '{' {
			return 0, 0, true, false, false
		}
		return '}', end + 1, true, true, false
	}
	return 0, 0, false, false, false
}

// windowsSimplePossibleHeader accepts a balanced one-line condition with no
// scriptblock or statement separator: Test-Path x, $env:CI, $a -gt 0. The
// header itself is judged with the whole action.
func windowsSimplePossibleHeader(header string) bool {
	header = strings.TrimSpace(header)
	return header != "" && !strings.ContainsAny(header, ";{}\r\n`")
}

func windowsSimpleKeyword(runes []rune, start int, keyword string) bool {
	if start+len(keyword) >= len(runes) ||
		!strings.EqualFold(string(runes[start:start+len(keyword)]), keyword) {
		return false
	}
	next := runes[start+len(keyword)]
	return unicode.IsSpace(next) || next == '('
}

func windowsSimpleCMDIfHeader(header string) bool {
	if strings.ContainsAny(header, "%!^&|<>(){};`$") {
		return false
	}
	fields := strings.Fields(strings.ToLower(header))
	if len(fields) == 3 {
		return fields[0] == "if" && fields[1] == "exist" && fields[2] != ""
	}
	return len(fields) == 4 && fields[0] == "if" && fields[1] == "not" &&
		fields[2] == "exist" && fields[3] != ""
}

func windowsSimpleCloseParen(runes []rune, open int) int {
	depth := 1
	var quote rune
	for i := open + 1; i < len(runes); i++ {
		switch char := runes[i]; {
		case quote != 0:
			if char == quote {
				quote = 0
			} else if char == '`' && quote == '"' && i+1 < len(runes) {
				i++
			}
		case char == '\'' || char == '"':
			quote = char
		case char == '(':
			depth++
		case char == ')':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}

func windowsSimpleInertHeader(keyword, header string) bool {
	header = strings.TrimSpace(header)
	if strings.ContainsAny(header, ";|&{}()\r\n`") {
		return false
	}
	if keyword != "foreach" {
		return strings.EqualFold(header, "$true") || strings.EqualFold(header, "$false")
	}
	fields := strings.Fields(header)
	if len(fields) != 3 || !windowsSimpleVariableName(strings.ToLower(fields[0])) ||
		!strings.EqualFold(fields[1], "in") {
		return false
	}
	for _, item := range strings.Split(fields[2], ",") {
		if len(item) < 2 || item[0] != '\'' && item[0] != '"' ||
			item[len(item)-1] != item[0] || strings.ContainsAny(item[1:len(item)-1], "$;|&{}()\r\n`") {
			return false
		}
	}
	return true
}

func windowsSimpleContinuedLexemes(lexemes []windowsLexeme) []windowsLexeme {
	out := lexemes[:0]
	for _, lexeme := range lexemes {
		if lexeme.kind == windowsSeparatorLexeme && lexeme.operator == "newline" && len(out) != 0 {
			previous := out[len(out)-1]
			if previous.kind == windowsPipeLexeme || previous.kind == windowsSeparatorLexeme &&
				(previous.operator == ";" || previous.operator == "&&" || previous.operator == "||" || previous.operator == "&") {
				continue
			}
		}
		out = append(out, lexeme)
	}
	return out
}

type simpleWindowsState struct {
	cwd                string
	cwdUnknown         bool
	dirStack           []string
	uncertainVariables map[string]bool
}

type simpleWindowsGroupSnapshot struct {
	cwd        string
	cwdUnknown bool
	dirStack   []string
	variables  map[string]string
}

func (state *simpleWindowsState) groupSnapshot(variables map[string]string) simpleWindowsGroupSnapshot {
	return simpleWindowsGroupSnapshot{cwd: state.cwd, cwdUnknown: state.cwdUnknown,
		dirStack: slices.Clone(state.dirStack), variables: maps.Clone(variables)}
}

// A branch, loop, or script block may not leave its directory or variables
// changed. Retain child evidence but do not treat those side effects as facts
// for commands that follow the group.
func (state *simpleWindowsState) mergeGroup(before simpleWindowsGroupSnapshot, variables map[string]string) {
	if state.cwd != before.cwd || state.cwdUnknown != before.cwdUnknown ||
		!slices.Equal(state.dirStack, before.dirStack) {
		state.cwd, state.cwdUnknown, state.dirStack = "", true, nil
	}
	for name, value := range variables {
		if previous, present := before.variables[name]; !present || previous != value {
			delete(variables, name)
			if state.uncertainVariables == nil {
				state.uncertainVariables = make(map[string]bool)
			}
			state.uncertainVariables[name] = true
		}
	}
	for name := range before.variables {
		if _, present := variables[name]; !present {
			if state.uncertainVariables == nil {
				state.uncertainVariables = make(map[string]bool)
			}
			state.uncertainVariables[name] = true
		}
	}
}

func (state *simpleWindowsState) forgetKnownVariables(variables map[string]string) {
	for name := range state.uncertainVariables {
		if _, known := variables[name]; known {
			delete(state.uncertainVariables, name)
		}
	}
}

func (state *simpleWindowsState) referencesUncertainVariable(part string) bool {
	runes := []rune(part)
	var quote rune
	for index := 0; index < len(runes); index++ {
		char := runes[index]
		if char == '`' && quote != '\'' && index+1 < len(runes) {
			index++
			continue
		}
		if char == '\'' || char == '"' {
			switch quote {
			case 0:
				quote = char
			case char:
				if quote == '\'' && index+1 < len(runes) && runes[index+1] == '\'' {
					index++
				} else {
					quote = 0
				}
			}
			continue
		}
		if char != '$' || quote == '\'' || index+1 >= len(runes) ||
			!windowsSimpleVariableLetter(runes[index+1]) {
			continue
		}
		end := index + 2
		for end < len(runes) && (windowsSimpleVariableLetter(runes[end]) ||
			runes[end] >= '0' && runes[end] <= '9') {
			end++
		}
		if state.uncertainVariables[strings.ToLower(string(runes[index:end]))] {
			return true
		}
		index = end - 1
	}
	return false
}

func (state *simpleWindowsState) next(part string, dialect windowsDialect, input Input, variables map[string]string) {
	out := newParseOutput(input.DialectHint, 1)
	lexemes, ok := windowsLex(part, dialect, &out)
	if !ok || len(lexemes) == 0 {
		return
	}
	words := make([]windowsWord, 0, len(lexemes))
	for _, lexeme := range lexemes {
		if lexeme.kind == windowsWordLexeme {
			words = append(words, lexeme.word)
		}
	}
	if len(words) == 0 {
		return
	}
	program := strings.ToLower(words[0].value)
	change := false
	push := false
	pop := false
	cmdNoDriveSwitch := false
	arg := 1
	if dialect == windowsPowerShell {
		switch program {
		case "set-location", "sl", "cd", "chdir":
			change = true
		case "push-location", "pushd":
			change, push = true, true
		case "pop-location", "popd":
			change, pop = true, true
		case "invoke-expression", "iex":
			change = true
		}
		if change && !pop && arg < len(words) &&
			(strings.EqualFold(words[arg].value, "-Path") || strings.EqualFold(words[arg].value, "-LiteralPath")) {
			arg++
		}
	} else {
		switch program {
		case "cd", "chdir":
			change = true
			cmdNoDriveSwitch = true
			if arg < len(words) && strings.EqualFold(words[arg].value, "/d") {
				arg++
				cmdNoDriveSwitch = false
			}
		case "pushd":
			change, push = true, true
		case "popd":
			change, pop = true, true
		case "call":
			change = true
		}
	}
	if !change {
		return
	}
	if pop {
		if len(words) != 1 || len(state.dirStack) == 0 {
			state.cwd, state.cwdUnknown = "", true
			return
		}
		state.cwd = state.dirStack[len(state.dirStack)-1]
		state.dirStack = state.dirStack[:len(state.dirStack)-1]
		state.cwdUnknown = state.cwd == ""
		return
	}
	if arg == len(words) && dialect == windowsPowerShell && !push {
		_, _, state.cwd = deriveWindowsPathWithPolicy(input.ActiveHome, input.CWD,
			input.ActiveHome, pathExpansionPolicy{expandTilde: true})
		state.cwdUnknown = state.cwd == ""
		return
	}
	if arg+1 != len(words) {
		state.cwd, state.cwdUnknown = "", true
		return
	}
	if dialect == windowsPowerShell && strings.HasPrefix(words[arg].value, "-") ||
		dialect == windowsCMD && strings.HasPrefix(words[arg].value, "/") &&
			!strings.HasPrefix(words[arg].value, "//") {
		state.cwd, state.cwdUnknown = "", true
		return
	}
	next, known := windowsSimpleLocationPath(words[arg], dialect, input, variables)
	if !known {
		state.cwd, state.cwdUnknown = "", true
		return
	}
	if cmdNoDriveSwitch && !strings.EqualFold(parseWindowsPath(input.CWD).volume, parseWindowsPath(next).volume) {
		state.cwd, state.cwdUnknown = "", true
		return
	}
	if push {
		state.dirStack = append(state.dirStack, state.cwd)
	}
	state.cwd, state.cwdUnknown = next, false
}

func windowsSimpleLocationPath(word windowsWord, dialect windowsDialect, input Input, variables map[string]string) (string, bool) {
	value := word.value
	if word.wildcard || strings.ContainsAny(value, "`*?[]\r\n") {
		return "", false
	}
	recognizedHome := false
	if value == "~" || strings.HasPrefix(value, `~\`) || strings.HasPrefix(value, "~/") {
		recognizedHome = true
	} else {
		home := input.ActiveHome
		prefixes := []string{"%USERPROFILE%", "%HOMEDRIVE%%HOMEPATH%"}
		if dialect == windowsPowerShell {
			prefixes = []string{"$HOME", "$env:USERPROFILE"}
		}
		for _, prefix := range prefixes {
			if len(value) < len(prefix) || !strings.EqualFold(value[:len(prefix)], prefix) {
				continue
			}
			suffix := value[len(prefix):]
			if suffix != "" && suffix[0] != '/' && suffix[0] != '\\' {
				continue
			}
			if prefix == "$HOME" {
				if assigned, ok := variables["$home"]; ok {
					home = assigned
				}
			}
			value = home + suffix
			recognizedHome = true
			break
		}
	}
	if word.expands && !recognizedHome || strings.ContainsAny(value, "$%") {
		return "", false
	}
	_, _, next := deriveWindowsPathWithPolicy(value, input.CWD, input.ActiveHome,
		pathExpansionPolicy{expandTilde: true})
	return next, next != ""
}

func windowsSimpleRelativePathOperand(part string, dialect Dialect) bool {
	facts := Analyze(Input{Tool: "shell", Command: part, DialectHint: dialect})
	for _, path := range facts.Paths {
		if path.Flavor == PathFlavorWindows && !path.Absolute {
			return true
		}
	}
	return strings.Contains(part, `.\`) || strings.Contains(part, `..\`)
}
