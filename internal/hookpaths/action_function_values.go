// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

const (
	actionFunctionValuePrefix  = "\x00function:"
	actionFunctionUnknownValue = "?"
	actionFunctionKnownPrefix  = "\x02"
	actionFunctionMaxSteps     = 16
	actionFunctionMaxDepth     = 8
)

// A function declaration retains only literal assignments and calls. The
// calls are resolved when the function runs, after later declarations have
// taken effect. Other bodies cannot establish a later pathname value.
func actionFunctionValue(function *syntax.FuncDecl, home string) string {
	if function == nil || function.Body == nil || function.Body.Background || function.Body.Negated ||
		function.Body.Coprocess || len(function.Body.Redirs) != 0 {
		return actionFunctionUnknownValue
	}
	block, ok := function.Body.Cmd.(*syntax.Block)
	if !ok || len(block.Stmts) == 0 || len(block.Stmts) > actionFunctionMaxSteps {
		return actionFunctionUnknownValue
	}
	var steps []string
	for _, stmt := range block.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || stmt.Coprocess || len(stmt.Redirs) != 0 {
			return actionFunctionUnknownValue
		}
		if len(call.Args) == 0 && len(call.Assigns) > 0 {
			for _, assign := range call.Assigns {
				if assign.Name == nil || assign.Value == nil || assign.Append || assign.Array != nil ||
					assign.Index != nil || assign.Name.Value == "HOME" || assign.Name.Value == "PWD" ||
					actionWordTildePrefix(assign.Value) {
					return actionFunctionUnknownValue
				}
				value, fixed := StaticWord(assign.Value, home)
				if !fixed || !actionFunctionField(value) || !actionFunctionField(assign.Name.Value) {
					return actionFunctionUnknownValue
				}
				steps = append(steps, "A\x00"+assign.Name.Value+"\x00"+value)
			}
		} else if len(call.Assigns) == 0 && len(call.Args) > 0 && len(call.Args) <= actionFunctionMaxSteps {
			words := make([]string, len(call.Args))
			for i, arg := range call.Args {
				if actionWordTildePrefix(arg) {
					return actionFunctionUnknownValue
				}
				words[i], ok = StaticWord(arg, home)
				if !ok || !actionFunctionField(words[i]) {
					return actionFunctionUnknownValue
				}
				if _, plain := actionWordValue(arg, nil, "", home); !plain {
					return actionFunctionUnknownValue
				}
			}
			steps = append(steps, "C\x00"+strings.Join(words, "\x00"))
		} else {
			return actionFunctionUnknownValue
		}
		if len(steps) > actionFunctionMaxSteps {
			return actionFunctionUnknownValue
		}
	}
	encoded := actionFunctionKnownPrefix + strings.Join(steps, "\x01")
	if len(encoded) > MaxWriteTargetPathBytes {
		return actionFunctionUnknownValue
	}
	return encoded
}

func actionFunctionField(value string) bool {
	return len(value) <= MaxWriteTargetPathBytes && !strings.ContainsAny(value, "\x00\x01\x02")
}

// actionKeepAcrossFunctionCall returns the value states after a call of a
// function the command defines. The tracker forgets every value at a call of
// a function whose effect it does not know, as the function may assign any
// name; a reader of known protected values must also consider that it did
// not. A function the tracker knows, and one whose body only assigns names
// (actionFunctionBodyEffect), leave exactly the states they establish, so a
// value the call overwrites is not kept and a value it assigns from a known
// parameter is not lost. A call with assignments of its own leaves the states
// its body establishes as well: the assignments hold for the body only.
func actionKeepAcrossFunctionCall(stmt *syntax.Stmt, before, after []actionValues, lookup func(string) *syntax.FuncDecl, cwd, home string, steps *int) []actionValues {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return after
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return after
	}
	defined := false
	for _, state := range before {
		if _, defined = state[actionFunctionValuePrefix+program]; defined {
			break
		}
	}
	if !defined {
		return after
	}
	// A call in the background runs in a subshell: it does not leave the
	// states its body establishes in this shell.
	foreground := !stmt.Background && !stmt.Coprocess
	var next []actionValues
	for _, state := range before {
		through := actionUpdateValuesKept(stmt, []actionValues{state}, cwd, home, steps)
		if _, defined := state[actionFunctionValuePrefix+program]; defined {
			if !foreground {
				through = actionAppendValueCandidates(through, []actionValues{state})
			} else if applied := maps.Clone(state); !actionFunctionApplies(program, applied) {
				// The tracker forgot every value at this call.
				if effect, known := actionFunctionBodyEffect(lookup(program), call, state, lookup, 0, cwd, home, steps); known {
					through = effect
				} else {
					through = actionAppendValueCandidates(through, []actionValues{state})
				}
			}
		}
		next = actionAppendValueCandidates(next, through)
	}
	return next
}

// actionFunctionApplies reports that the tracker knows every effect of a call
// of the function, and applies them to values.
func actionFunctionApplies(name string, values actionValues) bool {
	_, known := actionApplyFunctionValue(name, values, 0)
	return known
}

// actionFunctionBodyEffect returns the states a call of a function leaves
// when its body does nothing but assign names or call such a function, from
// the state before the call, with the known words of the call as its
// parameters. It reads no
// body that uses another parameter, a name that is readonly, or an
// assignment whose value is not known afterwards; the caller then keeps the
// states before the call as well.
func actionFunctionBodyEffect(function *syntax.FuncDecl, call *syntax.CallExpr, state actionValues, lookup func(string) *syntax.FuncDecl, depth int, cwd, home string, steps *int) ([]actionValues, bool) {
	if depth >= actionFunctionMaxDepth || function == nil || function.Body == nil || function.Body.Background || function.Body.Negated ||
		function.Body.Coprocess || len(function.Body.Redirs) != 0 {
		return nil, false
	}
	block, ok := function.Body.Cmd.(*syntax.Block)
	if !ok || len(block.Stmts) == 0 || len(block.Stmts) > actionFunctionMaxSteps {
		return nil, false
	}
	params := actionCallParameters(call, state, cwd, home)
	var assigned []string
	for _, stmt := range block.Stmts {
		body, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || stmt.Background || stmt.Negated || stmt.Coprocess || len(stmt.Redirs) != 0 {
			return nil, false
		}
		if len(body.Args) != 0 {
			name, fixed := StaticWord(body.Args[0], home)
			if !fixed || len(body.Assigns) != 0 {
				return nil, false
			}
			if _, defined := state[actionFunctionValuePrefix+name]; defined {
				// A function the command defines: its effect is read when
				// the body runs.
				if lookup(name) == nil {
					return nil, false
				}
				continue
			}
			// Otherwise only a call that changes no state: the colon.
			if len(body.Args) != 1 || name != ":" {
				return nil, false
			}
			continue
		}
		for _, assign := range body.Assigns {
			if assign.Name == nil || assign.Value == nil || assign.Array != nil || assign.Index != nil ||
				assign.Name.Value == "HOME" || assign.Name.Value == "PWD" || !actionWordUsesGivenParameters(assign.Value, len(params)) {
				return nil, false
			}
			if _, readonly := state[actionReadonlyValuePrefix+assign.Name.Value]; readonly {
				return nil, false
			}
			assigned = append(assigned, assign.Name.Value)
		}
	}
	bound := maps.Clone(state)
	// The assignments before the call hold for the body.
	prefix := map[string]bool{}
	for _, assign := range call.Assigns {
		if assign.Name == nil || assign.Array != nil || assign.Index != nil || assign.Append ||
			assign.Name.Value == "HOME" || assign.Name.Value == "PWD" || assign.Name.Value == "IFS" {
			return nil, false
		}
		if _, readonly := state[actionReadonlyValuePrefix+assign.Name.Value]; readonly {
			return nil, false
		}
		prefix[assign.Name.Value] = true
		value, known := "", true
		if assign.Value != nil {
			value, known = actionWordValue(assign.Value, state, cwd, home)
		}
		if known {
			bound[assign.Name.Value] = value
		} else {
			delete(bound, assign.Name.Value)
		}
	}
	for i, param := range params {
		if key := strconv.Itoa(i + 1); param != nil {
			bound[key] = *param
		} else {
			delete(bound, key)
		}
	}
	states := []actionValues{bound}
	for _, stmt := range block.Stmts {
		inner := stmt.Cmd.(*syntax.CallExpr)
		name := ""
		if len(inner.Args) != 0 {
			name, _ = StaticWord(inner.Args[0], home)
		}
		if _, defined := bound[actionFunctionValuePrefix+name]; !defined || name == "" {
			states = actionUpdateValuesKept(stmt, states, cwd, home, steps)
		} else {
			var next []actionValues
			for _, current := range states {
				effect, known := actionFunctionBodyEffect(lookup(name), inner, current, lookup, depth+1, cwd, home, steps)
				if !known {
					return nil, false
				}
				next = actionAppendValueCandidates(next, effect)
			}
			states = next
		}
		if actionKeptSaturated(states) {
			return nil, false
		}
	}
	var result []actionValues
	for _, after := range states {
		for _, name := range assigned {
			if _, known := after[name]; !known {
				return nil, false
			}
		}
		// The parameters belong to the call, not to the caller.
		for i := range params {
			key := strconv.Itoa(i + 1)
			if value, had := state[key]; had {
				after[key] = value
			} else {
				delete(after, key)
			}
		}
		// A name set before the call returns to its value, unless the body
		// assigned it: a shell may keep that assignment, so both are kept.
		restore := func(skip func(string) bool) actionValues {
			restored := maps.Clone(after)
			for name := range prefix {
				if skip(name) {
					continue
				}
				if value, had := state[name]; had {
					restored[name] = value
				} else {
					delete(restored, name)
				}
			}
			return restored
		}
		result = actionAppendValueCandidates(result, []actionValues{restore(func(string) bool { return false })})
		if slices.ContainsFunc(assigned, func(name string) bool { return prefix[name] }) {
			result = actionAppendValueCandidates(result, []actionValues{restore(func(name string) bool { return slices.Contains(assigned, name) })})
		}
	}
	return result, true
}

// actionCallParameters returns the positional parameters a call gives, in
// order: nil for a field of a value not known. A word that is one quoted
// field is one field whatever its value; any other word with a known value is
// the fields actionWordFields reads, none for an empty value. The list stops
// at a word whose fields are not known (an unquoted pattern character, a brace pair
// that expands, a list such as "$@", an unknown value, a separator set the command changed): the
// parameters after it have no known position.
func actionCallParameters(call *syntax.CallExpr, state actionValues, cwd, home string) []*string {
	var params []*string
	_, ifs := state["IFS"]
	for _, arg := range call.Args[1:] {
		if actionWordBraceExpands(arg) {
			break
		}
		arg = actionUnescapedLiterals(arg)
		value, known := actionWordValue(arg, state, cwd, home)
		if actionWordQuotedField(arg) {
			if known {
				params = append(params, &value)
			} else {
				params = append(params, nil)
			}
			continue
		}
		if !known || ifs {
			break
		}
		fields, split := actionWordFields(arg, state, cwd, home)
		if !split {
			break
		}
		for i := range fields {
			params = append(params, &fields[i])
		}
	}
	return params
}

// actionWordFields returns the fields a word expands to under the default
// separators, part by part: literal and quoted text stays in the field it
// touches, and only the value of an unquoted expansion is split at blanks. A
// word that is only quoted text next to an empty expansion is one field, and
// an unquoted expansion that is empty adds none. It reports false when a part
// has no known value or expands to a list.
func actionWordFields(word *syntax.Word, state actionValues, cwd, home string) ([]string, bool) {
	var fields []string
	field, open := "", false
	for i, part := range word.Parts {
		value, known := actionWordValue(&syntax.Word{Parts: []syntax.WordPart{part}}, state, cwd, home)
		if !known {
			return nil, false
		}
		switch part := part.(type) {
		case *syntax.Lit:
			// Literal text with a pattern character expands to names the
			// reader does not know; a brace pair that expands was refused
			// above, and one that does not stays literal.
			if i > 0 && strings.HasPrefix(part.Value, "~") || strings.ContainsAny(part.Value, "*?[") {
				return nil, false
			}
			field, open = field+value, true
		case *syntax.SglQuoted:
			field, open = field+value, true
		case *syntax.DblQuoted:
			if actionDoubleQuotedList(part) {
				return nil, false
			}
			field, open = field+value, true
		default:
			if strings.ContainsAny(value, "*?[") {
				// An unquoted value with a pattern character is matched
				// against names.
				return nil, false
			}
			for _, r := range value {
				switch {
				case !strings.ContainsRune(" \t\n", r):
					field, open = field+string(r), true
				case open:
					fields, field, open = append(fields, field), "", false
				}
			}
		}
	}
	if open {
		fields = append(fields, field)
	}
	return fields, true
}

// actionWordBraceExpands reports a word the shell brace-expands: an unquoted
// and closed pair of braces with an unquoted comma or ".." at its top level. Quoted text,
// an escaped brace and the value of an expansion are never brace-expanded, and
// a pair without a comma or a sequence, such as {name}, is literal text.
func actionWordBraceExpands(word *syntax.Word) bool {
	var text []byte
	for _, part := range word.Parts {
		lit, ok := part.(*syntax.Lit)
		if !ok {
			// Anything but literal text counts as one ordinary character.
			text = append(text, "x"...)
			continue
		}
		for i := 0; i < len(lit.Value); i++ {
			if lit.Value[i] == 0x5c && i+1 < len(lit.Value) {
				text = append(text, "xx"...)
				i++
				continue
			}
			text = append(text, lit.Value[i])
		}
	}
	for start := range text {
		if text[start] != 0x7b {
			continue
		}
		depth, splits := 0, false
		for end := start; end < len(text); end++ {
			switch {
			case text[end] == 0x7b:
				depth++
			case text[end] == 0x7d:
				depth--
			case depth == 1 && (text[end] == 0x2c || text[end] == 0x2e && end+1 < len(text) && text[end+1] == 0x2e):
				splits = true
			}
			if depth == 0 {
				// Only a pair that closes expands; an opening brace with a
				// comma after it and no closing brace is literal text.
				if splits {
					return true
				}
				break
			}
		}
	}
	return false
}

// actionUnescapedLiterals returns the word with the backslash of each escaped
// character of its literal parts removed, which is the text the shell reads;
// the printed form of a literal part keeps the backslash.
func actionUnescapedLiterals(word *syntax.Word) *syntax.Word {
	plain := &syntax.Word{Parts: make([]syntax.WordPart, len(word.Parts))}
	for i, part := range word.Parts {
		plain.Parts[i] = part
		if lit, ok := part.(*syntax.Lit); ok && strings.Contains(lit.Value, "\\") {
			var text strings.Builder
			for j := 0; j < len(lit.Value); j++ {
				if lit.Value[j] == 0x5c && j+1 < len(lit.Value) {
					j++
					if lit.Value[j] == 0x0a {
						continue
					}
				}
				text.WriteByte(lit.Value[j])
			}
			plain.Parts[i] = &syntax.Lit{Value: text.String()}
		}
	}
	return plain
}

// actionWordQuotedField reports a word that expands to exactly one field:
// quoted text, and literal text without a pattern character, but no unquoted
// expansion and no list such as "$@".
func actionWordQuotedField(word *syntax.Word) bool {
	if word == nil || len(word.Parts) == 0 {
		return false
	}
	for _, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.SglQuoted:
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[~") {
				return false
			}
		case *syntax.DblQuoted:
			if actionDoubleQuotedList(part) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

// actionDoubleQuotedList reports a double-quoted part that expands to a list
// of fields, such as "$@".
func actionDoubleQuotedList(part *syntax.DblQuoted) bool {
	list := false
	syntax.Walk(part, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok {
			list = list || param.Param == nil || param.Param.Value == "@" || param.Index != nil
		}
		return !list
	})
	return list
}

// actionWordUsesGivenParameters reports that a word reads no special
// parameter, and no positional parameter past the count the call gives.
func actionWordUsesGivenParameters(word *syntax.Word, count int) bool {
	plain := true
	syntax.Walk(word, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil {
			name := param.Param.Value
			if number, err := strconv.Atoi(name); err == nil {
				plain = plain && number >= 1 && number <= count
			} else if name != "" && strings.Contains("@*#?-$!", name[:1]) {
				plain = false
			}
		}
		return plain
	})
	return plain
}

func actionClearFunctionValues(values actionValues) {
	for name := range values {
		if !strings.HasPrefix(name, "\x00") {
			delete(values, name)
		}
	}
}

// The output is used only for a command substitution. Assignment effects
// apply to the caller's candidate values; the substitution uses a clone.
func actionApplyFunctionValue(name string, values actionValues, depth int) (string, bool) {
	if depth >= actionFunctionMaxDepth {
		return "", false
	}
	encoded, present := values[actionFunctionValuePrefix+name]
	if !present || !strings.HasPrefix(encoded, actionFunctionKnownPrefix) {
		return "", false
	}
	var output strings.Builder
	for _, step := range strings.Split(strings.TrimPrefix(encoded, actionFunctionKnownPrefix), "\x01") {
		fields := strings.Split(step, "\x00")
		if len(fields) == 3 && fields[0] == "A" {
			if readonly := values[actionReadonlyValuePrefix+fields[1]]; readonly == "?" {
				return "", false
			} else if readonly == "" {
				values[fields[1]] = fields[2]
			}
			continue
		}
		if len(fields) < 2 || fields[0] != "C" {
			return "", false
		}
		part, ok := actionFunctionStaticCall(fields[1:], values, depth+1, false)
		if !ok || output.Len()+len(part) > MaxWriteTargetPathBytes {
			return "", false
		}
		output.WriteString(part)
	}
	return output.String(), true
}

func actionFunctionStaticCall(words []string, values actionValues, depth int, bypassFunction bool) (string, bool) {
	if len(words) == 0 || depth >= actionFunctionMaxDepth {
		return "", false
	}
	program := words[0]
	if !bypassFunction && !strings.Contains(program, "/") {
		if _, defined := values[actionFunctionValuePrefix+program]; defined {
			return actionApplyFunctionValue(program, values, depth)
		}
	}
	if program == "builtin" || program == "command" {
		if len(words) < 2 {
			return "", false
		}
		if program == "builtin" && strings.Contains(words[1], "/") {
			return "", false
		}
		return actionFunctionStaticCall(words[1:], values, depth+1, true)
	}
	if program == ":" && len(words) == 1 {
		return "", true
	}
	if program != "printf" && program != "/usr/bin/printf" && program != "/bin/printf" {
		return "", false
	}
	if len(words) < 2 {
		return "", false
	}
	formatIndex := 1
	boundName := ""
	if program == "printf" {
		option := words[1]
		if option == "-v" {
			if len(words) < 4 || !actionEvalAssignmentName(words[2]) {
				return "", false
			}
			boundName, formatIndex = words[2], 3
		} else if strings.HasPrefix(option, "-v") {
			boundName, formatIndex = strings.TrimPrefix(option, "-v"), 2
			if !actionEvalAssignmentName(boundName) {
				return "", false
			}
		} else if option == "--" {
			formatIndex = 2
		}
	}
	if formatIndex >= len(words) {
		return "", false
	}
	format := words[formatIndex]
	result := ""
	if format == "%s" && len(words) == formatIndex+2 {
		result = words[formatIndex+1]
	} else if !strings.Contains(format, "%") && len(words) == formatIndex+1 {
		var known bool
		result, known = actionPrintfLiteral(format)
		if !known {
			return "", false
		}
	} else {
		return "", false
	}
	if boundName != "" {
		if readonly := values[actionReadonlyValuePrefix+boundName]; readonly == "?" {
			return "", false
		} else if readonly == "" {
			values[boundName] = result
		}
		return "", true
	}
	return result, true
}

func actionFunctionSubstitutionValue(name string, values actionValues) (string, bool) {
	return actionApplyFunctionValue(name, maps.Clone(values), 0)
}
