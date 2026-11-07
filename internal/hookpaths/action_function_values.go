// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
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

// actionKeepAcrossFunctionCall adds the values before a call of a function
// the command defines to those after it. The tracker forgets every value at
// such a call, as the function may assign any name; a reader of known
// protected values must also consider that it did not.
func actionKeepAcrossFunctionCall(stmt *syntax.Stmt, before, after []actionValues, home string) []actionValues {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return after
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return after
	}
	for _, state := range before {
		if _, defined := state[actionFunctionValuePrefix+program]; defined {
			return actionAppendValueCandidates(after, before)
		}
	}
	return after
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
