// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package hookpaths resolves tool write targets in the invoking user's process.
package hookpaths

import (
	"encoding/base64"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

const Header = "X-DefenseClaw-Resolved-Writes"

// CWDKey carries the hook process's cwd for a gateway whose ProtectHome
// prevents it from validating that directory locally.
const CWDKey = "\x00cwd"

// TruncatedKey means at least one static write target could not fit in the
// bounded evidence. The gateway must not treat the remaining map as complete.
const TruncatedKey = "\x00truncated"

// OperandFactsKey marks a client that enumerates shell write operands. The
// gateway can fail closed on an omitted private operand only with this marker;
// older headers did not promise facts for command destinations.
const OperandFactsKey = "\x00operand-facts"

// SourceLinkFactPrefix identifies a copy source inspected by the user-side hook.
const SourceLinkFactPrefix = "\x00source-link:"

// SedRelinkFactPrefix marks an in-place sed entry whose existing final link
// has a dot-dot hop. The gateway may not be able to inspect that entry.
const SedRelinkFactPrefix = "\x00sed-relink:"

// maxWriteTargetLinkDepth matches the Linux kernel limit (MAXSYMLINKS) for
// one path resolution. Every followed link counts, also in parent components,
// so a link loop ends here and reports an unresolvable target.
const maxWriteTargetLinkDepth = 40

// MaxWriteTargets bounds the distinct write operands one request carries,
// far above any realistic command. Resolve and Decode share it, so the native
// hook runner and the shell hooks (hook resolve-writes) send, and the gateway
// accepts, the same bound for every connector.
const MaxWriteTargets = 512

// MaxWriteTargetPathBytes bounds one operand. A longer operand is omitted and
// the map is marked truncated.
const MaxWriteTargetPathBytes = 1024

// maxEncodedTargets bounds the JSON map. MaxHeaderValueBytes is its unpadded
// base64 size plus slack; it stays well inside one argv string for curl -H in
// the shell hooks (128 KiB on Linux).
const (
	maxEncodedTargets   = 64 << 10
	MaxHeaderValueBytes = 88 << 10
)

// MaxPayloadBytes is the hook payload cap, the same for the hook client and
// the gateway request body. The shell walk below covers a whole command up to
// this size, past the smaller ActionFacts analysis limits.
const MaxPayloadBytes = 1 << 20

// ShellWriteOperands lists the file operands of the output redirects in a
// shell command as absolute, cleaned paths, spelled the way the shell opens
// them (backslash escapes, single, double and ANSI-C quotes resolved). The
// hook client and the gateway both use it, so a client-resolved operand has
// the key the gateway looks up. ok is false when the command is over
// MaxPayloadBytes or does not parse; its operands are then unknown. dynamic
// reports a redirect target that is not a static word (a parameter other
// than HOME, a substitution or a glob), which is not listed.
func ShellWriteOperands(command, cwd, home string) (operands []string, ok, dynamic bool) {
	file, parsed := parseShell(command)
	if !parsed {
		return nil, false, false
	}
	for _, occurrence := range shellWriteOccurrences(file, cwd, home) {
		if !occurrence.Static {
			dynamic = true
			continue
		}
		if occurrence.Path != "" {
			operands = append(operands, occurrence.Path)
		}
	}
	return operands, true, dynamic
}

type shellWriteOccurrence struct {
	Path   string
	Offset int
	Static bool
}

func shellWriteOccurrences(file *syntax.File, cwd, home string) []shellWriteOccurrence {
	var occurrences []shellWriteOccurrence
	poison := shellVariablePoisonForFile(file, home)
	states := shellWordStates(file, home, poison)
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		offset := -1
		if redirect.Word != nil {
			offset = int(redirect.Word.Pos().Offset())
		}
		name, static := staticShellWordWithVars(redirect.Word, home, states.varsFor(redirect.Word), poison)
		if !static || name == "" {
			occurrences = append(occurrences, shellWriteOccurrence{Offset: offset, Static: false})
			return true
		}
		occurrences = append(occurrences, shellWriteOccurrence{
			Path: OperandPath(name, cwd), Offset: offset, Static: true,
		})
		return true
	})
	return occurrences
}

// ShellExtraWriteOperands lists destinations that the command-link proof
// understands but ActionFacts does not emit as write PathFacts.
func ShellExtraWriteOperands(command, cwd, home string) []string {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var operands []string
	poison := shellVariablePoisonForFile(file, home)
	states := shellWordStates(file, home, poison)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		operands = append(operands, shellCallExtraWriteOperands(call, cwd, home, states.varsFor(call.Args[0]), poison)...)
		return true
	})
	return operands
}

// ShellDynamicWriteOperands lists conservative literal candidates for dynamic
// redirect targets. unknown reports a dynamic target whose value has no bounded
// literal candidate, so the caller must fail closed when the target matters.
func ShellDynamicWriteOperands(command, cwd, home string) (operands []string, unknown bool) {
	file, ok := parseShell(command)
	if !ok {
		return nil, true
	}
	poison := shellVariablePoisonForFile(file, home)
	states := shellWordStates(file, home, poison)
	candidates := shellVariableCandidates(file, home)
	seen := map[string]bool{}
	add := func(name string) {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return
		}
		path := OperandPath(name, cwd)
		if !seen[path] {
			seen[path] = true
			operands = append(operands, path)
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		redirect, ok := node.(*syntax.Redirect)
		if !ok || redirect.Word == nil {
			return true
		}
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		default:
			return true
		}
		if _, static := staticShellWordWithVars(redirect.Word, home, states.varsFor(redirect.Word), poison); static {
			return true
		}
		names, wordUnknown := shellWordDynamicParamNames(redirect.Word, home)
		if candidates.allUnknown || wordUnknown {
			unknown = true
			return true
		}
		if len(names) == 0 {
			return true
		}
		for _, name := range names {
			values := candidates.values[name]
			if candidates.unknown[name] || len(values) == 0 {
				unknown = true
			}
			for _, value := range values {
				add(value)
			}
		}
		return true
	})
	return operands, unknown
}

func shellCallExtraWriteOperands(
	call *syntax.CallExpr, cwd, home string, vars shellVariables, poison shellVariablePoison,
) []string {
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		var static bool
		words[i], static = staticShellWordWithVars(arg, home, vars, poison)
		if !static {
			return nil
		}
	}
	cmdCWD, programWords, ok := envCommandWords(words, cwd)
	if !ok || len(programWords) == 0 {
		return nil
	}
	for slices.Contains(multicallPrograms, programBase(programWords[0])) && len(programWords) > 1 {
		programWords = programWords[1:]
	}
	program := programBase(programWords[0])
	var operands []string
	var destination string
	switch program {
	case "ln", "gln":
		if len(programWords) < 3 {
			return nil
		}
		for i := 1; i < len(programWords); i++ {
			if programWords[i] == "-f" || programWords[i] == "--force" ||
				strings.HasPrefix(programWords[i], "-") && strings.Contains(programWords[i], "f") {
				destination = programWords[len(programWords)-1]
				break
			}
		}
	case "rsync":
		if len(programWords) >= 3 {
			destination = programWords[len(programWords)-1]
		}
	case "tee":
		for _, target := range teeDestinations(programWords[1:]) {
			operands = append(operands, OperandPath(target, cmdCWD))
		}
	case "cp", "gcp":
		static := makeStatic(len(programWords) - 1)
		if destination = cpDestination(programWords[1:], static, cmdCWD); destination != "" {
			operands = append(operands, destination)
		}
	case "mv", "gmv", "install":
		if destination = finalOperandDestination(programWords[1:], cmdCWD); destination != "" {
			operands = append(operands, destination)
		}
	case "dd":
		for _, arg := range programWords[1:] {
			if output, ok := strings.CutPrefix(arg, "of="); ok && output != "" {
				operands = append(operands, OperandPath(output, cmdCWD))
			}
		}
	case "sed", "gsed":
		for _, name := range sedInPlaceFiles(programWords) {
			if sedFollowsInPlaceLinks(programWords) || sedParentProtected(name, cmdCWD, home) {
				operands = append(operands, OperandPath(name, cmdCWD))
			}
		}
	case "truncate":
		for _, name := range truncateFiles(programWords[1:]) {
			operands = append(operands, OperandPath(name, cmdCWD))
		}
	case "tar", "gtar", "bsdtar":
		operands = append(operands, tarExplicitExtractMembers(program, programWords[1:], cmdCWD)...)
	}
	if destination != "" && !strings.HasPrefix(destination, "-") &&
		(program != "rsync" || runtime.GOOS == "windows" || !strings.Contains(destination, ":")) &&
		!strings.Contains(destination, "://") && !strings.Contains(destination, "::") {
		operands = append(operands, OperandPath(destination, cmdCWD))
	}
	return operands
}

// OperandPath preserves dot-dot in the command operand until link resolution.
// filepath.Join would erase a directory link before the following dot-dot.
func OperandPath(name, cwd string) string {
	// Keep the old canonical spelling for ordinary operands. Only dot-dot
	// needs a raw spelling until the component walk has followed links.
	if !strings.Contains(filepath.ToSlash(name), "/../") &&
		!strings.HasSuffix(filepath.ToSlash(name), "/..") {
		if !filepath.IsAbs(name) && filepath.IsAbs(cwd) {
			return filepath.Join(cwd, name)
		}
		return filepath.Clean(name)
	}
	if filepath.IsAbs(name) || !filepath.IsAbs(cwd) {
		return name
	}
	return cwd + string(filepath.Separator) + name
}

// parseShell parses a command of at most MaxPayloadBytes as bash, or else as
// POSIX sh.
func parseShell(command string) (*syntax.File, bool) {
	if len(command) > MaxPayloadBytes {
		return nil, false
	}
	var file *syntax.File
	var err error
	for _, variant := range []syntax.LangVariant{syntax.LangBash, syntax.LangPOSIX} {
		file, err = syntax.NewParser(syntax.Variant(variant)).Parse(strings.NewReader(command), "")
		if err == nil {
			return file, true
		}
	}
	return nil, false
}

// staticShellWord expands a redirect word that names one fixed path: quotes,
// escapes, a leading ~/ and $HOME. Anything whose value depends on the
// runtime (another parameter, a substitution, a glob, ~user) is not static.
func staticShellWord(
	word *syntax.Word, env expand.Environ, haveHome bool, vars shellVariables, poison shellVariablePoison,
) (string, bool) {
	if word == nil {
		return "", false
	}
	for i, part := range word.Parts {
		switch part := part.(type) {
		case *syntax.Lit:
			if strings.ContainsAny(part.Value, "*?[") {
				return "", false
			}
			if i == 0 && strings.HasPrefix(part.Value, "~") &&
				(!haveHome || part.Value != "~" && !strings.HasPrefix(part.Value, "~/")) {
				return "", false
			}
		case *syntax.SglQuoted:
		case *syntax.DblQuoted:
			for _, inner := range part.Parts {
				switch inner := inner.(type) {
				case *syntax.Lit:
				case *syntax.ParamExp:
					if !staticShellParam(inner, haveHome, vars, poison) {
						return "", false
					}
				default:
					return "", false
				}
			}
		case *syntax.ParamExp:
			if !staticShellParam(part, haveHome, vars, poison) {
				return "", false
			}
		default:
			return "", false
		}
	}
	// Fields removes quotes and backslash escapes like the shell; a target
	// that splits into several fields is an ambiguous redirect, not a write.
	fields, err := expand.Fields(&expand.Config{Env: env}, word)
	if err != nil || len(fields) != 1 {
		return "", false
	}
	applyShellParamAssignments(word, fields[0], env, haveHome, vars, poison)
	return fields[0], true
}

// StaticWord expands one shell word using only the known home directory.
func StaticWord(word *syntax.Word, home string) (string, bool) {
	return staticShellWordWithVars(word, home, nil, shellVariablePoison{})
}

func homeParam(param *syntax.ParamExp, haveHome bool) bool {
	return haveHome && param.Param != nil && param.Param.Value == "HOME" && !param.Excl && !param.Length &&
		!param.Width && !param.IsSet && param.Index == nil && param.Slice == nil && param.Repl == nil &&
		param.Names == 0 && param.Exp == nil && param.Flags == nil && param.NestedParam == nil &&
		len(param.Modifiers) == 0
}

type shellVariables map[string]string

type shellVariablePoison struct {
	all   bool
	names map[string]bool
}

func (p shellVariablePoison) poisoned(name string) bool {
	return p.all || p.names[name]
}

func (p *shellVariablePoison) add(name string) {
	if name == "" || name == "HOME" || !shellIdentifier(name) {
		return
	}
	if p.names == nil {
		p.names = map[string]bool{}
	}
	p.names[name] = true
}

func (v shellVariables) clone() shellVariables {
	if len(v) == 0 {
		return shellVariables{}
	}
	clone := make(shellVariables, len(v))
	for key, value := range v {
		clone[key] = value
	}
	return clone
}

func (v shellVariables) environ(home string) expand.Environ {
	values := make([]string, 0, len(v)+1)
	if home != "" {
		values = append(values, "HOME="+strings.TrimRight(home, "/"))
	}
	keys := make([]string, 0, len(v))
	for key := range v {
		if key != "HOME" {
			keys = append(keys, key)
		}
	}
	slices.Sort(keys)
	for _, key := range keys {
		values = append(values, key+"="+v[key])
	}
	return expand.ListEnviron(values...)
}

func staticShellWordWithVars(
	word *syntax.Word, home string, vars shellVariables, poison shellVariablePoison,
) (string, bool) {
	if vars == nil {
		vars = shellVariables{}
	}
	return staticShellWord(word, vars.environ(home), home != "", vars, poison)
}

func staticShellParam(param *syntax.ParamExp, haveHome bool, vars shellVariables, poison shellVariablePoison) bool {
	if homeParam(param, haveHome) {
		return true
	}
	if param == nil || param.Param == nil || param.Flags != nil || param.Excl ||
		param.Length || param.Width || param.IsSet || param.NestedParam != nil ||
		param.Index != nil || len(param.Modifiers) != 0 || param.Slice != nil ||
		param.Repl != nil || param.Names != 0 {
		return false
	}
	name := param.Param.Value
	if !shellIdentifier(name) || shellVolatileParam(name) || poison.poisoned(name) {
		return false
	}
	if param.Exp == nil {
		_, ok := vars[name]
		return ok
	}
	switch param.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
	default:
		return false
	}
	if param.Exp.Word == nil {
		return true
	}
	_, ok := staticShellWordWithVars(param.Exp.Word, "", vars, poison)
	return ok
}

func applyShellParamAssignments(
	word *syntax.Word, expanded string, env expand.Environ, haveHome bool, vars shellVariables, poison shellVariablePoison,
) {
	if word == nil || vars == nil {
		return
	}
	syntax.Walk(word, func(node syntax.Node) bool {
		param, ok := node.(*syntax.ParamExp)
		if !ok || param.Param == nil || param.Exp == nil {
			return true
		}
		switch param.Exp.Op {
		case syntax.AssignUnset, syntax.AssignUnsetOrNull:
		default:
			return true
		}
		name := param.Param.Value
		if name == "HOME" || !shellIdentifier(name) || poison.poisoned(name) {
			return true
		}
		current, present := vars[name]
		if present && (current != "" || param.Exp.Op == syntax.AssignUnset) {
			return true
		}
		if param.Exp.Word == nil {
			vars[name] = ""
			return true
		}
		value, ok := staticShellWord(param.Exp.Word, env, haveHome, vars, poison)
		if ok {
			vars[name] = value
		} else if expanded != "" {
			vars[name] = expanded
		}
		return true
	})
}

func shellApplyAssignments(
	assigns []*syntax.Assign, home string, vars shellVariables, poison shellVariablePoison,
) bool {
	ok := true
	for _, assign := range assigns {
		if assign == nil || assign.Append || assign.Naked || assign.Name == nil ||
			assign.Index != nil || assign.Array != nil || !shellIdentifier(assign.Name.Value) || assign.Name.Value == "HOME" ||
			poison.poisoned(assign.Name.Value) {
			ok = false
			continue
		}
		value, static := "", true
		if assign.Value != nil {
			value, static = staticShellWordWithVars(assign.Value, home, vars, poison)
		}
		if !static || strings.ContainsAny(value, "\x00\r\n") {
			delete(vars, assign.Name.Value)
			ok = false
			continue
		}
		vars[assign.Name.Value] = value
	}
	return ok
}

func shellExpandedCallWords(file *syntax.File, home string) map[int]string {
	expanded := map[int]string{}
	poison := shellVariablePoisonForFile(file, home)
	states := shellWordStates(file, home, poison)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		vars := states.varsFor(call.Args[0])
		for _, arg := range call.Args {
			if value, ok := staticShellWordWithVars(arg, home, vars, poison); ok {
				expanded[int(arg.Pos().Offset())] = value
			}
		}
		return true
	})
	return expanded
}

type shellWordStateMap map[int]shellVariables

func (m shellWordStateMap) varsFor(word *syntax.Word) shellVariables {
	if word == nil {
		return shellVariables{}
	}
	if vars, ok := m[int(word.Pos().Offset())]; ok {
		return vars.clone()
	}
	return shellVariables{}
}

func shellWordStates(file *syntax.File, home string, poison shellVariablePoison) shellWordStateMap {
	states := shellWordStateMap{}
	vars := shellVariables{}
	for _, stmt := range file.Stmts {
		shellProcessStraightStmt(stmt, home, vars, poison, states)
	}
	return states
}

func shellProcessStraightStmt(
	stmt *syntax.Stmt, home string, vars shellVariables, poison shellVariablePoison, states shellWordStateMap,
) {
	if stmt == nil {
		return
	}
	if block, ok := stmt.Cmd.(*syntax.Block); ok && shellStraightStmt(stmt) {
		shellRecordRedirectWords(stmt, vars, states)
		for _, child := range block.Stmts {
			shellProcessStraightStmt(child, home, vars, poison, states)
		}
		return
	}
	shellRecordStmtWords(stmt, vars, states)
	shellApplyStraightStmt(stmt, home, vars, poison)
}

func shellRecordStmtWords(stmt *syntax.Stmt, vars shellVariables, states shellWordStateMap) {
	syntax.Walk(stmt, func(node syntax.Node) bool {
		word, ok := node.(*syntax.Word)
		if ok {
			states[int(word.Pos().Offset())] = vars.clone()
		}
		return true
	})
}

func shellRecordRedirectWords(stmt *syntax.Stmt, vars shellVariables, states shellWordStateMap) {
	for _, redirect := range stmt.Redirs {
		if redirect.Word != nil {
			states[int(redirect.Word.Pos().Offset())] = vars.clone()
		}
	}
}

func shellApplyStraightStmt(stmt *syntax.Stmt, home string, vars shellVariables, poison shellVariablePoison) {
	if !shellStraightStmt(stmt) {
		return
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	if len(call.Args) == 0 {
		shellApplyAssignments(call.Assigns, home, vars, poison)
		return
	}
	if names, ok := shellUnsetNames(call, home, vars, poison); ok {
		for _, name := range names {
			if !poison.poisoned(name) {
				delete(vars, name)
			}
		}
	}
}

func shellStraightStmt(stmt *syntax.Stmt) bool {
	return stmt != nil && !stmt.Background && !stmt.Negated
}

func shellVariablePoisonForFile(file *syntax.File, home string) shellVariablePoison {
	allowed, allowedUnsets := shellAllowedStraightMutations(file, home)
	poison := shellVariablePoison{}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Assign:
			name := shellAssignName(node)
			if name != "" && !allowed[node] {
				poison.add(name)
			}
		case *syntax.ForClause:
			if iter, ok := node.Loop.(*syntax.WordIter); ok && iter.Name != nil {
				poison.add(iter.Name.Value)
			}
		case *syntax.BinaryArithm:
			if shellArithmeticAssignOp(node.Op) {
				poison.add(shellArithmeticName(node.X))
			}
		case *syntax.UnaryArithm:
			if node.Op == syntax.Inc || node.Op == syntax.Dec {
				poison.add(shellArithmeticName(node.X))
			}
		case *syntax.CallExpr:
			if allowedUnsets[node] || len(node.Args) == 0 {
				return true
			}
			program, static := shellStaticProgram(node, home)
			if !static {
				poison.all = true
				return true
			}
			shellPoisonCallMutation(node, programBase(program), home, &poison)
		}
		return true
	})
	return poison
}

type shellVariableCandidateSet struct {
	values     map[string][]string
	seen       map[string]map[string]bool
	unknown    map[string]bool
	allUnknown bool
}

func shellVariableCandidates(file *syntax.File, home string) shellVariableCandidateSet {
	candidates := shellVariableCandidateSet{
		values:  map[string][]string{},
		seen:    map[string]map[string]bool{},
		unknown: map[string]bool{},
	}
	states := shellWordStates(file, home, shellVariablePoison{})
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Assign:
			name := shellAssignName(node)
			if name == "" {
				return true
			}
			value, ok := shellCandidateAssignValue(node, home, states)
			if ok {
				candidates.add(name, value)
			} else {
				candidates.unknown[name] = true
			}
		case *syntax.ForClause:
			iter, ok := node.Loop.(*syntax.WordIter)
			if !ok || iter.Name == nil || !shellIdentifier(iter.Name.Value) {
				return true
			}
			if len(iter.Items) == 0 {
				candidates.unknown[iter.Name.Value] = true
				return true
			}
			for _, item := range iter.Items {
				value, ok := staticShellWordWithVars(item, home, states.varsFor(item), shellVariablePoison{})
				if ok {
					candidates.add(iter.Name.Value, value)
				} else {
					candidates.unknown[iter.Name.Value] = true
				}
			}
		case *syntax.BinaryArithm:
			if shellArithmeticAssignOp(node.Op) {
				if name := shellArithmeticName(node.X); name != "" {
					candidates.unknown[name] = true
				}
			}
		case *syntax.UnaryArithm:
			if node.Op == syntax.Inc || node.Op == syntax.Dec {
				if name := shellArithmeticName(node.X); name != "" {
					candidates.unknown[name] = true
				}
			}
		case *syntax.ParamExp:
			if node.Param == nil || node.Exp == nil {
				return true
			}
			if node.Exp.Op != syntax.AssignUnset && node.Exp.Op != syntax.AssignUnsetOrNull {
				return true
			}
			name := node.Param.Value
			if !shellIdentifier(name) || node.Exp.Word == nil {
				return true
			}
			value, ok := staticShellWordWithVars(node.Exp.Word, home, states.varsFor(node.Exp.Word), shellVariablePoison{})
			if ok {
				candidates.add(name, value)
			} else {
				candidates.unknown[name] = true
			}
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			program, static := shellStaticProgram(node, home)
			if !static {
				candidates.allUnknown = true
				return true
			}
			shellCandidateCallMutation(node, programBase(program), home, states, &candidates)
		}
		return true
	})
	return candidates
}

func (c *shellVariableCandidateSet) add(name, value string) {
	if name == "" || !shellIdentifier(name) || strings.ContainsAny(value, "\x00\r\n") {
		return
	}
	if c.seen[name] == nil {
		c.seen[name] = map[string]bool{}
	}
	if c.seen[name][value] {
		return
	}
	c.seen[name][value] = true
	c.values[name] = append(c.values[name], value)
}

func shellCandidateAssignValue(assign *syntax.Assign, home string, states shellWordStateMap) (string, bool) {
	if assign == nil || assign.Naked || assign.Name == nil || assign.Index != nil || assign.Array != nil {
		return "", false
	}
	name := assign.Name.Value
	value, ok := "", true
	if assign.Value != nil {
		value, ok = staticShellWordWithVars(assign.Value, home, states.varsFor(assign.Value), shellVariablePoison{})
	}
	if !ok {
		return "", false
	}
	if assign.Append {
		vars := shellVariables{}
		if assign.Value != nil {
			vars = states.varsFor(assign.Value)
		}
		prefix, ok := vars[name]
		if !ok {
			return "", false
		}
		value = prefix + value
	}
	return value, true
}

func shellCandidateCallMutation(
	call *syntax.CallExpr, program, home string, states shellWordStateMap, candidates *shellVariableCandidateSet,
) {
	switch program {
	case "eval", "source", ".", "trap", "let":
		candidates.allUnknown = true
	case "read":
		names := shellReadTargets(call.Args[1:], home)
		if len(names) == 0 {
			names = []string{"REPLY"}
		}
		for _, name := range names {
			candidates.unknown[name] = true
		}
	case "mapfile", "readarray":
		names := shellReadTargets(call.Args[1:], home)
		if len(names) == 0 {
			names = []string{"MAPFILE"}
		}
		for _, name := range names {
			candidates.unknown[name] = true
		}
	case "getopts":
		words, ok := shellStaticWords(call.Args[1:], home)
		if !ok {
			candidates.allUnknown = true
			return
		}
		if len(words) >= 2 {
			candidates.unknown[words[1]] = true
		}
	case "printf":
		words, ok := shellStaticWords(call.Args[1:], home)
		if !ok {
			return
		}
		for i := 0; i+1 < len(words); i++ {
			if words[i] != "-v" {
				continue
			}
			name := words[i+1]
			valueIndex := i + 3
			if valueIndex < len(call.Args) {
				value, ok := staticShellWordWithVars(
					call.Args[valueIndex], home, states.varsFor(call.Args[valueIndex]), shellVariablePoison{},
				)
				if ok {
					candidates.add(name, value)
				} else {
					candidates.unknown[name] = true
				}
			} else {
				candidates.unknown[name] = true
			}
			return
		}
	}
}

func shellAllowedStraightMutations(
	file *syntax.File, home string,
) (map[*syntax.Assign]bool, map[*syntax.CallExpr]bool) {
	allowed := map[*syntax.Assign]bool{}
	allowedUnsets := map[*syntax.CallExpr]bool{}
	var walk func(*syntax.Stmt)
	walk = func(stmt *syntax.Stmt) {
		if !shellStraightStmt(stmt) {
			return
		}
		if block, ok := stmt.Cmd.(*syntax.Block); ok {
			for _, child := range block.Stmts {
				walk(child)
			}
			return
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return
		}
		if len(call.Args) == 0 {
			for _, assign := range call.Assigns {
				if _, ok := shellPlainAssignment(assign, home); ok {
					allowed[assign] = true
				}
			}
			return
		}
		if _, ok := shellUnsetNames(call, home, nil, shellVariablePoison{}); ok {
			allowedUnsets[call] = true
		}
	}
	for _, stmt := range file.Stmts {
		walk(stmt)
	}
	return allowed, allowedUnsets
}

func shellPlainAssignment(assign *syntax.Assign, home string) (string, bool) {
	name := shellAssignName(assign)
	if name == "" || assign.Append || assign.Naked || assign.Index != nil ||
		assign.Array != nil {
		return "", false
	}
	value, static := "", true
	if assign.Value != nil {
		value, static = staticShellWordWithVars(assign.Value, home, nil, shellVariablePoison{})
	}
	if !static || strings.ContainsAny(value, "\x00\r\n") {
		return "", false
	}
	return name, true
}

func shellAssignName(assign *syntax.Assign) string {
	if assign == nil || assign.Name == nil || assign.Name.Value == "HOME" ||
		!shellIdentifier(assign.Name.Value) {
		return ""
	}
	return assign.Name.Value
}

func shellStaticProgram(call *syntax.CallExpr, home string) (string, bool) {
	if call == nil || len(call.Args) == 0 {
		return "", false
	}
	return StaticWord(call.Args[0], home)
}

func shellUnsetNames(
	call *syntax.CallExpr, home string, vars shellVariables, poison shellVariablePoison,
) ([]string, bool) {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return nil, false
	}
	words := make([]string, len(call.Args))
	for i, arg := range call.Args {
		value, ok := staticShellWordWithVars(arg, home, vars, poison)
		if !ok {
			return nil, false
		}
		words[i] = value
	}
	if programBase(words[0]) != "unset" {
		return nil, false
	}
	var names []string
	for _, word := range words[1:] {
		if strings.HasPrefix(word, "-") {
			continue
		}
		if !shellIdentifier(word) {
			return nil, false
		}
		names = append(names, word)
	}
	return names, len(names) > 0
}

func shellPoisonCallMutation(call *syntax.CallExpr, program, home string, poison *shellVariablePoison) {
	switch program {
	case "eval", "source", ".", "trap", "let":
		poison.all = true
	case "read":
		names := shellReadTargets(call.Args[1:], home)
		if len(names) == 0 {
			names = []string{"REPLY"}
		}
		for _, name := range names {
			poison.add(name)
		}
	case "mapfile", "readarray":
		names := shellReadTargets(call.Args[1:], home)
		if len(names) == 0 {
			names = []string{"MAPFILE"}
		}
		for _, name := range names {
			poison.add(name)
		}
	case "getopts":
		words, ok := shellStaticWords(call.Args[1:], home)
		if !ok {
			poison.all = true
			return
		}
		if len(words) >= 2 {
			poison.add(words[1])
		}
	case "printf":
		words, ok := shellStaticWords(call.Args[1:], home)
		if !ok {
			return
		}
		for i := 0; i+1 < len(words); i++ {
			if words[i] == "-v" {
				poison.add(words[i+1])
				return
			}
		}
	}
}

func shellReadTargets(args []*syntax.Word, home string) []string {
	words, ok := shellStaticWords(args, home)
	if !ok {
		return nil
	}
	var names []string
	for i := 0; i < len(words); i++ {
		word := words[i]
		if word == "--" {
			names = append(names, words[i+1:]...)
			break
		}
		if strings.HasPrefix(word, "-") {
			if word == "-a" || word == "-d" || word == "-n" || word == "-N" ||
				word == "-p" || word == "-t" || word == "-u" || word == "-C" ||
				word == "-c" || word == "-O" || word == "-s" {
				i++
			}
			continue
		}
		names = append(names, word)
	}
	out := names[:0]
	for _, name := range names {
		if shellIdentifier(name) {
			out = append(out, name)
		}
	}
	return out
}

func shellStaticWords(words []*syntax.Word, home string) ([]string, bool) {
	values := make([]string, len(words))
	for i, word := range words {
		value, ok := StaticWord(word, home)
		if !ok {
			return nil, false
		}
		values[i] = value
	}
	return values, true
}

func shellArithmeticAssignOp(op syntax.BinAritOperator) bool {
	return op == syntax.Assgn || op == syntax.AddAssgn || op == syntax.SubAssgn ||
		op == syntax.MulAssgn || op == syntax.QuoAssgn || op == syntax.RemAssgn ||
		op == syntax.AndAssgn || op == syntax.OrAssgn || op == syntax.XorAssgn ||
		op == syntax.ShlAssgn || op == syntax.ShrAssgn || op == syntax.AndBoolAssgn ||
		op == syntax.OrBoolAssgn || op == syntax.XorBoolAssgn || op == syntax.PowAssgn
}

func shellArithmeticName(expr syntax.ArithmExpr) string {
	word, ok := expr.(*syntax.Word)
	if !ok {
		return ""
	}
	name := word.Lit()
	if !shellIdentifier(name) {
		return ""
	}
	return name
}

func shellWordDynamicParamNames(word *syntax.Word, home string) ([]string, bool) {
	seen := map[string]bool{}
	var names []string
	unknown := false
	if word == nil {
		return nil, true
	}
	syntax.Walk(word, func(node syntax.Node) bool {
		if unknown {
			return false
		}
		switch node := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp:
			unknown = true
			return false
		case *syntax.ParamExp:
			name, ok := shellDynamicParamName(node, home)
			if !ok {
				unknown = true
				return false
			}
			if !seen[name] {
				seen[name] = true
				names = append(names, name)
			}
			return false
		}
		return true
	})
	return names, unknown
}

func shellDynamicParamName(param *syntax.ParamExp, home string) (string, bool) {
	if param == nil || param.Param == nil || param.Flags != nil || param.Excl ||
		param.Length || param.Width || param.IsSet || param.NestedParam != nil ||
		param.Index != nil || len(param.Modifiers) != 0 || param.Slice != nil ||
		param.Repl != nil || param.Names != 0 {
		return "", false
	}
	name := param.Param.Value
	if !shellIdentifier(name) || shellVolatileParam(name) {
		return "", false
	}
	if param.Exp == nil {
		return name, true
	}
	switch param.Exp.Op {
	case syntax.DefaultUnset, syntax.DefaultUnsetOrNull, syntax.AssignUnset, syntax.AssignUnsetOrNull:
	default:
		return "", false
	}
	if param.Exp.Word == nil {
		return name, true
	}
	_, ok := staticShellWordWithVars(param.Exp.Word, home, nil, shellVariablePoison{})
	return name, ok
}

func shellVolatileParam(name string) bool {
	return name == "RANDOM" || name == "SECONDS"
}

func shellIdentifier(value string) bool {
	if value == "" {
		return false
	}
	for i, r := range value {
		if i == 0 {
			if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') {
				return false
			}
			continue
		}
		if r != '_' && (r < 'A' || r > 'Z') && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
	}
	return true
}

// resolveWritePath follows existing links, including a link whose final file
// does not exist yet. The shared walk preserves components of link targets
// until each has been checked, so a linked directory before ".." is not
// removed lexically.
func resolveWritePath(path string, linkDepth int) (string, bool) {
	resolved, _, _, ok := walkWritePath("", path, linkDepth, false)
	return resolved, ok
}

// walkWritePath resolves both ordinary operands and raw symlink targets. base
// is the already-resolved directory containing a relative target. When collect
// is true, forms includes every traversed name and link hop for opaque-scope
// checks. A missing component is permitted at the end (redirects create
// files), but it cannot be crossed by "..": its link status is unknown.
func walkWritePath(base, path string, linkDepth int, collect bool) (string, []string, int, bool) {
	if linkDepth > maxWriteTargetLinkDepth {
		return "", nil, linkDepth, false
	}
	current := base
	absolute := filepath.IsAbs(path)
	if absolute {
		current = filepath.VolumeName(path) + string(filepath.Separator)
		path = strings.TrimPrefix(path, filepath.VolumeName(path))
	} else if !filepath.IsAbs(base) {
		return "", nil, linkDepth, false
	}
	var forms []string
	if collect && absolute {
		forms = append(forms, current)
	}
	add := func(form string) bool {
		if collect {
			forms = append(forms, form)
			return len(forms) <= maxOpaquePathForms
		}
		return true
	}
	// The stack records whether a component added after base is missing.
	// A resolved link is a physical directory, so ".." ascends from its
	// target. A missing component cannot be crossed: it may become a link
	// before the command executes.
	var crossed []bool
	for _, part := range strings.Split(filepath.ToSlash(path), "/") {
		switch part {
		case "", ".":
			continue
		case "..":
			if len(crossed) > 0 {
				if crossed[len(crossed)-1] {
					return "", nil, linkDepth, false
				}
				crossed = crossed[:len(crossed)-1]
			}
			current = filepath.Dir(current)
			if !add(current) {
				return "", nil, linkDepth, false
			}
		default:
			candidate := filepath.Join(current, part)
			if !add(candidate) {
				return "", nil, linkDepth, false
			}
			info, err := os.Lstat(candidate)
			if err != nil && !os.IsNotExist(err) {
				return "", nil, linkDepth, false
			}
			unknown := os.IsNotExist(err)
			if err == nil && info.Mode()&os.ModeSymlink != 0 {
				link, err := os.Readlink(candidate)
				if err != nil {
					return "", nil, linkDepth, false
				}
				var extra []string
				var nextDepth int
				var ok bool
				current, extra, nextDepth, ok = walkWritePath(current, link, linkDepth+1, collect)
				if !ok || collect && len(forms)+len(extra) > maxOpaquePathForms {
					return "", nil, linkDepth, false
				}
				linkDepth = nextDepth
				forms = append(forms, extra...)
				_, err = os.Lstat(current)
				if err != nil && !os.IsNotExist(err) {
					return "", nil, linkDepth, false
				}
				crossed = append(crossed, os.IsNotExist(err))
			} else {
				current = candidate
				crossed = append(crossed, unknown)
			}
		}
	}
	return filepath.Clean(current), forms, linkDepth, true
}

// AuthorizedKeysFiles names the user's authorized-keys files under ~/.ssh:
// the sshd default AuthorizedKeysFile (.ssh/authorized_keys and
// .ssh/authorized_keys2), the same set the direct-write rule
// persistence.ssh_authorized_keys_command protects. A symlink, a hard link
// and a direct write are judged against this one list.
var AuthorizedKeysFiles = [...]string{"authorized_keys", "authorized_keys2"}

// AuthorizedKeysPaths returns the AuthorizedKeysFiles paths under home.
func AuthorizedKeysPaths(home string) []string {
	paths := make([]string, 0, len(AuthorizedKeysFiles))
	for _, name := range AuthorizedKeysFiles {
		paths = append(paths, filepath.Join(home, ".ssh", name))
	}
	return paths
}

// ProtectedAuthorizedKeysPaths also includes sshd's Windows administrator
// key file, which may live outside the invoking user's home.
func ProtectedAuthorizedKeysPaths(home string) []string {
	paths := AuthorizedKeysPaths(home)
	if runtime.GOOS == "windows" {
		if programData := os.Getenv("ProgramData"); filepath.IsAbs(programData) {
			paths = append(paths, filepath.Join(programData, "ssh", "administrators_authorized_keys"))
		}
	}
	return paths
}

// ResolveWriteTarget resolves an absolute write operand the way the hook
// client does: links are followed, including one whose final file does not
// exist yet. ok is false when the target cannot be resolved.
func ResolveWriteTarget(path string) (string, bool) {
	return resolveWritePath(path, 0)
}

// protectedFile is the identity of one of the user's authorized-keys files. A
// hard link elsewhere names the same file under another path, so a target is
// compared by file identity (device and inode on Unix, volume serial and file
// index on Windows) and not by pathname alone.
type protectedFile struct {
	path    string
	info    os.FileInfo
	unknown bool
}

type protectedFiles []protectedFile

func newProtectedFiles(home string) protectedFiles {
	files := make(protectedFiles, 0, len(AuthorizedKeysFiles))
	for _, path := range ProtectedAuthorizedKeysPaths(home) {
		protected := protectedFile{path: path}
		info, err := os.Stat(path)
		switch {
		case err == nil:
			protected.info = info
		case !os.IsNotExist(err):
			protected.unknown = true
		}
		files = append(files, protected)
	}
	return files
}

// has reports a resolved target that is one of the protected paths.
func (files protectedFiles) has(resolved string) bool {
	for _, p := range files {
		if samePathName(resolved, p.path) {
			return true
		}
	}
	return false
}

// target maps a resolved write target to the protected path when both name
// the same file. When a protected file cannot be identified, a multiply
// linked target may be an alias of it and is reported as unresolvable.
func (files protectedFiles) target(resolved string) (string, bool) {
	var info os.FileInfo
	for _, p := range files {
		if p.info == nil && !p.unknown {
			continue
		}
		if info == nil {
			var err error
			if info, err = os.Stat(resolved); err != nil || !info.Mode().IsRegular() {
				return resolved, true
			}
		}
		if p.info != nil {
			if os.SameFile(info, p.info) {
				return p.path, true
			}
			continue
		}
		if linkCount(resolved, info) > 1 {
			return "", false
		}
	}
	return resolved, true
}

// Resolve returns a bounded, header-safe map from absolute write operands to
// their filesystem targets. An empty value means resolution was attempted but
// could not be trusted. A regular file maps to itself, unless it is a hard
// link to one of the user's authorized-keys files. An operand
// is never dropped silently: when one cannot be listed (over a bound, or the command exceeds
// the shell analysis limits) the map carries TruncatedKey.
func Resolve(payload []byte) string {
	if len(payload) > MaxPayloadBytes {
		return incompleteEvidence("")
	}
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return ""
	}
	field := func(names ...string) json.RawMessage {
		for _, name := range names {
			if value := envelope[name]; len(value) != 0 {
				return value
			}
		}
		return nil
	}
	var tool string
	_ = json.Unmarshal(field("tool_name", "toolName"), &tool)
	args := field("tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if len(args) == 0 {
		return ""
	}
	// The gateway names relative operands from the event cwd; use the same
	// directory so both sides build the same keys.
	var cwd string
	_ = json.Unmarshal(field("cwd"), &cwd)
	if !filepath.IsAbs(cwd) {
		var err error
		if cwd, err = os.Getwd(); err != nil {
			return incompleteEvidence("")
		}
	}
	cwd = filepath.Clean(cwd)
	home, err := os.UserHomeDir()
	if err != nil {
		return incompleteEvidence(cwd)
	}
	input := actionfacts.Input{Tool: tool, Args: args, CWD: cwd, ActiveHome: home}
	facts := actionfacts.Analyze(input)
	// A connector can name the shell text "cmd" while ActionFacts requires
	// its canonical command field. Resolve that exact string as a shell too.
	truncated := facts.Parse.Status == actionfacts.StatusLimitExceeded
	var operands, literalOperands []string
	var dynamicOperands, extraOperands []string
	var directoryOperands []RedirectOccurrence
	var directoryUnknown bool
	links := shellLinks{known: true}
	sourceFacts := map[string]string{}
	if physicalCWD, ok := ResolveWriteTarget(cwd); ok {
		sourceFacts[DirectoryFactPrefix+cwd] = physicalCWD
	} else {
		sourceFacts[DirectoryFactPrefix+cwd] = "?"
	}
	var safeRedirects []RedirectOccurrence
	var sedOperands map[string]bool
	var toolArgs map[string]json.RawMessage
	if json.Unmarshal(args, &toolArgs) == nil {
		for _, key := range []string{"command", "cmd"} {
			var command string
			if json.Unmarshal(toolArgs[key], &command) == nil && command != "" {
				fallback := input
				fallback.Tool, fallback.Args, fallback.Command = "Bash", nil, command
				fallbackFacts := actionfacts.Analyze(fallback)
				facts.Paths = append(facts.Paths, fallbackFacts.Paths...)
				truncated = truncated || fallbackFacts.Parse.Status == actionfacts.StatusLimitExceeded
				// A command over the analysis limits has no path facts, but
				// the gateway still checks each literal redirect operand.
				var parsed, dynamic, dynamicUnknown bool
				operands, parsed, dynamic = ShellWriteOperands(command, cwd, home)
				if dynamic {
					dynamicOperands, dynamicUnknown = ShellDynamicWriteOperands(command, cwd, home)
				}
				literalOperands = LiteralWriteOperands(command, cwd, home)
				extraOperands = ShellExtraWriteOperands(command, cwd, home)
				sedOperands = SedReplacedOperands(command, cwd, home)
				for path, safe := range sedOperands {
					if !safe {
						sourceFacts[SedRelinkFactPrefix+path] = "1"
					}
				}
				directoryOperands, directoryUnknown = ShellDirectoryWriteOperands(command, cwd, home, sourceFacts, true, false)
				truncated = truncated || directoryUnknown
				truncated = truncated || !parsed || dynamicUnknown
				// A link the command creates can make a later write a write
				// to a protected file (GAP-1505). The command of an
				// apply_patch tool is a patch envelope, not shell.
				if !isApplyPatchToolName(tool) {
					links = commandLinksWithFacts(command, cwd, home, sourceFacts, true)
					safeRedirects = SafeShellRedirectOccurrencesWithFacts(command, cwd, home, sourceFacts)
					truncated = truncated || !links.known
				}
				break
			}
		}
	}
	targets := map[string]string{CWDKey: cwd, OperandFactsKey: "1"}
	// The fixed part counts the truncation marker, so setting it never
	// exceeds the budget.
	protected := newProtectedFiles(home)
	size := 2 + len(jsonString(CWDKey)) + 1 + len(jsonString(cwd)) + 1 +
		len(jsonString(OperandFactsKey)) + 1 + 3 + 1 +
		len(jsonString(TruncatedKey)) + 1 + 3
	// A shell operand is already the literal path the shell opens; only a
	// path fact can still carry unexpanded syntax.
	add := func(path string, literal, safeRedirect bool) {
		if path == "" || !literal && (strings.ContainsAny(path, "*?[]$`") || strings.HasPrefix(path, "~")) {
			return
		}
		path = OperandPath(path, cwd)
		if old, present := targets[path]; present {
			if safeRedirect {
				return
			}
			size -= len(jsonString(path)) + 1 + len(jsonString(old)) + 1
			delete(targets, path)
		}
		if len(path) > MaxWriteTargetPathBytes || len(targets)-2 >= MaxWriteTargets {
			truncated = true
			return
		}
		resolved, ok := "", false
		if links.known {
			resolved, ok = links.resolve(path, protected)
		} else if safeRedirect {
			if direct, directOK := resolveWritePath(path, 0); directOK {
				resolved, ok = protected.target(direct)
			}
		} else if links.opaque && (!links.opaqueTarget(path) || !links.opaqueTargetExceptCopy(path, path) && slices.Contains(links.copyDestinations, path)) {
			resolved, ok = links.resolve(path, protected)
		}
		if !ok {
			resolved = ""
		}
		entry := len(jsonString(path)) + 1 + len(jsonString(resolved)) + 1
		if size+entry > maxEncodedTargets {
			truncated = true
			return
		}
		size += entry
		targets[path] = resolved
	}
	// Exact shell operands take precedence over a duplicate PathFact. Their
	// early-redirect exemption must not cover a later command writer.
	for i, operand := range operands {
		add(operand, true, i < len(safeRedirects) && safeRedirects[i].Safe)
	}
	for _, operand := range dynamicOperands {
		add(operand, true, false)
	}
	for _, operand := range literalOperands {
		add(operand, true, false)
	}
	for _, operand := range extraOperands {
		add(operand, true, false)
	}
	for operand := range sedOperands {
		add(operand, true, false)
	}
	for _, operand := range directoryOperands {
		add(operand.Path, true, operand.Safe)
	}
	for _, candidate := range facts.Paths {
		if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
			continue
		}
		path := candidate.Resolved
		if path == "" {
			path = candidate.Normalized
		}
		if raw, ok := RawDotDotOperand(candidate.Value, cwd); ok {
			path = raw
		}
		if slices.Contains(operands, path) && pathFactIsRedirect(candidate, facts.Commands) {
			continue
		}
		add(path, false, false)
	}
	// An apply_patch edit names its files in the patch envelope, not in a
	// redirect. Unknown targets make the map incomplete.
	patchTargets, patchKnown := ApplyPatchWriteTargets(tool, args, "", cwd, home)
	truncated = truncated || !patchKnown
	for _, target := range patchTargets {
		add(target, true, false)
	}
	for key, value := range sourceFacts {
		entry := len(jsonString(key)) + 1 + len(jsonString(value)) + 1
		if len(targets)-2 >= MaxWriteTargets || size+entry > maxEncodedTargets {
			truncated = true
			break
		}
		targets[key] = value
		size += entry
	}
	if truncated {
		targets[TruncatedKey] = "1"
	}
	encoded, err := json.Marshal(targets)
	if err != nil || len(encoded) > maxEncodedTargets {
		return incompleteEvidence(cwd)
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

// incompleteEvidence is the header for a tool call whose write operands
// could not be listed. The gateway must not treat it as complete.
func incompleteEvidence(cwd string) string {
	targets := map[string]string{TruncatedKey: "1"}
	if cwd != "" && len(cwd) <= MaxWriteTargetPathBytes {
		targets[CWDKey] = cwd
	}
	encoded, err := json.Marshal(targets)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(encoded)
}

func jsonString(value string) []byte {
	encoded, _ := json.Marshal(value)
	return encoded
}

// Decode accepts only the bounded client evidence format.
func Decode(value string) (map[string]string, bool) {
	if value == "" || len(value) > MaxHeaderValueBytes {
		return nil, false
	}
	data, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, false
	}
	var targets map[string]string
	if json.Unmarshal(data, &targets) != nil || len(targets) > MaxWriteTargets+3 ||
		(targets[TruncatedKey] != "" && targets[TruncatedKey] != "1") ||
		(targets[OperandFactsKey] != "" && targets[OperandFactsKey] != "1") {
		return nil, false
	}
	for key, value := range targets {
		if strings.HasPrefix(key, DirectoryFactPrefix) && value != "?" && !filepath.IsAbs(value) {
			return nil, false
		}
		if strings.HasPrefix(key, SourceLinkFactPrefix) && (value != "0" && value != "1" && value != "?") {
			return nil, false
		}
		if strings.HasPrefix(key, SedRelinkFactPrefix) && value != "1" {
			return nil, false
		}
	}
	return targets, true
}

// rawDotDotOperand keeps the shell spelling when a link can precede "..".
func RawDotDotOperand(value, cwd string) (string, bool) {
	if !strings.Contains(filepath.ToSlash(value), "/../") || strings.ContainsAny(value, "*?[]$`~") || !filepath.IsAbs(cwd) {
		return "", false
	}
	return OperandPath(value, cwd), true
}

func pathFactIsRedirect(candidate actionfacts.PathFact, commands []actionfacts.CommandFact) bool {
	for _, command := range commands {
		if command.ID != candidate.CommandID {
			continue
		}
		for _, redirect := range command.Redirects {
			if redirect.Access == candidate.Access && !redirect.Expands &&
				(redirect.Target == candidate.Value || redirect.Target == candidate.Normalized) {
				return true
			}
		}
	}
	return false
}

// Programs that create a link from their operands: ln and link always, cp
// with --link or --symbolic-link. mv and rename move a link to another name;
// cd changes what a relative link operand denotes. A multicall binary runs
// its first operand as the program. Archive, copy, and sync tools can
// preserve or extract links whose names this package cannot list.
var (
	linkPrograms      = []string{"ln", "gln", "link", "glink"}
	copyPrograms      = []string{"cp", "gcp"}
	renamePrograms    = []string{"mv", "gmv", "rename"}
	cdPrograms        = []string{"cd", "pushd", "popd"}
	multicallPrograms = []string{"busybox", "toybox"}
	archivePrograms   = []string{"rsync", "cpio", "bsdcpio", "pax", "tar", "gtar", "bsdtar", "unzip", "7z", "7za", "7zr"}
	copyLinkOption    = regexp.MustCompile(`(?:^|\s)(?:-[A-Za-z]*[ls][A-Za-z]*|--(?:link|symbolic-link))(?:[\s=]|$)`)
	// opaqueLink is a link that an interpreter, PowerShell or a Windows tool
	// creates from text this package does not evaluate.
	opaqueLink = regexp.MustCompile(`(?i)\bos\.(?:sym)?link\s*\(|\.(?:hardlink_to|symlink_to|link_to)\s*\(|` +
		`\bfs(?:\.promises)?\.(?:sym)?link(?:sync)?\s*\(|\bmklink\b|\bfsutil(?:\.exe)?\s+hardlink\b|` +
		`-itemtype\s+['"]?(?:hardlink|symboliclink|junction)\b|\bcreate(?:symbolic|hard)link\b`)
)

// linkAlias is a name that a link created by the command gives to target.
type linkAlias struct{ name, target string }

// shellLinks are the links one shell command creates. known is false when
// link names or operands are dynamic or an archive can extract links. opaque
// identifies a possible unreadable link; a dynamic program word alone keeps
// the older per-user behavior (GAP-1523).
type shellLinks struct {
	aliases          []linkAlias
	known            bool
	opaque           bool
	relative         bool // a link operand is relative to the working directory
	globalOpaque     bool
	opaqueScopes     []opaqueScope
	copyDestinations []string
}

// unknown marks the links unknown, and opaque when a link may be created.
func (l *shellLinks) unknown(opaque bool) {
	l.known = false
	l.opaque = l.opaque || opaque
	l.globalOpaque = l.globalOpaque || opaque
}

type opaqueScope struct {
	path string
	copy bool
}

// unknownIn confines an archive to its destination directory.
func (l *shellLinks) unknownIn(scope string) {
	l.addOpaqueScope(scope, false)
}

func (l *shellLinks) unknownCopyIn(scope string) {
	l.addOpaqueScope(scope, true)
}

func (l *shellLinks) addOpaqueScope(scope string, copyScope bool) {
	l.known = false
	l.opaque = true
	if scope == "" {
		l.globalOpaque = true
		return
	}
	l.opaqueScopes = append(l.opaqueScopes, opaqueScope{filepath.Clean(scope), copyScope})
}

func (l shellLinks) opaqueTarget(path string) bool {
	return l.opaqueTargetExceptCopy(path, "")
}

// opaqueTargetExceptCopy excludes only the copy operation's own destination
// scope. An archive or another operation covering that path still wins.
func (l shellLinks) opaqueTargetExceptCopy(path, ownCopy string) bool {
	// A second copy to the same name may follow a link created by the first.
	// Only one copy statement can claim the own-destination exemption.
	if ownCopy != "" {
		count := 0
		for _, destination := range l.copyDestinations {
			if destination == ownCopy {
				count++
			}
		}
		if count != 1 {
			ownCopy = ""
		}
	}
	if !l.opaque {
		return false
	}
	if l.globalOpaque || len(l.opaqueScopes) == 0 {
		return true
	}
	forms, complete := writePathForms(path, 0)
	if !complete {
		return true
	}
	for _, scope := range l.opaqueScopes {
		if scope.copy && scope.path == ownCopy {
			continue
		}
		for _, form := range forms {
			if form == scope.path || strings.HasPrefix(form, scope.path+string(filepath.Separator)) {
				return true
			}
		}
	}
	return false
}

// writePathForms includes every traversed name and link hop. An extractor
// may replace a link inside its scope after this check, so the intermediate
// forms matter even when the final target is outside that scope.
const maxOpaquePathForms = 256

func writePathForms(path string, linkDepth int) ([]string, bool) {
	_, forms, _, ok := walkWritePath("", path, linkDepth, true)
	return forms, ok
}

// commandLinks lists the links that ln, link and cp --link or
// --symbolic-link create in command, in any order: a link made after a write
// only makes the result more conservative.
func commandLinks(command, cwd, home string) shellLinks {
	return commandLinksWithFacts(command, cwd, home, nil, false)
}

func commandLinksWithFacts(command, cwd, home string, facts map[string]string, record bool) shellLinks {
	links := shellLinks{known: true}
	file, parsed := parseShell(command)
	if !parsed {
		// Resolve already marks a command that does not parse incomplete.
		if opaqueLink.MatchString(command) {
			links.unknown(true)
		}
		return links
	}
	if opaqueLinkText(file, command, home) {
		links.unknown(true)
		return links
	}
	env := expand.ListEnviron("HOME=" + strings.TrimRight(home, "/"))
	expandedWords := shellExpandedCallWords(file, home)
	renames, cds := false, false
	var copyScopes []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, isCall := node.(*syntax.CallExpr)
		if !isCall || len(call.Args) == 0 {
			return true
		}
		args := call.Args
		words := make([]string, len(args))
		static := make([]bool, len(args))
		for i, arg := range args {
			if value, ok := expandedWords[int(arg.Pos().Offset())]; ok {
				words[i], static[i] = value, true
			} else {
				words[i], static[i] = staticShellWord(arg, env, home != "", nil, shellVariablePoison{})
			}
		}
		program, start := "", call.Pos()
		if static[0] {
			program = programBase(words[0])
		}
		// busybox ln and toybox ln are ln (GAP-1521).
		for slices.Contains(multicallPrograms, program) && len(args) > 1 {
			args, words, static, start = args[1:], words[1:], static[1:], args[1].Pos()
			program = ""
			if static[0] {
				program = programBase(words[0])
			}
		}
		if opaqueProgram(program) {
			links.unknown(true)
			return true
		}
		switch {
		case program == "":
			// A program named by a parameter or a substitution may be ln.
			links.unknown(false)
		case slices.Contains(linkPrograms, program):
			if slices.Contains(static, false) || !links.add(program, words[1:], cwd) {
				links.unknown(true)
			}
		case slices.Contains(copyPrograms, program):
			destination := cpDestination(words[1:], static[1:], cwd)
			if destination != "" {
				links.copyDestinations = append(links.copyDestinations, destination)
			}
			option, dynamic := copyLinkOptions(args[1:], words[1:], static[1:])
			if copyPreservesLinks(words[1:], static[1:]) {
				copyScopes = append(copyScopes, destination)
				if cpDiskSymlink(words[1:], static[1:], cwd, home, facts, record) {
					links.unknownCopyIn(destination)
				}
			}
			switch {
			case option:
				if slices.Contains(static, false) || !links.add(program, words[1:], cwd) {
					links.unknown(true)
				}
			case dynamic:
				// A word that is not static may expand to a link option.
				links.unknown(false)
				copyScopes = append(copyScopes, cpDestination(words[1:], static[1:], cwd))
			}
		case slices.Contains(archivePrograms, program):
			destination := archiveDestination(program, words[1:], static[1:], cwd)
			opaqueIn := links.unknownIn
			if program == "rsync" && destination != "" {
				// Its own destination is an ordinary write operand.
				// A later write into the copied tree still sees the scope.
				links.copyDestinations = append(links.copyDestinations, destination)
				opaqueIn = links.unknownCopyIn
			}
			if slices.Contains(static[1:], false) {
				// An option supplied at runtime may select extraction.
				opaqueIn(destination)
			}
			if archiveMayLink(program, words[1:], static[1:]) {
				opaqueIn(destination)
			}
			if archiveCopiesLinks(program, words[1:], static[1:]) {
				copyScopes = append(copyScopes, destination)
				if copiesDiskSymlink(words[1:], static[1:], cwd, home, facts, record) {
					opaqueIn(destination)
				}
			}
		case slices.Contains(renamePrograms, program):
			renames = true
		case slices.Contains(cdPrograms, program):
			cds = true
		default:
			// A wrapper (sudo, env, xargs, find -exec, sh -c) may run one.
			text := command[start.Offset():call.End().Offset()]
			switch {
			case tactics.RunsProgram(text, linkPrograms...):
				links.unknown(true)
			case tactics.RunsProgram(text, copyPrograms...) && copyLinkOption.MatchString(text):
				// The option may be the wrapper's own, as in bash -lc.
				mayLink, copyWord := wrappedMayLink(text)
				links.unknown(mayLink || !copyWord)
			case tactics.RunsProgram(text, multicallPrograms...) || tactics.RunsProgram(text, archivePrograms...):
				if mayLink, _ := wrappedMayLink(text); mayLink {
					links.unknown(true)
				}
			}
			renames = renames || tactics.RunsProgram(text, renamePrograms...)
			cds = cds || tactics.RunsProgram(text, cdPrograms...)
		}
		return true
	})
	if len(links.aliases) > 0 {
		for _, scope := range copyScopes {
			links.unknownCopyIn(scope)
		}
	}
	if len(links.aliases) > 0 && (renames || cds && links.relative) {
		links.unknown(true)
	}
	// Scopes are read against the starting directory; after a directory
	// change a relative write may land in a scope under another name.
	if cds && len(links.opaqueScopes) > 0 {
		links.globalOpaque = true
	}
	return links
}

// dataPrograms only print, search or count text, so link API text in their
// arguments or here-documents is data, not code (GAP-1536).
var dataPrograms = []string{"echo", "printf", "grep", "egrep", "fgrep", "rg", "ag", "ack", "cat", "head", "tail",
	"wc", "sort", "uniq", "cut", "tr", "nl", "less", "more"}

// opaqueLinkText reports link API text that the command may run. Only a
// command made of data programs alone, without substitutions, is exempt: an
// interpreter may read the text from an argument, a here-document, a pipe or
// a file the command writes, under any name or wrapper.
func opaqueLinkText(file *syntax.File, command, home string) bool {
	if !opaqueLink.MatchString(command) {
		return false
	}
	for _, stmt := range file.Stmts {
		if !dataStatement(stmt, home) {
			return true
		}
	}
	return false
}

func dataStatement(stmt *syntax.Stmt, home string) bool {
	if stmt == nil || stmt.Background || stmt.Cmd == nil {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		if !dataStatement(cmd.X, home) || !dataStatement(cmd.Y, home) {
			return false
		}
	case *syntax.CallExpr:
		if len(cmd.Assigns) > 0 || len(cmd.Args) == 0 {
			return false
		}
		program, static := StaticWord(cmd.Args[0], home)
		if !static || !slices.Contains(dataPrograms, programBase(program)) {
			return false
		}
	default:
		return false
	}
	plain := true
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			plain = false
		}
		return plain
	})
	return plain
}

// linearShellStatements excludes loops, subshells, and command substitutions:
// their execution order can differ from source order.
func linearShellStatements(file *syntax.File) ([]*syntax.Stmt, bool) {
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt) bool
	collect = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated {
			return false
		}
		switch cmd := stmt.Cmd.(type) {
		case *syntax.BinaryCmd:
			if cmd.Op != syntax.AndStmt && cmd.Op != syntax.OrStmt {
				return false
			}
			return collect(cmd.X) && collect(cmd.Y)
		case *syntax.CallExpr:
			plain := true
			syntax.Walk(cmd, func(node syntax.Node) bool {
				switch node.(type) {
				case *syntax.CmdSubst, *syntax.ProcSubst:
					plain = false
					return false
				}
				return true
			})
			if !plain {
				return false
			}
			statements = append(statements, stmt)
			return true
		}
		return false
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt) {
			return nil, false
		}
	}
	slices.SortFunc(statements, func(a, b *syntax.Stmt) int {
		return int(a.Pos().Offset()) - int(b.Pos().Offset())
	})
	return statements, true
}

// RedirectOccurrence is one shell redirect in source order. The safety bit
// belongs to that occurrence, even when a later writer names the same path.
type RedirectOccurrence struct {
	Path   string
	Safe   bool
	Offset int
}

// SafeShellRedirectOccurrences reports redirects opened before any command
// in the line can create a link. An extracting command's own redirect opens
// before extraction begins.
func SafeShellRedirectOccurrences(command, cwd, home string) []RedirectOccurrence {
	return SafeShellRedirectOccurrencesWithFacts(command, cwd, home, nil)
}

// SafeShellRedirectOccurrencesWithFacts uses client source facts when the
// gateway cannot inspect a copy source in the user home.
func SafeShellRedirectOccurrencesWithFacts(command, cwd, home string, facts map[string]string) []RedirectOccurrence {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	writeOccurrences := shellWriteOccurrences(file, cwd, home)
	result := make([]RedirectOccurrence, 0, len(writeOccurrences))
	for _, occurrence := range writeOccurrences {
		if occurrence.Static && occurrence.Path != "" {
			result = append(result, RedirectOccurrence{Path: occurrence.Path, Offset: occurrence.Offset})
		}
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return result
	}
	seenLink := false
	byOffset := make(map[int]int, len(result))
	for i, occurrence := range result {
		byOffset[occurrence.Offset] = i
	}
	for _, stmt := range statements {
		for _, redirect := range stmt.Redirs {
			switch redirect.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			default:
				continue
			}
			offset := -1
			if redirect.Word != nil {
				offset = int(redirect.Word.Pos().Offset())
			}
			if index, ok := byOffset[offset]; ok {
				result[index].Safe = !seenLink
			}
		}
		start, end := int(stmt.Pos().Offset()), int(stmt.End().Offset())
		if start < 0 || end > len(command) || start >= end {
			seenLink = true
			continue
		}
		site := commandLinksWithFacts(command[start:end], cwd, home, facts, false)
		seenLink = seenLink || !site.known || len(site.aliases) > 0
	}
	return result
}

// ArchiveBeforeWrite reports an extraction followed by a shell redirect.
// The redirect on the extracting statement itself opens before extraction.
func ArchiveBeforeWrite(command, home string) bool {
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	statements, linear := linearShellStatements(file)
	if !linear {
		return false
	}
	extracted := false
	for _, stmt := range statements {
		if extracted {
			for _, redirect := range stmt.Redirs {
				switch redirect.Op {
				case syntax.RdrOut, syntax.AppOut, syntax.ClbOut, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
					return true
				}
			}
		}
		call := stmt.Cmd.(*syntax.CallExpr)
		if len(call.Args) == 0 {
			continue
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = StaticWord(arg, home)
		}
		program := programBase(words[0])
		if slices.Contains(multicallPrograms, program) && len(words) > 1 {
			words, static = words[1:], static[1:]
			program = programBase(words[0])
		}
		if slices.Contains(archivePrograms, program) && program != "rsync" &&
			!archiveCopiesLinks(program, words[1:], static[1:]) &&
			(slices.Contains(static[1:], false) || archiveMayLink(program, words[1:], static[1:])) {
			extracted = true
		}
	}
	return false
}

// Links are the links one shell command creates, read as Resolve reads them.
type Links struct {
	links     shellLinks
	protected protectedFiles
}

// CommandLinks reads the links that the shell command of a tool call
// creates. The command of an apply_patch tool is a patch envelope, not shell.
func CommandLinks(tool, command, cwd, home string) Links {
	return CommandLinksWithFacts(tool, command, cwd, home, nil)
}

// CommandLinksWithFacts uses copy-source link evidence from the user-side hook.
func CommandLinksWithFacts(tool, command, cwd, home string, facts map[string]string) Links {
	if command == "" || isApplyPatchToolName(tool) {
		return Links{links: shellLinks{known: true}}
	}
	links := Links{links: commandLinksWithFacts(command, cwd, home, facts, false)}
	if len(links.links.aliases) > 0 {
		links.protected = newProtectedFiles(home)
	}
	return links
}

// OpaqueTarget reports whether an unreadable link operation can affect path.
// Such operations include a wrapper or multicall binary running ln, an
// interpreter or Windows link call, an archive or sync link option, or an mv
// or relative cd with a link. Archive and copy scopes narrow the affected
// paths. A program word that is not static alone does not count (GAP-1523).
func (l Links) OpaqueTarget(path string) bool {
	return l.links.opaqueTarget(path)
}

// OpaqueTargetExceptOwnCopy checks all scopes except the scope created by
// this copy statement for its own destination.
func (l Links) OpaqueTargetExceptOwnCopy(path, ownCopy string) bool {
	return l.links.opaqueTargetExceptCopy(path, ownCopy)
}

// Target maps an absolute write operand through the links the command
// creates as Resolve does: a name that reaches one of the user's
// authorized-keys files maps to that file. ok is false when one of the names
// cannot be resolved.
func (l Links) Target(path string) (string, bool) {
	if len(l.links.aliases) == 0 {
		return path, true
	}
	return l.links.resolve(path, l.protected)
}

// copyLinkOptions reports a cp call with a static link option, and one with
// a word that is not static and may expand to an option.
func copyLinkOptions(args []*syntax.Word, words []string, static []bool) (option, dynamic bool) {
	for i, word := range words {
		if !static[i] {
			lit, isLit := args[i].Parts[0].(*syntax.Lit)
			dynamic = dynamic || !isLit || strings.HasPrefix(lit.Value, "-")
			continue
		}
		if word == "--" {
			break
		}
		option = option || copyLinkOption.MatchString(word)
	}
	return option, dynamic
}

func copyDestination(args []string, static []bool, cwd string) string {
	for i := len(args) - 1; i >= 0; i-- {
		if !static[i] {
			return ""
		}
		if args[i] == "--" {
			continue
		}
		if !strings.HasPrefix(args[i], "-") {
			path := args[i]
			if !filepath.IsAbs(path) {
				path = filepath.Join(cwd, path)
			}
			return filepath.Clean(path)
		}
	}
	return ""
}

// cpOperands reads the options that can change source and destination
// positions. Unknown or dynamic options make the destination unbounded.
func cpOperands(args []string, static []bool) (sources []string, destination string, preserves bool, ok bool) {
	var operands []string
	targetDir := ""
	options := true
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return nil, "", true, false
		}
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if !options || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, joined := strings.Cut(arg[2:], "=")
			option, unique := longOption(name, cpLongOptions)
			if !unique || option == "" {
				return nil, "", true, false
			}
			switch option {
			case "archive", "recursive", "no-dereference":
				preserves = true
			case "preserve":
				if joined && (value == "links" || strings.Contains(","+value+",", ",links,")) {
					preserves = true
				}
			case "target-directory", "suffix":
				if !joined {
					i++
					if i >= len(args) || !static[i] {
						return nil, "", true, false
					}
					value = args[i]
				}
				if value == "" {
					return nil, "", true, false
				}
				if option == "target-directory" {
					targetDir = value
				}
			case "no-preserve", "sparse", "reflink", "backup", "update", "context":
				// These take only an optional joined value.
			default:
				if joined {
					return nil, "", true, false
				}
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch arg[j] {
			case 'a', 'P', 'd', 'r', 'R':
				preserves = true
			case 't', 'S':
				value := arg[j+1:]
				if value == "" {
					i++
					if i >= len(args) || !static[i] {
						return nil, "", true, false
					}
					value = args[i]
				}
				if value == "" {
					return nil, "", true, false
				}
				if arg[j] == 't' {
					targetDir = value
				}
				j = len(arg)
			case 'b', 'f', 'H', 'i', 'L', 'l', 'n', 'p', 's', 'T', 'u', 'v', 'x':
			default:
				return nil, "", true, false
			}
		}
	}
	if targetDir != "" {
		if len(operands) == 0 {
			return nil, "", preserves, false
		}
		return operands, targetDir, preserves, true
	}
	if len(operands) < 2 {
		return nil, "", preserves, false
	}
	return operands[:len(operands)-1], operands[len(operands)-1], preserves, true
}

func cpDestination(args []string, static []bool, cwd string) string {
	_, destination, _, ok := cpOperands(args, static)
	if !ok {
		return ""
	}
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	return filepath.Clean(destination)
}

func envCommandWords(words []string, cwd string) (string, []string, bool) {
	if len(words) == 0 || programBase(words[0]) != "env" {
		return cwd, words, true
	}
	cmdCWD := cwd
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			if i+1 >= len(words) {
				return cmdCWD, nil, true
			}
			return cmdCWD, words[i+1:], true
		case word == "-C" || word == "--chdir":
			i++
			if i >= len(words) || words[i] == "" {
				return cmdCWD, nil, false
			}
			cmdCWD = OperandPath(words[i], cwd)
		case strings.HasPrefix(word, "--chdir="):
			value := strings.TrimPrefix(word, "--chdir=")
			if value == "" {
				return cmdCWD, nil, false
			}
			cmdCWD = OperandPath(value, cwd)
		case strings.HasPrefix(word, "-C") && len(word) > 2:
			cmdCWD = OperandPath(word[2:], cwd)
		case strings.Contains(word, "=") && !strings.HasPrefix(word, "-"):
			continue
		case strings.HasPrefix(word, "-"):
			return cmdCWD, nil, false
		default:
			return cmdCWD, words[i:], true
		}
	}
	return cmdCWD, nil, true
}

func teeDestinations(args []string) []string {
	var destinations []string
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--output-error") {
			if arg == "--output-error" {
				i++
			}
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		destinations = append(destinations, arg)
	}
	return destinations
}

func finalOperandDestination(args []string, cwd string) string {
	destination := ""
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			if arg == "-t" || arg == "--target-directory" {
				i++
			}
			continue
		}
		destination = arg
	}
	if destination == "" {
		return ""
	}
	return OperandPath(destination, cwd)
}

func truncateFiles(args []string) []string {
	var files []string
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && (arg == "-s" || arg == "--size" || arg == "-o" || arg == "--io-blocks") {
			i++
			continue
		}
		if options && (strings.HasPrefix(arg, "--size=") || strings.HasPrefix(arg, "-s") && len(arg) > 2) {
			continue
		}
		if options && strings.HasPrefix(arg, "-") && arg != "-" {
			continue
		}
		files = append(files, arg)
	}
	return files
}

func tarExplicitExtractMembers(program string, args []string, cwd string) []string {
	static := makeStatic(len(args))
	if !archiveMayLink(program, args, static) {
		return nil
	}
	destination, ok := tarDestination(args, static, cwd)
	if !ok {
		return nil
	}
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	destination = filepath.Clean(destination)
	var members []string
	options := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if options && arg == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(arg, "--") {
			name, _, joined := strings.Cut(arg[2:], "=")
			option, unique := longOption(name, []string{
				"file", "directory", "dir", "cd", "one-top-level", "strip-components", "exclude",
				"absolute-names", "get", "extract", "list", "create", "zstd",
			})
			if !unique {
				return nil
			}
			switch option {
			case "file", "directory", "dir", "cd", "one-top-level", "strip-components", "exclude":
				if !joined {
					i++
				}
			}
			continue
		}
		oldStyle := options && i == 0 && !strings.HasPrefix(arg, "-")
		if options && (oldStyle || strings.HasPrefix(arg, "-") && arg != "-") {
			cluster := strings.TrimPrefix(arg, "-")
			for j := 0; j < len(cluster); j++ {
				if strings.ContainsRune("fCXTbIKNgVHFL", rune(cluster[j])) {
					if oldStyle || j+1 == len(cluster) {
						i++
					}
					if !oldStyle {
						break
					}
				}
			}
			continue
		}
		members = append(members, arg)
	}
	operands := make([]string, 0, len(members))
	for _, member := range members {
		if member == "" || !shellAuthorizedKeysBase(member) {
			continue
		}
		operands = append(operands, OperandPath(member, destination))
	}
	return operands
}

// CopyDestination returns a statically understood cp destination.
func CopyDestination(argv []string, cwd string) string {
	if len(argv) < 2 || !slices.Contains(copyPrograms, programBase(argv[0])) {
		return ""
	}
	return cpDestination(argv[1:], makeStatic(len(argv)-1), cwd)
}

func cpDiskSymlink(args []string, static []bool, cwd, home string, facts map[string]string, record bool) bool {
	sources, _, _, ok := cpOperands(args, static)
	if !ok {
		return true
	}
	for _, source := range sources {
		if diskSourceMayLink(source, cwd, home, facts, record, os.Lstat) {
			return true
		}
	}
	return false
}

func copiesDiskSymlink(args []string, static []bool, cwd, home string, facts map[string]string, record bool) bool {
	operands := make([]string, 0, len(args))
	for i, arg := range args {
		if !static[i] || strings.HasPrefix(arg, "-") {
			continue
		}
		operands = append(operands, arg)
	}
	if len(operands) < 2 {
		// cpio/pax can take source names from stdin. A later write into the
		// destination must not assume those names were regular files.
		return true
	}
	for _, source := range operands[:len(operands)-1] {
		if diskSourceMayLink(source, cwd, home, facts, record, os.Lstat) {
			return true
		}
	}
	return false
}

func diskSourceMayLink(source, cwd, home string, facts map[string]string, record bool, lstat func(string) (os.FileInfo, error)) bool {
	path := OperandPath(source, cwd)
	key := SourceLinkFactPrefix + path
	if !record && facts != nil {
		if fact, ok := facts[key]; ok {
			return fact != "0"
		}
	}
	info, err := lstat(path)
	if err == nil {
		linked := info.Mode()&os.ModeSymlink != 0 || info.IsDir() && treeHasSymlink(path)
		if record {
			if linked {
				facts[key] = "1"
			} else {
				facts[key] = "0"
			}
		}
		return linked
	}
	if record {
		if os.IsNotExist(err) {
			facts[key] = "0"
			return false
		}
		facts[key] = "?"
		return true
	}
	// An older hook has no fact. ProtectHome and PrivateTmp turn even an
	// existing source into ENOENT for the gateway.
	return runtime.GOOS == "linux" &&
		((home != "" && (path == home || strings.HasPrefix(path, home+string(filepath.Separator)))) ||
			path == "/home" || strings.HasPrefix(path, "/home/") ||
			path == "/tmp" || strings.HasPrefix(path, "/tmp/") ||
			path == "/var/tmp" || strings.HasPrefix(path, "/var/tmp/"))
}

// treeHasSymlink reports a link inside a directory a recursive copy keeps.
// A tree that cannot be read or is larger than the bound counts as one.
func treeHasSymlink(root string) bool {
	seen, found := 0, false
	err := filepath.WalkDir(root, func(_ string, entry fs.DirEntry, err error) error {
		seen++
		if err != nil || seen > 4096 || entry.Type()&fs.ModeSymlink != 0 {
			found = true
			return filepath.SkipAll
		}
		return nil
	})
	return found || err != nil
}

// archiveDestination is the directory an archive call writes in, or "" when
// it can write anywhere.
func archiveDestination(program string, args []string, static []bool, cwd string) string {
	if program != "rsync" && !archiveCopiesLinks(program, args, static) && archiveNamesEscape(program, args, static) {
		return ""
	}
	destination := cwd
	if strings.HasSuffix(program, "tar") {
		var ok bool
		destination, ok = tarDestination(args, static, cwd)
		if !ok {
			return ""
		}
	} else if program == "rsync" || (program == "pax" || program == "cpio" || program == "bsdcpio") && archiveCopiesLinks(program, args, static) {
		return copyDestination(args, static, cwd)
	} else if program == "unzip" || program == "cpio" || program == "bsdcpio" || strings.HasPrefix(program, "7z") {
		for i, arg := range args {
			option := ""
			switch {
			case program == "unzip" && arg == "-d":
				option = "-d"
			case (program == "cpio" || program == "bsdcpio") && (arg == "-D" || arg == "--directory"):
				option = arg
			case strings.HasPrefix(program, "7z") && arg == "-o":
				option = "-o"
			}
			if option != "" && i+1 < len(args) {
				if !static[i+1] {
					return ""
				}
				destination = args[i+1]
			} else if program == "unzip" && strings.HasPrefix(arg, "-d") && len(arg) > 2 {
				if !static[i] {
					return ""
				}
				destination = arg[2:]
			} else if strings.HasPrefix(program, "7z") && strings.HasPrefix(arg, "-o") && len(arg) > 2 {
				destination = arg[2:]
			}
		}
	}
	if !filepath.IsAbs(destination) {
		destination = filepath.Join(cwd, destination)
	}
	return filepath.Clean(destination)
}

// tarDestination reads destination-bearing tar options in short clusters,
// old-style option words, and unique long-option abbreviations. Ambiguity
// leaves the archive scope global.
func tarDestination(args []string, static []bool, cwd string) (string, bool) {
	destination := cwd
	changed := false
	consume := func(value string) bool {
		if value == "" || changed {
			return false
		}
		destination, changed = value, true
		return true
	}
	options := true
	for i := 0; i < len(args); i++ {
		if !static[i] {
			return "", false
		}
		arg := args[i]
		if arg == "--" {
			options = false
			continue
		}
		if !options {
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, joined := strings.Cut(arg[2:], "=")
			option, unique := longOption(name, []string{"directory", "dir", "cd", "one-top-level"})
			if !unique {
				return "", false
			}
			switch option {
			case "directory", "dir", "cd":
				if !joined {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
					value = args[i]
				}
				if !consume(value) {
					return "", false
				}
			case "one-top-level":
				if joined && !consume(value) {
					return "", false
				}
			default:
				// A future or unknown destination option cannot be scoped safely.
				return "", false
			}
			continue
		}
		oldStyle := i == 0 && !strings.HasPrefix(arg, "-")
		if !oldStyle && !strings.HasPrefix(arg, "-") {
			continue
		}
		cluster := strings.TrimPrefix(arg, "-")
		for j := 0; j < len(cluster); j++ {
			switch cluster[j] {
			case 'C':
				value := cluster[j+1:]
				if oldStyle || value == "" {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
					value = args[i]
				}
				if !consume(value) {
					return "", false
				}
				if !oldStyle {
					j = len(cluster)
				}
			case 'f':
				if oldStyle || j+1 == len(cluster) {
					i++
					if i >= len(args) || !static[i] {
						return "", false
					}
				}
				if !oldStyle {
					j = len(cluster)
				}
			case 'x', 'z', 'j', 'J', 'v', 'O', 't', 'c', 'P', 'p', 'h', 'k', 'm', 'w', 'U':
			default:
				// Unknown short options may consume a path.
				return "", false
			}
		}
	}
	return destination, true
}

// opaqueProgram is a Windows program that creates links from operands this
// package does not read.
func opaqueProgram(program string) bool {
	switch program {
	case "mklink", "fsutil", "new-item":
		return true
	}
	return false
}

// archiveNamesEscape reports an extraction whose member names can leave the
// destination: cpio and pax keep absolute and parent names by default, as do
// tar -P, unzip -: and 7z -spf; an option supplied at runtime may be one.
func archiveNamesEscape(program string, args []string, static []bool) bool {
	if program == "cpio" || program == "bsdcpio" || program == "pax" {
		return true
	}
	tar := strings.HasSuffix(program, "tar")
	for i, arg := range args {
		if !static[i] {
			return true
		}
		if arg == "--" {
			return false
		}
		short := strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--")
		switch {
		case tar && (arg == "--absolute-names" || short && strings.ContainsRune(arg, 'P') ||
			i == 0 && !strings.HasPrefix(arg, "-") && strings.ContainsRune(arg, 'P')),
			program == "unzip" && short && strings.ContainsRune(arg, ':'),
			strings.HasPrefix(program, "7z") && strings.HasPrefix(arg, "-spf"):
			return true
		}
	}
	return false
}

func copyPreservesLinks(args []string, static []bool) bool {
	_, _, preserves, _ := cpOperands(args, static)
	return preserves
}

func archiveCopiesLinks(program string, args []string, static []bool) bool {
	if program == "rsync" {
		for i, arg := range args {
			if static[i] && (arg == "--links" || arg == "--archive" ||
				strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsAny(arg[1:], "al")) {
				return true
			}
		}
	}
	if program == "cpio" || program == "bsdcpio" || program == "pax" {
		for i, arg := range args {
			if static[i] && strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") &&
				(program == "pax" && strings.ContainsRune(arg, 'w') || strings.ContainsRune(arg, 'p')) {
				return true
			}
		}
	}
	return false
}

// archiveMayLink reports an archive or sync call that can create links.
func archiveMayLink(program string, args []string, static []bool) bool {
	tar := strings.HasSuffix(program, "tar")
	cpio := program == "cpio" || program == "bsdcpio"
	pax := program == "pax"
	if program == "unzip" || strings.HasPrefix(program, "7z") {
		// Listing and test modes do not extract. 7z needs an x or e command.
		if program == "unzip" {
			for i, arg := range args {
				if static[i] && (arg == "-l" || arg == "-t" || arg == "-Z") {
					return false
				}
			}
			return true
		}
		for i, arg := range args {
			if static[i] && (arg == "x" || arg == "e") {
				return true
			}
		}
		return false
	}
	for i, arg := range args {
		if !static[i] {
			continue
		}
		if arg == "--" {
			return false
		}
		if long, ok := strings.CutPrefix(arg, "--"); ok {
			name, _, _ := strings.Cut(long, "=")
			switch {
			case program == "rsync" && (name == "link-dest" || name == "hard-links"),
				cpio && (name == "link" || name == "extract"),
				tar && (name == "get" || len(name) >= 3 && strings.HasPrefix("extract", name)):
				return true
			}
			continue
		}
		cluster, option := strings.CutPrefix(arg, "-")
		switch {
		case !option:
			if i == 0 && tar && tarExtracts(arg) {
				return true
			}
		case program == "rsync" && strings.ContainsRune(cluster, 'H'),
			cpio && strings.ContainsAny(cluster, "il"),
			pax && strings.ContainsAny(cluster, "rl"),
			tar && tarExtracts(cluster):
			return true
		}
	}
	return false
}

// tarExtracts reports x in a tar option cluster, before an option that takes
// the rest of the word as its value.
func tarExtracts(cluster string) bool {
	for _, c := range cluster {
		switch {
		case c == 'x':
			return true
		case strings.ContainsRune("fCTXbIKNgVHFL", c):
			return false
		}
	}
	return false
}

func makeStatic(n int) []bool {
	static := make([]bool, n)
	for i := range static {
		static[i] = true
	}
	return static
}

// wrappedMayLink reads the words of a wrapper's text from the first ln, cp,
// or archive program on as that program's arguments and reports one that can
// link files; for cp a word with a parameter or a substitution counts as a
// link option. copyWord reports that a cp program word was found.
func wrappedMayLink(text string) (mayLink, copyWord bool) {
	words := strings.FieldsFunc(text, func(r rune) bool {
		return unicode.IsSpace(r) || strings.ContainsRune("\"'`;&|(){}<>=", r)
	})
	for i, word := range words {
		program, rest := programBase(word), words[i+1:]
		switch {
		case slices.Contains(linkPrograms, program):
			return true, copyWord
		case slices.Contains(copyPrograms, program):
			for _, arg := range rest {
				if strings.ContainsAny(arg, "$`") || copyLinkOption.MatchString(arg) {
					return true, true
				}
			}
			copyWord = true
		case slices.Contains(archivePrograms, program) && archiveMayLink(program, rest, makeStatic(len(rest))):
			return true, copyWord
		}
	}
	return false, copyWord
}

// programBase is a program's lowercased basename without ".exe".
func programBase(word string) string {
	if index := strings.LastIndexAny(word, `/\`); index >= 0 {
		word = word[index+1:]
	}
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

// Long options of ln and cp that matter here, and the flags that share their
// prefixes; GNU accepts any unambiguous abbreviation.
var (
	lnLongOptions = []string{"symbolic", "relative", "no-target-directory", "target-directory", "suffix",
		"force", "no-dereference", "backup", "interactive", "logical", "physical", "verbose", "directory",
		"help", "version"}
	cpLongOptions = []string{"link", "symbolic-link", "no-target-directory", "target-directory", "suffix",
		"sparse", "no-preserve", "archive", "attributes-only", "backup", "copy-contents", "debug",
		"dereference", "force", "interactive", "keep-directory-symlink", "no-clobber", "no-dereference",
		"preserve", "parents", "recursive", "reflink", "remove-destination", "strip-trailing-slashes",
		"update", "verbose", "one-file-system", "context", "help", "version"}
	optionsWithValue = []string{"target-directory", "suffix", "sparse", "no-preserve"}
)

// longOption expands an abbreviated long option. ok is false when it is
// ambiguous; an unknown option is a flag.
func longOption(name string, options []string) (string, bool) {
	if slices.Contains(options, name) {
		return name, true
	}
	match := ""
	for _, option := range options {
		if strings.HasPrefix(option, name) {
			if match != "" {
				return "", false
			}
			match = option
		}
	}
	return match, true
}

// add records the links that one ln, link or cp call creates. It returns
// false when its options or operands are not understood.
func (l *shellLinks) add(program string, args []string, cwd string) bool {
	if program == "link" || program == "glink" {
		if len(args) != 2 || strings.HasPrefix(args[0], "-") {
			return false
		}
		l.record(args[0], args[1], false, cwd)
		return true
	}
	copyCall := slices.Contains(copyPrograms, program)
	options := lnLongOptions
	if copyCall {
		options = cpLongOptions
	}
	hard, symbolic, relative, noTargetDir := false, false, false, false
	var targetDir string
	var operands []string
	optionsEnd := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if optionsEnd || arg == "-" || !strings.HasPrefix(arg, "-") {
			operands = append(operands, arg)
			continue
		}
		if arg == "--" {
			optionsEnd = true
			continue
		}
		if strings.HasPrefix(arg, "--") {
			name, value, hasValue := strings.Cut(arg[2:], "=")
			option, ok := longOption(name, options)
			if !ok {
				return false
			}
			if slices.Contains(optionsWithValue, option) && !hasValue {
				if i++; i >= len(args) {
					return false
				}
				value = args[i]
			}
			switch option {
			case "symbolic", "symbolic-link":
				symbolic = true
			case "link":
				hard = true
			case "relative":
				relative = true
			case "no-target-directory":
				noTargetDir = true
			case "target-directory":
				targetDir = value
			}
			continue
		}
		for j := 1; j < len(arg); j++ {
			switch c := arg[j]; {
			case c == 's':
				symbolic = true
			case c == 'l' && copyCall:
				hard = true
			case c == 'r' && !copyCall:
				relative = true
			case c == 'T':
				noTargetDir = true
			case c == 't' || c == 'S':
				value := arg[j+1:]
				if value == "" {
					if i++; i >= len(args) {
						return false
					}
					value = args[i]
				}
				if c == 't' {
					targetDir = value
				}
				j = len(arg)
			}
		}
	}
	if copyCall && !hard && !symbolic {
		return true
	}
	sources, dest, dir := operands, "", targetDir
	switch {
	case targetDir != "":
	case len(operands) == 1 && !copyCall:
		dir = cwd
		l.relative = true
	case len(operands) == 2:
		sources, dest = operands[:1], operands[1]
		if !noTargetDir {
			// The name is a directory when it exists as one.
			dir = dest
		}
	case len(operands) > 2:
		sources, dir = operands[:len(operands)-1], operands[len(operands)-1]
	}
	// A symbolic link stores its target as written, relative to the link's
	// directory; ln -r, a hard link and cp --link name the source file.
	literal := symbolic && !relative
	for _, source := range sources {
		if dest != "" {
			l.record(source, dest, literal, cwd)
		}
		if dir != "" {
			l.record(source, filepath.Join(dir, filepath.Base(filepath.Clean(source))), literal, cwd)
		}
	}
	return true
}

// record adds the alias that a link at name to source creates, under the
// literal name and the name with its directory's existing links resolved.
func (l *shellLinks) record(source, name string, literal bool, cwd string) {
	if source == "" || name == "" {
		return
	}
	l.relative = l.relative || !filepath.IsAbs(source) || !filepath.IsAbs(name)
	name = absolutePath(name, cwd)
	target := source
	if !filepath.IsAbs(target) {
		base := cwd
		if literal {
			base = filepath.Dir(name)
		}
		target = base + string(filepath.Separator) + target
	}
	l.aliases = append(l.aliases, linkAlias{name: name, target: target})
	if dir, ok := resolveWritePath(filepath.Dir(name), 0); ok {
		if resolved := filepath.Join(dir, filepath.Base(name)); resolved != name {
			l.aliases = append(l.aliases, linkAlias{name: resolved, target: target})
		}
	}
}

func absolutePath(path, cwd string) string {
	if !filepath.IsAbs(path) {
		path = filepath.Join(cwd, path)
	}
	return filepath.Clean(path)
}

// maxLinkAliasSteps bounds the names one write operand is followed through.
const maxLinkAliasSteps = 256

// resolve maps an absolute write operand to its target as resolveWritePath
// and protectedFiles.target do, and also through the links the command
// creates: when a name the operand may denote, itself or under a linked
// directory, reaches a protected file, that file is the target. ok is false
// when one of those names cannot be resolved.
func (l shellLinks) resolve(path string, protected protectedFiles) (string, bool) {
	target := func(path string) (string, bool) {
		resolved, ok := resolveWritePath(path, 0)
		if ok {
			resolved, ok = protected.target(resolved)
		}
		return resolved, ok
	}
	resolved, ok := target(path)
	if !ok || len(l.aliases) == 0 || protected.has(resolved) {
		return resolved, ok
	}
	seen := map[string]bool{path: true}
	queue := []string{path}
	for steps := 0; len(queue) > 0; {
		name := queue[0]
		queue = queue[1:]
		forms := []string{name}
		if dir, ok := resolveWritePath(filepath.Dir(name), 0); ok {
			forms = append(forms, filepath.Join(dir, filepath.Base(name)))
		}
		if full, ok := resolveWritePath(name, 0); ok {
			forms = append(forms, full)
		}
		for _, form := range forms {
			for _, alias := range l.aliases {
				rest, under := cutPathPrefix(form, alias.name)
				if !under {
					continue
				}
				next := alias.target
				if rest != "" {
					next += string(filepath.Separator) + rest
				}
				if seen[next] {
					continue
				}
				seen[next] = true
				if steps++; steps > maxLinkAliasSteps {
					return "", false
				}
				linked, ok := target(next)
				if !ok {
					return "", false
				}
				if protected.has(linked) {
					return linked, true
				}
				queue = append(queue, next)
			}
		}
	}
	return resolved, true
}

// cutPathPrefix returns the rest of path under prefix. Names compare without
// case on macOS and Windows, whose file systems usually ignore it.
func cutPathPrefix(path, prefix string) (string, bool) {
	if len(path) < len(prefix) || !samePathName(path[:len(prefix)], prefix) {
		return "", false
	}
	rest := path[len(prefix):]
	if rest == "" {
		return "", true
	}
	if !os.IsPathSeparator(rest[0]) {
		return "", false
	}
	return rest[1:], true
}

func samePathName(a, b string) bool {
	if runtime.GOOS == "darwin" || runtime.GOOS == "windows" {
		return strings.EqualFold(a, b)
	}
	return a == b
}
