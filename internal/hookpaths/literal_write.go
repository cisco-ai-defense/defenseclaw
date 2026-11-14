// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

var (
	literalOpenCall = lazyregexp.New(`\b(?:open|File\.open|fs\.openSync|os\.open|(?:io\.)?FileIO)\s*\(`)
	// The writer APIs whose first argument is the file they write. writeFile
	// and appendFile are Node's callback and fs.promises forms (GAP-0366).
	literalWriteCall      = lazyregexp.New(`\b(?:appendFileSync|writeFileSync|appendFile|writeFile|File\.write|File\.binwrite)\s*\(`)
	literalNodeStream     = lazyregexp.New(`\brequire\s*\(\s*['"]fs['"]\s*\)\s*\.createWriteStream\s*\(`)
	literalPathWrite      = lazyregexp.New(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.write_(?:text|bytes)\s*\(`)
	literalPathOpen       = lazyregexp.New(`\b(?:pathlib\.)?Path\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\.open\s*\(\s*['"]([waxr][waxr+bt]*)['"]\s*\)`)
	literalPythonPathCall = lazyregexp.New(`\b(?:pathlib\.)?Path\s*\(`)
	literalPerlOpen       = lazyregexp.New(`\bopen\s+(?:my\s+)?(?:\$?\w+)\s*,\s*['"](?:>>|>)['"]\s*,\s*['"]([^'"]+)['"]`)
	// The copy and move APIs whose second argument is the file they write;
	// literalCopyAPI says which names each language really has
	// (rel-1-0-2:GAP-0429).
	literalCopyCall         = lazyregexp.New(`\b(?:shutil\.(?:copyfile|copy2|copy|move)|copyFileSync|copyFile|cpSync|copyfile|copy2|FileUtils\.(?:copy_file|copy|cp|install|move|mv)|IO\.copy_stream|(?:File::Copy::)?(?:copy|cp|move|mv))\s*\(`)
	literalPythonCopyImport = lazyregexp.New(`\bfrom\s+shutil\s+import\s+copyfile\b`)
	literalPerlCopy         = lazyregexp.New(`\b((?:File::Copy::)?(?:copy|cp|move|mv))\s+['"][^'"]+['"]\s*,\s*(['"][^'"]+['"])`)
	literalPerlImport       = lazyregexp.New(`\buse\s+File::Copy\b`)
)

// LiteralWriteOperands lists fixed write paths inside a directly invoked
// interpreter, awk program, or sed in-place command. The shell and gateway
// call this same extractor before resolving each operand through links.
func LiteralWriteOperands(command, cwd, home string) (operands []string) {
	return literalWriteOperandsDepth(command, cwd, home, 0)
}

// KnownWriteOperands reads concrete writer targets with the values supplied
// by a tool's execution environment. include lets the caller retain targets
// in an active state root outside the account's default protected file set.
// It is consulted only for resolved writer operands, never for assignments
// or read-only arguments.
func KnownWriteOperands(command, cwd, home string, environment map[string]string, include func(string) bool) []string {
	operands, _ := literalWriteOperandsWithParsedKnown(command, cwd, home, 0, nil, actionValues(environment), include)
	return operands
}

// KnownProtectedWriteTarget applies the shared writer readers to a tool
// command with its known environment. include checks the active protected
// root in addition to the hook's built-in protected file set.
func KnownProtectedWriteTarget(command, cwd, home string, environment map[string]string, include func(string) bool) bool {
	for _, path := range KnownWriteOperands(command, cwd, home, environment, include) {
		if include != nil && include(path) {
			return true
		}
	}
	return false
}

// LiteralWriteOperandsWithCopies is LiteralWriteOperands that also lists,
// once for each call, the operands a plain cp call of the command names as
// its own destination. Only that write of the cp may skip the own copy
// scope of the cp, as the path facts of the same call do (GAP-2582).
func LiteralWriteOperandsWithCopies(command, cwd, home string) (operands, copies []string) {
	return literalWriteOperandsWithCopies(command, cwd, home, 0)
}

func literalWriteOperandsDepth(command, cwd, home string, depth int) []string {
	operands, _ := literalWriteOperandsWithCopies(command, cwd, home, depth)
	return operands
}

func literalWriteOperandsWithCopies(command, cwd, home string, depth int) (operands, copies []string) {
	return literalWriteOperandsWithParsed(command, cwd, home, depth, nil)
}

// literalWriteOperandsWithParsed reuses a shell tree already parsed for this
// command. Nested interpreter bodies still get their own parse.
func literalWriteOperandsWithParsed(command, cwd, home string, depth int, file *syntax.File) (operands, copies []string) {
	return literalWriteOperandsWithParsedKnown(command, cwd, home, depth, file, nil, nil)
}

func literalWriteOperandsWithParsedKnown(command, cwd, home string, depth int, file *syntax.File, initial actionValues, include func(string) bool) (operands, copies []string) {
	if depth > 4 {
		return nil, nil
	}
	if file == nil {
		var ok bool
		file, ok = parseShell(command)
		if !ok {
			return nil, nil
		}
	}
	add := func(name string) bool {
		if name == "" || strings.ContainsAny(name, "\x00\r\n") {
			return false
		}
		if !filepath.IsAbs(name) && !filepath.IsAbs(cwd) {
			return false
		}
		operands = append(operands, OperandPath(name, cwd))
		return true
	}
	boundName, boundValue := boundedProgramAssignment(file, home)
	// Read each top-level statement with the values that precede it. The
	// candidates are immutable until this statement has been walked, so
	// there is no per-statement snapshot of cloned candidate maps.
	values := actionValues{"HOME": home, "PWD": cwd}
	if initial != nil {
		values = maps.Clone(initial)
		if _, ok := values["HOME"]; !ok {
			values["HOME"] = home
		}
		values["PWD"] = cwd
	}
	// The gateway blocks a command past this statement limit regardless of
	// its concrete target. Keep the forgetting reading, but do not expand
	// candidates for a command already over the limit. Short calls take the
	// normal path without another parse.
	trackKept := len(command) < 1024 || !actionfacts.ShellStatementsOverBudget(command)
	var kept []actionValues
	if trackKept {
		if initial == nil {
			kept = []actionValues{{"HOME": home, "PWD": cwd}}
		} else {
			kept = []actionValues{maps.Clone(values)}
		}
	}
	steps := 0
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	// A definition runs nothing. A body is read once, where it is defined,
	// when the command may call it, so an uncalled body stays inert.
	called := calledFunctions(file, home)
	functions := map[string]*syntax.FuncDecl{}
	redefined := map[string]bool{}
	if include != nil {
		for _, root := range file.Stmts {
			if function, ok := root.Cmd.(*syntax.FuncDecl); ok && function.Name != nil {
				redefined[function.Name.Value] = functions[function.Name.Value] != nil
				functions[function.Name.Value] = function
			}
		}
	}
	// A call is read where it runs: the effective directory goes into the
	// launcher descent (a shell -c body, eval), so a script the body names is
	// the file of that name where the call stands, not in the folder the hook
	// started in. Where the call runs in no other folder, the starting folder
	// is the only reading (rel-1-0-9:GAP-1038).
	placed := newPlacedCalls(file, command, cwd, home)
	programOperands := func(words []string, stmt *syntax.Stmt, call *syntax.CallExpr, environment actionValues) []string {
		readFiles := len(file.Stmts) == 1
		dirs := placed.of(call)
		if len(dirs) == 1 && dirs[0] == cwd {
			return literalProgramOperandsKnown(words, stmt, cwd, home, depth, readFiles, environment, include)
		}
		var names []string
		for _, dir := range dirs {
			names = append(names, literalProgramOperandsKnown(words, stmt, dir, home, depth, readFiles, environment, include)...)
		}
		return names
	}
	var knownValues map[*syntax.Word]string
	knownValuesRead := false
	var shadow *knownShadow
	if include != nil {
		shadow = newKnownShadow(file, home)
	}
	for _, root := range file.Stmts {
		if depth >= 4 || !knownReachedCompound(root) {
			// The reader scans the statements of a compound command as it
			// reaches them.
			shadow.scan(root)
		}
		candidates := append([]actionValues{values}, kept...)
		if initial != nil && len(kept) > 0 {
			candidates = kept
		}
		saturated := actionKeptSaturated(kept)
		if saturated {
			candidates = candidates[:1]
		}
		if include != nil && depth < 4 && knownReachedCompound(root) {
			// A compound command with known values is read in the order the
			// shell runs it, so a target only an unreached statement names is
			// not a write. Past a reader bound other than the reading count,
			// the whole statement is read below as if every part may run.
			writes, after, complete, continues := knownReachedWrites(root, file, candidates, cwd, home, depth, include, shadow)
			for _, name := range writes {
				add(name)
			}
			if complete {
				if !continues {
					break
				}
				actionUpdateValues(root, values, cwd, home)
				if trackKept {
					// The reader followed every statement, so its states are the
					// ones a later statement sees; the whole-statement tracker
					// forgets a value at a call of a function the command defines.
					if len(after) != 0 && !actionKeptSaturated(after) {
						kept = after
					} else {
						kept = actionUpdateValuesKept(root, kept, cwd, home, &steps)
					}
				}
				continue
			}
		}
		for _, redirect := range root.Redirs {
			if redirect.Word == nil || !actionOutputRedirect(redirect.Op) {
				continue
			}
			for _, candidate := range candidates {
				if include != nil {
					if value, known := actionClientRedirectWordValue(redirect.Word, candidate, cwd, home); known &&
						include(OperandPath(value, cwd)) {
						add(value)
					}
				}
				if value, possible := actionOptionalEmptyPrefix(redirect.Word, candidate, cwd, home); possible &&
					(protectedReachPath(OperandPath(value, cwd), protected, ssh) || include != nil && include(OperandPath(value, cwd))) {
					add(value)
					break
				}
			}
		}
		syntax.Walk(root, func(node syntax.Node) bool {
			if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
				return declaration.Name != nil && (called[declaration.Name.Value] || called[knownUnshadowed(declaration.Name.Value)])
			}
			stmt, ok := node.(*syntax.Stmt)
			if !ok {
				return true
			}
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			// A copy operand with one known parameter value can also be a
			// brace word. Keep that reading alongside the candidate values.
			var copyValues map[*syntax.Word]string
			if first, ok := StaticWord(call.Args[0], home); ok && slices.Contains(copyPrograms, programBase(first)) {
				if !knownValuesRead {
					knownValues, knownValuesRead = knownWordParameterValues(command, file, home), true
				}
				copyValues = knownValues
			}
			callCandidates := candidates
			if len(callCandidates) > 1 {
				dynamic := false
				for _, arg := range call.Args[1:] {
					if wordExpandsParameter(arg) {
						dynamic = true
						break
					}
				}
				if !dynamic {
					callCandidates = callCandidates[:1]
				}
			}
			added := make(map[string]bool)
			positiveOnly := false
			addCall := func(name string) bool {
				path := OperandPath(name, cwd)
				if positiveOnly && !protectedReachPath(path, protected, ssh) && (include == nil || !include(path)) {
					return false
				}
				if added[path] || !add(name) {
					return false
				}
				added[path] = true
				return true
			}
			if saturated {
				// A name lost at the cap may be a protected writer target.
				// Keep names that still have one certain value, including a
				// straight-line assignment made after saturation.
				probe := filepath.Join(ssh, "authorized_keys")
				words := make([]string, len(call.Args))
				unknown := false
				for i, arg := range call.Args {
					words[i], _ = StaticWord(arg, home)
					if i > 0 && wordExpandsParameter(arg) {
						if value, fixed := actionWordValue(shellUnescapedWord(arg), kept[0], cwd, home); fixed {
							words[i] = value
						} else {
							words[i], unknown = probe, true
						}
					}
				}
				if unknown {
					for _, name := range programOperands(words, stmt, call, initial) {
						if samePathName(OperandPath(name, cwd), probe) {
							addCall(probe)
							break
						}
					}
				}
			}
		candidate:
			for index, known := range callCandidates {
				positiveOnly = index > 0
				callEnvironment := initial
				if initial != nil && len(call.Assigns) > 0 {
					callEnvironment = maps.Clone(initial)
					for _, assignment := range call.Assigns {
						if assignment.Name == nil {
							continue
						}
						if value, fixed := actionWordValue(assignment.Value, known, cwd, home); fixed {
							callEnvironment[assignment.Name.Value] = value
						} else {
							delete(callEnvironment, assignment.Name.Value)
						}
					}
				}
				words := make([]string, len(call.Args))
				// The brace words of a plain cp call, or of another writer, are
				// the fixed words bash makes of them, so its real targets are
				// listed (rel-1-0-6 GAP-0202, GAP-0228): the hook client resolves
				// them like any operand. tee ~/.ssh/authorized_key{s,x} writes the
				// keys file; a managed gateway that cannot search the home only
				// sees the targets the client lists.
				var braces map[int][]string
				var argStatic []bool
				if first, ok := StaticWord(call.Args[0], home); ok && slices.Contains(braceOperandPrograms, programBase(first)) {
					argStatic = make([]bool, len(call.Args))
					for i, arg := range call.Args {
						_, argStatic[i] = StaticWord(arg, home)
						if _, known := copyValues[arg]; known && i > 0 {
							argStatic[i] = true
						}
					}
					braces = copyBraceWordFields(call.Args, argStatic, expand.ListEnviron("HOME="+strings.TrimRight(home, "/")))
				}
				for i, arg := range call.Args {
					var static bool
					words[i], static = StaticWord(arg, home)
					if value, known := copyValues[arg]; known && !static && i > 0 {
						words[i], static = value, true
					}
					if braces[i] != nil {
						continue
					}
					if i == 0 && !static {
						if value, known := actionWordValue(shellUnescapedWord(arg), known, cwd, home); known {
							words[i], static = value, true
						}
					}
					if i == 0 && !static && simpleShellParameter(arg) == boundName {
						words[i], static = boundValue, true
					}
					if !static && i > 0 && wordExpandsParameter(arg) {
						// A newly resolved parameter operand is positive evidence
						// only when it reaches a protected target.
						if value, fixed := actionWordValue(shellUnescapedWord(arg), known, cwd, home); fixed &&
							!strings.Contains(value, actionGeneratedMarker) {
							words[i], static = value, true
							if index == 0 {
								positiveOnly = true
							}
						} else if value, possible := actionOptionalEmptyPrefix(arg, known, cwd, home); possible &&
							(protectedReachPath(OperandPath(value, cwd), protected, ssh) || include != nil && include(OperandPath(value, cwd))) {
							// Only the protected empty-prefix possibility contributes
							// a write. An unknown parameter proves no safe target.
							words[i], static, positiveOnly = value, true, true
						}
					}
					if !static {
						// Interpreter arguments after fixed code do not change that
						// code. Keep its write operands even though argv is dynamic.
						if i > 0 && fixedInterpreterCodePrefix(words[:i]) {
							for _, name := range programOperands(words[:i], stmt, call, callEnvironment) {
								addCall(name)
							}
						} else if i > 0 && awkProgramName(words[0]) {
							// A double-quoted awk program with an expansion: its
							// literal print targets stay targets (GAP-2197).
							if text, rendered := awkRenderedProgram(arg); rendered {
								prefix := append(append([]string(nil), words[:i]...), text)
								for _, name := range programOperands(prefix, stmt, call, callEnvironment) {
									addCall(name)
								}
							}
						} else if include != nil && i > 0 {
							if _, shell := shellCommandBodyIndex(words[:i]); shell {
								for _, name := range programOperands(words[:i], stmt, call, callEnvironment) {
									addCall(name)
								}
							}
						}
						continue candidate
					}
				}
				_, words, _ = spliceCopyBraceWords(call.Args, words, argStatic, braces)
				if include != nil && len(words) > 0 && len(call.Args[0].Parts) == 1 {
					if _, parameter := call.Args[0].Parts[0].(*syntax.ParamExp); parameter {
						if _, changedIFS := known["IFS"]; !changedIFS && strings.ContainsAny(words[0], " \t\n") {
							fields := strings.Fields(words[0])
							if len(fields) > 0 && len(fields) <= 8 {
								words = append(fields, words[1:]...)
							}
						}
					}
				}
				if include != nil && depth < 4 && len(words) > 0 {
					if function := functions[words[0]]; function != nil && function.Body != nil {
						if body, block := function.Body.Cmd.(*syntax.Block); block {
							var source strings.Builder
							if syntax.NewPrinter().Print(&source, &syntax.File{Stmts: body.Stmts}) == nil {
								bindings := maps.Clone(known)
								if bindings == nil {
									bindings = actionValues{}
								}
								for _, assignment := range call.Assigns {
									if assignment.Name == nil {
										continue
									}
									if value, fixed := actionWordValue(assignment.Value, known, cwd, home); fixed {
										bindings[assignment.Name.Value] = value
									} else {
										delete(bindings, assignment.Name.Value)
									}
								}
								for i, argument := range words[1:] {
									bindings[strconv.Itoa(i+1)] = argument
								}
								writes, _ := literalWriteOperandsWithParsedKnown(source.String(), cwd, home, depth+1, nil, bindings, include)
								for _, target := range writes {
									addCall(target)
								}
								continue candidate
							}
						}
					}
				}
				names := programOperands(words, stmt, call, callEnvironment)
				// A plain cp call lists only its own destination; a literal shell
				// body (sh -c BODY) lists the own destinations of its cp calls.
				var own []string
				switch program := programBase(words[0]); program {
				case "cp", "gcp":
					own = names
				case "sh", "bash", "dash", "ash", "zsh", "ksh":
					if body, ok := shellCommandBodyIndex(words); ok {
						_, own = literalWriteOperandsWithParsedKnown(words[body], cwd, home, depth+1, nil, callEnvironment, include)
					}
				}
				credit := make(map[string]int, len(own))
				for _, name := range own {
					credit[OperandPath(name, cwd)]++
				}
				for _, name := range names {
					if addCall(name) && credit[operands[len(operands)-1]] > 0 {
						credit[operands[len(operands)-1]]--
						copies = append(copies, operands[len(operands)-1])
					}
				}
			}
			return true
		})
		if include != nil && knownExitStatement(root, home) {
			break
		}
		actionUpdateValues(root, values, cwd, home)
		if trackKept {
			next := actionUpdateValuesKept(root, kept, cwd, home, &steps)
			if include != nil {
				next = actionKeepAcrossFunctionCall(root, kept, next, func(name string) *syntax.FuncDecl {
					if _, known := functions[name]; !known {
						name = knownUnshadowed(name)
					}
					if redefined[name] {
						return nil
					}
					return functions[name]
				}, cwd, home, &steps)
			}
			kept = next
		}
	}
	operands = append(operands, literalPipelineOperands(file, called, cwd, home, depth)...)
	operands = append(operands, literalGeneratedScriptOperands(file, cwd, home, depth)...)
	return operands, copies
}

// SedReplacedOperands names sed -i operands whose directory entry is
// replaced, so a pre-existing link at that entry is not a target write.
func SedReplacedOperands(command, cwd, home string) map[string]bool {
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	replaced := map[string]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			var static bool
			words[i], static = StaticWord(arg, home)
			if !static {
				return true
			}
		}
		if (programBase(words[0]) == "sed" || programBase(words[0]) == "gsed") &&
			!sedFollowsInPlaceLinks(words) {
			for _, name := range sedInPlaceFiles(words) {
				if !filepath.IsAbs(name) {
					if !filepath.IsAbs(cwd) {
						continue
					}
					name = OperandPath(name, cwd)
				}
				parent, ok := ResolveWriteTarget(rawParent(name))
				if !ok {
					continue
				}
				entry := filepath.Join(parent, filepath.Base(name))
				protected := false
				for _, path := range ProtectedAuthorizedKeysPaths(home) {
					if samePathName(entry, path) {
						protected = true
						break
					}
				}
				if !protected {
					replaced[name] = true
				}
			}
		}
		return true
	})
	return replaced
}

func sedParentProtected(name, cwd, home string) bool {
	parent, ok := ResolveWriteTarget(rawParent(OperandPath(name, cwd)))
	if !ok {
		return true
	}
	entry := filepath.Join(parent, filepath.Base(name))
	for _, path := range ProtectedAuthorizedKeysPaths(home) {
		if samePathName(entry, path) {
			return true
		}
	}
	return false
}

func rawParent(path string) string {
	index := strings.LastIndexAny(path, `/\`)
	if index < 0 {
		return "."
	}
	if index == 0 {
		return path[:1]
	}
	return path[:index]
}

func sedFollowsInPlaceLinks(words []string) bool {
	for _, word := range words[1:] {
		if word == "--" {
			break
		}
		if sedLongOption(word) == "follow-symlinks" {
			return true
		}
	}
	return false
}

// sedLongOptions are the GNU sed long options; getopt_long takes any
// unambiguous prefix of one (--fo is --follow-symlinks, --f is ambiguous).
var sedLongOptions = []string{
	"binary", "debug", "expression", "file", "follow-symlinks", "help", "in-place",
	"line-length", "null-data", "posix", "quiet", "regexp-extended", "sandbox",
	"separate", "silent", "unbuffered", "version", "zero-terminated",
}

// sedLongOption names the long option a --word spells, exactly or as an
// unambiguous prefix, and "" for anything else (GAP-2529).
func sedLongOption(word string) string {
	if !strings.HasPrefix(word, "--") || len(word) < 3 {
		return ""
	}
	name, _, _ := strings.Cut(word[2:], "=")
	match := ""
	for _, option := range sedLongOptions {
		if option == name {
			return option
		}
		if strings.HasPrefix(option, name) {
			if match != "" {
				return ""
			}
			match = option
		}
	}
	return match
}

// InPlaceEditOperands lists the files a sed -i or perl -i call of the
// command edits in place, as absolute paths read in cwd, whatever their
// parent directory, with the known values expanded (knownValueWord; user
// is the login of the statement, PlacedStatement.User). The editor replaces the
// directory entry; a caller that follows the name through a link the same
// command makes to a directory reads the file the edit replaces (GAP-2522).
func InPlaceEditOperands(command, cwd, home string, user KnownUser) []string {
	return inPlaceEditOperands(command, cwd, home, user, false)
}

// FollowedInPlaceEditOperands lists the files a sed -i --follow-symlinks
// (or gsed) call of the command edits, as absolute paths read in cwd. GNU
// sed then rewrites the file a link names instead of replacing the link,
// so a caller follows the operand name itself (GAP-2529).
func FollowedInPlaceEditOperands(command, cwd, home string, user KnownUser) []string {
	return inPlaceEditOperands(command, cwd, home, user, true)
}

func inPlaceEditOperands(command, cwd, home string, user KnownUser, followedOnly bool) (operands []string) {
	readInPlaceEdits(command, cwd, home, user, func(name string, followed bool) {
		if followed || !followedOnly {
			operands = append(operands, name)
		}
	})
	return operands
}

// readInPlaceEdits calls edit with each in-place editor operand of command
// (InPlaceEditOperands), and whether sed follows its links
// (FollowedInPlaceEditOperands).
func readInPlaceEdits(command, cwd, home string, user KnownUser, edit func(name string, followed bool)) {
	file, ok := parseShell(command)
	if !ok || !filepath.IsAbs(cwd) {
		return
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = knownValueWord(arg, home, user)
		}
		if index, wrapped := plainWrappedChild(words, static); wrapped {
			words, static = words[index:], static[index:]
		}
		if slices.Contains(static, false) {
			return true
		}
		var files []string
		followed := false
		switch programBase(words[0]) {
		case "sed", "gsed":
			files, followed = sedInPlaceFiles(words), sedFollowsInPlaceLinks(words)
		case "perl":
			files = perlInPlaceFiles(words)
		}
		for _, name := range files {
			if name != "" && !strings.ContainsAny(name, "\x00\r\n") {
				edit(OperandPath(name, cwd), followed)
			}
		}
		return true
	})
}

// perlInPlaceFiles lists the file operands of perl -i (-pi -e CODE FILE,
// -i.bak -ne CODE FILE). Without -e the first operand is the script.
func perlInPlaceFiles(words []string) []string {
	inPlace, script := false, false
	var files []string
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case word == "--":
			files = append(files, words[i+1:]...)
			i = len(words)
		case strings.HasPrefix(word, "-") && len(word) > 1 && !strings.HasPrefix(word, "--"):
			cluster := word[1:]
			for j := 0; j < len(cluster); j++ {
				switch string(cluster[j]) {
				case "i":
					inPlace = true
					j = len(cluster) // the rest is the backup suffix
				case "e", "E":
					script = true
					if j == len(cluster)-1 {
						i++
					}
					j = len(cluster)
				case "I", "M", "m", "x", "C", "d", "D", "F", "0":
					j = len(cluster) // takes the rest of the word
				}
			}
		case strings.HasPrefix(word, "-"):
			continue
		case !script:
			script = true
		default:
			files = append(files, word)
		}
	}
	if !inPlace {
		return nil
	}
	return files
}

// sedInPlaceFiles lists the file operands of a sed -i call as GNU sed reads
// it (the sed of Linux and gsed). The suffix and the backup names it makes
// come from sedGNUInPlace and sedInPlaceWrites.
func sedInPlaceFiles(words []string) []string {
	files, _, _ := sedGNUInPlace(words)
	return files
}

// sedGNUInPlace reads a sed command line with GNU sed's grammar: the file
// operands the -i or --in-place option edits in place, and its backup suffix
// ("" for none). -i takes the rest of its own word as the suffix, never the
// next word (-i.bak, -ni.bak, --in-place=.bak, --in=.bak).
func sedGNUInPlace(words []string) (files []string, suffix string, inPlace bool) {
	script, options := false, true
	operand := func(word string) {
		if !script {
			script = true
			return
		}
		files = append(files, word)
	}
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case !options || !strings.HasPrefix(word, "-"):
			operand(word)
		case word == "-":
			continue
		case word == "--":
			options = false
		case strings.HasPrefix(word, "--"):
			_, value, valued := strings.Cut(word, "=")
			switch sedLongOption(word) {
			case "in-place":
				inPlace, suffix = true, value
			case "expression", "file":
				script = true
				if !valued {
					i++
				}
			case "line-length":
				if !valued {
					i++
				}
			}
		default:
			// A short option cluster (-si, -Ei, -ni): -i takes the rest of
			// the word as its backup suffix; -e, -f and -l take the rest or
			// the next word as their value (GAP-2529, GAP-2531).
		cluster:
			for j := 1; j < len(word); j++ {
				switch word[j] {
				case 'i':
					inPlace, suffix = true, word[j+1:]
					break cluster
				case 'e', 'f', 'l':
					if word[j] != 'l' {
						script = true
					}
					if j == len(word)-1 {
						i++
					}
					break cluster
				}
			}
		}
	}
	if !inPlace {
		return nil, "", false
	}
	return files, suffix, true
}

// sedBSDInPlace reads a sed command line with BSD sed's grammar (macOS
// /usr/bin/sed): -i and -I take the suffix from the rest of their word or,
// when nothing follows them in the word, from the NEXT word (-i .bak; an
// empty next word is no backup; -i -e makes the suffix "-e"). BSD sed has no
// long options, and options end at the first operand. The hook cannot know which sed runs, so
// sedInPlaceWrites judges this reading and the GNU one together.
func sedBSDInPlace(words []string) (files []string, suffix string, inPlace bool) {
	script, options := false, true
	for i := 1; i < len(words); i++ {
		word := words[i]
		switch {
		case !options || !strings.HasPrefix(word, "-") || word == "-":
			options = false
			if !script {
				script = true
			} else {
				files = append(files, word)
			}
		case word == "--":
			options = false
		case strings.HasPrefix(word, "--"):
			return nil, "", false // illegal option: BSD sed runs nothing
		default:
		cluster:
			for j := 1; j < len(word); j++ {
				switch word[j] {
				case 'i', 'I':
					inPlace, suffix = true, word[j+1:]
					if j == len(word)-1 && i+1 < len(words) {
						i++
						suffix = words[i]
					}
					break cluster
				case 'e', 'f':
					script = true
					if j == len(word)-1 {
						i++
					}
					break cluster
				}
			}
		}
	}
	if !inPlace {
		return nil, "", false
	}
	return files, suffix, true
}

// sedInPlaceWrites lists every path a sed -i call can write, as typed (the
// caller resolves them from the working directory): the files it edits and
// the backups its suffix names, under the GNU and the BSD reading of the
// command line. The hook cannot know which sed runs, so a name either
// reading writes is judged. The backup name is what the sed writes:
//
//   - GNU sed 4.9, no "*" in the suffix: the operand as typed plus the
//     suffix; with "*": every "*" is replaced by the operand as typed
//     (directory included), so "bak_*" and sub/f name bak_sub/f.
//   - BSD sed (macOS 15): the operand as typed plus the suffix, verbatim; a
//     "*" is an ordinary character.
//
// Both rules are checked against the real programs by TestSedInPlaceNameRule.
func sedInPlaceWrites(words []string) []string {
	return append(sedGNUWrites(words), sedBSDWrites(words)...)
}

// sedGNUWrites is sedInPlaceWrites under the GNU reading.
func sedGNUWrites(words []string) (writes []string) {
	files, suffix, ok := sedGNUInPlace(words)
	for _, file := range files {
		if !ok || file == "" {
			continue // sed fails on an empty file name and writes nothing
		}
		writes = append(writes, file)
		switch {
		case suffix == "":
		case strings.Contains(suffix, "*"):
			writes = append(writes, strings.ReplaceAll(suffix, "*", file))
		default:
			writes = append(writes, file+suffix)
		}
	}
	return writes
}

// sedBSDWrites is sedInPlaceWrites under the BSD reading.
func sedBSDWrites(words []string) (writes []string) {
	files, suffix, ok := sedBSDInPlace(words)
	for _, file := range files {
		if !ok || file == "" {
			continue
		}
		writes = append(writes, file)
		if suffix != "" {
			writes = append(writes, file+suffix)
		}
	}
	return writes
}

func literalInterpreterWrites(code, language, cwd, home string) []string {
	if len(code) > 16<<10 {
		return nil
	}
	pathString := literalString
	if language == "python" || strings.HasPrefix(language, "python3") {
		pathString = literalPythonString
	}
	var paths []string
	for _, loc := range literalOpenCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		call, ok := literalBoundedCall(code, loc[1]-1)
		if !ok {
			continue
		}
		args := literalCallArgs(call)
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		if (name == "FileIO" || name == "io.FileIO") && language != "python" {
			continue
		}
		switch {
		case name == "os.open" && len(args) >= 2 && literalOSWriteFlags(args[1]):
			if path, ok := pathString(args[0]); ok {
				paths = append(paths, path)
			}
		case name == "open" && len(args) >= 3 && perlRedirectMode(args[1]):
			if mode, ok := literalString(args[1]); ok && (mode == ">" || mode == ">>") {
				if path, ok := pathString(args[2]); ok {
					paths = append(paths, path)
				}
			}
		case len(args) >= 1:
			pathArg := args[0]
			if language == "python" {
				pathArg = literalCallArgument(args, 0, "file")
			}
			modeArg := ""
			if len(args) >= 2 {
				modeArg = args[1]
			}
			for _, arg := range args[1:] {
				if strings.HasPrefix(strings.TrimSpace(arg), "mode=") {
					modeArg = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(arg), "mode="))
				}
			}
			if mode, ok := literalString(modeArg); ok && literalWriteMode(mode) {
				if path, ok := pathString(pathArg); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalWriteCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		if name := strings.TrimSpace(code[loc[0] : loc[1]-1]); (name == "writeFile" || name == "appendFile") && language != "node" {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := pathString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, loc := range literalNodeStream.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) > 0 {
				if path, ok := pathString(args[0]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	perlCopyImported := false
	pythonCopyfileImported := false
	if language == "python" {
		for _, loc := range literalPythonCopyImport.FindAllStringIndex(code, -1) {
			if literalCodePosition(code, loc[0], language) {
				pythonCopyfileImported = true
				break
			}
		}
	}
	if language == "perl" {
		for _, loc := range literalPerlImport.FindAllStringIndex(code, -1) {
			if literalCodePosition(code, loc[0], language) {
				perlCopyImported = true
				break
			}
		}
	}
	for _, loc := range literalCopyCall.FindAllStringIndex(code, -1) {
		if !literalCodePosition(code, loc[0], language) {
			continue
		}
		name := strings.TrimSpace(code[loc[0] : loc[1]-1])
		if !literalCopyAPI(language, name, perlCopyImported) &&
			(language != "python" || name != "copyfile" || !pythonCopyfileImported) {
			continue
		}
		if call, ok := literalBoundedCall(code, loc[1]-1); ok {
			args := literalCallArgs(call)
			if len(args) >= 2 {
				destination := args[1]
				if language == "python" {
					destination = literalCallArgument(args, 1, "dst")
				}
				if path, ok := pathString(destination); ok {
					paths = append(paths, path)
					if language == "python" && (name == "shutil.copy" || name == "shutil.copy2" || name == "shutil.move") {
						source := literalCallArgument(args, 0, "src")
						if sourcePath, fixed := pathString(source); fixed {
							if info, err := pathStat(OperandPath(path, cwd)); err == nil && info.IsDir() {
								paths = append(paths, filepath.Join(path, filepath.Base(sourcePath)))
							}
						}
					}
				}
			}
		}
	}
	if language == "perl" {
		for _, match := range literalPerlCopy.FindAllStringSubmatchIndex(code, -1) {
			if literalCodePosition(code, match[0], language) &&
				literalCopyAPI(language, code[match[2]:match[3]], perlCopyImported) {
				if path, ok := pathString(code[match[4]:match[5]]); ok {
					paths = append(paths, path)
				}
			}
		}
	}
	for _, match := range literalPathWrite.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	for _, match := range literalPathOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) &&
			(strings.HasPrefix(code[match[0]:match[1]], "pathlib.") ||
				strings.Contains(code[:match[0]], "from pathlib import Path")) &&
			validPythonWriteMode(code[match[4]:match[5]]) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	if language == "python" || strings.HasPrefix(language, "python3") {
		for _, loc := range unprovenWriter.FindAllStringIndex(code, -1) {
			name := strings.TrimSpace(code[loc[0] : loc[1]-1])
			if (name != "write_text" && name != "write_bytes") || !pythonExecutableCodePosition(code, loc[0]) {
				continue
			}
			if destination, fixed := pythonReboundReceiver(code, loc[1], home); fixed {
				paths = append(paths, destination)
			}
		}
		for _, match := range literalPathHomeJoinOpen.FindAllStringSubmatchIndex(code, -1) {
			if !pythonExecutableCodePosition(code, match[0]) {
				continue
			}
			call, fixed := literalBoundedCall(code, match[1]-1)
			if !fixed {
				continue
			}
			args := literalCallArgs(call)
			if len(args) == 0 {
				continue
			}
			if mode, fixed := literalString(args[0]); fixed && literalWriteMode(mode) {
				paths = append(paths, filepath.Join(home, code[match[2]:match[3]]))
			}
		}
		for _, loc := range literalPythonPathCall.FindAllStringIndex(code, -1) {
			if !pythonExecutableCodePosition(code, loc[0]) {
				continue
			}
			call, fixed := literalBoundedCall(code, loc[1]-1)
			if !fixed {
				continue
			}
			end := loc[1] - 1 + len(call)
			if end > len(code) {
				continue
			}
			suffix := code[end:]
			if !strings.HasPrefix(suffix, ".write_text(") && !strings.HasPrefix(suffix, ".write_bytes(") &&
				!strings.HasPrefix(suffix, ".open(") {
				continue
			}
			args := literalCallArgs(call)
			if len(args) != 1 {
				continue
			}
			path, fixed := literalPythonString(args[0])
			if !fixed {
				continue
			}
			if strings.HasPrefix(suffix, ".open(") {
				open, known := literalBoundedCall(suffix, len(".open"))
				if !known {
					continue
				}
				arguments := literalCallArgs(open)
				if len(arguments) == 0 {
					continue
				}
				mode, known := literalString(arguments[0])
				if !known || !literalWriteMode(mode) {
					continue
				}
			}
			paths = append(paths, path)
		}
	}
	for _, match := range literalPerlOpen.FindAllStringSubmatchIndex(code, -1) {
		if literalCodePosition(code, match[0], language) {
			paths = append(paths, code[match[2]:match[3]])
		}
	}
	return paths
}

func literalCallArgument(args []string, position int, keyword string) string {
	for _, arg := range args {
		name, value, found := strings.Cut(strings.TrimSpace(arg), "=")
		if found && strings.TrimSpace(name) == keyword {
			return strings.TrimSpace(value)
		}
	}
	if position < len(args) {
		return args[position]
	}
	return ""
}

// literalCopyAPI reports the copy and move APIs of a language that write
// their second argument: Python shutil, Node fs copies, Perl File::Copy
// (copy and move are exported, cp and mv on request) and Ruby FileUtils.
// A move renames when it can and copies through a link across file systems,
// so it is a write of its destination (rel-1-0-2:GAP-0429).
func literalCopyAPI(language, name string, perlImported bool) bool {
	switch language {
	case "python":
		return strings.HasPrefix(name, "shutil.")
	case "node":
		return name == "copyFileSync" || name == "copyFile" || name == "cpSync" || name == "cp"
	case "perl":
		if base, qualified := strings.CutPrefix(name, "File::Copy::"); qualified {
			name, perlImported = base, true
		}
		return perlImported && (name == "copy" || name == "cp" || name == "move" || name == "mv")
	case "ruby":
		return strings.HasPrefix(name, "FileUtils.") || name == "IO.copy_stream"
	}
	return false
}

func perlRedirectMode(arg string) bool {
	mode, ok := literalString(arg)
	return ok && (mode == ">" || mode == ">>")
}

func literalWriteMode(mode string) bool {
	return strings.ContainsAny(mode, "wax+") || mode == ">" || mode == ">>"
}

func validPythonWriteMode(mode string) bool {
	if mode == "" || !strings.ContainsRune("waxr", rune(mode[0])) {
		return false
	}
	plus, binary, text := 0, 0, 0
	for _, flag := range mode[1:] {
		switch flag {
		case '+':
			plus++
		case 'b':
			binary++
		case 't':
			text++
		default:
			return false
		}
	}
	return plus <= 1 && binary+text <= 1 && (mode[0] != 'r' || plus == 1)
}

func literalOSWriteFlags(flags string) bool {
	for _, flag := range []string{"O_WRONLY", "O_RDWR", "O_APPEND", "O_TRUNC", "O_CREAT"} {
		if strings.Contains(flags, flag) {
			return true
		}
	}
	return false
}

func literalString(arg string) (string, bool) {
	arg = strings.TrimSpace(arg)
	if len(arg) < 2 || arg[0] != arg[len(arg)-1] || arg[0] != '\'' && arg[0] != '"' {
		return "", false
	}
	value := arg[1 : len(arg)-1]
	if strings.Contains(value, "\\") || strings.ContainsRune(value, rune(arg[0])) {
		return "", false
	}
	return value, true
}

// Python folds adjacent literal strings and literal + literal at compile
// time. Accept only those bounded forms when proving a path argument.
func literalPythonString(arg string) (string, bool) {
	if value, ok := literalString(arg); ok {
		return value, true
	}
	arg = strings.TrimSpace(arg)
	if len(arg) > MaxWriteTargetPathBytes || len(arg) < 4 {
		return "", false
	}
	var out strings.Builder
	segments := 0
	for pos := 0; pos < len(arg); {
		quote := arg[pos]
		if quote != '\'' && quote != '"' {
			return "", false
		}
		pos++
		start := pos
		for pos < len(arg) && arg[pos] != quote {
			if arg[pos] == '\\' {
				return "", false
			}
			pos++
		}
		if pos == len(arg) {
			return "", false
		}
		out.WriteString(arg[start:pos])
		segments++
		pos++
		for pos < len(arg) && (arg[pos] == ' ' || arg[pos] == '\t') {
			pos++
		}
		if pos < len(arg) && arg[pos] == '+' {
			pos++
			for pos < len(arg) && (arg[pos] == ' ' || arg[pos] == '\t') {
				pos++
			}
			if pos == len(arg) {
				return "", false
			}
		}
	}
	return out.String(), segments > 1
}

func literalBoundedCall(code string, open int) (string, bool) {
	depth := 0
	var quote byte
	for i := open; i < len(code); i++ {
		c := code[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return code[open : i+1], true
			}
		}
	}
	return "", false
}

func literalCallArgs(call string) []string {
	open := strings.IndexByte(call, '(')
	if open < 0 || !strings.HasSuffix(call, ")") {
		return nil
	}
	var args []string
	start, depth := open+1, 0
	var quote byte
	for i := start; i < len(call)-1; i++ {
		c := call[i]
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case '(':
			depth++
		case ')':
			depth--
		case ',':
			if depth == 0 {
				args = append(args, strings.TrimSpace(call[start:i]))
				start = i + 1
			}
		}
	}
	return append(args, strings.TrimSpace(call[start:len(call)-1]))
}

func literalCodePosition(code string, position int, language string) bool {
	var quote byte
	comment := false
	perlHashDelimiters := 0
	for i := 0; i < position; i++ {
		c := code[i]
		if comment {
			if c == '\n' {
				comment = false
			}
			continue
		}
		if quote != 0 {
			if c == '\\' {
				i++
			} else if c == quote {
				quote = 0
			}
		} else if c == '\'' || c == '"' {
			quote = c
		} else if c == '#' {
			if language == "perl" && perlHashDelimiters > 0 {
				perlHashDelimiters--
			} else if language == "perl" && perlHashRegexpStart(code, i) > 0 {
				perlHashDelimiters = perlHashRegexpStart(code, i)
			} else if literalCommentStart(code, i, language) {
				comment = true
			}
		}
	}
	return quote == 0 && !comment
}

func perlHashRegexpStart(code string, i int) int {
	for _, operator := range []string{"s", "m", "qr", "tr", "y"} {
		start := i - len(operator)
		if start < 0 || code[start:i] != operator ||
			start > 0 && !strings.ContainsRune(" \t\n;=~(", rune(code[start-1])) {
			continue
		}
		if operator == "m" || operator == "qr" {
			return 1
		}
		return 2
	}
	return 0
}

func literalCommentStart(code string, i int, language string) bool {
	switch language {
	case "python", "ruby":
		return true
	case "perl":
		// Perl's $#name is an array index, not a comment.
		return i == 0 || code[i-1] != '$'
	default:
		// JavaScript uses # in private names, not for comments.
		return false
	}
}

// shellUnescapedWord is word with the backslashes the shell removes taken
// out of its literal parts: any escaped byte outside quotes, and an escaped
// $, `, ", \ or newline inside double quotes. Single-quoted text is kept.
// The word itself is not changed.
func shellUnescapedWord(word *syntax.Word) *syntax.Word {
	if word == nil {
		return nil
	}
	var convert func(parts []syntax.WordPart, quoted bool) []syntax.WordPart
	convert = func(parts []syntax.WordPart, quoted bool) []syntax.WordPart {
		out := make([]syntax.WordPart, 0, len(parts))
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				if !strings.Contains(part.Value, "\\") {
					out = append(out, part)
					continue
				}
				var value strings.Builder
				for i := 0; i < len(part.Value); i++ {
					c := part.Value[i]
					if c == '\\' && i+1 < len(part.Value) && (!quoted || strings.IndexByte("$`\"\\\n", part.Value[i+1]) >= 0) {
						i++
						if part.Value[i] == '\n' {
							continue // a line continuation
						}
						c = part.Value[i]
					}
					value.WriteByte(c)
				}
				copied := *part
				copied.Value = value.String()
				out = append(out, &copied)
			case *syntax.DblQuoted:
				copied := *part
				copied.Parts = convert(part.Parts, true)
				out = append(out, &copied)
			default:
				out = append(out, part)
			}
		}
		return out
	}
	copied := *word
	copied.Parts = convert(word.Parts, false)
	return &copied
}

func awkProgramName(word string) bool {
	switch programBase(word) {
	case "awk", "gawk", "mawk", "nawk":
		return true
	}
	return false
}

// wordExpandsParameter reports a word that contains a parameter expansion.
func wordExpandsParameter(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		if _, ok := node.(*syntax.ParamExp); ok {
			found = true
		}
		return !found
	})
	return found
}
