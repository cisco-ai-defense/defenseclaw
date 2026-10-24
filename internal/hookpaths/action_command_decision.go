// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ActionCommandDecision is the shared action-mode proof for command hooks and
// gateway routes. A nonempty reason means that an executed write can reach a
// protected file, or that a write-capable command has an unresolved program or
// target. The caller must enforce the same result with and without client
// resolved-write evidence.
//
// A call with no command text (a subagent delegation, a file or MCP tool)
// runs no shell, so there is nothing for this proof to decide on any OS: its
// own path facts judge it. The Windows grammar used to read such a call as a
// dynamic command and blocked every one of them (GAP-0958). A launcher with
// an empty child (cmd /c, pwsh -Command) still fails closed below.
func ActionCommandDecision(command, cwd, home string) string {
	if strings.TrimSpace(command) == "" {
		return ""
	}
	return actionCommandDecision(command, cwd, home, 0)
}

// "[" is a literal shell test builtin in program position. StaticWord
// rejects it as an unmatched glob opener, which is right for path operands
// but would mistake an ordinary guarded command for a computed executable.
func staticProgramWord(word *syntax.Word, home string) (string, bool) {
	if program, fixed := StaticWord(word, home); fixed {
		return program, true
	}
	if word != nil && len(word.Parts) == 1 {
		if literal, ok := word.Parts[0].(*syntax.Lit); ok && literal.Value == "[" {
			return "[", true
		}
	}
	return "", false
}

func actionCommandDecision(command, cwd, home string, depth int) string {
	if actionWindowsHome(home) {
		return actionWindowsCommandDecision(command, cwd, home, depth)
	}
	if command == "" || !filepath.IsAbs(cwd) || home == "" {
		return ""
	}
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return "dynamic-command"
	}
	if reason := UnprovenProtectedWrite(command, cwd, home); reason != "" {
		return reason
	}
	// apply_patch receives its writes from an envelope, often through a
	// heredoc. Check every envelope in the same action decision as shell
	// operands, including conditional branches and computed patch paths.
	patchTargets, patchKnown := ApplyPatchWriteTargets("Bash", nil, command, cwd, home)
	if !patchKnown {
		return "dynamic-argument"
	}
	patchProtected := newProtectedFiles(home)
	patchSSH := filepath.Join(home, ".ssh")
	for _, target := range patchTargets {
		if protectedReachPath(target, patchProtected, patchSSH) {
			return "dynamic-argument"
		}
	}
	file, ok := parseShell(command)
	if !ok {
		if actionTextMayWrite(command) && actionUncertaintyReaches(command, cwd, home) {
			return "shell-parse"
		}
		return ""
	}
	called := calledFunctions(file, home)
	functionArgs := actionLiteralFunctionArgs(file, home)
	boundPrograms := actionBoundProgramWords(file, home)
	straightLine := make(map[*syntax.Stmt]bool, len(file.Stmts))
	for _, stmt := range file.Stmts {
		straightLine[stmt] = true
	}
	bounded, boundedUnknown := BoundedShellWriteOperands(command, cwd, home)
	values := actionValues{"HOME": home, "PWD": cwd, "RANDOM": actionGeneratedMarker, "$": "1"}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	// reason is persistence evidence: a resolved protected target or an
	// unresolved write destination. uncertain is a child this proof cannot
	// read or model; it counts only with actionUncertaintyReaches below, and
	// the walk goes on so that a later write destination is still judged.
	reason, uncertain := "", ""
	syntax.Walk(file, func(node syntax.Node) bool {
		if reason != "" {
			return false
		}
		if loop, ok := node.(*syntax.ForClause); ok {
			actionBindLoopValue(loop, values, cwd, home)
			return true
		}
		if declaration, ok := node.(*syntax.FuncDecl); ok {
			if declaration.Name == nil || !called[declaration.Name.Value] {
				return false
			}
			for i, value := range functionArgs[declaration.Name.Value] {
				values[strconv.Itoa(i+1)] = value
			}
			return true
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		if straightLine[stmt] {
			for i := 1; i <= 9; i++ {
				delete(values, strconv.Itoa(i))
			}
			actionUpdateValues(stmt, values, cwd, home)
		} else {
			actionForgetValues(stmt, values, home)
		}
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil {
				continue
			}
			switch redirect.Op {
			case syntax.RdrIn, syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
				if value, fixed := actionWordValue(redirect.Word, values, cwd, home); fixed {
					if strings.Contains(value, actionGeneratedMarker) {
						if (redirect.Op != syntax.RdrIn || actionStmtMayWrite(stmt, home)) &&
							!actionGeneratedPathSafe(value, cwd, home) {
							reason = "dynamic-argument"
							return false
						}
					} else if redirect.Op == syntax.RdrIn && actionPrivateReadPath(value, cwd, home) ||
						redirect.Op != syntax.RdrIn && protectedReachPath(OperandPath(value, cwd), protected, ssh) {
						reason = "dynamic-argument"
						return false
					}
				}
				if _, fixed := StaticWord(redirect.Word, home); !fixed {
					if _, known := actionWordValue(redirect.Word, values, cwd, home); !known &&
						(redirect.Op != syntax.RdrIn || actionStmtMayWrite(stmt, home)) &&
						!provenBoundedRedirect(file, redirect, cwd, home) &&
						(len(bounded) == 0 || boundedUnknown) {
						if redirect.Op == syntax.RdrIn {
							// An unresolved input names no destination.
							uncertain = actionFirstUncertain(uncertain, actionUncertainSource)
							continue
						}
						reason = "dynamic-argument"
						return false
					}
				}
			}
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		program, fixed := staticProgramWord(call.Args[0], home)
		if !fixed {
			program, fixed = boundPrograms[call]
			if !fixed {
				uncertain = actionFirstUncertain(uncertain, "dynamic-command")
				return true
			}
		}
		words := make([]string, len(call.Args))
		words[0] = program
		for i, arg := range call.Args[1:] {
			value, static := StaticWord(arg, home)
			if !static {
				value, static = actionWordValue(arg, values, cwd, home)
			}
			if !static {
				safeProcess := actionKnownReadOnlyProcessSubstitution(arg, home)
				if actionPathArgument(programBase(program), i+1, len(call.Args)) &&
					!actionBoundedCallDestination(file, call, cwd, home) ||
					programBase(program) == "sort" && actionSortOutputWord(arg) ||
					wordHasCommandSubstitution(arg) && actionStmtMayWrite(stmt, home) &&
						!safeProcess {
					reason = "dynamic-argument"
					return false
				}
				// An unresolved copy or read source names no destination.
				if actionStmtMayWrite(stmt, home) && actionUnresolvedReadPathArgument(programBase(program)) && !safeProcess {
					uncertain = actionFirstUncertain(uncertain, actionUncertainSource)
				}
				if programBase(program) == "env" {
					var rendered strings.Builder
					if syntax.NewPrinter().Print(&rendered, arg) == nil && strings.Contains(rendered.String(), "=") {
						value = "ENV=?"
					}
				}
			}
			words[i+1] = value
		}
		if reason == "" && programBase(program) == "xargs" {
			if pipeline := literalPipelineOperands(file, called, cwd, home, depth); len(pipeline) > 0 {
				for _, target := range pipeline {
					if protectedReachPath(target, protected, ssh) {
						reason = "dynamic-argument"
						return false
					}
				}
				return true // A fixed producer bound every child operand.
			}
		}
		if child := actionChildDecision(words, stmt, cwd, home, depth); actionUncertainReason(child) {
			uncertain = actionFirstUncertain(uncertain, child)
		} else {
			reason = child
		}
		return reason == ""
	})
	return actionDecisionResult(reason, uncertain, command, cwd, home)
}

// actionUncertainSource is the internal class of an unresolved copy or read
// source. It leaves this package only as "dynamic-argument", with evidence.
const actionUncertainSource = "dynamic-source"

// actionUncertainReason reports a class that names no protected target: a
// script or interpreter body this proof does not read (an argument-taking or
// unreadable script, an interpreter host, stdin), eval or source, a computed
// program, a parse error or an unresolved copy source. Balanced defaults:
// such uncertainty is not persistence evidence by itself. A resolved
// protected target, an unresolved write destination and a copy into a
// protected directory stay evidence.
func actionUncertainReason(reason string) bool {
	switch reason {
	case "nested-shell", "interpreter-path", "interpreter-argument", "eval-source",
		"dynamic-command", "shell-parse", actionUncertainSource:
		return true
	}
	return false
}

func actionFirstUncertain(current, next string) string {
	if current != "" {
		return current
	}
	return next
}

// actionDecisionResult keeps an uncertain class only when the command text
// itself can reach a protected file (the release's protected-write evidence).
func actionDecisionResult(reason, uncertain, command, cwd, home string) string {
	if reason != "" || uncertain == "" || !actionUncertaintyReaches(command, cwd, home) {
		return reason
	}
	if uncertain == actionUncertainSource {
		return "dynamic-argument"
	}
	return uncertain
}

// actionUncertaintyReaches reports evidence that an unmodelled child can
// reach a protected file: the text names the .ssh directory (also as an 8.3
// alias) or an SSH key file, or one of its paths resolves to the home, the
// .ssh directory or a protected file. A -EncodedCommand payload is read too.
func actionUncertaintyReaches(command, cwd, home string) bool {
	return actionUncertaintyReachesDepth(command, cwd, home, 0)
}

func actionUncertaintyReachesDepth(command, cwd, home string, depth int) bool {
	if depth >= 8 {
		return true
	}
	if actionNamesSSH(command) || actionTextDynamicWrite(command) {
		return true
	}
	if !actionWindowsHome(home) {
		return protectedReachFromText(command, cwd, home)
	}
	words, _ := actionWindowsWords(command)
	root, rootKnown := actionWindowsPath(home, cwd, home)
	for i, word := range words {
		switch strings.ToLower(word) {
		case "-encodedcommand", "-enc", "-ec", "-e":
			if i+1 < len(words) {
				if decoded, ok := actionWindowsDecodeCommand(words[i+1]); ok &&
					actionUncertaintyReachesDepth(decoded, cwd, home, depth+1) {
					return true
				}
			}
		}
		if resolved, ok := actionWindowsPath(word, cwd, home); ok && rootKnown &&
			(resolved == root || strings.HasPrefix(resolved, root+"/.ssh")) {
			return true
		}
	}
	return false
}

func actionLiteralFunctionArgs(file *syntax.File, home string) map[string][]string {
	args := make(map[string][]string)
	counts := make(map[string]int)
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		if name, fixed := StaticWord(call.Args[0], home); fixed {
			counts[name]++
		}
		return true
	})
	for _, stmt := range file.Stmts {
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			continue
		}
		name, fixed := StaticWord(call.Args[0], home)
		if !fixed {
			continue
		}
		if counts[name] != 1 {
			continue
		}
		var values []string
		for _, word := range call.Args[1:] {
			value, known := StaticWord(word, home)
			if !known {
				values = nil
				break
			}
			values = append(values, value)
		}
		args[name] = values
	}
	return args
}

// A read-only producer with fixed words cannot choose a write target through
// its process-substitution body. The body is still walked separately for a
// protected read or a resolved protected redirect.
func actionKnownReadOnlyProcessSubstitution(word *syntax.Word, home string) bool {
	if len(word.Parts) != 1 {
		return false
	}
	sub, ok := word.Parts[0].(*syntax.ProcSubst)
	if !ok || sub.Op != syntax.CmdIn || len(sub.Stmts) != 1 {
		return false
	}
	stmt := sub.Stmts[0]
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || !strings.Contains(" printf echo sort ", " "+programBase(program)+" ") {
		return false
	}
	for _, arg := range call.Args[1:] {
		value, fixed := StaticWord(arg, home)
		if !fixed || programBase(program) == "sort" && strings.HasPrefix(value, "-") {
			return false
		}
	}
	return true
}

func actionBoundedCallDestination(file *syntax.File, call *syntax.CallExpr, cwd, home string) bool {
	if destination, ok := boundedCommandDestination(file, call, home); ok {
		return !protectedReachPath(OperandPath(destination, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh"))
	}
	return false
}

func wordHasCommandSubstitution(word *syntax.Word) bool {
	found := false
	syntax.Walk(word, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
		}
		return !found
	})
	return found
}

func actionTextMayWrite(command string) bool {
	return strings.ContainsAny(command, ">|<") || strings.Contains(command, "eval") ||
		strings.Contains(command, " -c ") || strings.Contains(command, " -e ")
}

func actionProgramMayWrite(program string) bool {
	switch program {
	case "echo", "printf", "cat", "head", "tail", "wc", "pwd", "true", "false", "test", "[", "grep", "sort", "diff", "read", "mapfile", "readarray", "cd":
		return false
	}
	return true // Unknown programs can write internally.
}

// actionSortOutputWord reports an attached sort output option, -oFILE or
// --output=FILE: its value is a write destination.
func actionSortOutputWord(word *syntax.Word) bool {
	var rendered strings.Builder
	if syntax.NewPrinter().Print(&rendered, word) != nil {
		return true
	}
	value := strings.TrimLeft(rendered.String(), `"'`)
	return strings.HasPrefix(value, "-o") && len(value) > 2 || strings.HasPrefix(value, "--output=")
}

func actionStmtMayWrite(stmt *syntax.Stmt, home string) bool {
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
			return true
		}
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if known && programBase(program) == "sort" {
		for _, arg := range call.Args[1:] {
			var rendered strings.Builder
			if syntax.NewPrinter().Print(&rendered, arg) != nil {
				continue
			}
			value := rendered.String()
			if value == "-o" || value == "--output" || strings.HasPrefix(value, "-o") && len(value) > 2 ||
				strings.HasPrefix(value, "--output=") {
				return true
			}
		}
	}
	return !known || actionProgramMayWrite(programBase(program))
}

func actionPrivateReadPath(value, cwd, home string) bool {
	resolved, ok := ResolveWriteTarget(OperandPath(value, cwd))
	if !ok {
		return false
	}
	for _, name := range []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
		key := filepath.Join(home, ".ssh", name)
		if samePathName(resolved, key) {
			return true
		}
		resolvedInfo, err1 := os.Stat(resolved)
		keyInfo, err2 := os.Stat(key)
		if err1 == nil && err2 == nil && os.SameFile(resolvedInfo, keyInfo) {
			return true
		}
	}
	return false
}

// Keep the common reader set identical in POSIX shells and on a Windows home.
// The Windows branch also has native readers; POSIX type is only a name lookup.
// Identity use by ssh and ssh-keygen does not emit key bytes.
func actionPrivateKeyReader(program string, windows bool) bool {
	switch program {
	case "cat", "head", "tail", "sort", "wc", "grep":
		return true
	case "type", "get-content", "get-childitem":
		return windows
	}
	return false
}

// A generated basename is safe only when its parent is an ordinary resolved
// directory and no existing name it might select aliases a protected file.
// This retains ordinary log/date/temp names without claiming an invented
// numeric value for RANDOM or date(1).
func actionGeneratedPathSafe(value, cwd, home string) bool {
	if !strings.Contains(value, actionGeneratedMarker) {
		return false
	}
	target := OperandPath(value, cwd)
	parent := filepath.Dir(target)
	if strings.Contains(parent, actionGeneratedMarker) {
		return false
	}
	physical, ok := ResolveWriteTarget(parent)
	if !ok {
		return false
	}
	ssh, ok := ResolveWriteTarget(filepath.Join(home, ".ssh"))
	if !ok || samePathName(physical, ssh) || strings.HasPrefix(physical, ssh+string(filepath.Separator)) {
		return false
	}
	pattern := strings.ReplaceAll(filepath.Base(target), actionGeneratedMarker, "*")
	directory, err := os.Open(parent)
	if err != nil {
		return false
	}
	names, err := directory.Readdirnames(4097)
	_ = directory.Close()
	if err != nil && err != io.EOF || len(names) > 4096 {
		return false
	}
	protected := newProtectedFiles(home)
	for _, name := range names {
		matched, err := filepath.Match(pattern, name)
		if err != nil {
			return false
		}
		if !matched {
			continue
		}
		candidate := filepath.Join(parent, name)
		if _, ok := ResolveWriteTarget(candidate); !ok ||
			protectedReachPath(candidate, protected, filepath.Join(home, ".ssh")) {
			return false
		}
	}
	return true
}

func actionPathArgument(program string, index, count int) bool {
	switch program {
	case "cp", "gcp", "mv", "gmv", "install", "ln", "rsync":
		return index == count-1
	case "tee", "dd", "touch", "truncate", "sed", "gsed", "tar", "busybox":
		return index > 0
	case "python", "python3", "node", "nodejs", "ruby", "perl", "sh", "bash", "zsh", "dash", "ksh", "mksh":
		return index == 1 && count == 2
	}
	return false
}

func actionUnresolvedReadPathArgument(program string) bool {
	switch program {
	case "cp", "gcp", "mv", "gmv", "install", "ln", "rsync",
		"cat", "head", "tail", "sort", "wc":
		return true
	}
	return false
}

func actionChildDecision(words []string, stmt *syntax.Stmt, cwd, home string, depth int) string {
	if len(words) == 0 || words[0] == "" {
		return ""
	}
	program := programBase(words[0])
	// A directly executable script is an interpreter launch too. Route it
	// through the same cwd, argument and body proof as an explicit launcher.
	interpreter := ""
	switch filepath.Ext(program) {
	case ".sh", ".bash", ".dash":
		interpreter = "sh"
	case ".zsh":
		interpreter = "zsh"
	case ".ksh":
		interpreter = "ksh"
	case ".py":
		interpreter = "python3"
	case ".js", ".mjs", ".cjs":
		interpreter = "node"
	case ".rb":
		interpreter = "ruby"
	case ".pl":
		interpreter = "perl"
	case ".ps1", ".cmd", ".bat":
		return "nested-shell"
	}
	if interpreter != "" {
		child := append([]string{interpreter}, words...)
		return actionChildDecision(child, stmt, cwd, home, depth+1)
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for i, word := range words[1:] {
		if strings.Contains(word, actionGeneratedMarker) &&
			(actionPathArgument(program, i+1, len(words)) || actionProgramMayWrite(program)) &&
			!actionGeneratedPathSafe(word, cwd, home) {
			return "dynamic-argument"
		}
	}
	for _, target := range directLiteralProgramOperands(words, stmt, cwd, home) {
		if protectedReachPath(target, protected, ssh) {
			return "dynamic-argument"
		}
	}
	if program == "sort" {
		for i := 1; i < len(words); i++ {
			word := words[i]
			if word == "--" {
				break
			}
			var target string
			switch {
			case word == "-o" || word == "--output":
				if i+1 >= len(words) {
					return "dynamic-argument"
				}
				target = words[i+1]
			case strings.HasPrefix(word, "--output="):
				target = strings.TrimPrefix(word, "--output=")
			case strings.HasPrefix(word, "-o") && len(word) > 2:
				target = word[2:]
			default:
				continue
			}
			if target == "" || protectedReachPath(OperandPath(target, cwd), protected, ssh) {
				return "dynamic-argument"
			}
		}
	}
	if actionPrivateKeyReader(program, false) {
		for _, source := range words[1:] {
			if source != "" && !strings.HasPrefix(source, "-") &&
				actionPrivateReadPath(source, cwd, home) {
				return "dynamic-argument"
			}
		}
	}
	if program == "eval" {
		return "eval-source"
	}
	if program == "make" || program == "gmake" {
		return actionMakeDecision(words, actionMakeAssignments(stmt, home), cwd, home)
	}
	if program == "rsync" && len(words) >= 3 && strings.Contains(strings.Join(words[1:len(words)-1], " "), "-a") {
		protected := newProtectedFiles(home)
		ssh := filepath.Join(home, ".ssh")
		for _, source := range words[1 : len(words)-1] {
			if strings.HasPrefix(source, "-") {
				continue
			}
			if protectedReachPath(OperandPath(source, cwd), protected, ssh) {
				return "copy-directory"
			}
		}
	}
	if posixShellProgram(program) {
		if index, ok := shellCommandBodyIndex(words); ok {
			if index >= len(words) || words[index] == "" {
				return "nested-shell"
			}
			return actionCommandDecision(words[index], cwd, home, depth+1)
		}
		for _, word := range words[1:] {
			if word == "-c" || strings.Contains(word, "c") && strings.HasPrefix(word, "-") && len(word) <= 4 {
				return "nested-shell" // Unknown shell options conceal the -c operand.
			}
		}
		if script, ok := shellScriptOperand(words); ok {
			if !actionScriptInsideCWD(script, cwd) || len(words) > 2 {
				return "nested-shell"
			}
			content, read := readIndirectSource(script, cwd)
			if !read {
				return "nested-shell"
			}
			return actionCommandDecision(content, cwd, home, depth+1)
		}
		return "nested-shell" // stdin, -s or an unrecognized option.
	}
	if program == "python" || strings.HasPrefix(program, "python3") || program == "node" || program == "nodejs" || program == "perl" || program == "ruby" {
		if len(words) < 2 {
			return "interpreter-path" // stdin
		}
		if program == "perl" && len(words) >= 5 && (words[1] == "-pi" || words[1] == "-ip") && words[2] == "-e" {
			for _, target := range words[4:] {
				if target == "" || protectedReachPath(OperandPath(target, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
					return "interpreter-path"
				}
			}
			return ""
		}
		if (program == "python" || strings.HasPrefix(program, "python3")) && words[1] == "-m" && len(words) >= 3 && words[2] != "" {
			return "" // A named installed module has no shell program word to expand.
		}
		if words[1] == "-" {
			if code, known := actionLiteralHereDocument(stmt); known {
				if class, _ := unprovenInterpreterCode(code, program, cwd, home, true); class != "" {
					return class
				}
				for _, target := range literalInterpreterWrites(code, program) {
					if protectedReachPath(OperandPath(target, cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
						return "interpreter-path"
					}
				}
				return ""
			}
			return "interpreter-path"
		}
		if words[1] == "-c" || words[1] == "-e" {
			if len(words) < 3 || words[2] == "" {
				return "interpreter-path"
			}
			if class, _ := unprovenInterpreterCode(words[2], program, cwd, home, true); class != "" {
				return class
			}
			return ""
		}
		if strings.HasPrefix(words[1], "-") {
			return "interpreter-path"
		}
		if !actionScriptInsideCWD(words[1], cwd) || len(words) > 2 {
			return "interpreter-path"
		}
		content, read := readIndirectSource(words[1], cwd)
		if !read {
			return "interpreter-path"
		}
		if class, _ := unprovenInterpreterCode(content, program, cwd, home, true); class != "" {
			return class
		}
		return ""
	}
	switch program {
	case "source", ".":
		if len(words) != 2 || words[1] == "" || !actionScriptInsideCWD(words[1], cwd) {
			return "eval-source"
		}
		content, read := readIndirectSource(words[1], cwd)
		if !read {
			return "eval-source"
		}
		return actionCommandDecision(content, cwd, home, depth+1)
	case "git":
		return actionGitDecision(words, cwd, home, depth+1)
	case "command", "exec", "busybox", "time", "nohup":
		index := 1
		for index < len(words) && strings.HasPrefix(words[index], "-") {
			option := words[index]
			if option == "--" {
				index++
				break
			}
			switch {
			case program == "command" && option == "-p",
				program == "exec" && (option == "-c" || option == "-l"),
				program == "time" && option == "-p":
				index++
			case program == "command" && (option == "-v" || option == "-V"):
				return "" // Name lookup does not run a child.
			case program == "exec" && option == "-a":
				if index+1 >= len(words) || words[index+1] == "" {
					return "dynamic-command"
				}
				index += 2
			default:
				return "dynamic-command"
			}
		}
		if index >= len(words) {
			return "dynamic-command"
		}
		return actionWordsDecision(words[index:], cwd, home, depth+1)
	case "env":
		index := 1
		env := actionMakeAssignments(stmt, home)
		for index < len(words) {
			w := words[index]
			switch {
			case w == "--", w == "-i", w == "--ignore-environment", w == "-0", w == "-v":
				index++
			case w == "-C" || w == "--chdir" || w == "-u" || w == "--unset":
				if index+1 >= len(words) {
					return "dynamic-command"
				}
				if w == "-C" || w == "--chdir" {
					cwd = OperandPath(words[index+1], cwd)
				}
				index += 2
			case w == "-S" || w == "--split-string":
				if index+1 >= len(words) || words[index+1] == "" {
					return "dynamic-command"
				}
				return actionCommandDecision(words[index+1], cwd, home, depth+1)
			case strings.HasPrefix(w, "--chdir="):
				cwd = OperandPath(strings.TrimPrefix(w, "--chdir="), cwd)
				index++
			case strings.HasPrefix(w, "--unset=") || strings.HasPrefix(w, "-u") && len(w) > 2:
				index++
			case strings.Contains(w, "=") && !strings.HasPrefix(w, "-"):
				env = append(env, w)
				index++
			case strings.HasPrefix(w, "-"):
				return "dynamic-command"
			default:
				if actionMakeProgram(words[index]) {
					return actionMakeDecision(words[index:], env, cwd, home)
				}
				return actionWordsDecision(words[index:], cwd, home, depth+1)
			}
		}
		return ""
	case "nice", "ionice", "timeout", "stdbuf", "setsid", "chroot", "unshare", "nsenter", "flock", "sudo", "parallel", "xargs", "find", "script", "su":
		return actionWrappedDecision(program, words, cwd, home, depth+1)
	}
	return ""
}

func actionGitDecision(words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	aliases := make(map[string]string)
	commands := make(map[string]string)
	unknownOption := false
	index := 1
	for index < len(words) {
		word := words[index]
		if word == "--" {
			index++
			break
		}
		if !strings.HasPrefix(word, "-") {
			break
		}
		var config string
		switch {
		case word == "--config-env":
			return "dynamic-command" // Value comes from an unreported environment variable.
		case word == "-c":
			if index+1 >= len(words) || words[index+1] == "" {
				return "dynamic-command"
			}
			config = words[index+1]
			index += 2
		case strings.HasPrefix(word, "-c") && len(word) > 2:
			config = word[2:]
			index++
		case word == "-C" || word == "--git-dir" || word == "--work-tree" || word == "--namespace":
			if index+1 >= len(words) || words[index+1] == "" {
				return "dynamic-command"
			}
			if word == "-C" {
				cwd = OperandPath(words[index+1], cwd)
			}
			index += 2
		case strings.HasPrefix(word, "-C") && len(word) > 2:
			cwd = OperandPath(word[2:], cwd)
			index++
		case strings.HasPrefix(word, "--git-dir=") || strings.HasPrefix(word, "--work-tree=") ||
			strings.HasPrefix(word, "--namespace="):
			index++
		case word == "--bare" || word == "--no-pager" || word == "--paginate":
			index++
		default:
			unknownOption = true
			index++ // Keep scanning for a known read subcommand.
		}
		if config != "" {
			name, value, ok := strings.Cut(config, "=")
			if !ok || value == "" {
				return "dynamic-command"
			}
			lower := strings.ToLower(name)
			if strings.HasPrefix(lower, "alias.") {
				aliases[strings.TrimPrefix(lower, "alias.")] = value
			} else if lower == "core.sshcommand" || lower == "core.pager" || lower == "core.editor" ||
				lower == "core.fsmonitor" || lower == "core.hookspath" {
				commands[lower] = value
			}
		}
	}
	if index >= len(words) || words[index] == "" {
		return "dynamic-command"
	}
	subcommand := strings.ToLower(words[index])
	if subcommand == "archive" {
		// Plain git archive writes only to stdout. Options such as --output
		// and --exec add a filesystem target or an external program.
		if !unknownOption && len(commands) == 0 && len(words) == index+2 &&
			words[index+1] != "" && !strings.HasPrefix(words[index+1], "-") {
			return ""
		}
		return "dynamic-command"
	}
	if unknownOption && !strings.Contains(" blame diff for-each-ref grep log ls-files ls-remote rev-parse show status ", " "+subcommand+" ") {
		return "dynamic-command"
	}
	if alias, ok := aliases[subcommand]; ok {
		if strings.HasPrefix(alias, "!") {
			return actionCommandDecision(strings.TrimPrefix(alias, "!"), cwd, home, depth+1)
		}
		return actionCommandDecision("git "+alias+" "+strings.Join(words[index+1:], " "), cwd, home, depth+1)
	}
	for name, command := range commands {
		switch name {
		case "core.sshcommand":
			if subcommand != "fetch" && subcommand != "push" && subcommand != "pull" && subcommand != "clone" && subcommand != "ls-remote" {
				continue
			}
		case "core.editor":
			if subcommand != "commit" && subcommand != "tag" && subcommand != "rebase" && subcommand != "merge" {
				continue
			}
		case "core.pager":
			if subcommand != "log" && subcommand != "show" && subcommand != "diff" && subcommand != "blame" {
				continue
			}
		case "core.hookspath":
			return "dynamic-command" // A hook script can run outside the work directory.
		}
		if reason := actionCommandDecision(command, cwd, home, depth+1); reason != "" {
			return reason
		}
	}
	if !strings.Contains(" add apply bisect blame branch checkout cherry-pick clean clone commit config diff fetch for-each-ref grep init log ls-files ls-remote merge mv pull push rebase reflog remote reset restore rev-parse rm show stash status submodule switch tag worktree ", " "+subcommand+" ") {
		return "dynamic-command" // Could be an alias loaded from config.
	}
	return ""
}

func actionLiteralHereDocument(stmt *syntax.Stmt) (string, bool) {
	if stmt == nil {
		return "", false
	}
	for _, redirect := range stmt.Redirs {
		if redirect.Op != syntax.Hdoc && redirect.Op != syntax.DashHdoc || redirect.Hdoc == nil {
			continue
		}
		var code strings.Builder
		for _, part := range redirect.Hdoc.Parts {
			literal, ok := part.(*syntax.Lit)
			if !ok {
				return "", false
			}
			code.WriteString(literal.Value)
		}
		return code.String(), true
	}
	return "", false
}

func actionWordsDecision(words []string, cwd, home string, depth int) string {
	if len(words) == 0 || words[0] == "" {
		return "dynamic-command"
	}
	program := programBase(words[0])
	for i, word := range words[1:] {
		if word == "" && actionPathArgument(program, i+1, len(words)) {
			return "dynamic-argument"
		}
	}
	return actionChildDecision(words, nil, cwd, home, depth)
}

func actionScriptInsideCWD(script, cwd string) bool {
	path := OperandPath(script, cwd)
	resolved, ok := ResolveWriteTarget(path)
	return ok && (resolved == cwd || strings.HasPrefix(resolved, cwd+string(filepath.Separator)))
}

func actionWrappedDecision(program string, words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	index := 1
	sudoList := false
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		word := words[index]
		if word == "--" {
			index++
			break
		}
		if (program == "su" || program == "script" || program == "flock") && (word == "-c" || word == "--command") {
			if index+1 >= len(words) {
				return "dynamic-command"
			}
			if program == "script" && index+2 < len(words) &&
				protectedReachPath(OperandPath(words[len(words)-1], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
				return "dynamic-argument"
			}
			return actionCommandDecision(words[index+1], cwd, home, depth+1)
		}
		if (program == "find" || program == "xargs") && strings.HasPrefix(word, "-exec") {
			break
		}
		value := false
		known := false
		switch program {
		case "nice":
			value = word == "-n" || word == "--adjustment"
			known = value || strings.HasPrefix(word, "-n") && len(word) > 2 || word == "--adjustment="
		case "ionice":
			value = word == "-c" || word == "-n" || word == "-p" || word == "-P"
			known = value || word == "-t" || strings.HasPrefix(word, "--class=") || strings.HasPrefix(word, "--classdata=")
		case "timeout":
			value = word == "-s" || word == "--signal" || word == "-k" || word == "--kill-after"
			known = value || word == "--foreground" || word == "--preserve-status" || word == "-v" || strings.HasPrefix(word, "--signal=") || strings.HasPrefix(word, "--kill-after=")
		case "stdbuf":
			value = word == "-i" || word == "-o" || word == "-e"
			known = value || len(word) > 2 && (strings.HasPrefix(word, "-i") || strings.HasPrefix(word, "-o") || strings.HasPrefix(word, "-e"))
		case "setsid":
			known = word == "-c" || word == "-f" || word == "-w" || word == "--ctty" || word == "--fork" || word == "--wait"
		case "chroot":
			value = word == "--userspec" || word == "--groups"
			known = value || strings.HasPrefix(word, "--userspec=") || strings.HasPrefix(word, "--groups=")
		case "unshare":
			known = strings.Contains(" -m -u -i -n -p -U -C -T -f -r --mount --uts --ipc --net --pid --user --cgroup --time --fork --map-root-user ", " "+word+" ") || strings.HasPrefix(word, "--mount-proc")
		case "nsenter":
			value = word == "-t" || word == "--target" || word == "-S" || word == "--setuid" || word == "-G" || word == "--setgid"
			known = value || strings.Contains(" -m -u -i -n -p -U -C -T --mount --uts --ipc --net --pid --user --cgroup --time ", " "+word+" ") || strings.Contains(word, "=")
		case "flock":
			value = word == "-E" || word == "--conflict-exit-code" || word == "-w" || word == "--timeout"
			known = value || strings.Contains(" -s -x -u -n -o -F --shared --exclusive --unlock --nonblock --close --no-fork ", " "+word+" ")
		case "sudo":
			if word == "-l" || word == "-ll" || word == "--list" {
				// sudo's list mode queries policy; the following command, if
				// present, is a query argument and is never executed.
				sudoList = true
				known = true
				break
			}
			value = strings.Contains(" -u -g -h -p -C -r -t --user --group --host --prompt --close-from --role --type ", " "+word+" ")
			known = value || strings.Contains(" -n -E -H -S -b -k -K -v --non-interactive --preserve-env ", " "+word+" ") || strings.HasPrefix(word, "--user=") || strings.HasPrefix(word, "--group=")
		case "script":
			known = word == "-q" || word == "-f" || word == "-e" || word == "--quiet" || word == "--flush"
		case "su":
			value = word == "-s" || word == "--shell" || word == "-g" || word == "--group"
			known = value || word == "-l" || word == "-m" || word == "-p" || word == "--login"
		case "xargs":
			value = word == "-I" || word == "-n" || word == "-P" || word == "-d" || word == "-s"
			known = value || word == "-0" || word == "-r" || strings.HasPrefix(word, "-I") || strings.HasPrefix(word, "-n") || strings.HasPrefix(word, "-P")
		case "parallel":
			known = true
		}
		if !known {
			return "dynamic-command"
		}
		if value {
			if index+1 >= len(words) || words[index+1] == "" {
				return "dynamic-command"
			}
			index += 2
		} else {
			index++
		}
	}
	if program == "sudo" && sudoList {
		return ""
	}
	if index >= len(words) {
		return "dynamic-command"
	}
	switch program {
	case "timeout":
		index++ // duration
	case "flock":
		if protectedReachPath(OperandPath(words[index], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
			return "dynamic-argument"
		}
		index++ // lock file
	case "chroot":
		index++ // new root
	case "script":
		if len(words)-index > 1 && protectedReachPath(OperandPath(words[len(words)-1], cwd), newProtectedFiles(home), filepath.Join(home, ".ssh")) {
			return "dynamic-argument"
		}
	case "su":
		return "dynamic-command" // login shell reads external startup code
	case "find":
		for i := index; i < len(words); i++ {
			if words[i] == "-exec" || words[i] == "-execdir" || words[i] == "-ok" {
				return actionWordsDecision(words[i+1:], cwd, home, depth+1)
			}
		}
		return ""
	case "xargs":
		operands := literalProgramOperands(words[index:], nil, cwd, home, depth+1, false)
		if len(operands) > 0 {
			for _, target := range operands {
				if protectedReachPath(target, newProtectedFiles(home), filepath.Join(home, ".ssh")) {
					return "dynamic-argument"
				}
			}
			return ""
		}
		if actionProgramMayWrite(programBase(words[index])) {
			return "dynamic-argument"
		}
		return ""
	case "parallel":
		return "dynamic-command"
	}
	if index >= len(words) {
		return "dynamic-command"
	}
	return actionWordsDecision(words[index:], cwd, home, depth+1)
}

// actionBindLoopValue binds the variable of a for loop over literal words or
// unquoted pathname patterns (expanded here, bounded). Every value is known,
// so the body is judged with one of them: the only value that can reach a
// protected file or a private key if there is one, else the first. With
// more than one such value, or any other item, the variable stays unknown.
func actionBindLoopValue(loop *syntax.ForClause, values actionValues, cwd, home string) {
	iter, ok := loop.Loop.(*syntax.WordIter)
	if !ok || iter.Name == nil {
		return
	}
	name := iter.Name.Value
	delete(values, name)
	if !iter.InPos.IsValid() || len(iter.Items) == 0 {
		return // "$@", or no iteration
	}
	var candidates []string
	for _, item := range iter.Items {
		if value, fixed := StaticWord(item, home); fixed {
			candidates = append(candidates, value)
			continue
		}
		if len(item.Parts) != 1 {
			return
		}
		literal, ok := item.Parts[0].(*syntax.Lit)
		if !ok || !strings.ContainsAny(literal.Value, "*?[") || strings.ContainsAny(literal.Value, "{}$`\\") {
			return
		}
		pattern := literal.Value
		if strings.HasPrefix(pattern, "~/") {
			pattern = filepath.Join(home, pattern[2:])
		}
		matches, err := filepath.Glob(OperandPath(pattern, cwd))
		if err != nil || len(matches) > 4096 {
			return
		}
		if len(matches) == 0 {
			matches = []string{pattern} // the shell keeps an unmatched word
		}
		candidates = append(candidates, matches...)
		if len(candidates) > 4096 {
			return
		}
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	var risky []string
	for _, candidate := range candidates {
		if candidate == "" || strings.ContainsAny(candidate, "\x00"+actionGeneratedMarker) {
			return
		}
		if protectedReachPath(OperandPath(candidate, cwd), protected, ssh) || actionPrivateReadPath(candidate, cwd, home) {
			risky = append(risky, candidate)
		}
	}
	switch len(risky) {
	case 0:
		values[name] = candidates[0]
	case 1:
		values[name] = risky[0]
	}
}

// actionNamesSSH reports text that names the .ssh directory (also as an 8.3
// alias), an authorized_keys file or a private key file.
func actionNamesSSH(text string) bool {
	lower := strings.ToLower(text)
	for _, name := range []string{".ssh", "ssh~", "authorized_keys", "id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"} {
		if strings.Contains(lower, name) {
			return true
		}
	}
	return false
}

// actionTextDynamicWrite reports a write to a computed target in text the
// proof could not parse or expand, such as the body of env -S "sh -c '...
// >> \"$destination\"'": a redirect or tee operand that starts with $ or a
// backtick. A computed destination is a possible protected destination.
func actionTextDynamicWrite(command string) bool {
	computed := func(index int) bool {
		for index < len(command) && strings.ContainsRune(" \t\\\"'", rune(command[index])) {
			index++
		}
		return index < len(command) && (command[index] == '`' || command[index] == '$' && !actionHomeReference(command[index:]))
	}
	for index := 0; index < len(command); index++ {
		if command[index] != '>' {
			continue
		}
		next := index + 1
		if next < len(command) && (command[next] == '>' || command[next] == '|') {
			next++
		}
		if next < len(command) && (command[next] == '&' || command[next] == '(') {
			continue // a descriptor copy (2>&1) or a process substitution
		}
		if computed(next) {
			return true
		}
	}
	for _, field := range strings.FieldsFunc(command, func(r rune) bool { return strings.ContainsRune(";|&\n", r) }) {
		words := strings.Fields(field)
		for index, word := range words {
			if strings.Trim(word, `"'\`) != "tee" {
				continue
			}
			for _, operand := range words[index+1:] {
				if strings.ContainsAny(operand, "<>") {
					break // a redirection, judged above
				}
				if operand = strings.TrimLeft(operand, `"'\`); strings.HasPrefix(operand, "$") && !actionHomeReference(operand) ||
					strings.HasPrefix(operand, "`") {
					return true
				}
			}
		}
	}
	return false
}

// actionHomeReference reports text that starts with $HOME or ${HOME} as a
// whole parameter: the known home, not a computed target.
func actionHomeReference(text string) bool {
	for _, prefix := range []string{"${HOME}", "$HOME"} {
		if rest, ok := strings.CutPrefix(text, prefix); ok {
			return rest == "" || !(rest[0] == '_' || asciiLetter(rest[0]) || rest[0] >= '0' && rest[0] <= '9')
		}
	}
	return false
}
