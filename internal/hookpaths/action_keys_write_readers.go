// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// actionExpandedWordGlob reads a pattern made by an unquoted parameter or
// command substitution. Quoted expansions and assignment values do not
// pathname-expand; callers use this only for shell words that do.
func actionExpandedWordGlob(word *syntax.Word, values actionValues, cwd, home string, check func(string, bool, string) bool) bool {
	if word == nil {
		return false
	}
	expands := false
	for _, part := range word.Parts {
		switch part.(type) {
		case *syntax.ParamExp, *syntax.CmdSubst:
			expands = true
		}
	}
	if !expands {
		return false
	}
	value, known := actionWordValueWithGlob(word, values, cwd, home, true)
	return known && strings.ContainsAny(value, "*?[]") && check(value, false, cwd)
}

// actionOversizedBraceTarget keeps the fixed literal parts of a brace word
// whose expansion exceeds the field budget. The intervening alternatives
// become pathname patterns, so a long range cannot hide a protected target.
func actionOversizedBraceTarget(word *syntax.Word, home, cwd string, check func(string, bool, string) bool, quick func([]string) bool) bool {
	if word == nil || !actionWordHasBraceText(word) || shellparse.MinBraceFields(word) <= maxMentionBraceFields {
		return false
	}
	// For a modest range past the normal field cap, check its exact
	// members. Replacing {1..300} with * would include unrelated links.
	if fields := actionExactOversizedTouchFields(word, home); len(fields) > 0 {
		if quick != nil && quick(fields) {
			return false
		}
		for _, field := range fields {
			if check(field, false, cwd) {
				return true
			}
		}
		return false
	}
	value, known := actionWordValueWithGlob(word, actionValues{"HOME": home}, cwd, home, true)
	if !known {
		return false
	}
	var pattern strings.Builder
	depth := 0
	for _, r := range value {
		switch r {
		case '{':
			if depth == 0 {
				pattern.WriteByte('*')
			}
			depth++
		case '}':
			if depth == 0 {
				return false
			}
			depth--
		default:
			if depth == 0 {
				pattern.WriteRune(r)
			}
		}
	}
	return depth == 0 && check(pattern.String(), false, cwd)
}

// actionOversizedTouchOperands reads over-cap brace file operands in one
// touch call. Printed brace ranges and touch option values are not targets.
func actionOversizedTouchOperands(call *syntax.CallExpr, home, cwd string, check func(string, bool, string) bool, quick func([]string) bool) bool {
	found := false
	touchBraceFileOperands(call, home, func(word *syntax.Word) bool {
		if actionWordHasBraceText(word) && shellparse.MinBraceFields(word) > maxMentionBraceFields &&
			actionOversizedBraceTarget(word, home, cwd, check, quick) {
			found = true
			return false
		}
		return true
	})
	return found
}

// actionClientResolvedProtectedWrite reads only concrete output redirects,
// PowerShell writer operands, removals and mode or owner changes in the
// user's file-system view. The managed client sends a positive decision for
// these; a read through a link is not a write decision.
func actionClientResolvedProtectedWrite(file *syntax.File, command, cwd, home string, protected protectedFiles, ssh string) bool {
	uncalled := actionUncalledFunctions(file, command)
	values := actionValues{"HOME": home, "PWD": cwd, "USER": filepath.Base(home), "LOGNAME": filepath.Base(home)}
	currentCWD := cwd
	var directoryStack []string
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		if decl, ok := node.(*syntax.FuncDecl); ok && uncalled[decl] {
			return false
		}
		stmt, ok := node.(*syntax.Stmt)
		if !ok {
			return true
		}
		values["PWD"] = currentCWD
		actionUpdateValues(stmt, values, currentCWD, home)
		actionClientSpecialAssignments(stmt, values, home)
		for _, redirect := range stmt.Redirs {
			if redirect.Word == nil || !actionOutputRedirect(redirect.Op) {
				continue
			}
			value, known := actionClientRedirectWordValue(redirect.Word, values, currentCWD, home)
			if known && actionClientProtectedPath(value, currentCWD, protected, ssh) {
				found = true
				return false
			}
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if actionClientMutationCall(call, values, currentCWD, home, protected, ssh) ||
				actionClientPowerShellWrite(call, currentCWD, home, protected, ssh) {
				found = true
				return false
			}
			actionPosixAdvanceDirectory(call, values, home, &currentCWD, &directoryStack)
		}
		return true
	})
	return found || actionClientPipelineRemoval(file, cwd, home, protected, ssh) ||
		actionClientLoopRemoval(file, cwd, home, protected, ssh)
}

// actionClientWriteCandidate only admits a possible output redirect or a
// complete command word handled by the client reader. Descriptor copies such
// as 2>&1 and substrings in format or terraform are not candidates.
func actionClientWriteCandidate(command string) bool {
	for i := 0; i < len(command); i++ {
		if command[i] != '>' {
			continue
		}
		if i+1 < len(command) && command[i+1] == '&' && i+2 < len(command) &&
			(command[i+2] >= '0' && command[i+2] <= '9' || command[i+2] == '-') {
			continue
		}
		return true
	}
	lower := strings.ToLower(command)
	for _, word := range []string{"rm", "unlink", "chmod", "chown", "find", "pwsh", "powershell"} {
		for at := 0; at < len(lower); {
			i := strings.Index(lower[at:], word)
			if i < 0 {
				break
			}
			i += at
			before := i == 0 || !actionClientWordChar(lower[i-1])
			end := i + len(word)
			if before && (end == len(lower) || !actionClientWordChar(lower[end])) {
				return true
			}
			at = end
		}
	}
	return false
}

func actionClientWordChar(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_'
}

func actionOutputRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.AppAll, syntax.RdrInOut:
		return true
	}
	return false
}

func actionClientProtectedPath(value, cwd string, protected protectedFiles, ssh string) bool {
	return value != "" && !strings.ContainsAny(value, "*?[]\x00\x1f") &&
		protectedReachPath(OperandPath(value, cwd), protected, ssh)
}

// actionClientAnchor caches one resolved starting directory for a call.
type actionClientAnchor struct {
	path string
	ok   bool
}

// actionClientProtectedLinkPath supplies a client decision only when a link
// within the operand changes its path. The home and cwd may themselves be
// reached through links; existing readers judge direct names below them.
func actionClientProtectedLinkPath(value, cwd, home string, protected protectedFiles, ssh string, anchors map[string]actionClientAnchor) bool {
	if value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") {
		return false
	}
	path := OperandPath(value, cwd)
	resolved, ok := ResolveWriteTarget(path)
	if !ok {
		return false
	}
	anchor, rel := cwd, value
	if filepath.IsAbs(value) {
		if withinHome, underHome := cutPathPrefix(value, filepath.Clean(home)); underHome {
			anchor, rel = home, withinHome
		} else {
			volume := filepath.VolumeName(value)
			anchor = volume + string(filepath.Separator)
			separators := string(filepath.Separator)
			if filepath.Separator == '\\' {
				separators = `/\`
			}
			rel = strings.TrimLeft(value[len(volume):], separators)
		}
	}
	resolvedAnchor, cached := anchors[anchor]
	if !cached {
		resolvedAnchor.path, resolvedAnchor.ok = ResolveWriteTarget(anchor)
		anchors[anchor] = resolvedAnchor
	}
	if !resolvedAnchor.ok || samePathName(resolved, filepath.Join(resolvedAnchor.path, rel)) {
		return false
	}
	if protected.has(resolved) || samePathName(resolved, ssh) {
		return true
	}
	mapped, ok := protected.target(resolved)
	return ok && protected.has(mapped)
}

// actionClientSpecialAssignments retains the fixed output of the few echo
// substitutions the generic value reader deliberately leaves unresolved.
func actionClientSpecialAssignments(stmt *syntax.Stmt, values actionValues, home string) {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok {
		return
	}
	for _, assign := range call.Assigns {
		if assign.Name == nil || assign.Value == nil || assign.Append {
			continue
		}
		if value, known := actionClientEchoValue(assign.Value, home); known {
			values[assign.Name.Value] = value
		}
	}
}

func actionClientRedirectWordValue(word *syntax.Word, values actionValues, cwd, home string) (string, bool) {
	if actionWordHasBraceText(word) {
		fields := actionMentionBraceFields(word, home)
		if len(fields) == 1 {
			return fields[0], true
		}
		return "", false
	}
	if value, known := actionWordValue(word, values, cwd, home); known {
		return value, true
	}
	return actionClientEchoValue(word, home)
}

// actionClientEchoValue accepts a single fixed path printed by an echo
// substitution. -e with no backslash has the same output as plain echo;
// a brace field is accepted only when it makes exactly one output word.
func actionClientEchoValue(word *syntax.Word, home string) (string, bool) {
	if word == nil || len(word.Parts) != 1 {
		return "", false
	}
	part := word.Parts[0]
	if quoted, ok := part.(*syntax.DblQuoted); ok {
		if len(quoted.Parts) != 1 {
			return "", false
		}
		part = quoted.Parts[0]
	}
	sub, ok := part.(*syntax.CmdSubst)
	if !ok || len(sub.Stmts) != 1 || len(sub.Stmts[0].Redirs) != 0 {
		return "", false
	}
	call, ok := sub.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) < 2 || len(call.Args) > 3 {
		return "", false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "echo" {
		return "", false
	}
	at := 1
	if len(call.Args) == 3 {
		option, fixed := StaticWord(call.Args[1], home)
		if !fixed || option != "-e" {
			return "", false
		}
		at = 2
	}
	arg := call.Args[at]
	if actionWordHasBraceText(arg) {
		fields := actionMentionBraceFields(arg, home)
		if len(fields) == 1 {
			return fields[0], true
		}
		return "", false
	}
	value, fixed := StaticWord(arg, home)
	return value, fixed && value != "" && !strings.ContainsAny(value, "\\\x00\r\n\t ")
}

func actionClientPowerShellWrite(call *syntax.CallExpr, cwd, home string, protected protectedFiles, ssh string) bool {
	if len(call.Args) < 3 {
		return false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if !known || programBase(program) != "pwsh" && programBase(program) != "powershell" {
		return false
	}
	body, known := actionPowerShellCommandBody(call.Args, home)
	if !known {
		return false
	}
	file, parsed := parseShell(body)
	if !parsed {
		return false
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		cmd, ok := node.(*syntax.CallExpr)
		if !ok || len(cmd.Args) < 2 || found {
			return !found
		}
		name, fixed := StaticWord(cmd.Args[0], home)
		if !fixed {
			return true
		}
		switch strings.ToLower(programBase(name)) {
		case "add-content", "set-content", "out-file", "clear-content":
		default:
			return true
		}
		// A path option can follow -Value or -Encoding. Read it by name
		// before considering a positional path after those option values.
		namedPath := false
		for i := 1; i < len(cmd.Args); i++ {
			option, fixed := StaticWord(cmd.Args[i], home)
			if !fixed {
				continue
			}
			name, joined, colon := strings.Cut(option, ":")
			switch strings.ToLower(name) {
			case "-path", "-literalpath", "-filepath":
				namedPath = true
				if !colon {
					i++
					if i >= len(cmd.Args) {
						continue
					}
					joined, fixed = StaticWord(cmd.Args[i], home)
				}
				if fixed && actionClientProtectedPath(joined, cwd, protected, ssh) {
					found = true
					return false
				}
			}
		}
		if namedPath {
			return true
		}
		for i := 1; i < len(cmd.Args); i++ {
			value, fixed := StaticWord(cmd.Args[i], home)
			if !fixed {
				return true
			}
			if !strings.HasPrefix(value, "-") {
				found = actionClientProtectedPath(value, cwd, protected, ssh)
				return !found
			}
			name, _, colon := strings.Cut(strings.ToLower(value), ":")
			switch name {
			case "-value", "-encoding", "-inputobject", "-width", "-stream",
				"-erroraction", "-errorvariable", "-warningaction", "-warningvariable",
				"-informationaction", "-informationvariable", "-outvariable",
				"-outbuffer", "-pipelinevariable":
				if !colon {
					i++
				}
			case "-append", "-force", "-nonewline", "-passthru", "-whatif", "-confirm":
			default:
				return true
			}
		}
		return true
	})
	return found
}

func actionClientMutationCall(call *syntax.CallExpr, values actionValues, cwd, home string, protected protectedFiles, ssh string) bool {
	if len(call.Args) < 2 {
		return false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if !known {
		return false
	}
	switch programBase(program) {
	case "rm", "unlink":
		anchors := make(map[string]actionClientAnchor, 3)
		for _, word := range call.Args[1:] {
			value, known := actionWordValue(word, values, cwd, home)
			if !known || value == "" || strings.HasPrefix(value, "-") {
				continue
			}
			if actionClientProtectedLinkPath(value, cwd, home, protected, ssh, anchors) {
				// Removing a symlink without a trailing slash removes its
				// entry. Keep a protected entry blocked, but do not judge
				// an ordinary link by the file it names.
				if !strings.HasSuffix(value, "/") {
					path := OperandPath(value, cwd)
					if info, err := pathLstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
						parent, ok := ResolveWriteTarget(filepath.Dir(path))
						if !ok || protectedEntry(filepath.Join(parent, filepath.Base(path)), protected, ssh) {
							return true
						}
						continue
					}
				}
				return true
			}
		}
	case "chmod", "chown":
		anchors := make(map[string]actionClientAnchor, 3)
		operand := 0
		for _, word := range call.Args[1:] {
			value, known := actionWordValue(word, values, cwd, home)
			if !known || value == "" || strings.HasPrefix(value, "-") {
				continue
			}
			operand++
			if operand > 1 && actionClientProtectedLinkPath(value, cwd, home, protected, ssh, anchors) {
				return true
			}
		}
	case "find":
		return actionClientFindDelete(call, cwd, home, protected, ssh)
	case "perl":
		return actionClientPerlInPlace(call, cwd, home, protected, ssh)
	}
	return false
}

func actionClientFindDelete(call *syntax.CallExpr, cwd, home string, protected protectedFiles, ssh string) bool {
	var roots []string
	name := ""
	deletes := false
	for i := 1; i < len(call.Args); i++ {
		value, known := StaticWord(call.Args[i], home)
		if !known {
			return false
		}
		switch value {
		case "-delete":
			deletes = true
		case "-name", "-iname":
			i++
			if i >= len(call.Args) {
				return false
			}
			name, known = StaticWord(call.Args[i], home)
			if !known {
				return false
			}
		default:
			if !strings.HasPrefix(value, "-") && len(roots) == i-1 {
				roots = append(roots, value)
			}
		}
	}
	if !deletes || name == "" {
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		absoluteRoot := OperandPath(root, cwd)
		for _, target := range protected {
			if target.path != absoluteRoot && !strings.HasPrefix(target.path, absoluteRoot+string(filepath.Separator)) {
				continue
			}
			if matches, _ := filepath.Match(name, filepath.Base(target.path)); matches &&
				actionClientProtectedPath(target.path, cwd, protected, ssh) {
				return true
			}
		}
	}
	return false
}

func actionClientPerlInPlace(call *syntax.CallExpr, cwd, home string, protected protectedFiles, ssh string) bool {
	inPlace, code := false, false
	for _, arg := range call.Args[1:] {
		value, known := StaticWord(arg, home)
		if !known {
			return false
		}
		if code {
			code = false
			continue
		}
		if value == "-e" {
			code = true
			continue
		}
		if strings.HasPrefix(value, "-") {
			inPlace = inPlace || strings.Contains(value, "i")
			continue
		}
		if inPlace && protectedReachPath(OperandPath(value, cwd), protected, ssh) {
			return true
		}
	}
	return false
}

func actionClientPipelineRemoval(file *syntax.File, cwd, home string, protected protectedFiles, ssh string) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		pipe, ok := node.(*syntax.BinaryCmd)
		if !ok || pipe.Op != syntax.Pipe {
			return true
		}
		producer, left := pipe.X.Cmd.(*syntax.CallExpr)
		consumer, right := pipe.Y.Cmd.(*syntax.CallExpr)
		if !left || !right || len(producer.Args) != 2 || len(consumer.Args) < 2 {
			return true
		}
		from, f := StaticWord(producer.Args[0], home)
		to, t := StaticWord(consumer.Args[0], home)
		remove, r := StaticWord(consumer.Args[1], home)
		if !f || !t || !r || programBase(from) != "echo" || programBase(to) != "xargs" ||
			programBase(remove) != "rm" {
			return true
		}
		path, known := StaticWord(producer.Args[1], home)
		found = known && protectedReachPath(OperandPath(path, cwd), protected, ssh)
		return !found
	})
	return found
}

func actionClientLoopRemoval(file *syntax.File, cwd, home string, protected protectedFiles, ssh string) bool {
	for _, statement := range file.Stmts {
		loop, ok := statement.Cmd.(*syntax.ForClause)
		if !ok || loop.Select || len(loop.Do) != 1 {
			continue
		}
		iteration, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iteration.Name == nil || len(iteration.Items) == 0 || len(iteration.Items) > 8 {
			continue
		}
		call, ok := loop.Do[0].Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			continue
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed || programBase(program) != "rm" {
			continue
		}
		for _, item := range iteration.Items {
			value, fixed := StaticWord(item, home)
			if !fixed {
				continue
			}
			values := actionValues{"HOME": home, "PWD": cwd, iteration.Name.Value: value}
			for _, word := range call.Args[1:] {
				if path, fixed := actionWordValue(word, values, cwd, home); fixed &&
					!strings.HasPrefix(path, "-") && protectedReachPath(OperandPath(path, cwd), protected, ssh) {
					return true
				}
			}
		}
	}
	return false
}
