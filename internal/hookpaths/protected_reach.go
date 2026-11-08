// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// RegistrationWriteReach runs the shared concrete shell mutation reader against a
// caller-supplied registration set. It uses the same value, directory and
// link resolution as the protected state decision, including ordered shell
// assignments and cd-relative operands. It reports only a proved write.
func RegistrationWriteReach(command, cwd, home string, names []string) bool {
	if command == "" || !filepath.IsAbs(cwd) || len(names) == 0 {
		return false
	}
	if !RegistrationWriteCandidate(command) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := make(protectedFiles, 0, len(names))
	fileProtected := make(protectedFiles, 0, len(names))
	for _, name := range names {
		if !filepath.IsAbs(name) {
			continue
		}
		name = filepath.Clean(name)
		entry := protectedFile{path: name}
		if info, err := pathStat(name); err == nil {
			entry.info = info
		} else if !os.IsNotExist(err) {
			entry.unknown = true
		}
		protected = append(protected, entry)
		if entry.info == nil || !entry.info.IsDir() {
			fileProtected = append(fileProtected, entry)
		}
	}
	if actionClientResolvedProtectedWrite(file, command, cwd, home, protected, "") {
		return true
	}
	readOperands := func(body, dir string, user KnownUser) bool {
		writes := LiteralWriteOperands(body, dir, home)
		writes = append(writes, InPlaceEditOperands(body, dir, home, user)...)
		if strings.Contains(body, ">") {
			redirects, _, _ := ShellWriteOperands(body, dir, home)
			writes = append(writes, redirects...)
			bounded, _ := BoundedShellWriteOperands(body, dir, home)
			writes = append(writes, bounded...)
		}
		for _, path := range writes {
			if protectedReachPath(OperandPath(path, dir), fileProtected, "") {
				return true
			}
		}
		return false
	}
	if readOperands(command, cwd, KnownUser{Name: ActionKnownUser(command, home)}) {
		return true
	}
	if registrationPatchReach(file, cwd, home, protected) {
		return true
	}
	if registrationCopyReach(file, cwd, home, fileProtected) {
		return true
	}
	if registrationLoopReach(file, command, cwd, home, protected) ||
		registrationFindRsyncReach(file, cwd, home, protected) {
		return true
	}
	if strings.Contains(command, "cd ") || strings.Contains(command, "pushd ") {
		if statements, ok := TopLevelStatements(command, cwd, home); ok {
			for _, statement := range statements {
				if readOperands(statement.Command, statement.Dir, statement.User) {
					return true
				}
			}
		}
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	currentCWD := cwd
	var stack []string
	found := false
	uncalled := actionUncalledFunctions(file, command)
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
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok {
			return true
		}
		values["PWD"] = currentCWD
		actionUpdateValues(stmt, values, currentCWD, home)
		if len(call.Args) < 2 {
			actionPosixAdvanceDirectory(call, values, home, &currentCWD, &stack)
			return true
		}
		program, known := staticProgramWord(call.Args[0], home)
		base := programBase(program)
		if known && (base == "rm" || base == "rmdir" || base == "unlink" || base == "mv" ||
			base == "chmod" || base == "chown" || base == "chgrp" || base == "setfacl" || base == "chattr") {
			lastOperand := len(call.Args) - 1
			targetDir := false
			for _, word := range call.Args[1:] {
				value, fixed := StaticWord(word, home)
				if fixed && (value == "-t" || value == "--target-directory" || strings.HasPrefix(value, "--target-directory=")) {
					targetDir = true
				}
			}
			for index, word := range call.Args[1:] {
				receives := base == "mv" && !targetDir && index+1 == lastOperand
				if receives && !actionWordHasBraceText(word) {
					continue // the last operand receives the source
				}
				if actionWordHasBraceText(word) {
					fields := actionMentionBraceFields(word, home)
					if receives && len(fields) > 0 {
						// mv dir{,.bak}: the last field receives the first.
						fields = fields[:len(fields)-1]
					}
					for _, value := range fields {
						if protectedReachPath(OperandPath(value, currentCWD), protected, "") {
							found = true
							return false
						}
					}
					continue
				}
				value, known := actionWordValueWithGlob(word, values, currentCWD, home, true)
				if !known || value == "" || strings.HasPrefix(value, "-") {
					continue
				}
				if strings.ContainsAny(value, "*?[") && actionWordHasUnquotedGlob(word, command) {
					paths := actionBoundedGlob(OperandPath(value, currentCWD), false)
					if len(paths) > 64 {
						continue
					}
					for _, path := range paths {
						if protectedReachPath(path, protected, "") {
							found = true
							return false
						}
					}
					continue
				}
				if !strings.ContainsAny(value, "*?[") && protectedReachPath(OperandPath(value, currentCWD), protected, "") {
					found = true
					return false
				}
			}
		}
		actionPosixAdvanceDirectory(call, values, home, &currentCWD, &stack)
		return true
	})
	return found
}

// registrationItemPaths lists the paths one word of a loop list or an
// operand names: its brace fields, its unquoted glob matches, or its value.
func registrationItemPaths(word *syntax.Word, command, cwd, home string) []string {
	if actionWordHasBraceText(word) {
		return actionMentionBraceFields(word, home)
	}
	value, known := actionWordValueWithGlob(word, actionValues{"HOME": home, "PWD": cwd}, cwd, home, true)
	if !known || value == "" {
		return nil
	}
	if strings.ContainsAny(value, "*?[") && actionWordHasUnquotedGlob(word, command) {
		matches := actionBoundedGlob(OperandPath(value, cwd), false)
		if len(matches) > 64 {
			return nil
		}
		return matches
	}
	return []string{value}
}

// registrationLoopReach reads a for loop over literal, brace or glob items
// whose body removes or moves the loop variable (for f in dir/hook-*; do
// rm -f "$f"; done) with the loop name bound to each item.
func registrationLoopReach(file *syntax.File, command, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		loop, ok := node.(*syntax.ForClause)
		if found || !ok || loop.Select {
			return !found
		}
		iteration, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iteration.Name == nil || len(iteration.Items) == 0 || len(iteration.Items) > 8 {
			return true
		}
		var items []string
		for _, item := range iteration.Items {
			items = append(items, registrationItemPaths(item, command, cwd, home)...)
		}
		for _, item := range items {
			values := actionValues{"HOME": home, "PWD": cwd, iteration.Name.Value: item}
			for _, body := range loop.Do {
				syntax.Walk(body, func(inner syntax.Node) bool {
					stmt, ok := inner.(*syntax.Stmt)
					if !ok || found {
						return !found
					}
					for _, path := range registrationLoopStatementTargets(stmt, values, cwd, home) {
						if protectedReachPath(OperandPath(path, cwd), protected, "") {
							found = true
							return false
						}
					}
					return true
				})
			}
		}
		return true
	})
	return found
}

// registrationLoopStatementTargets lists the paths one statement of a loop
// body writes, removes, moves, re-modes or replaces, with the loop name bound
// to the current item: its output redirects and the target operands of the
// mutating programs the straight-line reader also knows.
func registrationLoopStatementTargets(stmt *syntax.Stmt, values actionValues, cwd, home string) []string {
	var targets []string
	add := func(word *syntax.Word) {
		path, fixed := actionWordValue(word, values, cwd, home)
		if fixed && path != "" && !strings.HasPrefix(path, "-") {
			targets = append(targets, path)
		}
	}
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.AppClob, syntax.RdrAll, syntax.AppAll:
			add(redirect.Word)
		}
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 {
		return targets
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed {
		return targets
	}
	operands := call.Args[1:]
	switch programBase(program) {
	case "rm", "unlink", "shred", "rmdir", "chmod", "chown", "chgrp", "setfacl", "chattr", "truncate", "tee":
		for _, word := range operands {
			add(word)
		}
	case "mv":
		sources := operands
		toDirectory := false
		for _, word := range operands {
			value, fixed := StaticWord(word, home)
			toDirectory = toDirectory || fixed && (value == "-t" || strings.HasPrefix(value, "--target-directory"))
		}
		if !toDirectory && len(sources) > 1 {
			sources = sources[:len(sources)-1]
		}
		for _, word := range sources {
			add(word)
		}
	case "cp", "install", "ln":
		add(operands[len(operands)-1])
	case "sed", "perl":
		editing := false
		for _, word := range operands {
			value, fixed := StaticWord(word, home)
			editing = editing || fixed && (strings.HasPrefix(value, "-i") || value == "--in-place" || strings.HasPrefix(value, "--in-place="))
		}
		if editing {
			for _, word := range operands {
				add(word)
			}
		}
	case "dd":
		for _, word := range operands {
			if value, fixed := actionWordValue(word, values, cwd, home); fixed {
				if target, ok := strings.CutPrefix(value, "of="); ok && target != "" {
					targets = append(targets, target)
				}
			}
		}
	}
	return targets
}

// registrationFindRsyncReach reads the two tools that empty a folder without
// naming what they remove: find with -delete or an rm/mv -exec (narrowed by
// -name or -iname when given), and rsync --delete into a folder.
func registrationFindRsyncReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 2 {
			return !found
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			value, fixed := StaticWord(arg, home)
			if !fixed {
				return true
			}
			words[i] = value
		}
		switch programBase(words[0]) {
		case "find":
			found = registrationFindReach(words, cwd, protected)
		case "rsync":
			found = registrationRsyncReach(words, cwd, protected)
		case "install":
			found = registrationInstallReach(words, cwd, protected)
		case "dd":
			for _, word := range words[1:] {
				target, ok := strings.CutPrefix(word, "of=")
				if rest, tilde := strings.CutPrefix(target, "~/"); tilde {
					target = filepath.Join(home, rest)
				}
				if ok && target != "" && protectedReachPath(OperandPath(target, cwd), protected, "") {
					found = true
				}
			}
		}
		return !found
	})
	return found
}

func registrationFindReach(words []string, cwd string, protected protectedFiles) bool {
	var roots, names []string
	deletes, insensitive := false, false
	for i := 1; i < len(words); i++ {
		switch word := words[i]; word {
		case "-delete":
			deletes = true
		case "-exec", "-execdir", "-ok", "-okdir":
			if i+1 < len(words) {
				switch programBase(words[i+1]) {
				case "rm", "unlink", "shred", "mv":
					deletes = true
				}
			}
		case "-name", "-iname":
			if i+1 < len(words) {
				insensitive = insensitive || word == "-iname"
				names = append(names, words[i+1])
				i++
			}
		default:
			if len(roots) == i-1 && !strings.HasPrefix(word, "-") && word != "!" && word != "(" {
				roots = append(roots, word)
			}
		}
	}
	if !deletes {
		return false
	}
	if len(roots) == 0 {
		roots = []string{"."}
	}
	for _, root := range roots {
		root = OperandPath(root, cwd)
		for _, target := range protected {
			if target.path != root && !strings.HasPrefix(target.path, root+string(filepath.Separator)) {
				continue
			}
			if len(names) == 0 {
				return true
			}
			base := filepath.Base(target.path)
			for _, pattern := range names {
				if insensitive {
					pattern, base = strings.ToLower(pattern), strings.ToLower(base)
				}
				if matched, _ := filepath.Match(pattern, base); matched {
					return true
				}
			}
		}
	}
	return false
}

// registrationInstallReach reads install SOURCE DEST, install SOURCE... DIR
// and install -t DIR SOURCE...: the destination file or the file the
// source name takes in the destination folder.
func registrationInstallReach(words []string, cwd string, protected protectedFiles) bool {
	var operands []string
	directory := ""
	for i := 1; i < len(words); i++ {
		switch word := words[i]; {
		case word == "-t" || word == "--target-directory":
			if i+1 < len(words) {
				directory = words[i+1]
				i++
			}
		case strings.HasPrefix(word, "--target-directory="):
			directory = strings.TrimPrefix(word, "--target-directory=")
		case word == "-m" || word == "-o" || word == "-g" || word == "--mode" || word == "--owner" || word == "--group":
			i++
		case strings.HasPrefix(word, "-") && word != "-":
		default:
			operands = append(operands, word)
		}
	}
	if directory == "" && len(operands) >= 2 {
		last := operands[len(operands)-1]
		operands = operands[:len(operands)-1]
		// A last operand that is a folder (or is written with a trailing
		// separator) receives each source under the source name; only a
		// plain file name is itself the written target.
		if info, err := pathStat(OperandPath(last, cwd)); strings.HasSuffix(last, "/") || (err == nil && info.IsDir()) {
			directory = last
		} else if protectedReachPath(OperandPath(last, cwd), protected, "") {
			return true
		}
	}
	for _, source := range operands {
		if directory != "" && protectedReachPath(filepath.Join(OperandPath(directory, cwd), filepath.Base(source)), protected, "") {
			return true
		}
	}
	return false
}

func registrationRsyncReach(words []string, cwd string, protected protectedFiles) bool {
	deletes := false
	destination := ""
	for _, word := range words[1:] {
		if strings.HasPrefix(word, "--delete") {
			deletes = true
		}
		if !strings.HasPrefix(word, "-") {
			destination = word
		}
	}
	if !deletes || destination == "" || strings.Contains(destination, ":") {
		return false
	}
	destination = OperandPath(destination, cwd)
	for _, target := range protected {
		if target.path == destination || strings.HasPrefix(target.path, destination+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// registrationCopyReach resolves a copy into a directory to the actual file
// name supplied by its source. A directory receiving some other name is not
// itself a registration write.
func registrationCopyReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || found {
			return !found
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		argv := make([]string, len(call.Args))
		for i, word := range call.Args {
			value, fixed := StaticWord(word, home)
			if !fixed {
				return true
			}
			argv[i] = value
		}
		if !IsCopyProgram(argv) {
			return true
		}
		dest := CopyDestination(argv, cwd)
		if dest == "" {
			return true
		}
		source := argv[len(argv)-2]
		if CopyDestinationOperand(argv) != argv[len(argv)-1] {
			source = argv[len(argv)-1]
		}
		if source == "" || strings.HasPrefix(source, "-") {
			return true
		}
		if info, err := pathStat(dest); err != nil || !info.IsDir() {
			return true
		}
		if protectedReachPath(filepath.Join(dest, filepath.Base(source)), protected, "") {
			found = true
			return false
		}
		return true
	})
	return found
}

// RegistrationArchivePossibleReach reports an extraction into a directory
// containing a registration when the archive's entries are not named in the
// command. This is a possible write; callers choose its profile grade.
func RegistrationArchivePossibleReach(command, cwd, home string, names []string) string {
	if !strings.Contains(command, "tar") && !strings.Contains(command, "unzip") {
		return ""
	}
	file, ok := parseShell(command)
	if !ok {
		return ""
	}
	found := ""
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 || found != "" {
			return found == ""
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed {
			return true
		}
		args := make([]string, 0, len(call.Args)-1)
		for _, word := range call.Args[1:] {
			value, fixed := StaticWord(word, home)
			if !fixed {
				return true
			}
			args = append(args, value)
		}
		for _, dest := range ArchiveExtractionDestinations(program, args) {
			folder := OperandPath(dest, cwd)
			// A generic ancestor such as /tmp is not a registered hook
			// folder merely because a test home happens to live below it.
			if !slices.Contains(names, folder) {
				continue
			}
			for _, name := range names {
				if name != folder && strings.HasPrefix(name, folder+string(filepath.Separator)) {
					found = folder
					return false
				}
			}
		}
		return true
	})
	return found
}

// RegistrationWriteCandidate is the shared reader's cheap hot-path gate.
func RegistrationWriteCandidate(command string) bool {
	if strings.ContainsAny(command, ">") {
		return true
	}
	for _, word := range []string{"rm", "mv", "cp", "ln", "sed", "perl", "patch", "chmod", "chown", "chgrp", "setfacl", "chattr", "find", "truncate", "touch", "install", "rsync", "tar", "unzip", "dd", "tee", "sponge", "python", "node", "ruby", "bash", "zsh", "dash", "ksh", "sh"} {
		if strings.Contains(command, word) {
			return true
		}
	}
	return false
}

// registrationReadSmall reads a patch source of at most 1 MiB through the
// network-share-bounded opener.
func registrationReadSmall(name string) ([]byte, bool) {
	f, err := pathOpen(name)
	if err != nil {
		return nil, false
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, 1<<20+1))
	return body, err == nil && len(body) <= 1<<20
}

// registrationPatchReach reads a literal patch source named by the same
// command. It uses the caller's registration set for the target comparison.
func registrationPatchReach(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || found {
			return !found
		}
		call, ok := stmt.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) < 2 {
			return true
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed || programBase(program) != "patch" {
			return true
		}
		var operands []string
		patchSource := ""
		for i := 1; i < len(call.Args); i++ {
			word, fixed := StaticWord(call.Args[i], home)
			if !fixed {
				return true
			}
			if word == "--dry-run" {
				return true
			}
			if word == "-i" || word == "--input" {
				i++
				if i < len(call.Args) {
					patchSource, _ = StaticWord(call.Args[i], home)
				}
				continue
			}
			if value, ok := strings.CutPrefix(word, "--input="); ok {
				patchSource = value
				continue
			}
			if strings.HasPrefix(word, "-") {
				continue
			}
			operands = append(operands, word)
		}
		if len(operands) > 0 && protectedReachPath(OperandPath(operands[0], cwd), protected, "") {
			found = true
			return false
		}
		if patchSource == "" && len(operands) > 1 {
			patchSource = operands[len(operands)-1]
		}
		if patchSource == "" {
			for _, redirect := range stmt.Redirs {
				if redirect.Op == syntax.RdrIn && redirect.Word != nil {
					patchSource, _ = StaticWord(redirect.Word, home)
					break
				}
			}
		}
		if patchSource == "" {
			return true
		}
		body, ok := registrationReadSmall(OperandPath(patchSource, cwd))
		if !ok {
			return true
		}
		for _, line := range strings.Split(string(body), "\n") {
			if path, ok := strings.CutPrefix(line, "+++ b/"); ok {
				path, _, _ = strings.Cut(path, "\t")
				if protectedReachPath(OperandPath(path, cwd), protected, "") {
					found = true
					return false
				}
			}
		}
		return true
	})
	return found
}
