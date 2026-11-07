// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
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
	readOperands := func(body, dir string) bool {
		writes := LiteralWriteOperands(body, dir, home)
		writes = append(writes, InPlaceEditOperands(body, dir, home)...)
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
	if readOperands(command, cwd) {
		return true
	}
	if registrationPatchReach(file, cwd, home, protected) {
		return true
	}
	if registrationCopyReach(file, cwd, home, fileProtected) {
		return true
	}
	if strings.Contains(command, "cd ") || strings.Contains(command, "pushd ") {
		if statements, ok := TopLevelStatements(command, cwd, home); ok {
			for _, statement := range statements {
				if readOperands(statement.Command, statement.Dir) {
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
				if base == "mv" && !targetDir && index+1 == lastOperand {
					continue // the last operand receives the source
				}
				if actionWordHasBraceText(word) {
					for _, value := range actionMentionBraceFields(word, home) {
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
					paths, err := filepath.Glob(OperandPath(value, currentCWD))
					if err != nil || len(paths) > 64 {
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
		if info, err := os.Stat(dest); err != nil || !info.IsDir() {
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
		body, err := os.ReadFile(OperandPath(patchSource, cwd))
		if err != nil || len(body) > 1<<20 {
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
