// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// ProtectedReach runs the shared concrete shell mutation reader against a
// caller-supplied registration set. It uses the same value, directory and
// link resolution as the protected state decision, including ordered shell
// assignments and cd-relative operands. It reports only a proved write.
func ProtectedReach(command, cwd, home string, names []string) bool {
	if command == "" || !filepath.IsAbs(cwd) || len(names) == 0 {
		return false
	}
	if !actionClientWriteCandidate(command) && !strings.Contains(command, "rmdir") && !strings.Contains(command, "perl") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := make(protectedFiles, 0, len(names))
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
	}
	if actionClientResolvedProtectedWrite(file, command, cwd, home, protected, "") {
		return true
	}
	if protectedPipelineRemoval(file, cwd, home, protected) {
		return true
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
		if known && programBase(program) == "find" && protectedFindDelete(call, currentCWD, home, protected) {
			found = true
			return false
		}
		if known && programBase(program) == "perl" && protectedPerlInPlace(call, currentCWD, home, protected) {
			found = true
			return false
		}
		if known && (programBase(program) == "rm" || programBase(program) == "rmdir" || programBase(program) == "unlink") {
			for _, word := range call.Args[1:] {
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

func protectedFindDelete(call *syntax.CallExpr, cwd, home string, protected protectedFiles) bool {
	if len(call.Args) < 4 {
		return false
	}
	root, known := StaticWord(call.Args[1], home)
	if !known {
		return false
	}
	root = OperandPath(root, cwd)
	name, deletes := "", false
	for i := 2; i < len(call.Args); i++ {
		word, known := StaticWord(call.Args[i], home)
		if !known {
			return false
		}
		switch word {
		case "-name", "-iname":
			i++
			if i >= len(call.Args) {
				return false
			}
			name, known = StaticWord(call.Args[i], home)
			if !known {
				return false
			}
		case "-delete":
			deletes = true
		}
	}
	if !deletes || name == "" {
		return false
	}
	for _, target := range protected {
		if target.path == root || !strings.HasPrefix(target.path, root+string(filepath.Separator)) {
			continue
		}
		if match, err := filepath.Match(name, filepath.Base(target.path)); err == nil && match {
			return true
		}
	}
	return false
}

func protectedPerlInPlace(call *syntax.CallExpr, cwd, home string, protected protectedFiles) bool {
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
		if inPlace && protectedReachPath(OperandPath(value, cwd), protected, "") {
			return true
		}
	}
	return false
}

func protectedPipelineRemoval(file *syntax.File, cwd, home string, protected protectedFiles) bool {
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
		found = known && protectedReachPath(OperandPath(path, cwd), protected, "")
		return !found
	})
	return found
}
