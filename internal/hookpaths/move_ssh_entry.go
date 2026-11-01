// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionMoveProtectedEntry reports a plain mv (or gmv) whose renamed or
// replaced directory entry is the .ssh directory or one of the protected
// authorized-keys entries, read as the user: a source entry (mv ~/.ssh
// elsewhere), a destination entry, or the entry a move into a directory
// places (mv x/authorized_keys ~/.ssh, mv -t ~/.ssh ..., a link to ~/.ssh,
// a ../.ssh spelling). A move into the .ssh directory under any name is a
// write into that directory, as cp into it is. A per-user gateway reads the
// same entries from its own disk; a managed gateway behind ProtectHome
// cannot, so the hook client sends this reading as ActionDecisionKey
// (GAP-2581). A destination that is a link to a file is judged by the link
// entry itself (rename replaces the link), so the GAP-2559 benign move onto
// a link keeps its allow.
func actionMoveProtectedEntry(command, cwd, home string) bool {
	if command == "" || home == "" || !filepath.IsAbs(cwd) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	values := actionValues{"HOME": home, "PWD": cwd}
	called := calledFunctions(file, home)
	moved := false
	// After a cd the shell may stand elsewhere; only absolute operands are
	// read then, so a relative spelling is never placed in the wrong tree.
	relativeOK := true
	for _, stmt := range file.Stmts {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if moved {
				return false
			}
			if declaration, isFunction := node.(*syntax.FuncDecl); isFunction {
				return declaration.Name != nil && called[declaration.Name.Value]
			}
			call, isCall := node.(*syntax.CallExpr)
			if !isCall || len(call.Args) < 2 {
				return true
			}
			program, known := staticProgramWord(call.Args[0], home)
			if !known {
				return true
			}
			switch programBase(program) {
			case "cd", "pushd", "popd":
				relativeOK = false
				return true
			case "mv", "gmv":
			default:
				return true
			}
			entries, into, read := moveEntries(call, values, cwd, home, relativeOK)
			if !read {
				return true
			}
			if into != "" && sameDirectory(into, ssh) {
				moved = true
				return false
			}
			for _, entry := range entries {
				if protectedEntry(entry, protected, ssh) {
					moved = true
					return false
				}
			}
			return true
		})
		if moved {
			return true
		}
		actionUpdateValues(stmt, values, cwd, home)
	}
	return false
}

// moveEntries lists the directory entries a static mv call renames or
// replaces, each with its directory resolved as the user and its own name
// kept, and into, the resolved directory a move into a directory places its
// sources in (empty for a rename onto an entry).
func moveEntries(call *syntax.CallExpr, values actionValues, cwd, home string, relativeOK bool) (entries []string, into string, read bool) {
	var operands []string
	target := ""
	noTarget, options := false, true
	args := call.Args[1:]
	for i := 0; i < len(args); i++ {
		value, known := actionWordValue(args[i], values, cwd, home)
		if !known || strings.ContainsAny(value, "*?[") {
			return nil, "", false
		}
		switch {
		case options && value == "--":
			options = false
		case options && (value == "-t" || value == "--target-directory"):
			if i+1 >= len(args) {
				return nil, "", false
			}
			i++
			next, fixed := actionWordValue(args[i], values, cwd, home)
			if !fixed {
				return nil, "", false
			}
			target = next
		case options && strings.HasPrefix(value, "--target-directory="):
			target = strings.TrimPrefix(value, "--target-directory=")
		case options && value == "--no-target-directory":
			noTarget = true
		case options && strings.HasPrefix(value, "--"):
		case options && len(value) > 1 && strings.HasPrefix(value, "-"):
			flags := value[1:]
			if at := strings.IndexByte(flags, 0x74); at >= 0 { // -t DIR, -tDIR, -ft DIR
				if rest := flags[at+1:]; rest != "" {
					target = rest
				} else if i+1 < len(args) {
					i++
					next, fixed := actionWordValue(args[i], values, cwd, home)
					if !fixed {
						return nil, "", false
					}
					target = next
				} else {
					return nil, "", false
				}
				flags = flags[:at]
			}
			noTarget = noTarget || strings.ContainsRune(flags, 0x54) // -T
		default:
			operands = append(operands, value)
		}
	}
	path := func(value string) (string, bool) {
		if value == "" || !filepath.IsAbs(value) && !relativeOK {
			return "", false
		}
		resolved := OperandPath(value, cwd)
		return resolved, filepath.IsAbs(resolved)
	}
	entryOf := func(resolved string) (string, bool) {
		name := filepath.Base(resolved)
		parent, ok := ResolveWriteTarget(filepath.Dir(resolved))
		if !ok || name == "." || name == ".." || name == "/" {
			return "", false
		}
		return filepath.Join(parent, name), true
	}
	sources := operands
	directory := ""
	if target != "" {
		directory = target
	} else {
		if len(operands) < 2 {
			return nil, "", false
		}
		sources = operands[:len(operands)-1]
	}
	for _, source := range sources {
		if resolved, ok := path(source); ok {
			if entry, ok := entryOf(resolved); ok {
				entries = append(entries, entry)
			}
		}
	}
	if directory == "" {
		destination := operands[len(operands)-1]
		resolved, ok := path(destination)
		if !ok {
			return entries, "", true
		}
		info, err := pathStat(resolved)
		if noTarget || err != nil || !info.IsDir() {
			if entry, ok := entryOf(resolved); ok {
				entries = append(entries, entry)
			}
			return entries, "", true
		}
		directory = destination
	}
	resolved, ok := path(directory)
	if !ok {
		return entries, "", true
	}
	placed, ok := ResolveWriteTarget(resolved)
	if !ok {
		return entries, "", true
	}
	for _, source := range sources {
		name := filepath.Base(strings.TrimRight(source, "/"))
		if name == "" || name == "." || name == ".." || name == "/" {
			continue
		}
		entries = append(entries, filepath.Join(placed, name))
	}
	return entries, placed, true
}

// sameDirectory reports a resolved directory that is dir, with dir read
// through its own links: a move into the .ssh directory under any name is a
// write into it, as cp into it is.
func sameDirectory(resolved, dir string) bool {
	if samePathName(resolved, dir) {
		return true
	}
	target, ok := ResolveWriteTarget(dir)
	return ok && samePathName(resolved, target)
}
