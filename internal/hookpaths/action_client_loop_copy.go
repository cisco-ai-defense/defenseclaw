// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A fixed for-word list gives each copy destination one concrete value.
// This positive client fact lets a managed gateway judge a link it cannot
// follow through ProtectHome. Earlier statements and other body calls must
// leave the current directory, iterator and link unchanged.
func actionClientLoopCopyDestinationProtected(command, cwd, home string) bool {
	return loopCopyDestinationProtected(command, cwd, home, false)
}

// LoopCopyDestinationProtected checks fixed loop destinations of copy calls
// in the gateway's own filesystem view. Move and install calls have different
// destination-link behavior and are left to their existing readers.
func LoopCopyDestinationProtected(command, cwd, home string) bool {
	return loopCopyDestinationProtected(command, cwd, home, true)
}

func loopCopyDestinationProtected(command, cwd, home string, copyOnly bool) bool {
	if !filepath.IsAbs(cwd) || home == "" {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	for _, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			if !actionClientLoopCopyNoop(top, cwd, home) {
				return false
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 {
			return false
		}
		var destination *syntax.Word
		for _, stmt := range loop.Do {
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
				return false
			}
			if candidate, ok := actionClientLoopCopyDestination(call, home, copyOnly); ok {
				if destination != nil {
					return false
				}
				destination = candidate
			} else if !actionClientLoopCopyNoop(stmt, cwd, home) {
				return false
			}
		}
		if destination == nil {
			return false
		}
		usesLoopName := false
		syntax.Walk(destination, func(part syntax.Node) bool {
			if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == iter.Name.Value {
				usesLoopName = true
			}
			return true
		})
		if !usesLoopName {
			return false
		}
		for _, item := range iter.Items {
			value, fixed := StaticWord(item, home)
			if !fixed || value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") {
				return false
			}
			values := actionValues{"HOME": home, "PWD": cwd, iter.Name.Value: value}
			if target, known := actionWordValue(destination, values, cwd, home); known &&
				actionClientProtectedPath(target, cwd, protected, ssh) {
				return true
			}
		}
		return false
	}
	return false
}

func actionClientLoopCopyTop(stmt *syntax.Stmt, cwd, home string) (*syntax.ForClause, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return nil, false
	}
	if loop, ok := stmt.Cmd.(*syntax.ForClause); ok {
		return loop, true
	}
	if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt &&
		actionClientLoopCopyNoop(pair.X, cwd, home) {
		return actionClientLoopCopyTop(pair.Y, cwd, home)
	}
	return nil, false
}

func actionClientLoopCopyNoop(stmt *syntax.Stmt, cwd, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return false
	}
	switch program {
	case "true", ":":
		return len(call.Args) == 1
	case "cd":
		if len(call.Args) != 2 {
			return false
		}
		value, fixed := StaticWord(call.Args[1], home)
		return fixed && samePathName(OperandPath(value, cwd), cwd)
	case "echo":
		for _, arg := range call.Args[1:] {
			if _, fixed := StaticWord(arg, home); !fixed {
				return false
			}
		}
		return true
	}
	return false
}

func actionClientLoopCopyDestination(call *syntax.CallExpr, home string, copyOnly bool) (*syntax.Word, bool) {
	if len(call.Args) < 3 {
		return nil, false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return nil, false
	}
	base := programBase(program)
	if base != "cp" && base != "gcp" && base != "mv" && base != "install" {
		return nil, false
	}
	if copyOnly && base != "cp" && base != "gcp" {
		return nil, false
	}
	for i := 1; i < len(call.Args)-2; i++ {
		option, fixed := StaticWord(call.Args[i], home)
		if !fixed {
			return nil, false
		}
		if base == "install" && option == "-m" && i+1 < len(call.Args)-2 {
			i++
			mode, fixed := StaticWord(call.Args[i], home)
			if !fixed || mode == "" || strings.Trim(mode, "01234567") != "" {
				return nil, false
			}
			continue
		}
		switch option {
		case "--":
			if i != len(call.Args)-3 {
				return nil, false
			}
		case "-f", "-i", "--force", "--interactive":
			if base == "install" {
				return nil, false
			}
		default:
			return nil, false
		}
	}
	sourceWord := call.Args[len(call.Args)-2]
	source, fixed := StaticWord(sourceWord, home)
	if !fixed {
		// A quoted source remains one operand. Its value does not change
		// the copy destination named by the final word.
		if base != "cp" && base != "gcp" || len(sourceWord.Parts) != 1 {
			return nil, false
		}
		if _, quoted := sourceWord.Parts[0].(*syntax.DblQuoted); !quoted {
			return nil, false
		}
	} else if source == "" || strings.HasPrefix(source, "-") || strings.ContainsAny(source, "*?[]\x00\x1f") {
		return nil, false
	}
	return call.Args[len(call.Args)-1], true
}
