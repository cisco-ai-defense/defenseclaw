// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"maps"
	"os"
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
	if !filepath.IsAbs(cwd) || home == "" || !strings.Contains(command, "for") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	assignments := actionValues{"HOME": home, "PWD": cwd}
	for _, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			if name, value, assigned := actionClientLoopCopyAssignment(top, home); assigned {
				assignments[name] = value
			} else if !actionClientLoopCopyNoop(top, cwd, home) {
				return false
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 {
			return false
		}
		loopAssignments := maps.Clone(assignments)
		delete(loopAssignments, iter.Name.Value)
		var destination *syntax.Word
		for _, stmt := range loop.Do {
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
				return false
			}
			if candidate, ok := actionClientLoopCopyDestination(call, loopAssignments, cwd, home, copyOnly); ok {
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
			loopValues := actionValues{"HOME": home, "PWD": cwd, iter.Name.Value: value}
			if target, known := actionWordValue(destination, loopValues, cwd, home); known &&
				actionClientProtectedPath(target, cwd, protected, ssh) {
				return true
			}
		}
		// A preceding copy loop does not replace a destination link. Keep
		// checking later loops, and forget the iterator's final value.
		delete(assignments, iter.Name.Value)
	}
	return false
}

func actionClientLoopCopyAssignment(stmt *syntax.Stmt, home string) (string, string, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", "", false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", "", false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Append || assign.Array != nil || assign.Index != nil ||
		assign.Name.Value == "HOME" || assign.Name.Value == "PWD" {
		return "", "", false
	}
	if assign.Value == nil {
		return assign.Name.Value, "", true
	}
	value, fixed := StaticWord(assign.Value, home)
	return assign.Name.Value, value, fixed && !strings.ContainsAny(value, "*?[]\x00\x1f")
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

func actionClientLoopCopyDestination(call *syntax.CallExpr, assignments actionValues, cwd, home string, copyOnly bool) (*syntax.Word, bool) {
	if len(call.Args) < 2 {
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
	if !copyOnly && len(assignments) > 2 && base != "cp" && base != "gcp" {
		// Earlier assignments are only tracked for copy sources. Keep move
		// and install on their existing entry semantics.
		return nil, false
	}
	// For cp the source slot, the word before the destination, is never read:
	// empty, option-shaped, dynamic or missing, the name still reaches a writer.
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
	if base == "cp" || base == "gcp" {
		return call.Args[len(call.Args)-1], true
	}
	// A move or install replaces the destination entry, a link included, so
	// its destination is judged only for a source it plainly names.
	if len(call.Args) < 3 {
		return nil, false
	}
	source, fixed := StaticWord(call.Args[len(call.Args)-2], home)
	endOfOptions := false
	if len(call.Args) > 3 {
		option, fixed := StaticWord(call.Args[len(call.Args)-3], home)
		endOfOptions = fixed && option == "--"
	}
	if !fixed || source == "" || strings.HasPrefix(source, "-") && !endOfOptions || strings.ContainsAny(source, "*?[]\x00\x1f") {
		return nil, false
	}
	return call.Args[len(call.Args)-1], true
}

func actionClientLoopCopySourceStartupUnknown() bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "BASH_FUNC_") {
			return true
		}
	}
	return false
}
