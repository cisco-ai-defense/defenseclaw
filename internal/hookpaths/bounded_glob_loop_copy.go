// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/expand"
	"mvdan.cc/sh/v3/syntax"
)

// GlobLoopCopyFactPrefix is the hook user's complete expansion of a loop's
// project glob and the derived copy destinations. A managed gateway reads
// this because it cannot list the user's project directory.
const GlobLoopCopyFactPrefix = "\x00glob-loop-copy:"

func globLoopCopyFactKey(loop *syntax.ForClause, cwd string) string {
	return GlobLoopCopyFactPrefix + strconv.FormatUint(uint64(loop.Pos().Offset()), 10) + ":" + cwd
}

// BoundedGlobLoopCopyDestinations lists destinations derived from a single
// plain *.txt loop. The loop body has one assignment, one ordinary copy,
// and optionally an echo with a redirect. Any other binding or program keeps
// the usual unknown-target reading.
func BoundedGlobLoopCopyDestinations(command, cwd, home string, facts map[string]string) []string {
	return boundedGlobLoopCopyDestinationsWithFile(command, cwd, home, facts, nil)
}

// boundedGlobLoopCopyDestinationsWithFile reuses a shell tree already read
// for this client command.
func boundedGlobLoopCopyDestinationsWithFile(command, cwd, home string, facts map[string]string, file *syntax.File) []string {
	if !strings.Contains(command, "for") || !strings.Contains(command, "*.txt") || !strings.Contains(command, "cp") {
		return nil
	}
	if file == nil {
		var ok bool
		file, ok = parseShell(command)
		if !ok {
			return nil
		}
	}
	var paths []string
	for _, destinations := range boundedGlobLoopCopyCalls(file, cwd, home, facts, false) {
		paths = append(paths, destinations...)
	}
	slices.Sort(paths)
	return paths
}

func boundedGlobLoopCopyCalls(file *syntax.File, cwd, home string, facts map[string]string, record bool) map[*syntax.CallExpr][]string {
	if file == nil || !filepath.IsAbs(cwd) {
		return nil
	}
	result := map[*syntax.CallExpr][]string{}
	priorBindings := map[string]string{}
	priorIndex, priorSafe := 0, true
	var globCandidates []string
	globRead, globComplete := false, false
	for index, top := range file.Stmts {
		loop, ok := top.Cmd.(*syntax.ForClause)
		if !ok || top.Background || top.Negated || top.Coprocess || len(top.Redirs) != 0 || loop.Select {
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) != 1 || len(iter.Items[0].Parts) != 1 {
			continue
		}
		pattern, ok := iter.Items[0].Parts[0].(*syntax.Lit)
		if !ok || pattern.Value != "*.txt" || len(loop.Do) < 2 || len(loop.Do) > 3 {
			continue
		}
		assignName, assignWord, assignmentOK := boundedGlobLoopAssignment(loop.Do[0])
		if !assignmentOK {
			continue
		}
		copyStmt := loop.Do[1]
		copy, ok := copyStmt.Cmd.(*syntax.CallExpr)
		if !ok || copyStmt.Background || copyStmt.Negated || len(copyStmt.Redirs) != 0 ||
			len(copy.Assigns) != 0 || len(copy.Args) != 3 {
			continue
		}
		program, fixed := StaticWord(copy.Args[0], home)
		if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" ||
			!boundedLoopQuotedScalarWord(copy.Args[1], iter.Name.Value) ||
			!boundedLoopQuotedScalarWord(copy.Args[2], assignName) {
			continue
		}
		if len(loop.Do) == 3 && !boundedGlobLoopEcho(loop.Do[2], home) {
			continue
		}
		if priorSafe {
			priorBindings, priorSafe = boundedGlobLoopPriorValues(file.Stmts[priorIndex:index], home, priorBindings)
			priorIndex = index
		}
		if !priorSafe {
			continue
		}
		bindings := priorBindings
		validAssignment := true
		syntax.Walk(assignWord, func(node syntax.Node) bool {
			if !validAssignment {
				return false
			}
			switch part := node.(type) {
			case *syntax.ParamExp:
				if part.Param == nil || part.Param.Value != iter.Name.Value &&
					bindings[part.Param.Value] == "" && part.Param.Value != "HOME" && part.Param.Value != "PWD" {
					validAssignment = false
				}
			case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp:
				validAssignment = false
			}
			return validAssignment
		})
		if !validAssignment {
			continue
		}
		key := globLoopCopyFactKey(loop, cwd)
		if !record && facts != nil {
			if destinations, ok := decodeGlobLoopCopyFact(facts[key]); ok {
				result[copy] = destinations
			}
			continue
		}
		if !globRead {
			globRead = true
			if !actionGlobViewHidden(cwd, home) {
				// Include dot names and case variants. Bash may have dotglob
				// or nocaseglob from startup files or an earlier statement.
				entries, complete, _ := actionExpandGlob(filepath.Join(cwd, "*"), cwd, false,
					actionProcessOwnsHome(home), func() bool { return true })
				if complete {
					for _, entry := range entries {
						if copyTextGlobName(filepath.Base(entry)) {
							globCandidates = append(globCandidates, entry)
						}
					}
					globComplete = len(globCandidates) > 0 && len(globCandidates) <= 32
				}
			}
		}
		if !globComplete {
			continue
		}
		var destinations []string
		for _, candidate := range globCandidates {
			name := filepath.Base(candidate)
			if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, " \t\r\n\\\x00") {
				destinations = nil
				break
			}
			vars := []string{"HOME=" + home, "PWD=" + cwd, iter.Name.Value + "=" + name}
			for variable, value := range bindings {
				vars = append(vars, variable+"="+value)
			}
			fields, err := shellparse.Fields(&expand.Config{Env: expand.ListEnviron(vars...)}, assignWord)
			if err != nil || len(fields) != 1 || fields[0] == "" || strings.ContainsAny(fields[0], "*?[]\x00\x1f") {
				destinations = nil
				break
			}
			destinations = append(destinations, OperandPath(fields[0], cwd))
		}
		if len(destinations) != len(globCandidates) {
			continue
		}
		slices.Sort(destinations)
		result[copy] = destinations
		if record && facts != nil {
			if encoded, err := json.Marshal(destinations); err == nil {
				facts[key] = string(encoded)
			}
		}
	}
	return result
}

func boundedGlobLoopAssignment(stmt *syntax.Stmt) (string, *syntax.Word, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return "", nil, false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return "", nil, false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Value == nil || assign.Append || assign.Array != nil || assign.Index != nil {
		return "", nil, false
	}
	return assign.Name.Value, assign.Value, true
}

func boundedGlobLoopEcho(stmt *syntax.Stmt, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 1 ||
		stmt.Redirs[0].Op != syntax.AppOut {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) != 2 {
		return false
	}
	program, fixed := StaticWord(call.Args[0], home)
	return fixed && program == "echo"
}

func boundedGlobLoopPriorValues(prior []*syntax.Stmt, home string, bindings map[string]string) (map[string]string, bool) {
	for _, stmt := range prior {
		if stmt.Background || stmt.Negated {
			return nil, false
		}
		if name, word, ok := boundedGlobLoopAssignment(stmt); ok {
			if name == "HOME" || name == "PWD" || name == "IFS" {
				return nil, false
			}
			value, fixed := StaticWord(word, home)
			if !fixed || value == "" || strings.ContainsAny(value, "*?[]$`\x00\x1f") {
				return nil, false
			}
			bindings[name] = value
			continue
		}
		unsafe := false
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if unsafe {
				return false
			}
			switch node := node.(type) {
			case *syntax.Assign:
				if node.Name != nil && bindings[node.Name.Value] != "" {
					unsafe = true
				}
			case *syntax.ParamExp:
				if node.Index != nil || node.Slice != nil || node.Exp != nil && node.Param != nil &&
					bindings[node.Param.Value] != "" {
					unsafe = true
				}
			case *syntax.FuncDecl, *syntax.ArithmCmd, *syntax.ArithmExp:
				unsafe = true
			case *syntax.DeclClause:
				unsafe = true
			case *syntax.CallExpr:
				if len(node.Args) == 0 {
					return true
				}
				program, fixed := StaticWord(node.Args[0], home)
				if !fixed && node.Args[0].Lit() == "[" {
					program, fixed = "[", true
				}
				if !fixed || strings.Contains(" eval source . trap alias read export declare local typeset unset printf command builtin exec cd pushd popd ", " "+program+" ") {
					unsafe = true
				}
				if program == "set" && (len(node.Args) != 2 || node.Args[1].Lit() != "-e") {
					unsafe = true
				}
			}
			return !unsafe
		})
		if unsafe {
			return nil, false
		}
	}
	return bindings, true
}

func decodeGlobLoopCopyFact(encoded string) ([]string, bool) {
	var paths []string
	if encoded == "" || json.Unmarshal([]byte(encoded), &paths) != nil || len(paths) == 0 || len(paths) > 32 {
		return nil, false
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || len(path) > MaxWriteTargetPathBytes || strings.IndexByte(path, 0) >= 0 {
			return nil, false
		}
	}
	return paths, true
}
