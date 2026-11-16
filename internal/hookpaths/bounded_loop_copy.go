// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// BoundedLoopCopyDestinations names the ordinary destinations of a first
// top-level copy loop over short fixed names. A separate client reading
// checks the other destinations possible when IFS splits an unquoted word.
func BoundedLoopCopyDestinations(command, cwd, home string) []string {
	if !strings.Contains(command, "for") || !strings.Contains(command, "cp") || !strings.Contains(command, "/") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var destinations []string
	for _, paths := range boundedLoopCopyCalls(file, cwd, home) {
		destinations = append(destinations, paths...)
	}
	slices.Sort(destinations)
	return destinations
}

func boundedLoopCopyCalls(file *syntax.File, cwd, home string) map[*syntax.CallExpr][]string {
	if file == nil || !filepath.IsAbs(cwd) {
		return nil
	}
	result := map[*syntax.CallExpr][]string{}
	for _, loop := range simpleLoopCopies(file, home, 6, true) {
		// Four six-byte names keep the IFS candidate check below its cap.
		if len(loop.values) > 4 {
			continue
		}
		var paths []string
		for _, value := range loop.values {
			paths = append(paths, OperandPath(loop.prefix+value, cwd))
		}
		result[loop.call] = paths
	}
	return result
}

type simpleLoopCopy struct {
	call   *syntax.CallExpr
	prefix string
	values []string
}

func simpleLoopCopies(file *syntax.File, home string, maxName int, firstOnly bool) []simpleLoopCopy {
	var copies []simpleLoopCopy
	for index, top := range file.Stmts {
		if firstOnly && index != 0 {
			continue
		}
		loop, ok := top.Cmd.(*syntax.ForClause)
		if !ok || top.Background || top.Negated || top.Coprocess || len(top.Redirs) != 0 ||
			loop.Select || len(loop.Do) != 1 {
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 || len(iter.Items) > 32 {
			continue
		}
		body := loop.Do[0]
		call, ok := body.Cmd.(*syntax.CallExpr)
		if !ok || body.Background || body.Negated || body.Coprocess || len(body.Redirs) != 0 ||
			len(call.Assigns) != 0 || len(call.Args) != 3 {
			continue
		}
		program, fixed := StaticWord(call.Args[0], home)
		if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" ||
			!boundedLoopUnquotedScalarWord(call.Args[1], iter.Name.Value) {
			continue
		}
		prefix, ok := boundedLoopDestinationPrefix(call.Args[2], iter.Name.Value)
		if !ok {
			continue
		}
		copy := simpleLoopCopy{call: call, prefix: prefix}
		for _, item := range iter.Items {
			value, fixed := StaticWord(item, home)
			if !fixed || !boundedLoopPlainName(value, maxName) {
				copy.values = nil
				break
			}
			copy.values = append(copy.values, value)
		}
		if len(copy.values) == len(iter.Items) {
			copies = append(copies, copy)
		}
	}
	return copies
}

func boundedLoopPlainName(value string, maxName int) bool {
	if value == "" || value == "." || value == ".." || len(value) > maxName || filepath.Base(value) != value {
		return false
	}
	for i := 0; i < len(value); i++ {
		b := value[i]
		alphanumeric := b >= '0' && b <= '9' || b >= 'A' && b <= 'Z' || b >= 'a' && b <= 'z'
		if !alphanumeric && b != '.' && b != '_' {
			return false
		}
	}
	return true
}

func boundedLoopUnquotedScalarWord(word *syntax.Word, name string) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	param, ok := word.Parts[0].(*syntax.ParamExp)
	return ok && simpleScalarParameter(param) && param.Param.Value == name
}

func boundedLoopDestinationPrefix(word *syntax.Word, name string) (string, bool) {
	if word == nil || len(word.Parts) != 2 {
		return "", false
	}
	literal, ok := word.Parts[0].(*syntax.Lit)
	if !ok || !strings.HasSuffix(literal.Value, "/") ||
		!boundedLoopPlainName(strings.TrimSuffix(literal.Value, "/"), 32) {
		return "", false
	}
	param, ok := word.Parts[1].(*syntax.ParamExp)
	return literal.Value, ok && simpleScalarParameter(param) && param.Param.Value == name
}

func boundedLoopQuotedScalarWord(word *syntax.Word, name string) bool {
	if word == nil || len(word.Parts) != 1 {
		return false
	}
	quoted, ok := word.Parts[0].(*syntax.DblQuoted)
	if !ok || len(quoted.Parts) != 1 {
		return false
	}
	param, ok := quoted.Parts[0].(*syntax.ParamExp)
	return ok && simpleScalarParameter(param) && param.Param.Value == name
}

// actionClientBoundedLoopCopyPotentialProtected checks the paths an arbitrary
// inherited IFS could make from the two unquoted operands. Only the hook
// user's readable view supplies positive evidence; the managed gateway uses
// the authenticated action-decision fact carried by Resolve.
func actionClientBoundedLoopCopyPotentialProtected(command, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || home == "" || !strings.Contains(command, "for") || !strings.Contains(command, "cp") ||
		!strings.Contains(command, "/") ||
		actionGlobViewHidden(cwd, home) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	checks := 0
	for _, loop := range simpleLoopCopies(file, home, 24, false) {
		for _, value := range loop.values {
			fragments := boundedLoopFragments(value)
			destinations := []string{loop.prefix, loop.prefix + value}
			for _, fragment := range fragments {
				destinations = append(destinations, loop.prefix+fragment, fragment)
			}
			seen := map[string]bool{}
			for _, destination := range destinations {
				dir := OperandPath(destination, cwd)
				if seen[dir] {
					continue
				}
				seen[dir] = true
				if protectedReachPath(dir, protected, ssh) {
					return true
				}
				info, err := pathStat(dir)
				if err != nil || !info.IsDir() {
					continue
				}
				for _, source := range fragments {
					checks++
					if checks > 4096 {
						// Only a loop given a bounded negative proof must
						// fail closed when its positive check is incomplete.
						return len(boundedLoopCopyCalls(file, cwd, home)[loop.call]) != 0
					}
					if protectedReachPath(filepath.Join(dir, source), protected, ssh) {
						return true
					}
				}
			}
		}
	}
	return false
}

func boundedLoopFragments(value string) []string {
	var fragments []string
	for start := 0; start < len(value); start++ {
		for end := start + 1; end <= len(value); end++ {
			fragments = append(fragments, value[start:end])
		}
	}
	return fragments
}
