// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// CopySourceGlobFactPrefix carries the hook user's complete expansion of a
// plain cp source glob. The managed gateway cannot list that project folder.
const CopySourceGlobFactPrefix = "\x00copy-source-glob:"

func copySourceGlobFactKey(call *syntax.CallExpr, dir string) string {
	return CopySourceGlobFactPrefix + strconv.FormatUint(uint64(call.Pos().Offset()), 10) + ":" + dir
}

// copySourceGlobDestinations accepts only cp PATTERN DEST with no options or
// other operands. Every expanded source must be a non-option file name. The
// destination and every possible child name are then concrete write paths;
// a symlink at any of them is still checked as a protected write.
func copySourceGlobDestinations(call *syntax.CallExpr, dir, home string, facts map[string]string, record bool) ([]string, bool) {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) != 3 || !filepath.IsAbs(dir) {
		return nil, false
	}
	program, fixed := StaticWord(call.Args[0], home)
	if !fixed || programBase(program) != "cp" && programBase(program) != "gcp" {
		return nil, false
	}
	source := call.Args[1]
	if len(source.Parts) != 1 {
		return nil, false
	}
	pattern, plain := source.Parts[0].(*syntax.Lit)
	if !plain || pattern.Value != "*.txt" {
		return nil, false
	}
	destination, fixed := StaticWord(call.Args[2], home)
	if !fixed || destination == "" || strings.HasPrefix(destination, "-") ||
		strings.ContainsAny(destination, "*?[]$`\x00\r\n") {
		return nil, false
	}
	key := copySourceGlobFactKey(call, dir)
	if !record && facts != nil {
		if encoded := facts[key]; encoded != "" {
			if paths, ok := decodeCopySourceGlobFact(encoded); ok && paths[0] == OperandPath(destination, dir) {
				valid := true
				for _, path := range paths[1:] {
					name := filepath.Base(path)
					if filepath.Dir(path) != paths[0] || !copyTextGlobName(name) || strings.HasPrefix(name, "-") {
						valid = false
						break
					}
				}
				if valid {
					return paths, true
				}
			}
		}
		return nil, false
	}
	if actionGlobViewHidden(dir, home) {
		return nil, false
	}
	// Include dot names and case variants. Shell startup files may enable
	// dotglob or nocaseglob before this call runs.
	entries, complete, _ := actionExpandGlob(OperandPath("*", dir), dir, false, actionProcessOwnsHome(home), func() bool { return true })
	if !complete {
		return nil, false
	}
	var candidates []string
	for _, entry := range entries {
		if copyTextGlobName(filepath.Base(entry)) {
			candidates = append(candidates, entry)
		}
	}
	if len(candidates) == 0 || len(candidates) > 32 {
		return nil, false
	}
	paths := []string{OperandPath(destination, dir)}
	for _, source := range candidates {
		name := filepath.Base(source)
		if name == "" || strings.HasPrefix(name, "-") || strings.ContainsAny(name, "/\\\x00") {
			return nil, false
		}
		paths = append(paths, filepath.Join(paths[0], name))
	}
	slices.Sort(paths[1:])
	if record && facts != nil {
		if encoded, err := json.Marshal(paths); err == nil {
			facts[key] = string(encoded)
		}
	}
	return paths, true
}

func copyTextGlobName(name string) bool {
	return len(name) >= len(".txt") && strings.EqualFold(name[len(name)-len(".txt"):], ".txt")
}

func decodeCopySourceGlobFact(encoded string) ([]string, bool) {
	var paths []string
	if json.Unmarshal([]byte(encoded), &paths) != nil || len(paths) < 2 || len(paths) > 33 {
		return nil, false
	}
	for _, path := range paths {
		if !filepath.IsAbs(path) || len(path) > MaxWriteTargetPathBytes || strings.IndexByte(path, 0) >= 0 {
			return nil, false
		}
	}
	return paths, true
}

// CopySourceGlobDestinations returns the bounded destinations of a sole
// plain copy call, including children when the destination is a directory.
func CopySourceGlobDestinations(command, cwd, home string, facts map[string]string) []string {
	if !strings.ContainsAny(command, "*?[") || !strings.Contains(command, "cp") ||
		strings.HasPrefix(strings.TrimSpace(command), "for ") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok || len(file.Stmts) != 1 || len(file.Stmts[0].Redirs) != 0 {
		return nil
	}
	call, ok := file.Stmts[0].Cmd.(*syntax.CallExpr)
	if !ok {
		return nil
	}
	paths, safe := copySourceGlobDestinations(call, cwd, home, facts, false)
	if !safe {
		return nil
	}
	return paths
}
