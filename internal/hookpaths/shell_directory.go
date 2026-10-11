// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"bytes"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// DirectoryFactPrefix carries the physical directory observed by the hook
// for a logical shell directory. A question mark means it was not readable.
const DirectoryFactPrefix = "\x00directory:"

// ShellDirectoryWriteOperands lists writes after static shell directory changes.
// Bash keeps a logical PWD for cd -L and cd .., while relative writes traverse
// links in that spelling. The hook records each physical directory so a
// sandboxed gateway can make the same decision without Lstat under home/tmp.
// unknown is true only when an unresolved directory is followed by a write.
func ShellDirectoryWriteOperands(command, cwd, home string, directoryFacts map[string]string, record, strict bool) (operands []RedirectOccurrence, unknown bool) {
	file, parsed := parseShell(command)
	if !parsed || !filepath.IsAbs(cwd) {
		return nil, false
	}
	var statements []*syntax.Stmt
	var collect func(*syntax.Stmt) bool
	collect = func(stmt *syntax.Stmt) bool {
		if stmt == nil || stmt.Background || stmt.Negated {
			return false
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			if binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt {
				return collect(binary.X) && collect(binary.Y)
			}
			if binary.Op != syntax.Pipe && binary.Op != syntax.PipeAll {
				return false
			}
		} else if _, ok := stmt.Cmd.(*syntax.CallExpr); !ok {
			return false
		}
		statements = append(statements, stmt)
		return true
	}
	for _, stmt := range file.Stmts {
		if !collect(stmt) {
			return nil, false
		}
	}
	if len(statements) < 2 {
		return nil, false
	}
	physical := func(logical string) (string, bool) {
		key := DirectoryFactPrefix + logical
		if !record && directoryFacts != nil {
			if value, present := directoryFacts[key]; present {
				return value, filepath.IsAbs(value)
			}
			if strict && directoryFactRequired(logical, home) {
				return "", false
			}
		}
		if !record && strict && directoryFactRequired(logical, home) {
			return "", false
		}
		value, ok := ResolveWriteTarget(logical)
		if record && directoryFacts != nil {
			if ok {
				directoryFacts[key] = value
			} else {
				directoryFacts[key] = "?"
			}
		}
		return value, ok
	}
	current := filepath.Clean(cwd)
	physicalCurrent, cwdKnown := physical(current)
	var stack []string
	changed := false
	safety := SafeShellRedirectOccurrencesWithFacts(command, cwd, home, directoryFacts)
	redirectIndex := 0
	for _, stmt := range statements {
		var rendered bytes.Buffer
		if syntax.NewPrinter().Print(&rendered, stmt) != nil {
			return nil, true
		}
		statement := rendered.String()
		redirects, _, _ := ShellWriteOperands(statement, current, home)
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		program, static, arg := "", false, 1
		if isCall && len(call.Args) > 0 {
			program, static = StaticWord(call.Args[0], home)
			if static && (program == "builtin" || program == "command") && len(call.Args) > 1 {
				program, static = StaticWord(call.Args[1], home)
				arg = 2
			}
		}
		if static && (program == "cd" || program == "pushd" || program == "popd") {
			changed = true
			if program == "popd" {
				if len(stack) == 0 {
					cwdKnown = false
				} else {
					current = stack[len(stack)-1]
					stack = stack[:len(stack)-1]
					physicalCurrent, cwdKnown = physical(current)
				}
				redirectIndex += len(redirects)
				continue
			}
			physicalMode := false
			for arg < len(call.Args) {
				option, ok := StaticWord(call.Args[arg], home)
				if !ok || option != "--" && (len(option) < 2 || option[0] != '-' || strings.Trim(option[1:], "PLe@") != "") {
					break
				}
				for _, flag := range option[1:] {
					if flag == 'P' {
						physicalMode = true
					} else if flag == 'L' {
						physicalMode = false
					}
				}
				arg++
				if option == "--" {
					break
				}
			}
			directory := home
			if arg < len(call.Args) {
				var ok bool
				directory, ok = StaticWord(call.Args[arg], home)
				if !ok || directory == "-" || arg+1 != len(call.Args) {
					cwdKnown = false
					redirectIndex += len(redirects)
					continue
				}
			}
			previous := current
			absolute := directory == "~" || strings.HasPrefix(directory, "~/") || filepath.IsAbs(directory)
			switch {
			case directory == "~":
				current = home
			case strings.HasPrefix(directory, "~/"):
				current = filepath.Join(home, directory[2:])
			case filepath.IsAbs(directory):
				current = filepath.Clean(directory)
			default:
				current = filepath.Join(current, directory)
			}
			resolved, ok := physical(current)
			physicalCurrent = resolved
			cwdKnown = ok && (absolute || cwdKnown)
			if physicalMode && ok {
				current = resolved
			}
			if program == "pushd" {
				stack = append(stack, previous)
			}
			redirectIndex += len(redirects)
			continue
		}
		if !changed {
			redirectIndex += len(redirects)
			continue
		}
		literals := LiteralWriteOperands(statement, current, home)
		inner := actionfacts.Input{Tool: "Bash", Command: statement, CWD: current, ActiveHome: home}
		facts := actionfacts.Analyze(inner)
		writes := make([]RedirectOccurrence, 0, len(redirects)+len(literals))
		for _, redirect := range redirects {
			occurrence := RedirectOccurrence{Path: redirect}
			if redirectIndex < len(safety) {
				occurrence.Safe = safety[redirectIndex].Safe
			}
			redirectIndex++
			writes = append(writes, occurrence)
		}
		for _, literal := range literals {
			writes = append(writes, RedirectOccurrence{Path: literal})
		}
		for _, candidate := range facts.Paths {
			if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
				continue
			}
			target := candidate.Resolved
			if target == "" {
				target = candidate.Normalized
			}
			if raw, ok := RawDotDotOperand(candidate.Value, current); ok {
				target = raw
			}
			// POSIX command facts can retain a relative operand when the
			// event CWD uses native Windows syntax. The shell still opens it
			// relative to that CWD.
			if !filepath.IsAbs(target) && candidate.Value != "" &&
				!strings.HasPrefix(candidate.Value, "/") &&
				!strings.ContainsAny(candidate.Value, "*?[]$`~\x00\r\n") {
				target = OperandPath(candidate.Value, current)
			}
			if target != "" && filepath.IsAbs(target) {
				if slices.Contains(redirects, target) && pathFactIsRedirect(candidate, facts.Commands) {
					continue
				}
				writes = append(writes, RedirectOccurrence{Path: target})
			}
		}
		if cwdKnown {
			for i, write := range writes {
				if strings.HasPrefix(write.Path, current+string(filepath.Separator)) {
					writes[i].Path = OperandPath(strings.TrimPrefix(write.Path, current+string(filepath.Separator)), physicalCurrent)
				}
			}
		}
		if len(writes) > 0 && !cwdKnown {
			unknown = true
		}
		operands = append(operands, writes...)
	}
	return operands, unknown
}

func directoryFactRequired(directory, home string) bool {
	if runtime.GOOS != "linux" {
		return false
	}
	for _, root := range []string{home, "/home", "/tmp", "/var/tmp"} {
		if root != "" && (directory == root || strings.HasPrefix(directory, root+string(filepath.Separator))) {
			return true
		}
	}
	return false
}
