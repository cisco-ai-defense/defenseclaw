// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// withCappedWindowsReadings gives back simples with the readings the
// Windows reading cap dropped where they may matter. Past
// maxSimpleWindowsOtherReadings a statement after folder moves that may fail
// keeps one UnresolvedFolder reading, which the unknown tier reads only for
// POSIX shells, so a padded relative write of DefenseClaw state after
// failed moves was allowed (rel-1-0-10:GAP-1281, a regression of the
// GAP-1228 cap against its parent). The statement is read again in each
// capped folder where a relative operand of it may name a protected file
// (cappedReadingMayNameProtectedFile), as it was below the cap, and the
// benign readings stay dropped: a padded call costs what the cap allows.
// simples, which the call's memo holds, is not changed.
func withCappedWindowsReadings(request trustedActionRequest, simples []actionfacts.SimpleCommand) []actionfacts.SimpleCommand {
	var out []actionfacts.SimpleCommand
	for index, simple := range simples {
		folders := simple.CappedFolders()
		if len(folders) == 0 {
			if out != nil {
				out = append(out, simple)
			}
			continue
		}
		var operands []actionfacts.PathFact
		read := false
		for _, folder := range folders {
			if !read {
				input := request.Input
				input.Command, input.Args, input.Argv, input.CWD = simple.Text, nil, nil, folder
				operands, read = cappedReadingOperands(actionfacts.Analyze(input)), true
				if len(operands) == 0 {
					break
				}
			}
			if !cappedReadingMayNameProtectedFile(operands, folder, request.Input.ActiveHome) {
				continue
			}
			if out == nil {
				out = append(make([]actionfacts.SimpleCommand, 0, len(simples)+len(folders)), simples[:index]...)
			}
			out = append(out, actionfacts.SimpleCommand{Text: simple.Text, CWD: folder, OtherFolder: true})
		}
		if out != nil {
			out = append(out, simple)
		}
	}
	if out == nil {
		return simples
	}
	return out
}

// cappedReadingOperands are the relative operands of a Windows statement
// that read, write, append to or remove a file.
func cappedReadingOperands(facts actionfacts.Facts) []actionfacts.PathFact {
	var operands []actionfacts.PathFact
	for _, candidate := range facts.Paths {
		switch candidate.Access {
		case actionfacts.PathAccessRead, actionfacts.PathAccessWrite, actionfacts.PathAccessAppend, actionfacts.PathAccessDelete:
		default:
			continue
		}
		value := strings.ReplaceAll(candidate.Value, `\`, "/")
		if value == "" || strings.HasPrefix(value, "/") || strings.HasPrefix(value, "~") || strings.HasPrefix(value, "$") ||
			strings.HasPrefix(value, "-") || strings.Contains(value, ":") {
			continue // absolute, a drive, a home or variable spelling, a flag, a URL
		}
		candidate.Value = value
		operands = append(operands, candidate)
	}
	return operands
}

// cappedReadingMayNameProtectedFile reports a relative operand that, in
// folder, may be a protected file: one the unknown tier names
// (unresolvedFolderNamesProtectedFile) when spelled from the home, if the
// file is below it, or as written; or any file below a folder named
// .ssh or (.)defenseclaw, whose every file is protected. Compared with
// forward slashes and lower-case, as Windows names are.
func cappedReadingMayNameProtectedFile(operands []actionfacts.PathFact, folder, home string) bool {
	lower := func(value string) string { return strings.ToLower(strings.ReplaceAll(value, `\`, "/")) }
	dir, base := lower(folder), strings.TrimRight(lower(home), "/")
	for _, operand := range operands {
		value := lower(operand.Value)
		file := path.Join(dir, value)
		if slices.ContainsFunc(strings.Split(path.Dir(file), "/"), func(part string) bool {
			return part == ".ssh" || part == ".defenseclaw" || part == "defenseclaw"
		}) {
			return true
		}
		if unresolvedFolderNamesProtectedFile(value, "/home/user", operand.Access) {
			return true
		}
		if base != "" {
			if relative, below := strings.CutPrefix(file, base+"/"); below &&
				unresolvedFolderNamesProtectedFile(relative, "/home/user", operand.Access) {
				return true
			}
		}
	}
	return false
}
