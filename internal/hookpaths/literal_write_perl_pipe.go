// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// perlPipeWrites passes only syntactically fixed pipe commands to the shared
// shell reader. List-form arguments are quoted as distinct shell words so a
// metacharacter inside an argument cannot become shell syntax.
func perlPipeWrites(tokens []perlToken, calls []perlCall, skip map[int]bool, cwd, home string) []string {
	var paths []string
	for _, call := range calls {
		if call.name != "open" || skip[call.start] || call.argc < 2 {
			continue
		}
		if call.argc == 2 {
			spec, fixed := perlArgumentLiteral(tokens, call.args[1])
			if !fixed {
				continue
			}
			var command string
			switch {
			case strings.HasPrefix(spec, "|"):
				command = strings.TrimPrefix(spec, "|")
			case strings.HasSuffix(spec, "|"):
				command = strings.TrimSuffix(spec, "|")
			default:
				continue
			}
			if command != "" {
				paths = append(paths, perlShellWrites(command, cwd, home)...)
			}
			continue
		}
		mode, fixed := perlArgumentLiteral(tokens, call.args[1])
		if !fixed || mode != "|-" && mode != "-|" {
			continue
		}
		if call.argc == 3 {
			command, fixed := perlArgumentLiteral(tokens, call.args[2])
			if fixed && command != "" {
				paths = append(paths, perlShellWrites(command, cwd, home)...)
			}
			continue
		}
		var words []string
		for _, arg := range call.args[2:] {
			word, fixed := perlArgumentLiteral(tokens, arg)
			if !fixed || word == "" {
				words = nil
				break
			}
			words = append(words, perlShellQuote(word))
		}
		if len(words) != 0 {
			paths = append(paths, perlShellWrites(strings.Join(words, " "), cwd, home)...)
		}
	}
	return paths
}

func perlShellQuote(word string) string {
	return "'" + strings.ReplaceAll(word, "'", "'\"'\"'") + "'"
}

func perlShellWrites(command, cwd, home string) []string {
	paths := literalWriteOperandsDepth(command, cwd, home, 1)
	if redirects, parsed, _ := ShellWriteOperands(command, cwd, home); parsed {
		paths = append(paths, redirects...)
	}
	return paths
}
