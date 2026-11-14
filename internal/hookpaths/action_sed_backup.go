// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionSedInPlaceWrite reports a sed -i call of the command that writes a
// protected file, as the edited file or as the backup its suffix names. sed
// -i replaces the edited file by a rename and a new file, and writes a
// second path when a suffix is given: the backup (sedInPlaceWrites holds the
// name rules of GNU and BSD sed). Every word is read as bash passes it, an
// unmatched pattern word with its "*" literal (actionWordValueWithGlob), so
// the suffix "../.ssh/*" is not refused as a glob. The backup path decides,
// never a list of suffix strings (rel-1-0-10:GAP-0414).
//
// A relative name is judged from the working directory and from every
// directory a cd of the command names, so a cd in a subshell or a branch can
// not hide the write. A shell -c body is read the same way.
func actionSedInPlaceWrite(command, cwd, home string, memo *TargetMemo) bool {
	if command == "" || home == "" || len(command) > MaxPayloadBytes || !filepath.IsAbs(cwd) || actionWindowsHome(home) {
		return false // sed -i is a POSIX path; a Windows home has its own readers
	}
	return actionSedInPlaceWriteIn(command, cwd, home, memo.protectedFiles(home), filepath.Join(home, ".ssh"), memo, 0)
}

func actionSedInPlaceWriteIn(command, cwd, home string, protected protectedFiles, ssh string, memo *TargetMemo, depth int) bool {
	file, parsed := parseShell(command)
	if !parsed {
		return false
	}
	values := actionValues{"HOME": home, "PWD": cwd}
	dirs := []string{cwd}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) == 0 {
			return !found
		}
		words := make([]string, len(call.Args))
		static := make([]bool, len(call.Args))
		for i, arg := range call.Args {
			words[i], static[i] = actionWordValueWithGlob(arg, values, cwd, home, true)
		}
		if index, wrapped := plainWrappedChild(words, static); wrapped {
			words, static = words[index:], static[index:]
		}
		if slices.Contains(static, false) {
			return true
		}
		switch program := programBase(words[0]); {
		case program == "cd" || program == "pushd":
			for _, word := range words[1:] {
				if word != "" && !strings.HasPrefix(word, "-") {
					dirs = append(dirs, OperandPath(word, dirs[len(dirs)-1]))
					break
				}
			}
		case program == "sed" || program == "gsed":
			// An escaped character (\*) is the character itself to the shell;
			// the word text keeps the backslash, so both spellings are judged.
			variants := [][]string{words}
			if slices.ContainsFunc(words, func(word string) bool { return strings.Contains(word, `\`) }) {
				plain := make([]string, len(words))
				for i, word := range words {
					plain[i] = actionUnescapeShell(word)
				}
				variants = append(variants, plain)
			}
			for _, variant := range variants {
				for _, name := range sedInPlaceWrites(variant) {
					if strings.ContainsAny(name, "\x00\r\n") {
						continue
					}
					for _, dir := range dirs {
						if protectedReachPathWith(OperandPath(name, dir), protected, ssh, memo) {
							found = true
						}
					}
				}
			}
		case posixShellProgram(program) && depth < 8:
			if body, ok := actionShellCommandBody(words); ok {
				found = actionSedInPlaceWriteIn(body, cwd, home, protected, ssh, memo, depth+1)
			}
		}
		return !found
	})
	return found
}

// actionShellCommandBody returns the -c body of a POSIX shell call (bash -c
// BODY, sh -ec BODY), skipping the options that take a value.
func actionShellCommandBody(words []string) (string, bool) {
	for j := 1; j+1 < len(words); j++ {
		option := words[j]
		if !strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "+") {
			return "", false
		}
		switch option {
		case "-o", "+o", "-O", "+O", "--rcfile", "--init-file":
			j++ // This option consumes the next word (bash -O dotglob -c).
			continue
		}
		if option == "-c" || len(option) > 2 && !strings.HasPrefix(option, "--") &&
			!strings.ContainsAny(option, "=/") && strings.Contains(option[1:], "c") {
			return words[j+1], true
		}
	}
	return "", false
}

// actionUnescapeShell removes the backslash of each escaped character of an
// unquoted shell word text.
func actionUnescapeShell(word string) string {
	var out strings.Builder
	for i := 0; i < len(word); i++ {
		if word[i] == '\\' && i+1 < len(word) {
			i++
		}
		out.WriteByte(word[i])
	}
	return out.String()
}
