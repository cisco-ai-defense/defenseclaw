// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// StatementProgram reads the text of one shell statement up to a here-document
// operator or a quoted word (the prefix a reader stops at) and returns the
// program it runs and the static words of its arguments (an empty string for
// a word built at run time): the lowercased base name of the COMMAND word,
// behind the wrappers that pass the rest of argv on as written (command,
// builtin, nohup, exec, nice, env NAME=value, sudo, doas, timeout, stdbuf,
// ionice, setsid). It is the real consumer of the here-document or the
// quoted script that follows: a word of an operand list (grep bash, which sh)
// is not the program. known is false when the prefix does not parse to a
// plain command, its program is built at run time or a wrapper option is not
// one the readers know.
func StatementProgram(statement, home string) (program string, args []string, known bool) {
	file, ok := shellparse.Parse(statement)
	if !ok || file == nil || len(file.Stmts) == 0 {
		return "", nil, false
	}
	call, ok := file.Stmts[len(file.Stmts)-1].Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) == 0 {
		return "", nil, false
	}
	words, ok := actionLiteralCommandWords(call.Args, home)
	if !ok || len(words) == 0 {
		return "", nil, false
	}
	name, fixed := staticProgramWord(words[0], home)
	if !fixed {
		return "", nil, false
	}
	args = make([]string, 0, len(words)-1)
	for _, word := range words[1:] {
		value, _ := StaticWord(word, home)
		args = append(args, value)
	}
	return programBase(name), args, true
}
