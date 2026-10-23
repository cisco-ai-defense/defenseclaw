// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/sensor/tactics"
	"mvdan.cc/sh/v3/syntax"
)

// maxLinkTextDepth bounds the shell bodies (sh -c, find -exec sh -c) that a
// hard-link check reads through.
const maxLinkTextDepth = 4

var (
	// linkTextQuietPrograms run no text: hard-link API text cannot run
	// through them.
	linkTextQuietPrograms = []string{"cd", "pwd", "true", "false", ":"}
	linkTextShells        = []string{"sh", "bash", "zsh", "dash", "ksh", "mksh"}
)

// linkTextInert reports a statement that cannot run the hard-link API text
// (hardLinkCall) of its command: a data program (dataStatement); a cd, pwd,
// true, false or : without that text; an interpreter whose literal code (python
// -c, node, ruby or perl -e) holds the text only in strings or comments it
// cannot run; or a shell -c whose body is made of such statements. The text
// must not be anywhere else in an interpreter or shell statement, where its
// code could read it (an argument, a here-document), and a statement with a
// substitution is not inert. An executable call such as os.link( in the code
// is not inert.
func linkTextInert(stmt *syntax.Stmt, command, cwd, home string, depth int) bool {
	if dataStatement(stmt, home) {
		return true
	}
	if stmt == nil || stmt.Background || stmt.Cmd == nil || depth >= maxLinkTextDepth {
		return false
	}
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		return linkTextInert(cmd.X, command, cwd, home, depth) &&
			linkTextInert(cmd.Y, command, cwd, home, depth)
	case *syntax.CallExpr:
		if len(cmd.Assigns) > 0 || len(cmd.Args) == 0 || !linkTextPlainStatement(stmt) {
			return false
		}
		words := make([]string, len(cmd.Args))
		for i, arg := range cmd.Args {
			var static bool
			if words[i], static = StaticWord(arg, home); !static {
				return false
			}
		}
		statement := command[stmt.Pos().Offset():stmt.End().Offset()]
		if slices.Contains(linkTextQuietPrograms, programBase(words[0])) {
			return !hardLinkCall.MatchString(statement)
		}
		index, language := linkTextCode(words)
		if index < 0 {
			return false
		}
		code, word := words[index], cmd.Args[index]
		outside := command[stmt.Pos().Offset():word.Pos().Offset()] + "\n" +
			command[word.End().Offset():stmt.End().Offset()]
		if hardLinkCall.MatchString(outside) {
			return false
		}
		if language == "shell" {
			body, parsed := parseShell(code)
			if !parsed {
				return false
			}
			for _, inner := range body.Stmts {
				if !linkTextInert(inner, code, cwd, home, depth+1) {
					return false
				}
			}
			return true
		}
		return linkTextInertCode(code, language, cwd)
	}
	return false
}

// linkTextPlainStatement reports a statement without a substitution or a
// here-document, whose text lies outside the statement's own range.
func linkTextPlainStatement(stmt *syntax.Stmt) bool {
	for _, redirect := range stmt.Redirs {
		if redirect.Hdoc != nil {
			return false
		}
	}
	plain := true
	syntax.Walk(stmt, func(node syntax.Node) bool {
		switch node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			plain = false
		}
		return plain
	})
	return plain
}

// linkTextCode returns the index of the literal code word of an interpreter
// or shell call and its language: python, node, ruby, perl or shell; index is
// -1 for any other call.
func linkTextCode(words []string) (index int, language string) {
	program := programBase(words[0])
	switch {
	case program == "python" || strings.HasPrefix(program, "python3"):
		if _, ok := pythonLiteralCode(words); ok {
			return slices.Index(words, "-c") + 1, "python"
		}
	case program == "node" || program == "nodejs" || program == "ruby" || program == "perl":
		if len(words) > 2 && words[1] == "-e" {
			return 2, strings.TrimSuffix(program, "js")
		}
	case slices.Contains(linkTextShells, program):
		if index, ok := shellCommandBodyIndex(words); ok {
			return index, "shell"
		}
	}
	return -1, ""
}

// linkTextInertCode reports interpreter code in which hard-link API text is
// only data. Python code is read by guardrail's string scan when the binary
// has it (PythonInertTextMasked): the text of a string no part of the program
// can run is blanked. Without it, and for node, ruby and perl, only a program
// that prints string literals is inert (literalPrintProgram).
func linkTextInertCode(code, language, cwd string) bool {
	if language == "python" && PythonInertTextMasked != nil {
		masked := PythonInertTextMasked(code, cwd)
		return len(masked) == len(code) && masked != code && !hardLinkCall.MatchString(masked)
	}
	return literalPrintProgram(code, language)
}

// literalPrintCallees are the print calls of literalPrintProgram; a bare call
// without parentheses is Ruby and Perl syntax only.
var literalPrintCallees = map[string][]string{
	"python": {"print"},
	"node":   {"console.log", "console.error", "console.info", "console.warn"},
	"ruby":   {"puts", "print", "p"},
	"perl":   {"print", "say"},
}

// literalPrintProgram reports code that only prints string literals, such as
// print('os.link(') or console.log("fs.linkSync("): statements of one print
// call each, whose arguments are quoted strings joined by commas or +. A
// string that can run code is not a literal: a Python f-string or prefixed
// string, a JavaScript template, Ruby #{...}, #$ or #@ and a Perl $ or @ in
// double quotes.
func literalPrintProgram(code, language string) bool {
	callees := literalPrintCallees[language]
	if len(callees) == 0 {
		return false
	}
	bare := language == "ruby" || language == "perl"
	i := 0
	space := func() {
		for i < len(code) && (code[i] == ' ' || code[i] == '\t') {
			i++
		}
	}
	for statements := 0; ; statements++ {
		space()
		if i == len(code) {
			return statements > 0
		}
		callee := ""
		for _, name := range callees {
			if strings.HasPrefix(code[i:], name) && len(name) > len(callee) &&
				(i+len(name) == len(code) || !literalPrintNameByte(code[i+len(name)])) {
				callee = name
			}
		}
		if callee == "" {
			return false
		}
		i += len(callee)
		space()
		paren := i < len(code) && code[i] == '('
		if paren {
			i++
			space()
		} else if !bare {
			return false
		}
		for {
			length, ok := literalPrintString(code[i:], language)
			if !ok {
				return false
			}
			i += length
			space()
			if i < len(code) && (code[i] == ',' || code[i] == '+') {
				i++
				space()
				continue
			}
			break
		}
		if paren {
			if i == len(code) || code[i] != ')' {
				return false
			}
			i++
			space()
		}
		if i == len(code) {
			return true
		}
		if code[i] != ';' {
			return false
		}
		i++
	}
}

func literalPrintNameByte(c byte) bool {
	return c == '_' || c == '.' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

// literalPrintString returns the length of the quoted string literal that
// text starts with, or false when it starts with none or the literal can run
// code.
func literalPrintString(text, language string) (int, bool) {
	if text == "" || text[0] != '\'' && text[0] != '"' {
		return 0, false
	}
	quote := text[0]
	for i := 1; i < len(text); i++ {
		switch c := text[i]; {
		case c == '\\':
			i++
		case c == quote:
			return i + 1, true
		case c == '\n' || c == '\r':
			return 0, false
		case quote == '"' && language == "perl" && (c == '$' || c == '@'):
			return 0, false
		case quote == '"' && language == "ruby" && c == '#' && i+1 < len(text) &&
			(text[i+1] == '{' || text[i+1] == '$' || text[i+1] == '@'):
			return 0, false
		}
	}
	return 0, false
}

// wrappedHardLink reports a wrapper call (sudo, env, nice, sh -c, eval, find
// -exec, xargs) that may create a hard link. An ln, link or cp it names in
// its words is read with its own options up to a find -exec terminator, as a
// direct call is: a symbolic ln or a cp -s makes no hard link. A command text
// it runs (sh -c, eval, su -c) is read as a command. A wrapper with a dynamic
// word, or that may run ln or cp in a way its words do not show, may make
// one.
func wrappedHardLink(text string, words []string, static []bool, cwd, home string, depth int) bool {
	runs := tactics.RunsProgram(text, linkPrograms...) ||
		tactics.RunsProgram(text, copyPrograms...) && copyLinkOption.MatchString(text)
	if slices.Contains(static, false) || depth >= maxLinkTextDepth {
		return runs || slices.ContainsFunc(words[1:], func(word string) bool {
			return slices.Contains(linkPrograms, programBase(word)) ||
				slices.Contains(copyPrograms, programBase(word)) && copyLinkOption.MatchString(text)
		})
	}
	covered, hard := false, false
	for i := 1; i < len(words); i++ {
		end := i + 1
		for end < len(words) && words[end] != ";" && words[end] != "+" {
			end++
		}
		args, argsStatic := words[i+1:end], static[i+1:end]
		switch base := programBase(words[i]); {
		case slices.Contains(linkPrograms, base):
			covered = true
			hard = hard || !symbolicLinkCall(base, args, argsStatic)
		case slices.Contains(copyPrograms, base):
			if !slices.ContainsFunc(args, copyLinkOption.MatchString) {
				continue
			}
			covered = true
			parsed := cpOperands(args, argsStatic)
			hard = hard || !parsed.ok || parsed.hard
		case strings.ContainsAny(words[i], " \t\n;&|") &&
			(tactics.RunsProgram(words[i], linkPrograms...) || tactics.RunsProgram(words[i], copyPrograms...)):
			covered = true
			sources, opaque, wrapped := hardLinkSources(words[i], cwd, home, depth+1)
			hard = hard || len(sources) > 0 || opaque || wrapped
		}
	}
	return hard || runs && !covered
}
