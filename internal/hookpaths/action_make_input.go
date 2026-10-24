// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// actionMakeInput resolves only literal input that the hook can see in the
// command. An absent result leaves make -f - fail closed.
func actionMakeInput(stmt *syntax.Stmt, file *syntax.File, cwd, home string, inherited *string) *string {
	if stmt == nil {
		return inherited
	}
	input := inherited
	if file != nil {
		syntax.Walk(file, func(node syntax.Node) bool {
			pipe, ok := node.(*syntax.BinaryCmd)
			if !ok || pipe.Op != syntax.Pipe || pipe.Y != stmt {
				return true
			}
			input = actionMakeProducerInput(pipe.X, cwd, home)
			return false
		})
	}
	for _, redirect := range stmt.Redirs {
		if redirect.N != nil && redirect.N.Value != "0" {
			continue
		}
		switch redirect.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			input = nil
			if redirect.Hdoc != nil {
				var text strings.Builder
				known := true
				for _, part := range redirect.Hdoc.Parts {
					literal, ok := part.(*syntax.Lit)
					if !ok {
						known = false
						break
					}
					text.WriteString(literal.Value)
				}
				if known {
					value := text.String()
					quoted := false
					if redirect.Word != nil && len(redirect.Word.Parts) == 1 {
						switch redirect.Word.Parts[0].(type) {
						case *syntax.SglQuoted, *syntax.DblQuoted:
							quoted = true
						}
					}
					if quoted || !strings.ContainsAny(value, "\\$`") {
						input = &value
					}
				}
			}
		case syntax.WordHdoc:
			if text, known := StaticWord(redirect.Word, home); known {
				text += "\n"
				input = &text
			} else {
				input = nil
			}
		case syntax.RdrIn:
			input = nil
			if name, known := StaticWord(redirect.Word, home); known {
				input = actionMakeFileInput(name, cwd, home)
			}
		}
	}
	return input
}

func actionMakeFileInput(name, cwd, home string) *string {
	call := actionMakeCall{home: home, dir: cwd}
	path, known := call.path(name, cwd)
	if !known {
		return nil
	}
	text, found, readable := actionMakeRead(path)
	if !found || !readable {
		return nil
	}
	return &text
}

func actionMakeProducerInput(stmt *syntax.Stmt, cwd, home string) *string {
	if stmt == nil || len(stmt.Redirs) != 0 {
		return nil
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return nil
	}
	words := make([]string, len(call.Args))
	for i, word := range call.Args {
		value, known := StaticWord(word, home)
		if !known {
			return nil
		}
		words[i] = value
	}
	return actionMakeProducerWords(words, cwd, home)
}

func actionMakeProcessInput(word *syntax.Word, cwd, home string) *string {
	if word == nil || len(word.Parts) != 1 {
		return nil
	}
	sub, ok := word.Parts[0].(*syntax.ProcSubst)
	if !ok || sub.Op != syntax.CmdIn || len(sub.Stmts) != 1 {
		return nil
	}
	return actionMakeProducerInput(sub.Stmts[0], cwd, home)
}

func actionMakeFileOption(option string) bool {
	return option == "-f" || option == "--file" || option == "--makefile" ||
		strings.HasPrefix(option, "-") && !strings.HasPrefix(option, "--") && strings.HasSuffix(option, "f")
}

func actionMakeProducerWords(words []string, cwd, home string) *string {
	if len(words) == 0 {
		return nil
	}
	switch programBase(words[0]) {
	case "cat":
		if len(words) == 2 && !strings.HasPrefix(words[1], "-") {
			return actionMakeFileInput(words[1], cwd, home)
		}
	case "echo":
		if len(words) >= 2 && !strings.HasPrefix(words[1], "-") {
			for _, word := range words[1:] {
				if strings.Contains(word, "\\") {
					return nil // echo's backslash escapes differ among shells
				}
			}
			text := strings.Join(words[1:], " ") + "\n"
			return &text
		}
	case "printf":
		if len(words) == 2 && !strings.Contains(words[1], "%") {
			var out strings.Builder
			for i := 0; i < len(words[1]); i++ {
				if words[1][i] != '\\' {
					out.WriteByte(words[1][i])
					continue
				}
				i++
				if i == len(words[1]) {
					return nil
				}
				switch words[1][i] {
				case 'n':
					out.WriteByte('\n')
				case 't':
					out.WriteByte('\t')
				case 'r':
					out.WriteByte('\r')
				case '\\':
					out.WriteByte('\\')
				default:
					return nil
				}
			}
			text := out.String()
			return &text
		}
	}
	return nil
}
