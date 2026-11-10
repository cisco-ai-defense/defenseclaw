// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// A fixed for-word list gives each writer destination one concrete value.
// This positive client fact lets a managed gateway judge a link it cannot
// follow through ProtectHome. Earlier statements and other body calls must
// leave the current directory, iterator and link unchanged.
func actionClientLoopCopyDestinationProtected(command, cwd, home string) bool {
	return LoopCopyDestinationProtected(command, cwd, home)
}

// LoopCopyDestinationProtected checks fixed loop destinations of the calls
// named cp, mv, install, ln and tee in the gateway's own filesystem view. The
// destination is judged by the program's name, whatever its options and
// source words hold (rel-1-0-6:GAP-0880, GAP-0885).
func LoopCopyDestinationProtected(command, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || home == "" || !strings.Contains(command, "for") || !actionClientLoopWriterNamed(command) {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	protected := newProtectedFiles(home)
	keyDir := filepath.Join(home, ".ssh")
	for _, top := range file.Stmts {
		loop, ok := actionClientLoopCopyTop(top, cwd, home)
		if !ok {
			if !actionClientLoopCopyAssignment(top, home) && !actionClientLoopCopyNoop(top, cwd, home) {
				return false
			}
			continue
		}
		iter, ok := loop.Loop.(*syntax.WordIter)
		if !ok || iter.Name == nil || len(iter.Items) == 0 {
			return false
		}
		var destinations []*syntax.Word
		for _, stmt := range loop.Do {
			call, ok := stmt.Cmd.(*syntax.CallExpr)
			if !ok || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 || len(call.Assigns) != 0 || len(call.Args) == 0 {
				return false
			}
			if words := actionClientLoopWriterDestinations(call, home); len(words) != 0 {
				destinations = append(destinations, words...)
			} else if !actionClientLoopCopyNoop(stmt, cwd, home) {
				return false
			}
		}
		// A destination that does not name the iterator is a direct name that
		// the other readers judge.
		named := destinations[:0]
		for _, destination := range destinations {
			syntax.Walk(destination, func(part syntax.Node) bool {
				if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == iter.Name.Value {
					named = append(named, destination)
					return false
				}
				return true
			})
		}
		if len(named) == 0 {
			return false
		}
		for _, item := range iter.Items {
			value, fixed := StaticWord(item, home)
			if !fixed || value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") {
				return false
			}
			loopValues := actionValues{"HOME": home, "PWD": cwd, iter.Name.Value: value}
			for _, destination := range named {
				if target, known := actionWordValue(destination, loopValues, cwd, home); known &&
					actionClientProtectedPath(target, cwd, protected, keyDir) {
					return true
				}
			}
		}
	}
	return false
}

func actionClientLoopWriterNamed(command string) bool {
	for _, name := range []string{"cp", "mv", "install", "ln", "tee"} {
		if strings.Contains(command, name) {
			return true
		}
	}
	return false
}

// actionClientLoopCopyAssignment is a plain assignment of a fixed value to a
// name other than HOME and PWD.
func actionClientLoopCopyAssignment(stmt *syntax.Stmt, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) != 0 || len(call.Assigns) != 1 {
		return false
	}
	assign := call.Assigns[0]
	if assign.Name == nil || assign.Append || assign.Array != nil || assign.Index != nil ||
		assign.Name.Value == "HOME" || assign.Name.Value == "PWD" {
		return false
	}
	if assign.Value == nil {
		return true
	}
	value, fixed := StaticWord(assign.Value, home)
	return fixed && !strings.ContainsAny(value, "*?[]\x00\x1f")
}

func actionClientLoopCopyTop(stmt *syntax.Stmt, cwd, home string) (*syntax.ForClause, bool) {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return nil, false
	}
	if loop, ok := stmt.Cmd.(*syntax.ForClause); ok {
		return loop, true
	}
	if pair, ok := stmt.Cmd.(*syntax.BinaryCmd); ok && pair.Op == syntax.AndStmt &&
		actionClientLoopCopyNoop(pair.X, cwd, home) {
		return actionClientLoopCopyTop(pair.Y, cwd, home)
	}
	return nil, false
}

func actionClientLoopCopyNoop(stmt *syntax.Stmt, cwd, home string) bool {
	if stmt == nil || stmt.Background || stmt.Negated || len(stmt.Redirs) != 0 {
		return false
	}
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Assigns) != 0 || len(call.Args) == 0 {
		return false
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return false
	}
	switch program {
	case "true", ":":
		return len(call.Args) == 1
	case "cd":
		if len(call.Args) != 2 {
			return false
		}
		value, fixed := StaticWord(call.Args[1], home)
		return fixed && samePathName(OperandPath(value, cwd), cwd)
	case "echo":
		for _, arg := range call.Args[1:] {
			if _, fixed := StaticWord(arg, home); !fixed {
				return false
			}
		}
		return true
	}
	return false
}

// actionClientLoopWriterDestinations returns the destination operands of a
// call named cp, mv, install, ln or tee. The destination is read first and
// alone: no option and no source word decides whether it is judged. A
// target-directory option names the destination; otherwise it is the last
// operand (every operand of tee).
func actionClientLoopWriterDestinations(call *syntax.CallExpr, home string) []*syntax.Word {
	if len(call.Args) < 2 {
		return nil
	}
	program, fixed := staticProgramWord(call.Args[0], home)
	if !fixed {
		return nil
	}
	base := programBase(program)
	switch base {
	case "cp", "gcp", "mv", "install", "ln", "tee":
	default:
		return nil
	}
	args := call.Args[1:]
	var operands, directories []*syntax.Word
	for i := 0; i < len(args); i++ {
		text, whole := wordLiteralPrefix(args[i])
		if text == "--" && whole {
			operands = append(operands, args[i+1:]...)
			break
		}
		if !strings.HasPrefix(text, "-") || len(text) == 1 && whole {
			operands = append(operands, args[i])
			continue
		}
		if base == "tee" {
			continue
		}
		directory, next := actionClientTargetDirectoryOption(args, i, text, whole)
		if directory != nil {
			directories = append(directories, directory)
		}
		if next {
			i++
		}
	}
	switch {
	case len(directories) != 0:
		return directories
	case base == "tee":
		return operands
	case len(operands) != 0:
		return operands[len(operands)-1:]
	}
	return nil
}

// actionClientTargetDirectoryOption reads the option word args[i] of cp, mv,
// install or ln, given the literal text its word starts with. It returns the
// target directory the word names, and whether the option takes the next
// word as its argument.
func actionClientTargetDirectoryOption(args []*syntax.Word, i int, text string, whole bool) (*syntax.Word, bool) {
	if strings.HasPrefix(text, "--") {
		name, _, attached := strings.Cut(text[2:], "=")
		if name == "" || !strings.HasPrefix("target-directory", name) {
			return nil, false
		}
		if attached {
			return wordTrimPrefix(args[i], 2+len(name)+1), false
		}
		if whole && i+1 < len(args) {
			return args[i+1], true
		}
		return nil, false
	}
	for k := 1; k < len(text); k++ {
		switch text[k] {
		case 't':
			if k+1 < len(text) || !whole {
				return wordTrimPrefix(args[i], k+1), false
			}
			if i+1 < len(args) {
				return args[i+1], true
			}
			return nil, false
		case 'S', 'm', 'o', 'g':
			// The rest of the word, or the next word, is this option's argument.
			return nil, k+1 == len(text) && whole
		}
	}
	return nil, false
}

// wordLiteralPrefix is the text of the literal parts a word starts with, and
// whether the whole word is literal.
func wordLiteralPrefix(word *syntax.Word) (string, bool) {
	var out strings.Builder
	var walk func([]syntax.WordPart) bool
	walk = func(parts []syntax.WordPart) bool {
		for _, part := range parts {
			switch part := part.(type) {
			case *syntax.Lit:
				out.WriteString(unescapedLiteral(part.Value))
			case *syntax.SglQuoted:
				out.WriteString(part.Value)
			case *syntax.DblQuoted:
				if !walk(part.Parts) {
					return false
				}
			default:
				return false
			}
		}
		return true
	}
	whole := walk(word.Parts)
	return out.String(), whole
}

func unescapedLiteral(raw string) string {
	if !strings.Contains(raw, `\`) {
		return raw
	}
	var out strings.Builder
	for i := 0; i < len(raw); i++ {
		if raw[i] == '\\' && i+1 < len(raw) {
			i++
		}
		out.WriteByte(raw[i])
	}
	return out.String()
}

// wordTrimPrefix is the word without its first n literal characters.
func wordTrimPrefix(word *syntax.Word, n int) *syntax.Word {
	var trim func([]syntax.WordPart) []syntax.WordPart
	trim = func(parts []syntax.WordPart) []syntax.WordPart {
		var out []syntax.WordPart
		for i, part := range parts {
			if n == 0 {
				return append(out, parts[i:]...)
			}
			switch part := part.(type) {
			case *syntax.Lit:
				kept := *part
				kept.Value = dropLiteralCharacters(part.Value, &n)
				if kept.Value != "" {
					out = append(out, &kept)
				}
			case *syntax.SglQuoted:
				kept := *part
				kept.Value = dropLiteralCharacters(part.Value, &n)
				out = append(out, &kept)
			case *syntax.DblQuoted:
				kept := *part
				kept.Parts = trim(part.Parts)
				out = append(out, &kept)
			default:
				n = 0
				out = append(out, part)
			}
		}
		return out
	}
	trimmed := *word
	trimmed.Parts = trim(word.Parts)
	return &trimmed
}

// dropLiteralCharacters removes up to *n characters from the start of raw,
// a backslash and the character it escapes counting as one, and lowers *n by
// the number it removed.
func dropLiteralCharacters(raw string, n *int) string {
	i := 0
	for i < len(raw) && *n > 0 {
		if raw[i] == '\\' && i+1 < len(raw) {
			i++
		}
		i++
		*n--
	}
	return raw[i:]
}

func actionClientLoopCopySourceStartupUnknown() bool {
	if os.Getenv("BASH_ENV") != "" || os.Getenv("ENV") != "" {
		return true
	}
	for _, entry := range os.Environ() {
		if strings.HasPrefix(entry, "BASH_FUNC_") {
			return true
		}
	}
	return false
}
