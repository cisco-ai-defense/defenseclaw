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
// named cp, mv, install, ln and tee in the gateway filesystem view. The
// destination is judged by the program name alone, whatever its spelling,
// options and source words hold (rel-1-0-6:GAP-0880, GAP-0885). Per call the
// order is fixed: read the program name from the parsed word, then read the
// destination operand and judge it; nothing else decides before that.
func LoopCopyDestinationProtected(command, cwd, home string) bool {
	if !filepath.IsAbs(cwd) || home == "" || !strings.Contains(command, "for") {
		return false
	}
	file, ok := parseShell(command)
	if !ok {
		return false
	}
	scan := actionClientLoopScan{home: home, protected: newProtectedFiles(home), keyDir: filepath.Join(home, ".ssh")}
	for _, top := range file.Stmts {
		next, known := scan.statement(top, cwd)
		if scan.found {
			return true
		}
		if !known {
			return false
		}
		cwd = next
	}
	return false
}

type actionClientLoopScan struct {
	home      string
	protected protectedFiles
	keyDir    string
	found     bool
}

// statement judges every for loop in one statement and returns the directory
// the next statement starts in. It reports false when the statement changes
// the directory, HOME or PWD in a way that is not read, so later statements
// have no known view.
func (s *actionClientLoopScan) statement(stmt *syntax.Stmt, cwd string) (string, bool) {
	switch cmd := stmt.Cmd.(type) {
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.AndStmt {
			next, known := s.statement(cmd.X, cwd)
			if s.found || !known {
				return "", false
			}
			return s.statement(cmd.Y, next)
		}
	case *syntax.CallExpr:
		if dir, ok := actionClientLoopCopyChdir(cmd, cwd, s.home); ok {
			return dir, true
		}
	}
	if actionClientLoopCopyChangesState(stmt, s.home) {
		return "", false
	}
	syntax.Walk(stmt, func(node syntax.Node) bool {
		if loop, ok := node.(*syntax.ForClause); ok && s.loop(loop, cwd) {
			s.found = true
		}
		return !s.found
	})
	return cwd, true
}

// loop reports whether a writer in the loop body has a destination that names
// the loop variable and reaches a protected path for one of its fixed values.
func (s *actionClientLoopScan) loop(loop *syntax.ForClause, cwd string) bool {
	iter, ok := loop.Loop.(*syntax.WordIter)
	if !ok || iter.Name == nil || len(iter.Items) == 0 {
		return false
	}
	var named []*syntax.Word
	for _, stmt := range loop.Do {
		syntax.Walk(stmt, func(node syntax.Node) bool {
			if call, ok := node.(*syntax.CallExpr); ok {
				for _, destination := range actionClientLoopWriterDestinations(call, s.home) {
					if actionClientWordNamesVariable(destination, iter.Name.Value) {
						named = append(named, destination)
					}
				}
			}
			return true
		})
	}
	// A destination that does not name the iterator is a direct name that the
	// other readers judge.
	for _, item := range iter.Items {
		value, fixed := StaticWord(item, s.home)
		if !fixed || value == "" || strings.ContainsAny(value, "*?[]\x00\x1f") {
			continue
		}
		loopValues := actionValues{"HOME": s.home, "PWD": cwd, iter.Name.Value: value}
		for _, destination := range named {
			if target, known := actionWordValue(destination, loopValues, cwd, s.home); known &&
				actionClientProtectedPath(target, cwd, s.protected, s.keyDir) {
				return true
			}
		}
	}
	return false
}

func actionClientWordNamesVariable(word *syntax.Word, name string) bool {
	named := false
	syntax.Walk(word, func(part syntax.Node) bool {
		if param, ok := part.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == name {
			named = true
		}
		return !named
	})
	return named
}

// actionClientLoopCopyChdir reads a plain cd to one fixed directory.
func actionClientLoopCopyChdir(call *syntax.CallExpr, cwd, home string) (string, bool) {
	if len(call.Assigns) != 0 || len(call.Args) != 2 {
		return "", false
	}
	program, args, fixed := actionClientLoopCallProgram(call, home)
	if !fixed || program != "cd" || len(args) != 2 {
		return "", false
	}
	value, fixed := StaticWord(args[1], home)
	if !fixed || value == "" || strings.HasPrefix(value, "-") {
		return "", false
	}
	return OperandPath(value, cwd), true
}

// actionClientLoopCopyChangesState reports whether a statement moves the
// directory (a plain cd to a fixed directory is read before this check), sets
// HOME or PWD, or runs text the walk does not read.
func actionClientLoopCopyChangesState(stmt *syntax.Stmt, home string) bool {
	changes := false
	syntax.Walk(stmt, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok {
			return !changes
		}
		for _, assign := range call.Assigns {
			if assign.Name != nil && (assign.Name.Value == "HOME" || assign.Name.Value == "PWD") {
				changes = true
			}
		}
		if program, _, fixed := actionClientLoopCallProgram(call, home); fixed {
			switch program {
			case "cd", "pushd", "popd", "eval", "source", ".":
				changes = true
			}
		}
		return !changes
	})
	return changes
}

// actionClientLoopCallProgram reads the program a call runs from its parsed
// words, as Bash reads them (quotes and backslashes removed), after any
// command or builtin prefix. It returns the name and the words from the
// program on.
func actionClientLoopCallProgram(call *syntax.CallExpr, home string) (string, []*syntax.Word, bool) {
	args := call.Args
	for len(args) != 0 {
		program, fixed := staticProgramWord(args[0], home)
		if !fixed {
			return "", nil, false
		}
		if program != "command" && program != "builtin" {
			return program, args, true
		}
		args = args[1:]
		for len(args) != 0 {
			text, whole := wordLiteralPrefix(args[0])
			if !whole || text != "-p" && text != "--" {
				break
			}
			args = args[1:]
			if text == "--" {
				break
			}
		}
	}
	return "", nil, false
}

// actionClientLoopWriterDestinations returns the destination operands of a
// call named cp, mv, install, ln or tee. The destination is read first and
// alone: no option and no source word decides whether it is judged. A
// target-directory option names the destination; otherwise it is the last
// operand (every operand of tee).
func actionClientLoopWriterDestinations(call *syntax.CallExpr, home string) []*syntax.Word {
	program, words, fixed := actionClientLoopCallProgram(call, home)
	if !fixed || len(words) < 2 {
		return nil
	}
	base := programBase(program)
	switch base {
	case "cp", "gcp", "mv", "install", "ln", "tee":
	default:
		return nil
	}
	args := words[1:]
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
