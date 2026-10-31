// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// plainMoveLongOptions are the GNU mv long options that keep a two-operand
// call a rename of the first operand onto the second. Any other option
// (--target-directory, an abbreviation, --suffix=...) ends the reading.
var plainMoveLongOptions = map[string]bool{
	"--force": true, "--interactive": true, "--no-clobber": true, "--verbose": true,
	"--no-target-directory": true, "--backup": true,
}

// actionPlainMoveOntoLink reads a plain mv a b call (mv or gmv, options
// only among -f -i -n -v -b -T and their long forms, exactly two operands)
// whose destination is an existing symbolic link to a file, or a dangling
// one. rename(2) replaces that link entry and writes neither the file it
// names nor anything else (a cross-device GNU mv removes the destination
// first), so the move is judged by the entry: the directory of the link
// followed, its own name kept (GAP-2559, as the hook map does for
// GAP-2558). word is the destination word, entry the replaced entry.
func actionPlainMoveOntoLink(call *syntax.CallExpr, values actionValues, cwd, home string) (word *syntax.Word, entry string, ok bool) {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) < 3 || len(call.Args) > 6 {
		return nil, "", false
	}
	program, known := staticProgramWord(call.Args[0], home)
	if base := programBase(program); !known || base != "mv" && base != "gmv" {
		return nil, "", false
	}
	var operands []*syntax.Word
	options := true
	for _, arg := range call.Args[1:] {
		value, static := StaticWord(arg, home)
		if !static {
			return nil, "", false
		}
		switch {
		case options && value == "--":
			options = false
		case options && strings.HasPrefix(value, "--"):
			if !plainMoveLongOptions[value] {
				return nil, "", false
			}
		case options && len(value) > 1 && strings.HasPrefix(value, "-"):
			if strings.Trim(value[1:], "finvbT") != "" {
				return nil, "", false
			}
		default:
			operands = append(operands, arg)
		}
	}
	if len(operands) != 2 {
		return nil, "", false
	}
	destination := operands[1]
	value, known := actionWordValue(destination, values, cwd, home)
	if !known || value == "" || strings.ContainsAny(value, "*?[]") ||
		strings.HasSuffix(value, "/") || strings.HasSuffix(value, "/.") {
		return nil, "", false
	}
	path := OperandPath(value, cwd)
	if !filepath.IsAbs(path) {
		return nil, "", false
	}
	info, err := pathLstat(path)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return nil, "", false
	}
	if target, err := pathStat(path); err == nil && target.IsDir() || err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, "", false
	}
	name := filepath.Base(path)
	parent, resolved := ResolveWriteTarget(filepath.Dir(path))
	if !resolved || name == "." || name == ".." {
		return nil, "", false
	}
	return destination, filepath.Join(parent, name), true
}

// plainRemoveLongOptions keep rm a removal of each operand's own entry.
var plainRemoveLongOptions = map[string]bool{"--force": true, "--verbose": true, "--interactive": true}

// actionPlainRemovedLinks maps each operand of a plain rm or unlink (rm
// options only among -f -i -I -v and their long forms, no recursive or
// directory removal) that is an existing symbolic link, written with no
// trailing slash, to the entry it removes. unlink(2) removes the link entry
// and neither the file nor the directory it names, so such an operand is
// judged by its entry, its directory followed and its name kept, as a plain
// mv onto a link is (GAP-2590, GAP-2559).
func actionPlainRemovedLinks(call *syntax.CallExpr, values actionValues, cwd, home string) map[*syntax.Word]string {
	if call == nil || len(call.Assigns) != 0 || len(call.Args) < 2 {
		return nil
	}
	program, known := staticProgramWord(call.Args[0], home)
	if base := programBase(program); !known || base != "rm" && base != "unlink" {
		return nil
	}
	var removed map[*syntax.Word]string
	options := true
	for _, arg := range call.Args[1:] {
		value, static := StaticWord(arg, home)
		if !static {
			return nil
		}
		switch {
		case options && value == "--":
			options = false
			continue
		case options && strings.HasPrefix(value, "--"):
			name, _, _ := strings.Cut(value, "=")
			if !plainRemoveLongOptions[name] {
				return nil
			}
			continue
		case options && len(value) > 1 && strings.HasPrefix(value, "-"):
			if strings.Trim(value[1:], "fiIv") != "" {
				return nil
			}
			continue
		}
		operand, known := actionWordValue(arg, values, cwd, home)
		if !known || operand == "" || strings.ContainsAny(operand, "*?[]") ||
			strings.HasSuffix(operand, "/") || strings.HasSuffix(operand, "/.") {
			continue
		}
		path := OperandPath(operand, cwd)
		if !filepath.IsAbs(path) {
			continue
		}
		if info, err := pathLstat(path); err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		name := filepath.Base(path)
		parent, resolved := ResolveWriteTarget(filepath.Dir(path))
		if !resolved || name == "." || name == ".." {
			continue
		}
		if removed == nil {
			removed = make(map[*syntax.Word]string)
		}
		removed[arg] = filepath.Join(parent, name)
	}
	return removed
}

// protectedEntry reports an entry that is itself one of the protected
// authorized-keys names or the .ssh directory, each read with its own
// directory followed and its name kept; the file a link entry names is not
// followed.
func protectedEntry(entry string, protected protectedFiles, ssh string) bool {
	paths := []string{ssh}
	for _, file := range protected {
		paths = append(paths, file.path)
	}
	for _, path := range paths {
		if samePathName(entry, path) {
			return true
		}
		if parent, ok := ResolveWriteTarget(filepath.Dir(path)); ok && samePathName(entry, filepath.Join(parent, filepath.Base(path))) {
			return true
		}
	}
	return false
}

// MovedOntoLinkEntries lists, for a gateway that reads the file system
// itself, the plain move destinations of the facts that are an existing
// link to a file or a dangling one (movedOntoLinkEntries, GAP-2559).
func MovedOntoLinkEntries(facts actionfacts.Facts) map[string]bool {
	return movedOntoLinkEntries(facts)
}

// PlainMoveDestinationsWithStatements is PlainMoveDestinations, also for a
// plain mv that only its own simple command reads with a complete argv: a
// ~/ operand in a command list that the whole-command reading leaves
// partial (cd ~/ext && mv ~/p/a.txt /home/u/p/lnk, GAP-2559). Such a
// destination counts only when every simple command was read and no other
// write, append or redirect of the command names it.
func PlainMoveDestinationsWithStatements(input actionfacts.Input, facts actionfacts.Facts) map[string]bool {
	moved := PlainMoveDestinations(facts)
	if input.Command == "" {
		return moved
	}
	writers := map[string]int{}
	count := func(view actionfacts.Facts) {
		for _, candidate := range view.Paths {
			if candidate.Access != actionfacts.PathAccessWrite && candidate.Access != actionfacts.PathAccessAppend {
				continue
			}
			path := candidate.Resolved
			if path == "" {
				path = candidate.Normalized
			}
			if filepath.IsAbs(path) {
				writers[filepath.Clean(path)]++
			}
		}
	}
	var statements map[string]bool
	childWriters := map[string]int{}
	for _, simple := range actionfacts.SimpleCommands(input, facts) {
		if simple.EvaluationFailure != "" || !filepath.IsAbs(simple.CWD) {
			return moved
		}
		child := input
		child.Command, child.CWD, child.Args, child.Argv = simple.Text, simple.CWD, nil, nil
		childFacts := actionfacts.Analyze(child)
		count(childFacts)
		for path := range PlainMoveDestinations(childFacts) {
			if statements == nil {
				statements = map[string]bool{}
			}
			statements[path] = true
		}
	}
	for path, n := range writers {
		childWriters[path] = n
	}
	writers = map[string]int{}
	count(facts)
	for path := range statements {
		if !moved[path] && childWriters[path] == 1 && writers[path] <= 1 {
			moved[path] = true
		}
	}
	return moved
}
