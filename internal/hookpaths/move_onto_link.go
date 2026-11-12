// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// plainMoveLongOptions are the GNU mv long options that keep a two-operand
// call a rename of the first operand onto the second. Any other option
// (--target-directory, an abbreviation) ends the reading; --backup=CONTROL
// and the backup suffix are read in actionPlainMoveOntoLink.
var plainMoveLongOptions = map[string]bool{
	"--force": true, "--interactive": true, "--no-clobber": true, "--verbose": true,
	"--no-target-directory": true, "--backup": true,
}

// plainMoveBackupControls are the GNU --backup=CONTROL values.
var plainMoveBackupControls = map[string]bool{
	"none": true, "off": true, "numbered": true, "t": true, "existing": true, "nil": true, "simple": true, "never": true,
}

// actionPlainMoveOntoLink reads a plain mv a b call (mv or gmv, options
// only among -f -i -n -v -b -T, -S SUFFIX and their long forms, exactly two operands)
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
	// noTarget: -T (--no-target-directory) replaces a link to a directory
	// as an entry instead of moving into it.
	noTarget := false
	suffix, suffixSet := "", false
	args := call.Args[1:]
	for i := 0; i < len(args); i++ {
		arg := args[i]
		value, static := StaticWord(arg, home)
		if !static {
			return nil, "", false
		}
		// optionValue reads the value of -S or --suffix from the next word.
		optionValue := func() (string, bool) {
			if i++; i >= len(args) {
				return "", false
			}
			return StaticWord(args[i], home)
		}
		switch {
		case options && value == "--":
			options = false
		case options && (value == "-S" || value == "--suffix"):
			if suffix, static = optionValue(); !static {
				return nil, "", false
			}
			suffixSet = true
		case options && strings.HasPrefix(value, "--suffix="):
			suffix, suffixSet = strings.TrimPrefix(value, "--suffix="), true
		case options && strings.HasPrefix(value, "--backup="):
			// --backup=CONTROL keeps the replaced link as a backup entry
			// beside it (rel-1-0-6:GAP-0144).
			if !plainMoveBackupControls[strings.TrimPrefix(value, "--backup=")] {
				return nil, "", false
			}
		case options && strings.HasPrefix(value, "--"):
			if !plainMoveLongOptions[value] {
				return nil, "", false
			}
			noTarget = noTarget || value == "--no-target-directory"
		case options && len(value) > 1 && strings.HasPrefix(value, "-"):
			if strings.Trim(value[1:], "finvbT") != "" {
				return nil, "", false
			}
			noTarget = noTarget || strings.Contains(value[1:], "T")
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
	path := OperandPath(PlainMovePath(value), cwd)
	if !filepath.IsAbs(path) {
		return nil, "", false
	}
	info, err := pathLstat(path)
	if err != nil || !replaceableMoveLink(path, info, noTarget) {
		return nil, "", false
	}
	name := filepath.Base(path)
	parent, resolved := ResolveWriteTarget(filepath.Dir(path))
	if !resolved || name == "." || name == ".." {
		return nil, "", false
	}
	// The backup entry is the link renamed to its name with the suffix: a
	// suffix that leaves the directory or names a protected entry is not
	// read as plain.
	if suffixSet && (suffix == "" || strings.ContainsRune(suffix, filepath.Separator) || strings.Contains(suffix, "/") ||
		protectedEntry(filepath.Join(parent, name+suffix), newProtectedFiles(home), filepath.Join(home, ".ssh"))) {
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

// actionReplacedEntryWord reports a word that names one of entries, the
// link entries a plain mv earlier in the command replaced (its directory
// followed, its own name kept). After the move the name holds the moved
// file, so a read-only call on it reads that file, not the one the link
// named (rel-1-0-6:GAP-0217). A name with a trailing slash, a pattern or a
// value the scan cannot place is not read so.
func actionReplacedEntryWord(word *syntax.Word, values actionValues, cwd, home string, entries []string) bool {
	if len(entries) == 0 {
		return false
	}
	value, known := actionWordValue(word, values, cwd, home)
	if !known || value == "" || strings.ContainsAny(value, "*?[]") ||
		strings.HasSuffix(value, "/") || strings.HasSuffix(value, "/.") {
		return false
	}
	path := OperandPath(PlainMovePath(value), cwd)
	name := filepath.Base(path)
	parent, resolved := ResolveWriteTarget(filepath.Dir(path))
	if !filepath.IsAbs(path) || !resolved || name == "." || name == ".." {
		return false
	}
	entry := filepath.Join(parent, name)
	for _, replaced := range entries {
		if samePathName(entry, replaced) {
			return true
		}
	}
	return false
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
	if input.Command == "" {
		return PlainMoveDestinations(facts)
	}
	moved, _ := plainMoveDestinationsWithStatements(input, facts, actionfacts.SimpleCommands(input, facts))
	return moved
}

// plainMoveDestinationsWithStatements is PlainMoveDestinationsWithStatements
// that also lists the destinations a simple command moves onto with mv -T
// (noTargetMoveDestinations), from the per-command readings simples of the
// input (actionfacts.SimpleCommands).
func plainMoveDestinationsWithStatements(input actionfacts.Input, facts actionfacts.Facts, simples []actionfacts.SimpleCommand) (moved, noTarget map[string]bool) {
	moved = PlainMoveDestinations(facts)
	if input.Command == "" {
		return moved, nil
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
			if path = PlainMovePath(path); filepath.IsAbs(path) {
				writers[path]++
			}
		}
	}
	var statements map[string]bool
	childWriters := map[string]int{}
	for _, simple := range simples {
		if simple.EvaluationFailure != "" || !filepath.IsAbs(simple.CWD) {
			return moved, nil
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
		for path := range noTargetMoveDestinations(childFacts) {
			if noTarget == nil {
				noTarget = map[string]bool{}
			}
			noTarget[path] = true
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
	return moved, noTarget
}

// PlainMovePath is a move destination as the file system names it: Git
// Bash spells a Windows drive /c/... (GAP-0781 RV8-1), so on a native
// Windows host that spelling names the drive path (GAP-2559). A relative
// path is returned as it is.
func PlainMovePath(path string) string {
	if runtime.GOOS == "windows" {
		path = actionMSYSDrivePath(path)
	}
	if !filepath.IsAbs(path) {
		return path
	}
	return filepath.Clean(path)
}

// replaceableMoveLink reports a move destination that rename(2) replaces
// as an entry, writing nothing it names: a symbolic link to a file or a
// dangling one and, with -T (noTarget), a link to a directory or on
// Windows a junction, which mv -T replaces instead of moving into
// (GAP-2559). A link whose target cannot be read is not one.
func replaceableMoveLink(path string, info os.FileInfo, noTarget bool) bool {
	if info.Mode()&os.ModeSymlink == 0 {
		// Go reports a Windows junction (a mount point) as an irregular
		// entry, not as a link.
		return noTarget && runtime.GOOS == "windows" && info.Mode()&os.ModeIrregular != 0
	}
	target, err := pathStat(path)
	if err != nil {
		return errors.Is(err, fs.ErrNotExist)
	}
	return !target.IsDir() || noTarget
}

// plainMoveNoTargetArgv reports a complete mv argv that passes -T or
// --no-target-directory, with options only among -f -i -n -v -T, their
// long forms and --, and exactly two operands. A cluster with any other
// letter (-S takes the rest as its value, -t names a target directory) is
// not read.
func plainMoveNoTargetArgv(argv []string) bool {
	if len(argv) < 4 {
		return false
	}
	if base := programBase(argv[0]); base != "mv" && base != "gmv" {
		return false
	}
	noTarget, options, operands := false, true, 0
	for _, arg := range argv[1:] {
		switch {
		case options && arg == "--":
			options = false
		case options && strings.HasPrefix(arg, "--"):
			switch arg {
			case "--no-target-directory":
				noTarget = true
			case "--force", "--interactive", "--no-clobber", "--verbose":
			default:
				return false
			}
		case options && len(arg) > 1 && strings.HasPrefix(arg, "-"):
			if strings.Trim(arg[1:], "finvT") != "" {
				return false
			}
			noTarget = noTarget || strings.Contains(arg[1:], "T")
		default:
			operands++
		}
	}
	return noTarget && operands == 2
}

// noTargetMoveDestinations lists the destinations of the plain mv -T calls
// of the facts (plainMoveNoTargetArgv): each replaces its destination as
// an entry, also a link to a directory.
func noTargetMoveDestinations(facts actionfacts.Facts) map[string]bool {
	var out map[string]bool
	for _, command := range facts.Commands {
		if !command.ArgvComplete || !plainMoveNoTargetArgv(command.Argv) {
			continue
		}
		for _, candidate := range facts.Paths {
			if candidate.CommandID != command.ID || candidate.Access != actionfacts.PathAccessWrite {
				continue
			}
			path := candidate.Resolved
			if path == "" {
				path = candidate.Normalized
			}
			if path = PlainMovePath(path); filepath.IsAbs(path) {
				if out == nil {
					out = map[string]bool{}
				}
				out[path] = true
			}
		}
	}
	return out
}

// actionWindowsMoveUnsafe holds the characters that end the Windows plain
// move reading: quotes, variables, patterns, subexpressions, separators,
// redirects, the escape characters and line breaks.
const actionWindowsMoveUnsafe = "$%*?[](){}@;|&<>\"\x60\x27\x00\r\n"

// actionWindowsPlainMoveOntoLink reads one statement of the Windows target
// scan as a plain move onto an existing link (GAP-2559): Move-Item (and in
// the PowerShell reading mv, move, mi) with only -Force and -PassThru and one
// source and one destination, positional or named -Path, -LiteralPath and
// -Destination; in the plain (Git Bash) reading a GNU mv with options only
// among -f -i -n -v -T and two operands. The destination must be an
// existing link the move replaces as an entry (replaceableMoveLink; -T
// only in the plain reading: PowerShell has no such parameter). index is
// the destination word, entry the entry it replaces.
func actionWindowsPlainMoveOntoLink(statement []string, dir, home string, powerShell bool) (index int, entry string, ok bool) {
	if runtime.GOOS != "windows" || len(statement) < 3 || len(statement) > 8 {
		return 0, "", false
	}
	for _, word := range statement {
		if word == "" || strings.ContainsAny(word, actionWindowsMoveUnsafe) ||
			strings.HasSuffix(word, "/") || strings.HasSuffix(word, "\\") {
			return 0, "", false
		}
	}
	program := strings.ToLower(statement[0])
	noTarget := false
	index = -1
	switch {
	// Only PowerShell runs Move-Item; mv, move and mi are its aliases there.
	case program == "move-item" || powerShell && (program == "mv" || program == "move" || program == "mi"):
		named := map[string]int{}
		var positional []int
		for i := 1; i < len(statement); i++ {
			word := strings.ToLower(statement[i])
			if !strings.HasPrefix(word, "-") {
				positional = append(positional, i)
				continue
			}
			switch word {
			case "-force", "-passthru":
			case "-path", "-literalpath", "-destination":
				if _, repeated := named[word]; repeated || i+1 >= len(statement) || strings.HasPrefix(statement[i+1], "-") {
					return 0, "", false
				}
				i++
				named[word] = i
			default:
				return 0, "", false
			}
		}
		_, path := named["-path"]
		_, literal := named["-literalpath"]
		if path && literal {
			return 0, "", false
		}
		if !path && !literal {
			if len(positional) == 0 {
				return 0, "", false
			}
			positional = positional[1:]
		}
		if destination, isNamed := named["-destination"]; isNamed {
			index = destination
		} else if len(positional) != 0 {
			index, positional = positional[0], positional[1:]
		}
		if index < 0 || len(positional) != 0 {
			return 0, "", false
		}
	case !powerShell && (program == "mv" || program == "gmv"):
		var operands []int
		options := true
		for i := 1; i < len(statement); i++ {
			word := statement[i]
			switch {
			case options && word == "--":
				options = false
			case options && strings.HasPrefix(word, "--"):
				switch word {
				case "--no-target-directory":
					noTarget = true
				case "--force", "--interactive", "--no-clobber", "--verbose":
				default:
					return 0, "", false
				}
			case options && (strings.EqualFold(word, "-force") || strings.EqualFold(word, "-passthru")):
				// A PowerShell switch: GNU mv has no -F or -P option, so
				// this reading runs no move at all.
			case options && len(word) > 1 && strings.HasPrefix(word, "-"):
				if strings.Trim(word[1:], "finvT") != "" {
					return 0, "", false
				}
				noTarget = noTarget || strings.Contains(word[1:], "T")
			default:
				operands = append(operands, i)
			}
		}
		if len(operands) != 2 {
			return 0, "", false
		}
		index = operands[1]
	default:
		return 0, "", false
	}
	resolved, known := actionWindowsPath(statement[index], dir, home)
	if !known {
		return 0, "", false
	}
	destination := filepath.FromSlash(resolved)
	info, err := pathLstat(destination)
	if err != nil || !replaceableMoveLink(destination, info, noTarget) {
		return 0, "", false
	}
	name := filepath.Base(destination)
	parent, resolvedParent := ResolveWriteTarget(filepath.Dir(destination))
	if !resolvedParent || name == "." || name == ".." {
		return 0, "", false
	}
	return index, filepath.Join(parent, name), true
}

// WindowsMovedOntoLinkEntries lists, on a native Windows host, the
// destinations a plain move of the command replaces as a link entry
// (actionWindowsPlainMoveOntoLink in the PowerShell and the plain reading,
// in the directory each statement runs in) whose entry is not protected,
// keyed by WindowsMovedOntoLinkKey. A destination that another word of the
// command also names is not listed: a later write through that name is
// judged as written (GAP-2559).
func WindowsMovedOntoLinkEntries(command, cwd, home string) map[string]bool {
	if runtime.GOOS != "windows" || !actionWindowsHome(home) || command == "" || len(command) > MaxPayloadBytes {
		return nil
	}
	var out map[string]bool
	protected := newProtectedFiles(home)
	ssh := filepath.Join(home, ".ssh")
	text := actionWindowsBlankPatchText(command)
	for _, grammar := range []actionWindowsGrammar{0, actionWindowsPlainGrammar} {
		scan := actionWindowsScan(text, grammar|actionWindowsLiteralDollar)
		if !scan.ok {
			continue
		}
		named := map[string]int{}
		moved := map[string]bool{}
		effectiveCWD := cwd
		var directoryStack []string
		for _, span := range actionWindowsResolvedSpans(scan.words, cwd, home) {
			for _, word := range span.words {
				if resolved, known := actionWindowsPath(word, effectiveCWD, home); known {
					named[WindowsMovedOntoLinkKey(resolved)]++
				}
			}
			if index, entry, ok := actionWindowsPlainMoveOntoLink(span.words, effectiveCWD, home, grammar == 0); ok &&
				!protectedEntry(entry, protected, ssh) {
				if resolved, known := actionWindowsPath(span.words[index], effectiveCWD, home); known {
					moved[WindowsMovedOntoLinkKey(resolved)] = true
				}
			}
			actionWindowsAdvanceDirectory(span.words, home, &effectiveCWD, &directoryStack)
		}
		for key := range moved {
			if named[key] == 1 {
				if out == nil {
					out = map[string]bool{}
				}
				out[key] = true
			}
		}
	}
	return out
}

// WindowsMovedOntoLinkKey is the key of a path in WindowsMovedOntoLinkEntries:
// its clean file system name, folded to lower case as Windows names fold.
func WindowsMovedOntoLinkKey(path string) string {
	return strings.ToLower(filepath.Clean(filepath.FromSlash(PlainMovePath(path))))
}

// actionDirectStatements marks the statements of a command list that run on
// their own: top-level statements and the operands of && and ||, not a side
// of a pipeline, a subshell or a substitution, whose output could feed
// another command (GAP-2590).
func actionDirectStatements(file *syntax.File) map[*syntax.Stmt]bool {
	direct := map[*syntax.Stmt]bool{}
	var mark func(stmt *syntax.Stmt)
	mark = func(stmt *syntax.Stmt) {
		if stmt == nil {
			return
		}
		if binary, ok := stmt.Cmd.(*syntax.BinaryCmd); ok {
			if binary.Op == syntax.AndStmt || binary.Op == syntax.OrStmt {
				mark(binary.X)
				mark(binary.Y)
			}
			return
		}
		direct[stmt] = true
	}
	if file != nil {
		for _, stmt := range file.Stmts {
			mark(stmt)
		}
	}
	return direct
}

// actionWindowsPlainRemovedLinks reads one statement of the Windows target
// scan as a plain removal of link entries (rel-1-0-4:GAP-2590): in the
// PowerShell reading Remove-Item (and its aliases rm, del, erase, ri) with
// only -Force and positional, -Path or -LiteralPath operands, no -Recurse;
// in the plain (Git Bash) reading rm or unlink with options only among
// -f -i -I -v. Each operand that is an existing symbolic link to a file (or
// a dangling one), with no pattern or trailing slash, maps by its word index
// to the entry it removes; a directory link or a junction is not read
// (Windows PowerShell 5.1 Remove-Item can reach into a directory link).
func actionWindowsPlainRemovedLinks(statement []string, dir, home string, powerShell bool) map[int]string {
	if runtime.GOOS != "windows" || len(statement) < 2 || len(statement) > 16 {
		return nil
	}
	for _, word := range statement {
		if word == "" || strings.ContainsAny(word, actionWindowsMoveUnsafe) ||
			strings.HasSuffix(word, "/") || strings.HasSuffix(word, "\\") {
			return nil
		}
	}
	program := strings.TrimSuffix(strings.ToLower(statement[0]), ".exe")
	var operands []int
	switch {
	case program == "remove-item" || powerShell && (program == "rm" || program == "del" || program == "erase" || program == "ri"):
		for i := 1; i < len(statement); i++ {
			word := strings.ToLower(statement[i])
			switch {
			case word == "-force":
			case word == "-path" || word == "-literalpath":
				if i+1 >= len(statement) || strings.HasPrefix(statement[i+1], "-") {
					return nil
				}
				i++
				operands = append(operands, i)
			case strings.HasPrefix(word, "-"):
				return nil
			default:
				operands = append(operands, i)
			}
		}
	case !powerShell && (program == "rm" || program == "unlink"):
		options := true
		for i := 1; i < len(statement); i++ {
			word := statement[i]
			switch {
			case options && word == "--":
				options = false
			case options && strings.HasPrefix(word, "--"):
				if !plainRemoveLongOptions[word] {
					return nil
				}
			case options && len(word) > 1 && strings.HasPrefix(word, "-"):
				if strings.Trim(word[1:], "fiIv") != "" {
					return nil
				}
			default:
				operands = append(operands, i)
			}
		}
	default:
		return nil
	}
	var removed map[int]string
	for _, index := range operands {
		resolved, known := actionWindowsPath(statement[index], dir, home)
		if !known {
			continue
		}
		path := filepath.FromSlash(resolved)
		info, err := pathLstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		if target, err := pathStat(path); err == nil && target.IsDir() {
			continue
		}
		name := filepath.Base(path)
		parent, resolvedParent := ResolveWriteTarget(filepath.Dir(path))
		if !resolvedParent || name == "." || name == ".." {
			continue
		}
		if removed == nil {
			removed = make(map[int]string)
		}
		removed[index] = filepath.Join(parent, name)
	}
	return removed
}
