// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// registrationFlowReadSpans are the byte spans of the command whose words
// only name a file for it to be read (rel-1-0-10:GAP-0104). The flow net
// (registrationFlowMembers) leaves them out of the text it matches the
// registration set in and out of the words it resolves as links, so
// `cmp -s a ~/.claude/settings.json && echo SAME > /tmp/x` or
// `cp ~/.codex/config.toml /tmp/bak/config.toml` is no longer read as a
// write of the hook config. A word is left out by its role in its call:
//
//   - every operand of a reader call (actionKnownReadOnlyShell on the call
//     alone: sha256sum, shasum, cmp, cat, stat ...; behind sudo or env);
//   - the code and the words of python -c CODE, and the here-document of
//     python3 - <<'TAG', when a read grammar proves the code read-only
//     (actionfacts.InlineCodeHandoff ProvenReads);
//   - the sources of a cp with known options, when no source lands on a
//     registered file or folder;
//   - the members of a tar create (-c), and of a tar extract to standard
//     output (-x -O), with known options; the archive stays;
//   - the words of a for loop whose body is reader calls only and whose
//     variable is read nowhere else.
//
// A redirect target, a cp destination, a tar archive and every word of any
// other call keep the whole-text match. A reader prints what it reads, so
// a name can still reach a writer through the output (ls F | xargs rm,
// rm $(cat list)); a call that copies, moves or links into a folder that
// holds a registered file (cp -r X/.claude ~/), or that holds a runner of such data, a command
// substitution, $_, an indirect expansion, a function, a declaration, a
// rebound reader name, a program word that is not static or an assignment
// to a shell control variable leaves nothing out.
func registrationFlowReadSpans(file *syntax.File, cwd, home string, protected protectedFiles) [][2]int {
	if file == nil || actionRebindsReaderNames(file, home) || registrationFolderDestination(file, cwd, home, protected) {
		return nil
	}
	provenPython := map[*syntax.Stmt]bool{}
	syntax.Walk(file, func(node syntax.Node) bool {
		if stmt, ok := node.(*syntax.Stmt); ok && registrationProvenPythonRead(stmt, home) {
			provenPython[stmt] = true
		}
		return true
	})
	if registrationFlowDataRunner(file, home, provenPython) {
		return nil
	}
	var spans [][2]int
	add := func(word *syntax.Word) {
		if word == nil {
			return
		}
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		if start < end && registrationPlainWord(word) {
			spans = append(spans, [2]int{start, end})
		}
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Stmt:
			if provenPython[node] {
				call := node.Cmd.(*syntax.CallExpr)
				for _, word := range call.Args[1:] {
					add(word)
				}
				for _, redirect := range node.Redirs {
					if redirect.Op == syntax.Hdoc || redirect.Op == syntax.DashHdoc {
						add(redirect.Hdoc)
					}
				}
			}
		case *syntax.CallExpr:
			for _, word := range registrationCallReadWords(node, home, protected) {
				add(word)
			}
		case *syntax.ForClause:
			for _, word := range registrationReadLoopWords(file, node, home) {
				add(word)
			}
		}
		return true
	})
	return spans
}

// registrationFlowBlank returns the command with the spans blanked and the
// word filter that drops a static word inside one of them.
func registrationFlowBlank(command string, spans [][2]int) (string, func(*syntax.Word) bool) {
	if len(spans) == 0 {
		return command, func(*syntax.Word) bool { return false }
	}
	text := []byte(command)
	for _, span := range spans {
		for index := span[0]; index < span[1] && index < len(text); index++ {
			if text[index] != '\n' {
				text[index] = ' '
			}
		}
	}
	inside := func(word *syntax.Word) bool {
		start, end := int(word.Pos().Offset()), int(word.End().Offset())
		return slices.ContainsFunc(spans, func(span [2]int) bool { return span[0] <= start && end <= span[1] })
	}
	return string(text), inside
}

// registrationPlainWord reports a word whose text can do nothing but name a
// value: literal and quoted text and plain $name expansions. A substitution
// runs a command of its own, an expansion with an operator (${x:=v}) or an
// arithmetic one can assign a variable, and a brace list or an extended
// glob can make one word several (cp F{.bak,} names a destination), so such
// a word is never left out.
func registrationPlainWord(word *syntax.Word) bool {
	plain := true
	syntax.Walk(word, func(node syntax.Node) bool {
		if !plain {
			return false
		}
		switch node := node.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst, *syntax.ArithmExp, *syntax.ExtGlob, *syntax.BraceExp:
			plain = false
		case *syntax.Lit:
			plain = !strings.ContainsAny(node.Value, "{}")
		case *syntax.ParamExp:
			plain = !node.Excl && !node.Length && !node.Width && node.Index == nil &&
				node.Slice == nil && node.Repl == nil && node.Exp == nil && node.NestedParam == nil
		}
		return plain
	})
	return plain
}

// registrationDataRunners are programs that turn data into names they act
// on (xargs, read, an interpreter, patch, git, an archive extractor) or that
// run text: in a call that holds one, a name a reader prints may become an
// operand, so no word is left out.
var registrationDataRunners = map[string]bool{
	"xargs": true, "parallel": true, "eval": true, "source": true, ".": true, "exec": true,
	"read": true, "mapfile": true, "readarray": true, "sh": true, "bash": true, "zsh": true,
	"dash": true, "ksh": true, "fish": true, "csh": true, "tcsh": true, "pwsh": true, "powershell": true,
	"busybox": true, "node": true, "ruby": true, "perl": true, "php": true, "lua": true,
	"awk": true, "gawk": true, "mawk": true, "nawk": true, "sed": true, "gsed": true, "tclsh": true,
	"osascript": true, "patch": true, "git": true, "unzip": true, "cpio": true, "bsdtar": true,
	"7z": true, "7za": true, "find": true, "gfind": true, "make": true, "ssh": true, "scp": true,
	"su": true, "script": true, "watch": true, "trap": true, "alias": true, "command": true,
	"builtin": true, "enable": true, "set": true, "shopt": true, "declare": true, "typeset": true,
	"local": true, "export": true, "readonly": true, "unset": true, "hash": true,
}

// registrationPythonProgram matches a Python interpreter name.
var registrationPythonProgram = regexp.MustCompile(`^python[0-9.]*$`)

// registrationFlowDataRunner reports a call in which no word may be left
// out: it holds a data runner word (in any position, so a wrapper in front
// of it hides nothing), an interpreter that no read grammar proves, a tar
// extraction to disk or one with an option the reader does not know, a
// name-list option, a command substitution, $_ or an indirect expansion, a
// function or declaration, a program word that is not static, or an
// assignment to a shell control variable (PATH, IFS, BASH_ENV ...).
func registrationFlowDataRunner(file *syntax.File, home string, provenPython map[*syntax.Stmt]bool) bool {
	runner := false
	provenCalls := map[*syntax.CallExpr]bool{}
	for stmt := range provenPython {
		provenCalls[stmt.Cmd.(*syntax.CallExpr)] = true
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if runner {
			return false
		}
		switch node := node.(type) {
		case *syntax.CmdSubst, *syntax.FuncDecl, *syntax.DeclClause, *syntax.CoprocClause:
			runner = true
		case *syntax.ParamExp:
			runner = node.Excl || node.Param != nil && node.Param.Value == "_"
		case *syntax.Assign:
			runner = node.Name == nil || registrationControlName(node.Name.Value)
		case *syntax.ForClause:
			if iter, ok := node.Loop.(*syntax.WordIter); ok {
				runner = registrationControlName(iter.Name.Value)
			} else {
				runner = true
			}
		case *syntax.CallExpr:
			if len(node.Args) == 0 {
				return true
			}
			if _, known := staticProgramWord(node.Args[0], home); !known {
				runner = true
				return false
			}
			for index, arg := range node.Args {
				value, fixed := StaticWord(arg, home)
				if !fixed {
					continue
				}
				base := programBase(value)
				switch {
				case registrationDataRunners[base]:
					runner = true
				case index > 0 && (base == "tar" || base == "gtar"):
					// A wrapped tar (sudo tar -x) is not read here.
					runner = true
				case registrationPythonProgram.MatchString(base) && !(index == 0 && provenCalls[node]):
					runner = true
				case strings.HasPrefix(value, "--files-from") || strings.HasPrefix(value, "--include-from") ||
					strings.HasPrefix(value, "--exclude-from") || strings.HasPrefix(value, "--to-command"):
					runner = true
				}
				if runner {
					return false
				}
			}
			if program, _ := staticProgramWord(node.Args[0], home); programBase(program) == "tar" || programBase(program) == "gtar" {
				if mode, toStdout, _, ok := registrationTarRead(node, home); !ok || mode == 'x' && !toStdout {
					runner = true
				}
			}
		}
		return !runner
	})
	return runner
}

// registrationControlName is a variable that changes how the shell finds or
// runs a program or splits a word: every upper-case name (PATH, IFS,
// BASH_ENV, ENV, CDPATH ...) and zsh's path and fpath.
func registrationControlName(name string) bool {
	return name == "path" || name == "fpath" || strings.ContainsAny(name, "ABCDEFGHIJKLMNOPQRSTUVWXYZ")
}

// registrationProvenPythonRead reports python -c CODE [ARG...] and
// python3 - <<'TAG' (a quoted here-document, so no expansion) whose code
// the Python read grammar proves read-only.
func registrationProvenPythonRead(stmt *syntax.Stmt, home string) bool {
	call, ok := stmt.Cmd.(*syntax.CallExpr)
	if !ok || len(call.Args) < 2 || len(call.Assigns) != 0 || stmt.Background || stmt.Coprocess {
		return false
	}
	words, known := actionStaticWords(call.Args, home)
	if !known || !registrationPythonProgram.MatchString(programBase(words[0])) {
		return false
	}
	var hdoc *syntax.Redirect
	for _, redirect := range stmt.Redirs {
		switch redirect.Op {
		case syntax.Hdoc, syntax.DashHdoc:
			if hdoc != nil {
				return false
			}
			hdoc = redirect
		case syntax.RdrIn, syntax.WordHdoc, syntax.DplIn:
			return false
		}
	}
	switch {
	case words[1] == "-c" && len(words) >= 3 && hdoc == nil:
		return actionfacts.InlineCodeHandoff(words).ProvenReads
	case words[1] == "-" && len(words) == 2 && hdoc != nil && registrationQuotedDelimiter(hdoc.Word) && hdoc.Hdoc != nil:
		body, fixed := StaticWord(hdoc.Hdoc, home)
		return fixed && actionfacts.InlineCodeHandoff([]string{words[0], "-c", body}).ProvenReads
	}
	return false
}

// registrationQuotedDelimiter reports a here-document delimiter with a
// quoted part: the shell expands nothing in the body.
func registrationQuotedDelimiter(word *syntax.Word) bool {
	if word == nil {
		return false
	}
	return slices.ContainsFunc(word.Parts, func(part syntax.WordPart) bool {
		switch part.(type) {
		case *syntax.SglQuoted, *syntax.DblQuoted:
			return true
		}
		return false
	})
}

// registrationCallReadWords are the words of one call that it only reads.
func registrationCallReadWords(call *syntax.CallExpr, home string, protected protectedFiles) []*syntax.Word {
	if len(call.Args) < 2 || len(call.Assigns) != 0 {
		return nil
	}
	inner := call
	if wrapped, ok := actionReadOnlyWrappedCall(call, home); ok {
		inner = wrapped
	}
	program, known := staticProgramWord(inner.Args[0], home)
	if !known {
		return nil
	}
	switch base := programBase(program); base {
	case "cd", "pushd", "popd", "dirs", "echo", "printf":
		// A folder change decides what later relative names reach, and a
		// print hands its words on.
		return nil
	case "cp", "gcp":
		return registrationCopySources(inner, home, protected)
	case "tar", "gtar":
		if _, _, members, ok := registrationTarRead(inner, home); ok {
			return members
		}
		return nil
	}
	alone := &syntax.File{Stmts: []*syntax.Stmt{{Cmd: inner}}}
	if !actionKnownReadOnlyShell(alone, home) || !actionReadersAreSystemPrograms(alone, home, 0) {
		return nil
	}
	return inner.Args[1:]
}

// registrationCopyFlags are the cp options that copy the content of each
// source: no recursion or no-dereference (a link would be copied as a link
// to the registered file), no hard or symbolic link, no target option, no
// backup of the destination.
var registrationCopyFlags = map[byte]bool{'p': true, 'f': true, 'v': true, 'i': true, 'n': true, 'u': true, 'L': true}

// registrationCopySources are the sources of cp [OPTION]... SOURCE... DEST
// when every option is in registrationCopyFlags (or --preserve[=...],
// --dereference, --no-clobber, --verbose, --force), every operand is static
// and no source lands on a registered file or a folder that holds one.
func registrationCopySources(call *syntax.CallExpr, home string, protected protectedFiles) []*syntax.Word {
	var operands []*syntax.Word
	var values []string
	options := true
	for _, arg := range call.Args[1:] {
		value, fixed := StaticWord(arg, home)
		if !fixed {
			return nil
		}
		if options && value == "--" {
			options = false
			continue
		}
		if options && strings.HasPrefix(value, "-") && value != "-" {
			if !registrationCopyOption(value) {
				return nil
			}
			continue
		}
		operands = append(operands, arg)
		values = append(values, value)
	}
	if len(operands) < 2 {
		return nil
	}
	spelled := values[len(values)-1]
	dest, placed := registrationCopyDestination(spelled)
	if !placed {
		return nil
	}
	folder := len(values) > 2 || strings.HasSuffix(spelled, "/") || strings.HasSuffix(spelled, `\`)
	if info, err := callStat(dest); err == nil && info.IsDir() {
		folder = true
	}
	for _, source := range values[:len(values)-1] {
		landing := filepath.Clean(dest)
		if folder {
			landing = filepath.Join(landing, filepath.Base(source))
		}
		if registrationLandsOnMember(landing, protected) {
			return nil
		}
	}
	return operands[:len(operands)-1]
}

// registrationCopyDestination is the cp destination as a path of this
// host's file system, or false when the reader cannot place it. An absolute
// path is one. On Windows the POSIX shell the agents run (Git Bash) also
// names a drive as /c/... or /cygdrive/c/..., read as that drive path, and
// roots its scratch folders /tmp and /var/tmp at its own install: a copy out
// to one of them lands on no drive path a hook config has. There the copy
// out of a hook config (cp -p ~/.claude/settings.json /tmp/bak/) kept its
// tamper.agent_hook_config_write alert, as /tmp/... is not absolute
// (rel-1-0-10:GAP-0104, native Windows). Any other rooted name (/home/x, an
// fstab mount, //host) may be mapped anywhere, so it is not placed.
func registrationCopyDestination(dest string) (string, bool) {
	if runtime.GOOS != "windows" {
		return dest, filepath.IsAbs(dest)
	}
	if drive := actionfacts.MSYSDrivePath(dest); drive != dest {
		dest = filepath.FromSlash(drive)
	}
	if filepath.IsAbs(dest) {
		return dest, true
	}
	slashed := filepath.ToSlash(dest)
	if strings.HasPrefix(slashed, "//") {
		return "", false
	}
	clean := path.Clean(slashed)
	for _, root := range []string{"/tmp", "/var/tmp"} {
		if clean == root || strings.HasPrefix(clean, root+"/") {
			return dest, true
		}
	}
	return "", false
}

func registrationCopyOption(option string) bool {
	switch {
	case option == "--preserve" || strings.HasPrefix(option, "--preserve="),
		option == "--dereference", option == "--no-clobber", option == "--verbose", option == "--force":
		return true
	case strings.HasPrefix(option, "--"):
		return false
	}
	for index := 1; index < len(option); index++ {
		if !registrationCopyFlags[option[index]] {
			return false
		}
	}
	return true
}

// registrationLandsOnMember reports a path that is a registered file, a
// folder that holds one, or a link the hook resolves to one.
func registrationLandsOnMember(path string, protected protectedFiles) bool {
	prefix := path + string(filepath.Separator)
	for _, entry := range protected {
		if entry.path == path || strings.HasPrefix(entry.path, prefix) {
			return true
		}
	}
	if resolved, ok := ResolveWriteTarget(path); ok && protectedReachResolved(resolved, protected, "") {
		return true
	}
	return false
}

// registrationTarRead reads tar [-]BUNDLE [OPTION]... [MEMBER]...: the mode
// (c create, x extract, t list) and the member words the call only reads,
// for a create and for an extract to standard output (-O). ok is false for
// an option the reader does not know: --remove-files, --to-command,
// --checkpoint-action, -I, -T, -g and the rest may write a file, run a
// program or take names from data. The archive (-f VALUE) and the folder
// (-C VALUE) are never members.
func registrationTarRead(call *syntax.CallExpr, home string) (mode byte, toStdout bool, members []*syntax.Word, ok bool) {
	takesValue := 0
	options := true
	for index, arg := range call.Args[1:] {
		value, fixed := StaticWord(arg, home)
		if takesValue > 0 {
			takesValue--
			continue
		}
		if !fixed {
			if !options || !strings.HasPrefix(arg.Lit(), "-") {
				members = append(members, arg)
				continue
			}
			return 0, false, nil, false
		}
		bundle := ""
		switch {
		case options && value == "--":
			options = false
			continue
		case options && strings.HasPrefix(value, "--"):
			name, _, hasValue := strings.Cut(value, "=")
			switch name {
			case "--create":
				mode = 'c'
			case "--extract", "--get":
				mode = 'x'
			case "--list":
				mode = 't'
			case "--to-stdout":
				toStdout = true
			case "--gzip", "--bzip2", "--xz", "--zstd", "--verbose", "--preserve-permissions", "--dereference":
			case "--file", "--directory", "--exclude":
				if !hasValue {
					takesValue++
				}
			default:
				return 0, false, nil, false
			}
			continue
		case options && strings.HasPrefix(value, "-") && len(value) > 1:
			bundle = value[1:]
		case options && index == 0:
			bundle = value
		default:
			members = append(members, arg)
			continue
		}
		for at := 0; at < len(bundle); at++ {
			switch letter := bundle[at]; letter {
			case 'c', 'x', 't':
				mode = letter
			case 'O':
				toStdout = true
			case 'p', 'v', 'z', 'j', 'J', 'h':
			case 'f', 'C':
				if at+1 < len(bundle) {
					// A fused value (-fARCHIVE): the rest of the bundle.
					at = len(bundle)
				} else {
					takesValue++
				}
			default:
				return 0, false, nil, false
			}
		}
	}
	if takesValue > 0 || mode == 0 {
		return 0, false, nil, false
	}
	if mode == 't' || mode == 'x' && !toStdout {
		return mode, toStdout, nil, true
	}
	return mode, toStdout, members, true
}

// registrationReadLoopWords are the words of for NAME in WORD...; do BODY;
// done when every statement of BODY is a reader call with no redirect and
// NAME is expanded nowhere outside BODY (a later rm "$NAME" would write the
// last word).
func registrationReadLoopWords(file *syntax.File, loop *syntax.ForClause, home string) []*syntax.Word {
	iter, ok := loop.Loop.(*syntax.WordIter)
	if !ok || iter.Name == nil || len(loop.Do) == 0 {
		return nil
	}
	for _, stmt := range loop.Do {
		call, isCall := stmt.Cmd.(*syntax.CallExpr)
		if !isCall || len(stmt.Redirs) != 0 || stmt.Background || stmt.Coprocess || stmt.Negated {
			return nil
		}
		alone := &syntax.File{Stmts: []*syntax.Stmt{{Cmd: call}}}
		if !actionKnownReadOnlyShell(alone, home) || !actionReadersAreSystemPrograms(alone, home, 0) {
			return nil
		}
		if program, _ := staticProgramWord(call.Args[0], home); slices.Contains([]string{"cd", "pushd", "popd", "dirs"}, programBase(program)) {
			return nil
		}
	}
	bodyStart, bodyEnd := loop.DoPos.Offset(), loop.DonePos.Offset()
	outside := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if param, ok := node.(*syntax.ParamExp); ok && param.Param != nil && param.Param.Value == iter.Name.Value {
			if at := param.Pos().Offset(); at < bodyStart || at >= bodyEnd {
				outside = true
			}
		}
		return !outside
	})
	if outside {
		return nil
	}
	return iter.Items
}

// registrationFolderDestination reports a cp, mv, install, ln or rsync
// whose destination is a folder that holds a registered file (cp -r
// /tmp/x/.claude ~/): the names it writes are the sources' names, which the
// reader does not follow, so the call is left to the whole-text match.
func registrationFolderDestination(file *syntax.File, cwd, home string, protected protectedFiles) bool {
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if found || !ok || len(call.Args) < 2 {
			return !found
		}
		words, known := actionStaticWords(call.Args, home)
		if !known {
			return true
		}
		for index, word := range words {
			switch programBase(word) {
			case "cp", "gcp", "mv", "gmv", "install", "ginstall", "ln", "gln", "rsync":
			default:
				continue
			}
			var operands []string
			for _, operand := range words[index+1:] {
				if !strings.HasPrefix(operand, "-") {
					operands = append(operands, operand)
				} else if value, ok := strings.CutPrefix(operand, "--target-directory="); ok {
					operands = append(operands, value)
				}
			}
			for _, operand := range operands {
				path := filepath.Clean(OperandPath(strings.TrimSuffix(operand, "/"), cwd))
				prefix := path + string(filepath.Separator)
				if slices.ContainsFunc(protected, func(entry protectedFile) bool { return strings.HasPrefix(entry.path, prefix) }) {
					found = true
				}
			}
		}
		return !found
	})
	return found
}
