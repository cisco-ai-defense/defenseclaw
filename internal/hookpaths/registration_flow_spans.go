// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"mvdan.cc/sh/v3/syntax"
)

// registrationFlowSpans collects the parts of a command where the name of a
// registered file can reach a write (rel-1-0-10:GAP-0104): the words of a
// call that writes or runs text (for cp, install and rsync only the
// destination and option words; for tar only the archive it creates, or
// every word of an extraction onto disk), an output redirect target, a
// variable or loop binding that a later write may expand, a here-document
// fed to a program that writes, and every stage of a pipeline that feeds
// one that reads names or text from its input (xargs, a shell, a while
// read loop). A shell -c body is read the same way; inline interpreter code
// (python -c, python - <<EOF, node -e ...) that writes nothing does not
// count. Reads (sha256sum, stat, cat, cmp, diff, jq), copies out of a file,
// archive listings and extractions to standard output name a file without
// writing it. A command that declares a function or an alias, sets a trap,
// or runs text through eval or source is left whole (blanket): the walk does
// not follow what runs later.
type registrationFlowSpans struct {
	home    string
	depth   int
	bound   map[string]bool
	texts   []string
	words   []string
	blanket bool
}

// registrationReachTexts returns the texts and the static words of command
// in which a mention counts, or blanket when every mention does.
func registrationReachTexts(file *syntax.File, command, home string) (texts, words []string, blanket bool) {
	spans := registrationFlowSpans{home: home, bound: registrationBoundNames(file)}
	spans.statements(command, file.Stmts, false)
	return spans.texts, spans.words, spans.blanket
}

// registrationBoundNames are the variables the command assigns or loops
// over, with HOME, PWD, USER and LOGNAME: a write operand that expands only
// these spells a value the command itself names.
func registrationBoundNames(file *syntax.File) map[string]bool {
	bound := map[string]bool{"HOME": true, "PWD": true, "OLDPWD": true, "USER": true, "LOGNAME": true}
	syntax.Walk(file, func(node syntax.Node) bool {
		switch node := node.(type) {
		case *syntax.Assign:
			if node.Name != nil {
				bound[node.Name.Value] = true
			}
		case *syntax.WordIter:
			if node.Name != nil {
				bound[node.Name.Value] = true
			}
		}
		return true
	})
	return bound
}

// writeTarget adds a write operand. One that expands a value the command
// does not bind (an environment variable, a positional parameter, a command
// substitution) may name any file: every mention counts (find "$root"
// -delete; cat FILE).
func (s *registrationFlowSpans) writeTarget(src string, node syntax.Node) {
	unknown := false
	syntax.Walk(node, func(child syntax.Node) bool {
		switch child := child.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			unknown = true
		case *syntax.ParamExp:
			unknown = unknown || child.Param == nil || !s.bound[child.Param.Value]
		}
		return !unknown
	})
	if unknown {
		s.blanket = true
		return
	}
	s.add(src, node)
}

func (s *registrationFlowSpans) add(src string, node syntax.Node) {
	if node == nil || s.blanket {
		return
	}
	start, end := int(node.Pos().Offset()), int(node.End().Offset())
	if start < 0 || end > len(src) || start >= end {
		s.blanket = true
		return
	}
	s.texts = append(s.texts, src[start:end])
	syntax.Walk(node, func(child syntax.Node) bool {
		if word, ok := child.(*syntax.Word); ok {
			if value, fixed := StaticWord(word, s.home); fixed && value != "" && !strings.HasPrefix(value, "-") {
				s.words = append(s.words, value)
			}
		}
		return true
	})
}

// nested reads the command and process substitutions inside a node that does
// not count by itself (the words of a reader, a test).
func (s *registrationFlowSpans) nested(src string, node syntax.Node) {
	if node == nil {
		return
	}
	syntax.Walk(node, func(child syntax.Node) bool {
		switch child := child.(type) {
		case *syntax.CmdSubst:
			s.statements(src, child.Stmts, false)
			return false
		case *syntax.ProcSubst:
			s.statements(src, child.Stmts, false)
			return false
		}
		return true
	})
}

// statements reads a list; capable reports a part that may write, consumer
// a part that reads names or text from its standard input and may write.
func (s *registrationFlowSpans) statements(src string, stmts []*syntax.Stmt, piped bool) (capable, consumer bool) {
	for _, stmt := range stmts {
		c, k := s.statement(src, stmt, piped)
		capable, consumer = capable || c, consumer || k
	}
	return capable, consumer
}

// statement reads one statement. piped: its output feeds a consumer, so all
// of it counts.
func (s *registrationFlowSpans) statement(src string, stmt *syntax.Stmt, piped bool) (capable, consumer bool) {
	if stmt == nil || s.blanket {
		return false, false
	}
	capable, consumer = s.command(src, stmt, piped)
	for _, redir := range stmt.Redirs {
		switch redir.Op {
		case syntax.RdrOut, syntax.AppOut, syntax.RdrAll, syntax.AppAll, syntax.RdrClob, syntax.RdrInOut:
			if value, fixed := StaticWord(redir.Word, s.home); fixed && value == "/dev/null" {
				continue
			}
			s.writeTarget(src, redir.Word)
			capable = true
		case syntax.DplOut:
			if value, fixed := StaticWord(redir.Word, s.home); fixed && (value == "-" || value != "" && strings.Trim(value, "0123456789") == "") {
				continue
			}
			s.writeTarget(src, redir.Word)
			capable = true
		case syntax.Hdoc, syntax.DashHdoc:
			if consumer {
				s.add(src, redir.Hdoc)
			} else {
				s.nested(src, redir.Hdoc)
			}
		case syntax.WordHdoc:
			if consumer {
				s.add(src, redir.Word)
			} else {
				s.nested(src, redir.Word)
			}
		default:
			s.nested(src, redir.Word)
		}
	}
	if piped {
		s.add(src, stmt)
	}
	return capable, consumer
}

func (s *registrationFlowSpans) command(src string, stmt *syntax.Stmt, piped bool) (capable, consumer bool) {
	switch cmd := stmt.Cmd.(type) {
	case nil:
		return false, false
	case *syntax.CallExpr:
		return s.call(src, stmt, cmd)
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			rightCapable, rightConsumer := s.statement(src, cmd.Y, piped)
			leftCapable, leftConsumer := s.statement(src, cmd.X, piped || rightConsumer)
			return leftCapable || rightCapable, leftConsumer
		}
		leftCapable, leftConsumer := s.statement(src, cmd.X, piped)
		rightCapable, rightConsumer := s.statement(src, cmd.Y, piped)
		return leftCapable || rightCapable, leftConsumer || rightConsumer
	case *syntax.Subshell:
		return s.statements(src, cmd.Stmts, piped)
	case *syntax.Block:
		return s.statements(src, cmd.Stmts, piped)
	case *syntax.IfClause:
		for clause := cmd; clause != nil; clause = clause.Else {
			c, k := s.statements(src, clause.Cond, piped)
			c2, k2 := s.statements(src, clause.Then, piped)
			capable, consumer = capable || c || c2, consumer || k || k2
		}
		return capable, consumer
	case *syntax.WhileClause:
		c, k := s.statements(src, cmd.Cond, piped)
		c2, k2 := s.statements(src, cmd.Do, piped)
		capable = c || c2
		// A loop that writes reads its names from its input (while read f).
		return capable, capable || k || k2
	case *syntax.ForClause:
		capable, consumer = s.statements(src, cmd.Do, piped)
		if iter, ok := cmd.Loop.(*syntax.WordIter); ok {
			for _, item := range iter.Items {
				if capable {
					s.add(src, item)
				} else {
					s.nested(src, item)
				}
			}
		} else {
			s.nested(src, cmd.Loop)
		}
		return capable, consumer
	case *syntax.CaseClause:
		s.nested(src, cmd.Word)
		for _, item := range cmd.Items {
			c, k := s.statements(src, item.Stmts, piped)
			capable, consumer = capable || c, consumer || k
		}
		return capable, consumer
	case *syntax.DeclClause:
		// declare, export, local, readonly, typeset: a binding a later
		// write may expand.
		s.add(src, cmd)
		return false, false
	case *syntax.TimeClause:
		return s.statement(src, cmd.Stmt, piped)
	case *syntax.ArithmCmd, *syntax.LetClause, *syntax.TestClause:
		s.nested(src, cmd)
		return false, false
	default:
		// A function, coproc or construct the walk does not model.
		s.blanket = true
		return true, true
	}
}

// registrationBlanketBuiltins run text or define what runs later.
var registrationBlanketBuiltins = map[string]bool{
	"eval": true, "source": true, ".": true, "alias": true, "trap": true, "enable": true, "shopt": true,
}

// registrationBindingBuiltins bind a name a later word may expand.
var registrationBindingBuiltins = map[string]bool{
	"read": true, "mapfile": true, "readarray": true, "set": true, "getopts": true,
}

// registrationOperandWriters write only their operands, never names read
// from standard input.
var registrationOperandWriters = map[string]bool{
	"tee": true, "sponge": true, "dd": true, "cp": true, "gcp": true, "mv": true, "gmv": true,
	"rm": true, "rmdir": true, "unlink": true, "ln": true, "gln": true, "chmod": true,
	"chown": true, "chgrp": true, "touch": true, "truncate": true, "install": true,
	"shred": true, "setfacl": true, "chattr": true,
}

func (s *registrationFlowSpans) call(src string, stmt *syntax.Stmt, call *syntax.CallExpr) (capable, consumer bool) {
	for _, assign := range call.Assigns {
		s.add(src, assign)
	}
	if len(call.Args) == 0 {
		return false, false
	}
	if first, fixed := StaticWord(call.Args[0], s.home); fixed {
		base := programBase(first)
		if registrationBlanketBuiltins[base] {
			s.blanket = true
			return true, true
		}
		if registrationBindingBuiltins[base] || base == "printf" && registrationCallIsFlow(call, s.home) {
			s.add(src, call)
			return false, base == "read" || base == "mapfile" || base == "readarray"
		}
	}
	words, known := actionLiteralCommandWords(call.Args, s.home)
	if !known {
		// sudo -i / -s run the words through a shell: as words they are
		// the same command.
		words, known = registrationSudoShellWords(call.Args, s.home)
	}
	if known && len(words) > 0 {
		static := make([]string, len(words))
		fixed := make([]bool, len(words))
		for index, word := range words {
			static[index], fixed[index] = StaticWord(word, s.home)
		}
		if fixed[0] {
			program := programBase(static[0])
			if c, k, handled := s.shellBody(src, call, program, words, static, fixed); handled {
				return c, k
			}
			if c, k, handled := s.interpreter(src, stmt, call, program, static, fixed); handled {
				return c, k
			}
			if writes, handled := registrationOperandRoleWrites(program, static, fixed); handled {
				for _, index := range writes {
					s.writeTarget(src, words[index])
				}
				s.nested(src, call)
				return len(writes) > 0, program == "tar" || program == "rsync"
			}
		}
	}
	if registrationEditsInPlace(call, s.home) || registrationCallWrites(call, s.home) {
		s.writeTarget(src, call)
		program := ""
		if known && len(words) > 0 {
			if value, fixed := StaticWord(words[0], s.home); fixed {
				program = programBase(value)
			}
		}
		return true, !registrationOperandWriters[program]
	}
	s.nested(src, call)
	return false, false
}

// shellBody reads sh -c BODY (bash -lc, zsh -c ...) as a command of its own.
// Words after the body other than $0 are arguments the body may expand: they
// count.
func (s *registrationFlowSpans) shellBody(src string, call *syntax.CallExpr, program string, words []*syntax.Word, static []string, fixed []bool) (capable, consumer, handled bool) {
	switch program {
	case "sh", "bash", "dash", "zsh", "ash", "ksh":
	default:
		return false, false, false
	}
	index, ok := shellCommandBodyIndex(static)
	if !ok || !fixed[index] || s.depth >= 4 {
		return false, false, false
	}
	body, parsed := parseShell(static[index])
	if !parsed {
		return false, false, false
	}
	inner := registrationFlowSpans{home: s.home, depth: s.depth + 1, bound: registrationBoundNames(body)}
	for name := range s.bound {
		inner.bound[name] = true
	}
	capable, consumer = inner.statements(static[index], body.Stmts, false)
	if inner.blanket {
		s.add(src, call)
		return true, true, true
	}
	s.texts = append(s.texts, inner.texts...)
	s.words = append(s.words, inner.words...)
	// $0 and the arguments: the body may expand them.
	for _, argument := range words[min(index+1, len(words)):] {
		s.add(src, argument)
	}
	return capable, consumer, true
}

// interpreter judges python with inline code (-c) or a program read from a
// here-document (python3 - <<EOF): code that writes nothing makes the call a
// reader. The judge is an allowlist (actionfacts.PythonCodeOnlyReads): code
// it does not recognise may write. node, perl and ruby, and a script file,
// run code the reader does not see (handled false), as before
// rel-1-0-10:GAP-0104; the deny-list reading of their code was dropped
// (rel-1-0-10:GAP-0244).
func (s *registrationFlowSpans) interpreter(src string, stmt *syntax.Stmt, call *syntax.CallExpr, program string, static []string, fixed []bool) (capable, consumer, handled bool) {
	kind := actionInterpreterKind(program)
	if kind != "python" {
		return false, false, false
	}
	for index := range static {
		if !fixed[index] {
			return false, false, false
		}
	}
	code, inline := actionInterpreterInlineCode(static, 0)
	if !inline {
		if !registrationInterpreterReadsStdin(kind, static) {
			return false, false, false
		}
		var ok bool
		if code, ok = registrationHeredocCode(src, stmt); !ok {
			return false, false, false
		}
	}
	if !actionfacts.PythonCodeOnlyReads(code) {
		s.add(src, call)
		return true, true, true
	}
	return false, false, true
}

// registrationInterpreterReadsStdin reports an interpreter call that names
// no script: its program is its standard input (python3 -, python3 -u).
func registrationInterpreterReadsStdin(kind string, static []string) bool {
	for index := 1; index < len(static); index++ {
		word := static[index]
		switch {
		case word == "-":
			return true
		case word == "--" || !strings.HasPrefix(word, "-") || kind == "python" && word == "-m":
			return false
		case actionInterpreterOptionTakesValue(kind, word):
			index++
		}
	}
	return true
}

// registrationHeredocCode is the program a here-document feeds: its text
// when the delimiter is quoted or the text expands nothing.
func registrationHeredocCode(src string, stmt *syntax.Stmt) (string, bool) {
	for _, redir := range stmt.Redirs {
		if redir.Op != syntax.Hdoc && redir.Op != syntax.DashHdoc || redir.Hdoc == nil {
			continue
		}
		start, end := int(redir.Hdoc.Pos().Offset()), int(redir.Hdoc.End().Offset())
		if start < 0 || end > len(src) || start > end {
			return "", false
		}
		text := src[start:end]
		quoted := false
		for _, part := range redir.Word.Parts {
			switch part.(type) {
			case *syntax.SglQuoted, *syntax.DblQuoted:
				quoted = true
			}
		}
		if !quoted && strings.ContainsAny(text, "$`\\") {
			return "", false
		}
		return text, true
	}
	return "", false
}

// registrationOperandRoleWrites lists the word indexes a copy or archive call
// writes: for cp, install and rsync the destination (the last operand, or
// the -t value) and every option word with the value it takes; for tar the
// archive a create writes, every word of an extraction onto disk, nothing
// for a listing or an extraction to standard output. handled is false for
// any other program, a word the reader cannot spell, or a call it does not
// fully read (mv removes its sources; ln, --remove-source-files and
// --remove-files change them).
func registrationOperandRoleWrites(program string, static []string, fixed []bool) (writes []int, handled bool) {
	switch program {
	case "cp", "gcp", "install", "rsync":
		return registrationCopyWrites(program, static, fixed)
	case "tar", "gtar", "bsdtar":
		return registrationTarWrites(static, fixed)
	}
	return nil, false
}

// registrationCopyValueOptions are the cp, install and rsync options whose
// value is the next word. The names are one text, not one literal each: the
// GAP-0055 sweep reads every option-shaped literal of this package as an
// option of a program branch, and these are not.
var registrationCopyValueOptions = registrationFieldSet("-t -S --target-directory --suffix -m -o -g --mode --owner --group " +
	"-e --rsh -f --filter -T --temp-dir -B --block-size --rsync-path --exclude --include --exclude-from --include-from " +
	"--files-from --compare-dest --copy-dest --link-dest --backup-dir --chmod --chown --log-file --password-file " +
	"--partial-dir --max-size --min-size --bwlimit --timeout --port --out-format --info --debug --max-delete " +
	"--modify-window --compress-level --skip-compress --usermap --groupmap --iconv --contimeout --address")

// registrationTarLongModes are the tar long options that set the mode, by
// the letter of that mode; registrationTarLongValues take the next word;
// registrationTarLongUnread change files the reader does not follow (append,
// update, remove the sources, run a command).
var (
	registrationTarLongModes  = map[string]byte{}
	registrationTarLongStdout = registrationFieldSet("--to-stdout")
	registrationTarLongValues = registrationFieldSet("--directory --exclude --files-from --transform --owner --group " +
		"--mode --mtime --format --use-compress-program")
	registrationTarLongUnread = registrationFieldSet("--remove-files --append --update --delete --concatenate --catenate " +
		"--to-command --checkpoint-action --info-script --new-volume-script --rsh-command --rmt-command")
)

func init() {
	for _, pair := range strings.Fields("create:c extract:x get:x list:t diff:d compare:d") {
		name, letter, _ := strings.Cut(pair, ":")
		registrationTarLongModes["--"+name] = letter[0]
	}
}

// registrationFieldSet is the set of the space-separated names in text.
func registrationFieldSet(text string) map[string]bool {
	set := map[string]bool{}
	for _, name := range strings.Fields(text) {
		set[name] = true
	}
	return set
}

func registrationCopyWrites(program string, static []string, fixed []bool) ([]int, bool) {
	var writes, operands []int
	targetGiven := false
	options := true
	for index := 1; index < len(static); index++ {
		if !fixed[index] {
			return nil, false
		}
		word := static[index]
		switch {
		case options && word == "--":
			options = false
		case options && strings.HasPrefix(word, "-") && word != "-":
			if word == "--remove-source-files" || program == "install" && (word == "-d" || word == "--directory") {
				return nil, false
			}
			writes = append(writes, index)
			name, _, attached := strings.Cut(word, "=")
			if name == "--target-directory" || name == "-t" || strings.HasPrefix(word, "-t") && !strings.HasPrefix(word, "--") {
				targetGiven = true
			}
			if !attached && registrationCopyValueOptions[name] && index+1 < len(static) {
				index++
				writes = append(writes, index)
			}
		default:
			operands = append(operands, index)
		}
	}
	if !targetGiven && len(operands) > 0 {
		writes = append(writes, operands[len(operands)-1])
	}
	return writes, true
}

// registrationTarWrites reads the tar mode (the first word's letters, or a
// dash cluster, or a long mode) and the archive word.
func registrationTarWrites(static []string, fixed []bool) ([]int, bool) {
	mode, stdout := byte(0), false
	archive := -1
	// pending are the value letters of the clusters read so far, in order:
	// each takes the next word that is not an option (only f is the archive).
	var pending []byte
	setMode := func(letter byte) bool {
		if mode != 0 && mode != letter {
			return false
		}
		mode = letter
		return true
	}
	for index := 1; index < len(static); index++ {
		word := static[index]
		if !fixed[index] && len(pending) == 0 {
			// Only a value position (the archive of -cpf "$s/x.tar") may be
			// spelled at run time: elsewhere the word could be an option.
			return nil, false
		}
		if len(pending) > 0 && (!fixed[index] || !strings.HasPrefix(word, "-")) {
			if pending[0] == 'f' && archive < 0 {
				archive = index
			}
			pending = pending[1:]
			continue
		}
		switch {
		case strings.HasPrefix(word, "--"):
			name, _, attached := strings.Cut(word, "=")
			switch letter, isMode := registrationTarLongModes[name]; {
			case isMode:
				if !setMode(letter) {
					return nil, false
				}
			case registrationTarLongStdout[name]:
				stdout = true
			case name == "--file":
				if attached {
					archive = index
				} else if index+1 < len(static) {
					index++
					archive = index
				}
			case registrationTarLongValues[name]:
				if !attached {
					index++
				}
			case registrationTarLongUnread[name]:
				return nil, false
			}
		case index == 1 && !strings.HasPrefix(word, "-") || strings.HasPrefix(word, "-") && len(word) > 1:
			dashed := strings.HasPrefix(word, "-")
			letters := strings.TrimPrefix(word, "-")
			for at := 0; at < len(letters); at++ {
				switch letter := letters[at]; letter {
				case 'c', 'x', 't', 'd':
					if !setMode(letter) {
						return nil, false
					}
				case 'r', 'u', 'A':
					return nil, false
				case 'O':
					stdout = true
				case 'f', 'C', 'T', 'X', 'b', 'H', 'I', 'K', 'L', 'N', 'V', 'g':
					if dashed && at+1 < len(letters) {
						// -fARCHIVE, -C/dir: the rest of the word is the value.
						if letter == 'f' {
							archive = index
						}
						at = len(letters)
						continue
					}
					pending = append(pending, letter)
				}
			}
		}
	}
	switch {
	case mode == 't' || mode == 'd' || mode == 'x' && stdout:
		return nil, true
	case mode == 'c' && archive >= 0:
		return []int{archive}, true
	case mode == 'c' && !slices.Contains(pending, 'f'):
		// The archive goes to standard output (or $TAPE).
		return nil, true
	}
	return nil, false
}

// registrationSudoShellWords returns the command words of sudo (or doas)
// with -i or -s, after its options: sudo runs them through the target
// user's shell, which reads them as the same command. ok is false for any
// other call or an option the reader does not know.
func registrationSudoShellWords(args []*syntax.Word, home string) ([]*syntax.Word, bool) {
	if len(args) < 2 {
		return nil, false
	}
	program, fixed := StaticWord(args[0], home)
	if !fixed || programBase(program) != "sudo" && programBase(program) != "doas" {
		return nil, false
	}
	shell := false
	for index := 1; index < len(args); index++ {
		word, fixed := StaticWord(args[index], home)
		if !fixed {
			return nil, false
		}
		if word == "--" {
			index++
			if index >= len(args) || !shell {
				return nil, false
			}
			return args[index:], true
		}
		if !strings.HasPrefix(word, "-") || word == "-" {
			if !shell {
				return nil, false
			}
			return args[index:], true
		}
		if strings.HasPrefix(word, "--") {
			name, _, attached := strings.Cut(word, "=")
			switch name {
			case "--login", "--shell":
				shell = true
			case "--non-interactive", "--preserve-env", "--set-home", "--reset-timestamp", "--stdin":
			case "--user", "--group", "--host", "--prompt", "--role", "--type", "--close-from", "--chdir":
				if !attached {
					index++
				}
			default:
				return nil, false
			}
			continue
		}
		for at := 1; at < len(word); at++ {
			switch letter := word[at]; letter {
			case 'i', 's':
				shell = true
			case 'n', 'H', 'E', 'k', 'K', 'P', 'S', 'b', 'A':
			case 'u', 'g', 'C', 'h', 'p', 'r', 't', 'T', 'U', 'D':
				if at+1 == len(word) {
					index++
				}
				at = len(word)
			default:
				return nil, false
			}
		}
	}
	return nil, false
}
