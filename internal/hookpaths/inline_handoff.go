// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"mvdan.cc/sh/v3/syntax"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// inlineInterpreterNames are the substrings a command holds when it can run
// an inline-code interpreter (actionfacts.InlineCodeHandoff).
var inlineInterpreterNames = tminTable(tminInterpreters)

// InlineMaxShellDepth bounds how many nested shell -c bodies (and launcher
// bodies: su -c, script -c, ssh) the hand-off reader opens. A body past it
// is TRUNCATED, never read as allowed (bound rule, cap depth).
const InlineMaxShellDepth = 8

// inlineHandedWords returns the words of a call that follow the code of an
// inline-code interpreter child (python -c CODE ARG...): the words it is
// handed, fixed or not, and whether a runner (xargs, parallel) feeds it more
// at run time (actionfacts.InlineCodeHandoff is the one rule). handsIn is
// false for a call that is no such child, or whose code is proven read-only.
func inlineHandedWords(words []*syntax.Word, home string) (handed []*syntax.Word, fed, handsIn bool) {
	handed, fed, _, handsIn = inlineHandedWordsAs(words, home)
	return handed, fed, handsIn
}

// inlineHandedWordsAs is inlineHandedWords with the access of the code.
func inlineHandedWordsAs(words []*syntax.Word, home string) (handed []*syntax.Word, fed bool, access actionfacts.InlineAccess, handsIn bool) {
	static := make([]string, len(words))
	for i, word := range words {
		value, fixed := StaticWord(word, home)
		if !fixed {
			value = "$"
		}
		static[i] = value
	}
	handoff := actionfacts.InlineCodeHandoff(static)
	if handoff.From < 0 {
		return nil, false, 0, false
	}
	handed = words[handoff.From:]
	if handoff.CodeUnseen {
		// Code read from stdin and a variable the words do not bind
		// (python3 - "$out" <<EOF): the word names no path of its own.
		handed = slices.DeleteFunc(slices.Clone(handed), func(word *syntax.Word) bool {
			_, fixed := StaticWord(word, home)
			return !fixed
		})
	}
	return handed, handoff.Fed, handoff.Access, true
}

// InlineHandedPath is one word a call hands to inline code.
type InlineHandedPath struct {
	// Path is the absolute path of a fixed word; "" for a word only a runner
	// knows ("$f" of a while read or xargs loop) or that expands (a glob or a
	// brace list).
	Path string
	// Dynamic is set for such a word: it names the protected file only if the
	// command text names it.
	Dynamic bool
	// Access is what the code does with it (never actionfacts.InlineReads: the
	// hand-off of code proven read-only is not reported).
	Access actionfacts.InlineAccess
}

// InlineHandedPaths returns the words a command hands to an inline-code
// interpreter child as arguments (python -c CODE PATH): each fixed path is a
// path the code may write, since no reader proves the code read-only
// (rel-1-0-10:GAP-0365). The words are read with the values the command
// binds before the call (a variable-bound target), through shell -c bodies,
// launcher bodies (su -c, script -c, ssh), find -exec children, and a
// wrapper chain; a word with no fixed value is Dynamic. The caps are what
// the reading left unread: a wrapper or runner chain longer than
// actionfacts.InlineChainRounds, shell bodies nested deeper than
// InlineMaxShellDepth (the bound rule: the call is at least the unknown tier).
func InlineHandedPaths(command, cwd, home string) ([]InlineHandedPath, bounded.CapSet) {
	if !filepath.IsAbs(cwd) || !containsAny(command, inlineInterpreterNames) {
		return nil, bounded.CapSet{}
	}
	file, ok := parseShell(command)
	if !ok {
		return nil, bounded.CapSet{}
	}
	var trunc bounded.Truncated
	reading := &inlineReading{cwd: cwd, home: home, trunc: &trunc}
	reading.file(file, 0)
	// A relative word is read in the folder a cd of the list leads to.
	if strings.Contains(command, "cd") || strings.Contains(command, "pushd") {
		if statements, placed := TopLevelStatements(command, cwd, home); placed && len(statements) > 1 {
			for _, statement := range statements {
				more, caps := InlineHandedPaths(statement.Command, statement.Dir, home)
				reading.paths = append(reading.paths, more...)
				trunc.Merge(caps)
			}
		}
	}
	return reading.paths, trunc.Set()
}

// InlineHandsDynamic reports a hand-off of a word only a runner knows.
func InlineHandsDynamic(paths []InlineHandedPath) bool {
	return slices.ContainsFunc(paths, func(p InlineHandedPath) bool { return p.Dynamic })
}

// inlineShells are the shells whose -c body is read as a command of its own.
var inlineShells = []string{"sh", "bash", "dash", "ash", "zsh", "ksh"}

// CommandMentionsPath reports a command that spells the path as a whole path
// (with ~ and $HOME read as home), for a hand-off whose word only a runner
// knows.
func CommandMentionsPath(command, home, name string) bool {
	return registrationMentions(registrationHomeText(command, home), name, false)
}

// inlineWordValue is the text of a word: its static spelling, else the value
// the command binds, else "$" (a word only the runner knows).
func inlineWordValue(word *syntax.Word, values actionValues, cwd, home string) string {
	if value, fixed := StaticWord(word, home); fixed {
		return value
	}
	if value, fixed := actionWordValue(word, values, cwd, home); fixed {
		return value
	}
	return "$"
}

func containsAny(text string, names []string) bool {
	for _, name := range names {
		if strings.Contains(text, name) {
			return true
		}
	}
	return false
}

// inlineReading is one hand-off reading of a command.
type inlineReading struct {
	cwd, home string
	paths     []InlineHandedPath
	trunc     *bounded.Truncated
}

func (r *inlineReading) file(file *syntax.File, depth int) {
	values := actionValues{"HOME": r.home, "PWD": r.cwd}
	for _, top := range file.Stmts {
		syntax.Walk(top, func(node syntax.Node) bool {
			call, ok := node.(*syntax.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			words := make([]string, len(call.Args))
			for i, arg := range call.Args {
				words[i] = inlineWordValue(arg, values, r.cwd, r.home)
			}
			var assigned []string
			for _, assign := range call.Assigns {
				if assign.Value == nil || assign.Name == nil {
					continue
				}
				if value := inlineWordValue(assign.Value, values, r.cwd, r.home); value != "$" {
					assigned = append(assigned, value)
				}
			}
			r.call(words, assigned, depth)
			return true
		})
		actionUpdateValues(top, values, r.cwd, r.home)
	}
}

// call reads one call: a shell or launcher body opens, a find -exec child
// is read as a call of its own, and an inline interpreter child hands its
// words. assigned are the values of the assignments in front of the call
// (NAME=VALUE python3 -c CODE): code reads them from its environment.
func (r *inlineReading) call(words, assigned []string, depth int) {
	child, _, caps := actionfacts.InlineChild(words)
	r.trunc.Merge(caps)
	if len(child) > 0 {
		if programBase(child[0]) == "ssh" {
			if rest := sshCommandWords(child); len(rest) > 0 {
				r.call(rest, assigned, depth)
			}
		}
		if body, ok := launcherBody(child); ok {
			if !r.trunc.Within(bounded.Depth, depth+1, InlineMaxShellDepth) {
				return
			}
			if inner, parsed := parseShell(body); parsed {
				r.file(inner, depth+1)
			}
			return
		}
		if rest, ok := inlineLauncherChild(child); ok {
			r.call(rest, assigned, depth)
			return
		}
		if programBase(child[0]) == "find" {
			for _, exec := range findExecChildren(child) {
				r.call(exec, nil, depth)
			}
			return
		}
	}
	handoff := actionfacts.InlineCodeHandoff(words)
	r.trunc.Merge(handoff.Caps)
	if handoff.From < 0 {
		return
	}
	add := func(path string, dynamic bool) {
		r.paths = append(r.paths, InlineHandedPath{Path: path, Dynamic: dynamic, Access: handoff.Access})
	}
	if handoff.Fed {
		add("", true)
	}
	// A file the code itself opens for writing (open(PATH, 'a'),
	// writeFileSync(PATH, ...)) is a path it writes, read by the interpreter
	// literal reader the hook client lists its write targets with: python3 -c
	// "open('<home>/.defenseclaw/config.yaml','a').write(x)" handed no word
	// and was allowed in every pack (rel-1-0-10:GAP-1134).
	if handoff.Access == actionfacts.InlineWrites {
		for _, target := range literalInterpreterWrites(handoff.Code, handoff.Language, r.cwd, r.home) {
			add(OperandPath(target, r.cwd), false)
		}
	}
	for _, word := range assigned {
		if actionfacts.InlineHandedWordIsPath(word) {
			add(r.abs(word), false)
		}
	}
	// A word before the interpreter that binds a name (env NAME=VALUE): the
	// code reads it from its environment.
	for _, word := range words[:handoff.From] {
		if value, ok := inlineAssignedPath(word); ok {
			add(r.abs(value), false)
		}
	}
	for _, word := range words[handoff.From:] {
		switch {
		case word == "$" && handoff.CodeUnseen:
			// Code read from stdin and a variable the words do not bind
			// (python3 - "$out" <<EOF): no fixed path, and the code is not in the
			// words: owner traces run such scripts on their own files all day.
		case word == "$" || strings.Contains(word, "{}") || strings.ContainsAny(word, "*?[") || strings.Contains(word, "{") && strings.Contains(word, ","):
			add("", true) // a runner, a glob or a brace list: the value is not in the words
		default:
			if value, ok := inlineAssignedPath(word); ok {
				add(r.abs(value), false) // out=PATH: the code splits it
			} else if actionfacts.InlineHandedWordIsPath(word) {
				add(r.abs(word), false)
			}
		}
	}
}

// abs places a handed word: ~/ is the home (a word the shell leaves alone
// after an = still names it to the code), a relative word is in the folder
// the call runs in.
func (r *inlineReading) abs(word string) string {
	if rest, ok := strings.CutPrefix(word, "~/"); ok && r.home != "" {
		return filepath.Join(r.home, rest)
	}
	return OperandPath(word, r.cwd)
}

// inlineAssignedPath is the path of a NAME=PATH word (env NAME=VALUE, or a
// handed word code splits at the =), when the value can be one path.
func inlineAssignedPath(word string) (string, bool) {
	name, value, ok := strings.Cut(word, "=")
	if !ok || name == "" || value == "" || strings.ContainsAny(name, "/~.-:") || !actionfacts.InlineHandedWordIsPath(value) ||
		!strings.ContainsAny(value, "/~") {
		return "", false // a value with no slash or tilde (A=1, mode=r) names no path
	}
	for _, letter := range name {
		if letter != '_' && (letter < 'a' || letter > 'z') && (letter < 'A' || letter > 'Z') && (letter < '0' || letter > '9') {
			return "", false
		}
	}
	return value, true
}

// launcherBody returns the shell text a call runs: the -c body of a shell, the
// command of su -c and script -c, the remote command of ssh.
func launcherBody(child []string) (string, bool) {
	program := programBase(child[0])
	if slices.Contains(inlineShells, program) {
		if body, shell := shellCommandBodyIndex(child); shell && child[body] != "$" {
			return child[body], true
		}
		return "", false
	}
	switch program {
	case "su", "script":
		for i := 1; i+1 < len(child); i++ {
			if child[i] == "--command" || strings.HasPrefix(child[i], "-") && !strings.HasPrefix(child[i], "--") && strings.HasSuffix(child[i], "c") {
				return child[i+1], child[i+1] != "$"
			}
			if value, ok := strings.CutPrefix(child[i], tminTable(tminCommandEquals)[0]); ok {
				return value, value != "$"
			}
		}
	case "ssh":
		return inlineSSHCommand(child)
	}
	return "", false
}

// sshCommandWords are the words after the host of an ssh call, as one local
// call would carry them: the remote shell joins them with spaces, and a
// reading that stops at the joined text would lose their quoting.
func sshCommandWords(child []string) []string {
	if _, ok := inlineSSHCommand(child); !ok {
		return nil
	}
	valued := tminTable(tminSSHValueLetters)[0]
	for i := 1; i < len(child); i++ {
		word := child[i]
		switch {
		case word == "--":
			if i+2 < len(child) {
				return child[i+2:]
			}
			return nil
		case len(word) == 2 && word[0] == '-' && strings.IndexByte(valued, word[1]) >= 0:
			i++
		case strings.HasPrefix(word, "-"):
		default:
			return child[i+1:]
		}
	}
	return nil
}

// inlineSSHCommand is the command words after the host of an ssh call,
// joined as the remote shell reads them.
func inlineSSHCommand(child []string) (string, bool) {
	valued := tminTable(tminSSHValueLetters)[0]
	for i := 1; i < len(child); i++ {
		word := child[i]
		switch {
		case word == "--":
			if i+2 < len(child) {
				return strings.Join(child[i+2:], " "), true
			}
			return "", false
		case len(word) == 2 && word[0] == '-' && strings.IndexByte(valued, word[1]) >= 0:
			i++
		case strings.HasPrefix(word, "-"):
		default:
			if i+1 < len(child) {
				return strings.Join(child[i+1:], " "), true
			}
			return "", false
		}
	}
	return "", false
}

// inlineLauncherChild is the command a package or task launcher runs
// (uv run, poetry run, pipenv run, conda run, pdm run, rye run, watch): it
// runs its words as a program and hands the child the same words, so the
// reading continues at the first word that names an inline interpreter.
func inlineLauncherChild(child []string) ([]string, bool) {
	switch programBase(child[0]) {
	case tminTable(tminLaunchers)[0], tminTable(tminLaunchers)[1], tminTable(tminLaunchers)[2], tminTable(tminLaunchers)[3],
		tminTable(tminLaunchers)[4], tminTable(tminLaunchers)[5]:
		if len(child) < 3 || child[1] != tminTable(tminLauncherRun)[0] {
			return nil, false
		}
	case "watch":
	default:
		return nil, false
	}
	for index, word := range child[1:] {
		if actionfacts.InlineProgramHandsWords(programBase(word)) {
			return child[1+index:], true
		}
	}
	return nil, false
}

// findExecChildren lists the programs a find argv runs with -exec,
// -execdir, -ok and -okdir, each as its words up to the ; or + that ends it.
func findExecChildren(argv []string) [][]string {
	var children [][]string
	for i := 1; i+1 < len(argv); i++ {
		switch argv[i] {
		case "-exec", "-execdir", "-ok", "-okdir":
		default:
			continue
		}
		end := i + 1
		for end < len(argv) && argv[end] != ";" && argv[end] != "+" {
			end++
		}
		if end > i+1 {
			children = append(children, argv[i+1:end])
		}
		i = end
	}
	return children
}

// FindExecChildCommands lists the programs the find calls of a command run
// with -exec, -execdir, -ok and -okdir, each as a shell command of its own:
// the words of the child, a word that holds the handed entry ({}) put as a
// plain file name of the working folder, shell-quoted. A child with a word
// only a runner knows is left out. Judged as a call of its own, the child
// reaches what it names itself exactly as it would run directly
// (rel-1-0-10:GAP-0501, GAP-0660).
func FindExecChildCommands(command, cwd, home string) []string {
	if !filepath.IsAbs(cwd) || !strings.Contains(command, "find") {
		return nil
	}
	file, ok := parseShell(command)
	if !ok {
		return nil
	}
	var out []string
	syntax.Walk(file, func(node syntax.Node) bool {
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 4 {
			return true
		}
		words := make([]string, len(call.Args))
		for i, arg := range call.Args {
			value, fixed := StaticWord(arg, home)
			if !fixed {
				value = "$"
			}
			words[i] = value
		}
		child, _, _ := actionfacts.InlineChild(words)
		if len(child) < 4 || programBase(child[0]) != "find" {
			return true
		}
		for _, exec := range findExecChildren(child) {
			if slices.Contains(exec, "$") {
				continue
			}
			quoted := make([]string, len(exec))
			for i, word := range exec {
				word = strings.ReplaceAll(word, "{}", tminTable(tminFindEntry)[0])
				quoted[i] = "'" + strings.ReplaceAll(word, "'", `'\''`) + "'"
			}
			out = append(out, strings.Join(quoted, " "))
		}
		return true
	})
	return out
}
