// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"runtime"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// maxHereStringTwinBytes bounds the command text read for a here-string twin.
const maxHereStringTwinBytes = 16 << 10

// hereStringStateMutation judges a bash here-string (GAP-2047 row a:
// `xargs rm -rf <<< ~/.defenseclaw/installer`). ActionFacts parses POSIX sh,
// where `<<<` is a syntax error, so the whole action had no facts and ran in
// every mode. The here-string word gets the expansions of an argument (tilde
// included) and reaches the command as one line on stdin, so the action is
// judged as its POSIX twin `printf '%s\n' WORD | CMD`: a literal spelling of
// a state write blocks, and reads and project forms (`xargs cat <<< ...`,
// `xargs rm -f <<< build/a.o`) stay allowed, as they do in the twin.
func hereStringStateMutation(facts actionfacts.Facts, request trustedActionRequest) (mutates, judged bool) {
	if request.hereStringTwinsJudged || facts.Parse.Status != actionfacts.StatusInvalid || !hereStringTwinHome(facts.ActiveHome) {
		return false, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || len(command) > maxHereStringTwinBytes || !strings.Contains(command, "<<<") {
		return false, false
	}
	// The twins are judged by the whole dispatcher, the way their POSIX
	// spelling is judged when typed; they hold no here-string. The split
	// twin is what xargs makes of a fixed word (pod check30), the word twin
	// keeps the word whole; both are judged.
	// A read that binds in some calls of its function and not in others
	// (f; read() { :; }; f) has a reading for each call, and one rewritten
	// text holds one. The twin keeps the reading of the calls that bind: it
	// names the word the read gives, as the first call does, and the command
	// blocks when it reaches state. The calls that do not bind keep the value
	// they had, which no one text can say, so such a command is never judged
	// here (mixed): the walk of its calls, each with its own state, judges it.
	request.skipRunTimeShellTwin = true
	seen := map[string]bool{}
	request.hereStringPipeReading = true
	for _, split := range []bool{true, false} {
		twin, ok, mixed := hereStringPipeTwin(command, facts.ActiveHome, split, request.Input.LoopBindsStraightLine)
		if !ok || seen[twin] {
			continue
		}
		seen[twin] = true
		twinMutates, twinJudged := stateTwinMutates(request, twin)
		if twinMutates {
			return true, true
		}
		judged = judged || twinJudged && !mixed
	}
	return false, judged
}

// hereStringTwinHome reports a home the here-string twins are judged
// under: a POSIX home, and on Windows a drive home (C:\Users\x). Git Bash
// runs the Bash tool there and reads <<< as bash does, and the twin is
// judged by the whole dispatcher with its Windows readings. Without it a
// here-string read of state (cat <<< ~/.defenseclaw/config.yaml) named
// tamper.detector_state_write on Windows only (rel-1-0-10:GAP-0376).
func hereStringTwinHome(home string) bool {
	return strings.HasPrefix(home, "/") || runtime.GOOS == "windows" && actionfacts.DriveLetterPath(home)
}

// hereStringReadingTwinRequest is the reading twin of a bash call with a
// here-string the POSIX analysis cannot parse: the call with every
// CMD <<< WORD written as printf '%s\n' WORD | CMD (hereStringPipeTwin, the
// word kept whole). None for a call of another shape, a twin, a simple
// command of a call (the call itself is judged so), a read whose binding
// differs between its calls, or a twin that does not parse either.
func hereStringReadingTwinRequest(request trustedActionRequest, facts actionfacts.Facts) (trustedActionRequest, bool) {
	if request.readingTwin || request.hereStringTwinsJudged || request.simpleCommandPass || facts.Parse.Status != actionfacts.StatusInvalid {
		return trustedActionRequest{}, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || len(command) > maxHereStringTwinBytes || !strings.Contains(command, "<<<") {
		return trustedActionRequest{}, false
	}
	text, ok, mixed := hereStringPipeTwin(command, facts.ActiveHome, false, request.Input.LoopBindsStraightLine)
	if !ok || mixed || hereStringTwinPipesIntoReader(text) {
		return trustedActionRequest{}, false
	}
	twin := windowsReadingTwin(request)
	twin.Input.Tool, twin.Input.Command, twin.Input.Argv = "Bash", text, nil
	twin.Input.Args = nil
	if len(bytes.TrimSpace(request.Input.Args)) != 0 {
		// The rules that read the tool input read the twin's command there,
		// as the call carries its own.
		raw, err := json.Marshal(map[string]string{"command": text})
		if err != nil {
			return trustedActionRequest{}, false
		}
		twin.Input.Command, twin.Input.Args = "", raw
	}
	if actionfacts.Analyze(twin.Input).Parse.Status == actionfacts.StatusInvalid {
		return trustedActionRequest{}, false
	}
	twin.LegacyText = text
	twin.conflictSource = nil
	return twin, true
}

// hereStringTwinPipesIntoReader reports a twin with a pipe into read,
// mapfile or readarray. In a pipe the builtin binds its names in a subshell,
// so the twin reads them with the values they had before, where the
// here-string binds them in the shell itself (a read whose binding the walk
// could not prove stays a pipe in hereStringPipeTwin). Such a twin is no
// reading of the call: u=$USER; command echo IFS=x; read u <<< w; ... $u
// read $u as the login and blocked an ordinary write (rel-1-0-10:GAP-1083).
func hereStringTwinPipesIntoReader(text string) bool {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(text), "")
	if err != nil {
		return true
	}
	found := false
	syntax.Walk(file, func(node syntax.Node) bool {
		if found {
			return false
		}
		pipe, ok := node.(*syntax.BinaryCmd)
		if !ok || pipe.Op != syntax.Pipe && pipe.Op != syntax.PipeAll || pipe.Y == nil {
			return true
		}
		if call, ok := pipe.Y.Cmd.(*syntax.CallExpr); ok && len(call.Args) != 0 {
			switch call.Args[0].Lit() {
			case "read", "mapfile", "readarray":
				found = true
			}
		}
		return !found
	})
	return found
}

// hereStringPipeTwin rewrites every `CMD <<< WORD` statement of a bash
// command as `printf '%s\n' WORD | CMD`, keeping CMD's other redirections.
// With split, an xargs reader of a fixed word is judged as the call it
// makes with the word's line split the way xargs splits it
// (xargsStaticCallTwin). straight is Input.LoopBindsStraightLine: it tells which
// read name <<< word statements bind their word. A read that binds in some
// calls of its function only is the assignment name=word, the reading of the
// calls that bind, and the command is reported as mixed.
func hereStringPipeTwin(command, home string, split, straight bool) (string, bool, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return "", false, false
	}
	changed, refused, mixed, homeFixed := false, false, false, split && xargsHomeFixed(command)
	// read name <<< word sets name in this shell: its twin is the assignment
	// name=word, which the pipe twin would lose (the reader of a pipe is a
	// subshell). The default IFS and the builtin are needed for that.
	readBinds := actionfacts.ReadBindsHereString(file, straight)
	syntax.Walk(file, func(node syntax.Node) bool {
		stmt, ok := node.(*syntax.Stmt)
		if !ok || refused {
			return !refused
		}
		var word *syntax.Word
		rest := make([]*syntax.Redirect, 0, len(stmt.Redirs))
		for _, redirect := range stmt.Redirs {
			if redirect.Op != syntax.WordHdoc {
				rest = append(rest, redirect)
				continue
			}
			if word != nil || redirect.N != nil || redirect.Word == nil {
				refused = true
				return false
			}
			word = redirect.Word
		}
		if word == nil {
			return true
		}
		if stmt.Cmd == nil {
			refused = true
			return false
		}
		// A folder move reads no stdin and runs in the shell itself, where a
		// pipe would run it in a copy: the twin drops the word, so the
		// statements after it are read in the folder it moves to
		// (rel-1-0-10:GAP-1083).
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok && len(call.Args) != 0 {
			switch call.Args[0].Lit() {
			case "cd", "chdir", "pushd", "popd":
				stmt.Redirs, changed = rest, true
				return true
			}
		}
		// xargs runs its program with the here-string word as arguments:
		// judge that call itself (`xargs rm -rf <<< X` is `rm -rf X`).
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if value, static := xargsStaticValue(word, home); homeFixed && static {
				if direct, ok := xargsStaticCallTwin(call, value+"\n", home); ok {
					stmt.Cmd, stmt.Redirs, changed = direct, rest, true
					return true
				}
			}
			if direct, ok := xargsCallTwin(call, []*syntax.Word{word}); ok {
				stmt.Cmd, stmt.Redirs, changed = direct, rest, true
				return true
			}
		}
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if name, value, ok := actionfacts.HereStringRead(call, word); ok {
				all, some := readBinds(call)
				if all || some {
					mixed = mixed || !all
					stmt.Cmd, stmt.Redirs, changed = &syntax.CallExpr{Assigns: []*syntax.Assign{{
						Name:  &syntax.Lit{Value: name},
						Value: &syntax.Word{Parts: []syntax.WordPart{&syntax.Lit{Value: value}}},
					}}}, rest, true
					return true
				}
			}
		}
		printf := &syntax.Stmt{Cmd: &syntax.CallExpr{Args: []*syntax.Word{
			{Parts: []syntax.WordPart{&syntax.Lit{Value: "printf"}}},
			{Parts: []syntax.WordPart{&syntax.SglQuoted{Value: `%s\n`}}},
			word,
		}}}
		reader := &syntax.Stmt{Cmd: stmt.Cmd, Redirs: rest}
		stmt.Cmd = &syntax.BinaryCmd{Op: syntax.Pipe, X: printf, Y: reader}
		stmt.Redirs = nil
		changed = true
		return true
	})
	if refused || !changed {
		return "", false, false
	}
	var out strings.Builder
	if err := syntax.NewPrinter().Print(&out, file); err != nil {
		return "", false, false
	}
	return out.String(), true, mixed
}

// xargsCallTwin is what `xargs [-r] [-t] [-0] [-d D] [-n N] [-P N] [-I R]
// PROG ARGS...` runs with the static input items words: PROG ARGS...
// WORDS, or with -I R one PROG call per item with every argument spelled R
// replaced by it. -0 and -d change only how the input splits, and each item
// here is one shell word, so they give the same twin (rel-1-0-5 GAP-0052:
// `xargs -0 rm -rf <<< ~/.defenseclaw/hooks`). Other options (-a, -L, -E,
// -s, ...) give no twin.
func xargsCallTwin(call *syntax.CallExpr, words []*syntax.Word) (syntax.Command, bool) {
	if len(call.Assigns) != 0 || len(call.Args) < 2 || call.Args[0].Lit() != "xargs" || len(words) == 0 {
		return nil, false
	}
	replace := ""
	index := 1
	for ; index < len(call.Args); index++ {
		option := call.Args[index].Lit()
		switch {
		case option == "":
			return nil, false
		case option == "--":
			index++
		case option == "-r" || option == "-t" || option == "--no-run-if-empty" || option == "--verbose" ||
			option == "-0" || option == "--null":
			continue
		case option == "-n" || option == "-P" || option == "-I" || option == "-d" || option == "--delimiter":
			if index+1 >= len(call.Args) || option != "-d" && option != "--delimiter" && call.Args[index+1].Lit() == "" {
				return nil, false
			}
			index++
			if option == "-I" {
				replace = call.Args[index].Lit()
			}
			continue
		case strings.HasPrefix(option, "-I") && len(option) > 2:
			replace = option[2:]
			continue
		case strings.HasPrefix(option, "-n") && len(option) > 2, strings.HasPrefix(option, "-P") && len(option) > 2,
			strings.HasPrefix(option, "-d") && len(option) > 2, strings.HasPrefix(option, "--delimiter="):
			continue
		case strings.HasPrefix(option, "-"):
			return nil, false
		}
		break
	}
	if index >= len(call.Args) {
		return nil, false
	}
	if replace == "" {
		args := append(append(make([]*syntax.Word, 0, len(call.Args)-index+len(words)), call.Args[index:]...), words...)
		return &syntax.CallExpr{Args: args}, true
	}
	calls := make([]*syntax.Stmt, 0, len(words))
	for _, word := range words {
		args := make([]*syntax.Word, 0, len(call.Args)-index)
		replaced := false
		for _, arg := range call.Args[index:] {
			if arg.Lit() == replace {
				args = append(args, word)
				replaced = true
				continue
			}
			if strings.Contains(arg.Lit(), replace) {
				return nil, false
			}
			args = append(args, arg)
		}
		if !replaced {
			return nil, false
		}
		calls = append(calls, &syntax.Stmt{Cmd: &syntax.CallExpr{Args: args}})
	}
	if len(calls) == 1 {
		return calls[0].Cmd, true
	}
	return &syntax.Block{Stmts: calls}, true
}
