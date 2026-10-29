// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
	if facts.Parse.Status != actionfacts.StatusInvalid || !strings.HasPrefix(facts.ActiveHome, "/") {
		return false, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || len(command) > maxHereStringTwinBytes || !strings.Contains(command, "<<<") {
		return false, false
	}
	twin, ok := hereStringPipeTwin(command)
	if !ok {
		return false, false
	}
	twinRequest := request
	twinRequest.Input.Tool, twinRequest.Input.Command = "Bash", twin
	twinRequest.Input.Args, twinRequest.Input.Argv = nil, nil
	if actionfacts.Analyze(twinRequest.Input).Parse.Status == actionfacts.StatusInvalid {
		return false, false
	}
	// The twin is judged by the whole dispatcher, the way its POSIX
	// spelling is judged when typed; it holds no here-string.
	twinRequest.LegacyText = twin
	twinRequest.conflictSource = nil
	twinRequest.record, twinRequest.recordTelemetry = nil, nil
	for _, finding := range dispatchTrustedAction(context.Background(), twinRequest) {
		if finding.RuleID == "tamper.detector_state_write" && finding.contributesToEnforcement() {
			return true, true
		}
	}
	return false, true
}

// hereStringPipeTwin rewrites every `CMD <<< WORD` statement of a bash
// command as `printf '%s\n' WORD | CMD`, keeping CMD's other redirections.
func hereStringPipeTwin(command string) (string, bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(command), "")
	if err != nil {
		return "", false
	}
	changed, refused := false, false
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
		// xargs runs its program with the here-string word as arguments:
		// judge that call itself (`xargs rm -rf <<< X` is `rm -rf X`).
		if call, ok := stmt.Cmd.(*syntax.CallExpr); ok {
			if direct, ok := xargsCallTwin(call, []*syntax.Word{word}); ok {
				stmt.Cmd, stmt.Redirs, changed = direct, rest, true
				return true
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
		return "", false
	}
	var out strings.Builder
	if err := syntax.NewPrinter().Print(&out, file); err != nil {
		return "", false
	}
	return out.String(), true
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
