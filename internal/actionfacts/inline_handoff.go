// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// inlineHandsWords lists the inline-code interpreters that run the words
// after their code as the arguments of that code (sys.argv, process.argv,
// ARGV, $argv). Left out: lua (it takes the next word as a script to run),
// deno (eval takes no arguments) and perl, which the shell readers already
// treat as reading unless it edits in place or writes a literal path
// (perl -ne print FILE is a read of FILE, TestRegistrationWriteReachDestinationRoles).
var inlineHandsWords = map[string]bool{
	"python": true, "node": true, "bun": true, "ruby": true, "php": true,
}

// InlineChainRounds bounds the prefix chain InlineCodeHandoff reads before an
// inline interpreter: one round is a run of prefix wrappers (sudo, env,
// nice, timeout, ...) and then one xargs or parallel runner. A chain that
// still has a wrapper or a runner to read after the last round is TRUNCATED
// (bound rule, internal/guardrail/bounded, cap depth): what the call hands to
// the code past it is unknown.
const InlineChainRounds = 8

// InlineAccess is what an inline-code interpreter child does with the
// words it is handed.
type InlineAccess uint8

const (
	// InlineReads: the code is proven to write nothing (a read grammar
	// accepted it). A hand-off of such code names no reach.
	InlineReads InlineAccess = iota
	// InlineUnknown: the code is not proven read-only and names no file
	// write either (text read from stdin, code in a language with no read
	// grammar, a shape the grammar does not list). Every handed path is a
	// possible write: the unknown tier of the pack.
	InlineUnknown
	// InlineWrites: the code spells a call that writes a file, changes one,
	// or runs a program: the handed path is judged as a write of it.
	InlineWrites
)

// InlineHandoff is the reading of one argv that may run an inline
// interpreter child.
type InlineHandoff struct {
	// From is the index in argv of the first word handed to the code, or -1
	// when the call hands none (no inline interpreter child, a script or a
	// module run, or code proven read-only).
	From int
	// Fed is set when an xargs or parallel runner hands the child more words
	// at run time, from its input.
	Fed bool
	// Access is what the code does with the words it is handed.
	Access InlineAccess
	// CodeUnseen is set when the code is not in the words (read from stdin):
	// a word only a runner knows then names no path of its own.
	CodeUnseen bool
	// ProvenReads is set when the call is an inline interpreter child whose
	// code a read grammar proves read-only (From is then -1).
	ProvenReads bool
	// Caps is the caps the prefix chain hit: set when a wrapper or runner was
	// left unread (InlineChainRounds).
	Caps bounded.CapSet
}

// InlineCodeHandoff reads argv as a call that may run an inline-code
// interpreter child (python -c CODE ARG..., node -e, ruby -e, php -r, bun -e,
// python - ARG... with the code on stdin). The wrappers before the interpreter
// (sudo, env, nice, timeout, ...) are read through the shared prefix-wrapper
// reader, and an xargs or parallel runner is read through to its child (Fed is
// then set: the runner hands the child more words at run time, from its
// input). Every word from From on reaches the code as an argument (sys.argv,
// process.argv, ARGV, $argv). Code that a read grammar proves read-only is no
// hand-off at all; code that names a write call is InlineWrites; any other
// code is InlineUnknown (rel-1-0-10:GAP-0365, GAP-0657). It is the one
// hand-off rule: the shell readers of hookpaths and the gateway call it for
// every runner (direct argv, sh -c, a loop, find -exec, xargs, parallel, a
// variable-bound target).
func InlineCodeHandoff(argv []string) InlineHandoff {
	none := InlineHandoff{From: -1}
	offset, fed, caps := inlineChildAt(argv)
	none.Caps = caps
	argv = argv[offset:]
	if len(argv) < 2 {
		return none
	}
	key, row, ok := inlineInterpreterRow(argv[0])
	if !ok || !inlineHandsWords[key] {
		return none
	}
	for index := 1; index < len(argv); index++ {
		word := argv[index]
		if code, fused := inlineCodeOption(key, row, word); code {
			text, from := "", index+2
			switch {
			case fused:
				text, from = inlineFusedCode(key, word), index+1
			case index+1 < len(argv):
				text = argv[index+1]
			default:
				return none
			}
			access := inlineCodeAccess(key, text, index == 1 && !fused && word == row.options[0])
			if access == InlineReads {
				none.ProvenReads = true
				return none
			}
			return InlineHandoff{From: offset + from, Fed: fed, Access: access, Caps: caps}
		}
		switch {
		case word == "-" && key != "php" && (index+1 < len(argv) || fed):
			// The code is read from stdin (python3 - ARG <<EOF): its text is
			// not in the words, so it is no proven read.
			return InlineHandoff{From: offset + index + 1, Fed: fed, Access: InlineUnknown, CodeUnseen: true, Caps: caps}
		case inlineValueOptions[key][word]:
			index++
		case strings.HasPrefix(word, "-") && word != "-" && word != "--":
		default:
			return none // a script or a module runs: its words are not inline code
		}
	}
	return none
}

// inlineFusedCode is the code a python cluster carries after its c
// (python -c"import os", python -Bc code).
func inlineFusedCode(key, word string) string {
	if key != "python" {
		return ""
	}
	at := strings.IndexByte(word, 'c')
	if at < 0 {
		return ""
	}
	return word[at+1:]
}

// InlineCodeHandedFrom is InlineCodeHandoff's index of the first handed word
// and whether a runner feeds more, for a caller that needs no more.
func InlineCodeHandedFrom(argv []string) (from int, fed bool) {
	handoff := InlineCodeHandoff(argv)
	return handoff.From, handoff.Fed
}

// InlineChild returns the words of the command a chain of prefix wrappers
// (sudo, env, nice, timeout, ...) and xargs or parallel runners runs, whether
// a runner feeds it words at run time, and the caps the chain hit.
func InlineChild(argv []string) (child []string, fed bool, caps bounded.CapSet) {
	offset, fed, caps := inlineChildAt(argv)
	return argv[offset:], fed, caps
}

// inlineChildAt reads the prefix chain of argv: rounds of prefix wrappers
// and one runner each. A chain with something left to read after
// InlineChainRounds rounds reports the depth cap.
func inlineChildAt(argv []string) (offset int, fed bool, caps bounded.CapSet) {
	for round := 0; ; round++ {
		next, runner, progressed := inlineStep(argv, offset)
		if !progressed {
			return offset, fed, caps
		}
		if round >= InlineChainRounds {
			return offset, fed, bounded.Of(bounded.Depth)
		}
		offset, fed = next, fed || runner
	}
}

// inlineStep reads one round of the chain at offset: the run of prefix
// wrappers there, then one runner.
func inlineStep(argv []string, offset int) (next int, runner, progressed bool) {
	next = offset
	static := make([]bool, len(argv)-next)
	for i := range static {
		static[i] = true
	}
	if run, ok := StaticPrefixWrapperChild(argv[next:], static); ok {
		next += run.Index
		progressed = true
	}
	if child := inlineRunnerChild(argv[next:]); child >= 0 {
		next += child
		runner, progressed = true, true
	}
	return next, runner, progressed
}

// inlineRunnerChild returns the index of the child an xargs or parallel call
// runs (after its options and their values), or -1.
func inlineRunnerChild(argv []string) int {
	if len(argv) < 2 {
		return -1
	}
	valued := ""
	switch path.Base(argv[0]) {
	case "xargs":
		valued = "nLPsdEaIJ"
	case "parallel":
		valued = "jnNSadIL"
	default:
		return -1
	}
	for index := 1; index < len(argv); index++ {
		word := argv[index]
		switch {
		case word == "--":
			return index + 1
		case strings.HasPrefix(word, "--"):
			if name, _, attached := strings.Cut(word, "="); !attached && inlineRunnerLongValues[name] {
				index++
			}
		case len(word) == 2 && word[0] == '-' && strings.IndexByte(valued, word[1]) >= 0:
			index++
		case strings.HasPrefix(word, "-") && len(word) > 1:
		default:
			return index
		}
	}
	return -1
}

var inlineRunnerLongValues = map[string]bool{
	"--arg-file": true, "--delimiter": true, "--eof": true, "--replace": true, "--max-lines": true,
	"--max-args": true, "--max-procs": true, "--max-chars": true, "--jobs": true, "--sshlogin": true,
}

// InlineCodeHandedWords is the words InlineCodeHandedFrom hands on that can
// be one fixed path: no option dash, space, quote or shell syntax, so text
// carried as an argument is not a handed path.
func InlineCodeHandedWords(argv []string) []string {
	from, _ := InlineCodeHandedFrom(argv)
	if from < 0 {
		return nil
	}
	var words []string
	for _, word := range argv[from:] {
		if InlineHandedWordIsPath(word) {
			words = append(words, word)
		}
	}
	return words
}

// inlineValueOptions are the interpreter options that take the next word.
var inlineValueOptions = map[string]map[string]bool{
	"python": {"-X": true, "-W": true},
	"node":   {"-r": true, "--require": true, "--import": true, "--loader": true, "--experimental-loader": true},
	"ruby":   {"-I": true, "-r": true},
}

// inlineCodeOption reports the word that introduces the inline code: an
// option of the interpreter's row, or a short-option cluster that ends in it
// (python -Ic, ruby -pe). A python cluster may carry the code itself after
// the c (python -c"import os"): fused is then set and the code is this word.
func inlineCodeOption(key string, row inlineCapabilityRow, word string) (code, fused bool) {
	for _, option := range row.options {
		if word == option {
			return true, false
		}
	}
	if len(word) < 3 || word[0] != '-' || word[1] == '-' {
		return false, false
	}
	switch key {
	case "python":
		for at := 1; at < len(word); at++ {
			if word[at] == 'c' {
				return true, at+1 < len(word)
			}
			if !strings.ContainsRune("BEIOPRSbdiqsuvx", rune(word[at])) {
				break
			}
		}
	case "ruby":
		for _, letter := range word[1:] {
			if letter < 'A' || letter > 'z' || letter > 'Z' && letter < 'a' {
				return false, false
			}
		}
		return word[len(word)-1] == 'e', false
	}
	return false, false
}

// InlineHandedWordIsPath reports a word that can be one path: no option dash, no
// white space, no quote and no shell syntax.
func InlineHandedWordIsPath(word string) bool {
	return word != "" && word[0] != '-' && !strings.ContainsAny(word, " \t\r\n\"'`$;|&<>(){}")
}
