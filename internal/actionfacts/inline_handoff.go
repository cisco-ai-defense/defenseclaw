// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
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

// InlineCodeHandedFrom returns the index in argv of the first word an
// inline-code interpreter child (python -c CODE ARG..., node -e, ruby -e,
// php -r, bun -e) hands to its code, or -1. The wrappers before the
// interpreter (sudo, env, nice, timeout, ...) are read through the shared
// prefix-wrapper reader, and an xargs or parallel runner is read through to
// its child (fed is then set: the runner hands the child more words at run
// time, from its input). Every word from the index on reaches the code as an
// argument (sys.argv, process.argv, @ARGV, ARGV, $argv), and no reader
// proves the code read-only, so each is a path the code may write
// (rel-1-0-10:GAP-0365). It is the one hand-off rule: the shell readers of
// hookpaths and the gateway call it for every runner (direct argv, sh -c, a
// loop, find -exec, xargs, parallel, a variable-bound target).
func InlineCodeHandedFrom(argv []string) (from int, fed bool) {
	offset, fed := inlineChildAt(argv)
	argv = argv[offset:]
	if len(argv) < 3 {
		return -1, false
	}
	key, row, ok := inlineInterpreterRow(argv[0])
	if !ok || !inlineHandsWords[key] {
		return -1, false
	}
	for index := 1; index+1 < len(argv); index++ {
		word := argv[index]
		if code, fused := inlineCodeOption(key, row, word); code {
			if fused {
				return offset + index + 1, fed
			}
			return offset + index + 2, fed
		}
		switch {
		case inlineValueOptions[key][word]:
			index++
		case strings.HasPrefix(word, "-") && word != "-" && word != "--":
		default:
			return -1, false // a script or a module runs: its words are not inline code
		}
	}
	return -1, false
}

// InlineChild returns the words of the command a chain of prefix wrappers
// (sudo, env, nice, timeout, ...) and xargs or parallel runners runs, and
// whether a runner feeds it words at run time.
func InlineChild(argv []string) (child []string, fed bool) {
	offset, fed := inlineChildAt(argv)
	return argv[offset:], fed
}

func inlineChildAt(argv []string) (offset int, fed bool) {
	for range 4 {
		static := make([]bool, len(argv)-offset)
		for i := range static {
			static[i] = true
		}
		if run, ok := StaticPrefixWrapperChild(argv[offset:], static); ok {
			offset += run.Index
		}
		child := inlineRunnerChild(argv[offset:])
		if child < 0 {
			break
		}
		offset, fed = offset+child, true
	}
	return offset, fed
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
