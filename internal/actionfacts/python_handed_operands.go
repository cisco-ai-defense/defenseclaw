// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// PythonCodeHandedOperands returns the operand words of a python -c call
// whose inline code is not proven read-only (PythonCodeOnlyReads): the words
// after the code reach the code as sys.argv, so each is a path the code may
// write (rel-1-0-10:GAP-0365). argv starts with the program. A call with no
// inline code, with code that only reads, or with no operand returns nil.
// Every consumer that sees a runner hand words to a python child (the
// command classifier, the find -exec reader, the registration reader) uses
// this one rule.
func PythonCodeHandedOperands(argv []string) []string {
	if len(argv) < 3 {
		return nil
	}
	if !pythonProgramWord(argv[0]) {
		return nil
	}
	code, at, ok := PythonInlineCode(argv[1:])
	if !ok || PythonCodeOnlyReads(code) {
		return nil
	}
	var operands []string
	for _, operand := range argv[1+at+1:] {
		if pythonOperandIsPath(operand) {
			operands = append(operands, operand)
		}
	}
	return operands
}

// pythonOperandIsPath reports an operand that can be one path: a word with
// no option dash, no space, no quote and no shell syntax. A word that holds
// text (more code, a sentence, a command line carried as an argument) is
// not a path the code was handed.
func pythonOperandIsPath(operand string) bool {
	return operand != "" && !strings.HasPrefix(operand, "-") &&
		!strings.ContainsAny(operand, " \t\n\"'`$;|&<>(){}")
}

// PythonInlineCode finds the -c code in the arguments of a python call (the
// words after the program): the interpreter options before it (-I, -E, -s,
// -B, -u, -O, -X name, -W arg, ...) are skipped. at is the code's index in
// args.
func PythonInlineCode(args []string) (code string, at int, ok bool) {
	for i := 0; i+1 < len(args); i++ {
		switch word := args[i]; {
		case word == "-c":
			return args[i+1], i + 1, true
		case word == "-X" || word == "-W" || word == "-Q" || word == "--check-hash-based-pycs":
			i++
		case strings.HasPrefix(word, "-") && word != "-" && word != "--" && word != "-m":
		default:
			return "", 0, false
		}
	}
	return "", 0, false
}

// PythonCodeHandedOperandsOf is PythonCodeHandedOperands for a parsed
// command: the words are the exact ones (an unexpanded home spelling is kept
// as written), the wrappers that pass argv on (sudo, env, nice, timeout, ...)
// are stripped through the shared prefix-wrapper reader, and a xargs or
// parallel runner hands the child the words after its own options (and after
// ::: for parallel).
func PythonCodeHandedOperandsOf(command CommandFact) []string {
	words, ok := pythonCallWords(command)
	if !ok {
		return nil
	}
	var operands []string
	for _, operand := range PythonCodeHandedOperands(words) {
		if !strings.ContainsAny(operand, "$*?[`") {
			operands = append(operands, operand)
		}
	}
	return operands
}

// PythonCallInlineCode returns the inline code of a parsed command that is
// itself the python -c call once the wrappers and runners
// PythonCodeHandedOperandsOf looks through are stripped: the call that hands
// its operands to the code. A python call that is only words of another
// program (a find -exec child, a shell body) is not one; that program's
// reader judges the code (rel-1-0-10:GAP-0468).
func PythonCallInlineCode(command CommandFact) (string, bool) {
	words, ok := pythonCallWords(command)
	if !ok || len(words) < 3 || !pythonProgramWord(words[0]) {
		return "", false
	}
	code, _, inline := PythonInlineCode(words[1:])
	return code, inline
}

// pythonProgramWord reports a program word that names a python interpreter
// (python, python3, python3.12, a path to one, python.exe).
func pythonProgramWord(word string) bool {
	program := strings.ToLower(path.Base(strings.ReplaceAll(word, `\`, "/")))
	program = strings.TrimSuffix(program, ".exe")
	return program == "python" || posixVersionedPythonProgram(program)
}

// pythonCallWords returns the words of a POSIX command with the wrappers
// that pass argv on and an xargs or parallel runner stripped (see
// PythonCodeHandedOperandsOf).
func pythonCallWords(command CommandFact) ([]string, bool) {
	if command.Dialect != "" && command.Dialect != DialectPOSIX || len(command.Argv) < 3 {
		return nil, false
	}
	words := command.Argv
	static := make([]bool, len(words))
	for i := range static {
		static[i] = true
	}
	if len(command.Arguments) == len(command.Argv) {
		words = make([]string, len(command.Arguments))
		for i, argument := range command.Arguments {
			words[i] = argument.Value
			static[i] = !argument.Expands
			if words[i] == "" && argument.StaticGlob != "" && !strings.ContainsAny(argument.StaticGlob, "*?[]{}$`\\") {
				words[i], static[i] = argument.StaticGlob, true
			}
		}
	}
	for depth := 0; depth < 4; depth++ {
		if run, ok := StaticPrefixWrapperChild(words, static); ok && run.Index < len(words) {
			words, static = words[run.Index:], static[run.Index:]
			continue
		}
		if child, ok := runnerChildWords(words); ok {
			words = child
			static = make([]bool, len(words))
			for i := range static {
				static[i] = true
			}
			continue
		}
		break
	}
	return words, true
}

// runnerChildWords returns the child command of an xargs or parallel call,
// with the runner's own options removed and the ::: separators dropped (the
// words after them are the arguments the child receives).
func runnerChildWords(words []string) ([]string, bool) {
	if len(words) < 2 {
		return nil, false
	}
	program := strings.ToLower(path.Base(words[0]))
	if program != "xargs" && program != "parallel" {
		return nil, false
	}
	index := 1
	for index < len(words) && strings.HasPrefix(words[index], "-") && words[index] != "-" {
		switch words[index] {
		case "-n", "-I", "-i", "-j", "-P", "-L", "-s", "-d", "-E", "-a", "-N", "--jobs", "--max-args":
			index++
		}
		index++
	}
	if index >= len(words) {
		return nil, false
	}
	child := make([]string, 0, len(words)-index)
	for _, word := range words[index:] {
		if word != ":::" && word != "::::" {
			child = append(child, word)
		}
	}
	return child, len(child) > 0
}
