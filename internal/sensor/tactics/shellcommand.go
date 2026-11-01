// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package tactics

import (
	"slices"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
)

// shellWord is one word of a command after quote removal. quoted records
// that some of it was quoted, which makes it data rather than syntax.
type shellWord struct {
	text   string
	quoted bool
}

// shellCommand is one simple command: its words without redirections, and
// the pipeline it is a stage of.
type shellCommand struct {
	words    []shellWord
	pipeline int
}

// maxShellNesting bounds how deep substitutions and nested scripts are
// followed, so a crafted command line cannot make classification expensive.
const maxShellNesting = 4

// shellEscapable are the characters a backslash escapes outside quotes. Any
// other backslash is kept, so a Windows path keeps its separators.
const shellEscapable = " \t\n\"'\\|&;()<>$`"

// shellCommands splits a command line into its simple commands, following
// pipelines, lists, subshells, command substitutions and the scripts handed to
// sh -c, eval, PowerShell -Command and cmd /c. Comments and here-document
// bodies are skipped: they are text, not commands.
//
// A best-effort reading of POSIX shell -- enough to tell the program a
// command runs from words that merely appear in it -- and not a shell.
func shellCommands(cmdline string) []shellCommand {
	lexer := &shellLexer{}
	lexer.parse(cmdline, 0)
	return lexer.commands
}

type shellLexer struct {
	commands  []shellCommand
	pipelines int
	truncated bool // a script nested past maxShellNesting was not read
}

type hereDocument struct {
	delimiter string
	stripTabs bool
}

func (l *shellLexer) parse(script string, depth int) {
	if depth > maxShellNesting {
		l.truncated = true
		return
	}
	var (
		words    []shellWord
		word     strings.Builder
		inWord   bool
		quoted   bool
		target   bool          // the next word is a redirection target
		hereNext *hereDocument // the next word is a here-document delimiter
		pending  []hereDocument
	)
	l.pipelines++
	pipeline := l.pipelines
	next := func(at int) byte {
		if at+1 < len(script) {
			return script[at+1]
		}
		return 0
	}
	flush := func() {
		if !inWord {
			return
		}
		current := shellWord{text: word.String(), quoted: quoted}
		word.Reset()
		inWord, quoted = false, false
		switch {
		case hereNext != nil:
			hereNext.delimiter = current.text
			pending = append(pending, *hereNext)
			hereNext = nil
		case target:
			target = false
		default:
			words = append(words, current)
		}
	}
	end := func(piped bool) {
		flush()
		target, hereNext = false, nil
		if len(words) > 0 {
			command := shellCommand{words: words, pipeline: pipeline}
			l.commands = append(l.commands, command)
			words = nil
			if nested, ok := interpreterScript(command.words); ok {
				l.parse(nested, depth+1)
			}
		}
		if !piped {
			l.pipelines++
			pipeline = l.pipelines
		}
	}
	for i := 0; i < len(script); i++ {
		c := script[i]
		switch c {
		case '\'':
			inWord, quoted = true, true
			closing := strings.IndexByte(script[i+1:], '\'')
			if closing < 0 {
				word.WriteString(script[i+1:])
				i = len(script)
				break
			}
			word.WriteString(script[i+1 : i+1+closing])
			i += closing + 1
		case '"':
			inWord, quoted = true, true
			i = l.doubleQuoted(script, i+1, &word, depth)
		case '\\':
			if next(i) == '\n' {
				i++
				break
			}
			inWord = true
			if n := next(i); n != 0 && strings.IndexByte(shellEscapable, n) >= 0 {
				word.WriteByte(n)
				i++
				break
			}
			word.WriteByte(c)
		case '$':
			inWord = true
			if next(i) == '(' {
				i = l.substitution(script, i+1, depth)
				word.WriteString("$()")
				break
			}
			word.WriteByte(c)
		case '`':
			inWord = true
			i = l.backquoted(script, i+1, depth)
			word.WriteString("$()")
		case ' ', '\t', '\r':
			flush()
		case '\n':
			end(false)
			if len(pending) > 0 {
				i = skipHereDocuments(script, i+1, pending) - 1
				pending = nil
			}
		case ';', '(', ')':
			end(false)
		case '|':
			if next(i) == '|' {
				end(false)
				i++
				break
			}
			end(true)
			if next(i) == '&' {
				i++
			}
		case '&':
			switch next(i) {
			case '&':
				end(false)
				i++
			case '>':
				flush()
				i++
				if next(i) == '>' {
					i++
				}
				target = true
			default:
				end(false)
			}
		case '<', '>':
			// A word of digits right before the operator is the descriptor
			// being redirected, not an argument.
			if inWord && !quoted && strings.Trim(word.String(), "0123456789") == "" {
				word.Reset()
				inWord = false
			} else {
				flush()
			}
			switch {
			case c == '<' && next(i) == '<' && next(i+1) == '<':
				i += 2
				target = true
			case c == '<' && next(i) == '<':
				i++
				document := hereDocument{}
				if next(i) == '-' {
					i++
					document.stripTabs = true
				}
				hereNext = &document
			default:
				if n := next(i); n == '>' || n == '|' || n == '&' || (c == '<' && n == '>') {
					i++
				}
				target = true
			}
		case '#':
			if inWord {
				word.WriteByte(c)
				break
			}
			newline := strings.IndexByte(script[i:], '\n')
			if newline < 0 {
				i = len(script)
				break
			}
			i += newline - 1
		default:
			inWord = true
			word.WriteByte(c)
		}
	}
	end(false)
}

// doubleQuoted reads a double-quoted string starting after its opening quote
// and returns the index of the closing one. Substitutions inside it still
// run, so they are parsed as commands.
func (l *shellLexer) doubleQuoted(script string, start int, word *strings.Builder, depth int) int {
	for i := start; i < len(script); i++ {
		switch c := script[i]; c {
		case '"':
			return i
		case '\\':
			if i+1 < len(script) && strings.IndexByte("\"\\$`\n", script[i+1]) >= 0 {
				word.WriteByte(script[i+1])
				i++
				continue
			}
			word.WriteByte(c)
		case '$':
			if i+1 < len(script) && script[i+1] == '(' {
				i = l.substitution(script, i+1, depth)
				word.WriteString("$()")
				continue
			}
			word.WriteByte(c)
		case '`':
			i = l.backquoted(script, i+1, depth)
			word.WriteString("$()")
		default:
			word.WriteByte(c)
		}
	}
	return len(script)
}

// substitution parses the command substitution whose "(" is at open and
// returns the index of its closing ")". $(( )) is arithmetic and is skipped.
func (l *shellLexer) substitution(script string, open, depth int) int {
	closing := len(script)
	level := 0
	for i := open; i < len(script); i++ {
		if script[i] == '(' {
			level++
		} else if script[i] == ')' {
			if level--; level == 0 {
				closing = i
				break
			}
		}
	}
	if inner := script[open+1 : closing]; !strings.HasPrefix(inner, "(") {
		l.parse(inner, depth+1)
	}
	return closing
}

// backquoted parses a `...` substitution starting after its opening quote and
// returns the index of the closing one.
func (l *shellLexer) backquoted(script string, start, depth int) int {
	closing := strings.IndexByte(script[start:], '`')
	if closing < 0 {
		l.parse(script[start:], depth+1)
		return len(script)
	}
	l.parse(script[start:start+closing], depth+1)
	return start + closing
}

// skipHereDocuments returns the index just past the bodies of the pending
// here-documents, which start at start.
func skipHereDocuments(script string, start int, documents []hereDocument) int {
	position := start
	for _, document := range documents {
		for position < len(script) {
			line := script[position:]
			position = len(script)
			if newline := strings.IndexByte(line, '\n'); newline >= 0 {
				position = len(script) - len(line) + newline + 1
				line = line[:newline]
			}
			if document.stripTabs {
				line = strings.TrimLeft(line, "\t")
			}
			if strings.TrimRight(line, "\r") == document.delimiter {
				break
			}
		}
	}
	return position
}

// commandWrappers run the command that follows them; each lists its options
// that take a value.
var commandWrappers = map[string][]string{
	"sudo":    {"-u", "-g", "-h", "-p", "-C", "-D", "-r", "-t", "-U"},
	"doas":    {"-u", "-C"},
	"env":     {"-u", "-C"},
	"command": nil,
	"builtin": nil,
	"exec":    {"-a"},
	"nohup":   nil,
	"time":    nil,
	"nice":    {"-n"},
	"timeout": {"-s", "-k"},
	"stdbuf":  {"-i", "-o", "-e"},
	"xargs":   {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s"},
}

// shellKeywords open or close a compound command; the program is the word
// after them.
var shellKeywords = map[string]bool{
	"!": true, "{": true, "}": true, "if": true, "then": true, "else": true, "elif": true,
	"fi": true, "while": true, "until": true, "do": true, "done": true, "esac": true,
}

var shellAssignment = lazyregexp.New(`^[A-Za-z_][A-Za-z0-9_]*\+?=`)

// wrapperSwitches are the short options without a value that each command
// wrapper takes, as letters. An option outside them and commandWrappers
// leaves the wrapped program uncertain.
var wrapperSwitches = map[string]string{
	"sudo": "AbBEHKkNnPS", "doas": "ns", "env": "0iv", "command": "pVv", "exec": "cl",
	"time": "apqv", "timeout": "v", "xargs": "0oprtx",
}

// commandProgram returns the program a simple command runs and its
// arguments, past variable assignments, keywords and wrappers such as sudo,
// env, nice or xargs.
func commandProgram(words []shellWord) (string, []shellWord) {
	program, args, _ := resolveProgram(words)
	return program, args
}

// resolveProgram is commandProgram that also reports whether the program is
// certain. It is not when a wrapper has an option it does not know (a long
// option, an unknown letter, a value option ending a cluster) or when the
// program or a wrapper option is a dynamic word ($VAR, $(...)).
func resolveProgram(words []shellWord) (string, []shellWord, bool) {
	certain := true
	for index := 0; index < len(words); index++ {
		word := words[index]
		if !word.quoted && (shellKeywords[word.text] || shellAssignment.MatchString(word.text)) {
			continue
		}
		program := programName(word.text)
		certain = certain && !strings.Contains(word.text, "$")
		valued, wrapper := commandWrappers[program]
		if !wrapper {
			return program, words[index+1:], certain
		}
		for index+1 < len(words) && strings.HasPrefix(words[index+1].text, "-") {
			index++
			certain = certain && knownWrapperOption(program, words[index].text, valued)
			if slices.Contains(valued, words[index].text) {
				index++
			}
		}
		if program == "timeout" && index+1 < len(words) {
			index++ // the duration
		}
	}
	return "", nil, certain
}

// knownWrapperOption reports whether resolveProgram skips option of wrapper
// exactly as the wrapper reads it.
func knownWrapperOption(wrapper, option string, valued []string) bool {
	letters := option[1:]
	switch {
	case option == "--":
		return true
	case letters == "":
		return wrapper == "env" // env - is env -i
	case letters[0] == '-' || strings.Contains(option, "$"):
		return false
	case wrapper == "nice" && strings.Trim(letters, "0123456789") == "":
		return true // nice -5
	}
	for index := 0; index < len(letters); index++ {
		if strings.IndexByte(wrapperSwitches[wrapper], letters[index]) >= 0 {
			continue
		}
		if !slices.Contains(valued, "-"+letters[index:index+1]) {
			return false
		}
		// A value option takes the rest of the word, or the next word when
		// it stands alone (the only form resolveProgram skips past).
		return index+1 < len(letters) || len(letters) == 1
	}
	return true
}

// RunsProgram reports whether a shell command line may run one of programs
// (lowercased basenames without ".exe"): past assignments, keywords and
// wrappers (env, sudo, nice, nohup, time, exec, command, ...), in lists,
// pipelines and substitutions, and in the scripts handed to sh -c, eval,
// PowerShell -Command and cmd /c. It fails closed: a command whose program
// is uncertain, or a script nested past the limit, counts when one of its
// words names one of programs.
func RunsProgram(cmdline string, programs ...string) bool {
	lexer := &shellLexer{}
	lexer.parse(cmdline, 0)
	names := func(text string) bool {
		for _, token := range strings.FieldsFunc(text, func(r rune) bool {
			return unicode.IsSpace(r) || strings.ContainsRune("\"'`;&|(){}<>=", r)
		}) {
			if slices.Contains(programs, programName(token)) {
				return true
			}
		}
		return false
	}
	for _, command := range lexer.commands {
		program, _, certain := resolveProgram(command.words)
		if slices.Contains(programs, program) || !certain && names(joinWords(command.words, false)) {
			return true
		}
	}
	return lexer.truncated && names(cmdline)
}

// programName is a program's lowercased basename without ".exe".
func programName(word string) string {
	if index := strings.LastIndexAny(word, `/\`); index >= 0 {
		word = word[index+1:]
	}
	return strings.TrimSuffix(strings.ToLower(word), ".exe")
}

// firstOperand is the first argument that is not an option.
func firstOperand(args []shellWord) string {
	for _, arg := range args {
		if !strings.HasPrefix(arg.text, "-") {
			return arg.text
		}
	}
	return ""
}

var posixShells = map[string]bool{
	"sh": true, "bash": true, "zsh": true, "dash": true, "ksh": true, "ash": true, "mksh": true,
}

// interpreterScript returns the script a command hands to a shell (-c), to
// eval, to PowerShell (-Command) or to cmd (/c), so the commands in it are
// read as commands.
func interpreterScript(words []shellWord) (string, bool) {
	program, args := commandProgram(words)
	switch {
	case program == "eval":
		return joinWords(args, false), len(args) > 0
	case posixShells[program]:
		command := false
		for index, arg := range args {
			if !arg.quoted && len(arg.text) > 1 && (arg.text[0] == '-' || arg.text[0] == '+') {
				if arg.text[0] == '-' && !strings.HasPrefix(arg.text, "--") && strings.ContainsRune(arg.text[1:], 'c') {
					command = true
				}
				continue
			}
			if !command {
				return "", false
			}
			return scriptFrom(args[index:]), true
		}
	case program == "powershell" || program == "pwsh":
		for index, arg := range args {
			flag := strings.ToLower(arg.text)
			if len(flag) > 1 && (flag[0] == '-' || flag[0] == '/') && strings.HasPrefix("command", flag[1:]) {
				return scriptFrom(args[index+1:]), index+1 < len(args)
			}
		}
	case program == "cmd":
		for index, arg := range args {
			if flag := strings.ToLower(arg.text); flag == "/c" || flag == "/k" {
				return scriptFrom(args[index+1:]), index+1 < len(args)
			}
		}
	}
	return "", false
}

// scriptFrom is the script in an interpreter's remaining arguments. A quoted
// first argument is the whole script, as in sh -c 'script' name args. An
// unquoted one is a command line whose argv was joined with spaces, so its
// words are put back together, re-quoting the ones that were quoted.
func scriptFrom(args []shellWord) string {
	if len(args) > 0 && args[0].quoted {
		return args[0].text
	}
	return joinWords(args, true)
}

func joinWords(words []shellWord, requote bool) string {
	parts := make([]string, len(words))
	for index, word := range words {
		parts[index] = word.text
		if requote && word.quoted {
			parts[index] = "'" + strings.ReplaceAll(word.text, "'", `'\''`) + "'"
		}
	}
	return strings.Join(parts, " ")
}
