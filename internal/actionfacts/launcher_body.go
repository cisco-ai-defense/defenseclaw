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

package actionfacts

import (
	"path"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// ShellLauncherBody returns the script text a shell launcher argv runs and
// the dialect it is written in, read from the launcher's own grammar:
//
//   - powershell, powershell.exe, pwsh, pwsh.exe: the words after -Command
//     (-c and every prefix of it) joined with spaces, or those from the first
//     word that is not an option, which PowerShell runs as the command;
//   - cmd, cmd.exe: the words after /c, /k or /r joined with spaces;
//   - bash, sh, zsh, dash, ksh, mksh: the -c script word.
//
// Startup switches that do not change which text runs (-NoProfile, -NoLogo,
// -NonInteractive, -ExecutionPolicy X, /d, /q, /s ...) are skipped. An argv
// whose body is not one fixed text (-File, -EncodedCommand, -Command -, an
// option the grammar does not list, an empty word) has no body.
//
// Unlike nestedCommand, this does not require the switch that turns startup
// scripts off (-NoProfile, /d): a profile or AutoRun entry runs before the
// body, never instead of it, so the body runs as written whatever it is. The
// result is a second reading of the call, never a proof that the call is no
// more than the body.
func ShellLauncherBody(argv []string) (body string, dialect Dialect, ok bool) {
	call, ok := ShellLauncherCall(argv)
	return call.Body, call.Dialect, ok
}

// LauncherCall is the launcher a command runs and the script it is given.
type LauncherCall struct {
	// Start is the index of the launcher word: 0, or the word a wrapper runs.
	Start int
	// Body is the script text and Dialect its language.
	Body    string
	Dialect Dialect
	// Trailing is set when words follow the script word that the script may
	// run as code (the positional arguments of bash -c '"$@"' _ ...): they
	// are not part of Body (rel-1-0-10:GAP-0803).
	Trailing bool
	// Redirects are the redirections of the statement a launcher string
	// runs in (`cmd /c <script> >> <file>`), in their source text: the script
	// runs with them, so they are part of Body for a CMD or PowerShell
	// launcher (rel-1-0-10:GAP-0806). Empty for an argv.
	Redirects string
}

// ShellLauncherCall reads the launcher an argv runs: argv[0], or the command
// a wrapper (sudo, env, nohup, timeout, nice, exec, xargs, start, wsl ...)
// runs after its options, their operands, assignments, durations, switches
// and a start title. The wrapper reading is the one the over-limit launcher
// screen uses (launcherWrapper, launcherPrefix, launcherFlag in
// host_launcher_scan.go), so the screen and this reader name the same
// launcher (rel-1-0-10:GAP-0805). Then ShellLauncherBody's grammar reads the
// script. It is the first of ShellLauncherCalls.
func ShellLauncherCall(argv []string) (LauncherCall, bool) {
	calls, _ := ShellLauncherCalls(argv)
	if len(calls) == 0 {
		return LauncherCall{}, false
	}
	return calls[0], true
}

// ShellLauncherCalls is every launcher an argv may run, in word order: a
// word that may be a wrapper flag's operand or a start title as well as the
// launcher (sudo -u cmd, env -u pwsh, timeout -s sh, xargs -I bash, wsl -d
// cmd, start "<title>") is read both ways, as the screen reads it, so a
// launcher after it is read too (rel-1-0-10:GAP-0857). Each reading whose
// launcher grammar gives a script is one call; the caller judges each and
// keeps the strongest proven verdict.
//
// The first maxLauncherReadings successful calls and the final launcher call
// are returned. The walk reads the whole wrapper chain, so the last launcher
// word, the one the chain runs when every word before it is an operand or a
// title, is always read; a reading between that does not fit is not judged,
// and cut is set: the caller must treat the call as TRUNCATED (the one bound
// rule). cut is also set when the chain is still open at MaxArgvItems words
// (rel-1-0-10:GAP-0971).
func ShellLauncherCalls(argv []string) (calls []LauncherCall, cut bool) {
	starts, open := launcherStarts(argv)
	calls, skipped := launcherCallsAt(argv, starts)
	return calls, skipped || open && len(argv) > MaxArgvItems
}

// launcherCallsAt is the calls read at starts and whether a reading was
// skipped. A reading past the first maxLauncherReadings is skipped and the
// walk goes on to the last start without building another body, so the cost
// stays at maxLauncherReadings+2 bodies however long the chain.
func launcherCallsAt(argv []string, starts []int) (calls []LauncherCall, skipped bool) {
	for i, start := range starts {
		last := i == len(starts)-1
		if skipped && !last {
			continue
		}
		call, ok := shellLauncherCallAt(argv, start)
		if !ok {
			continue
		}
		if !last && len(calls) == maxLauncherReadings {
			skipped = true
			continue
		}
		calls = append(calls, call)
	}
	return calls, skipped
}

func shellLauncherCallAt(argv []string, start int) (LauncherCall, bool) {
	call := LauncherCall{Start: start}
	launcher := argv[start:]
	if len(launcher) < 2 || strings.TrimSpace(launcher[0]) != launcher[0] || launcher[0] == "" {
		return LauncherCall{}, false
	}
	ok := false
	switch launcherProgram(launcher[0]) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		call.Dialect = DialectPowerShell
		call.Body, ok = powerShellLauncherBody(launcher)
	case "cmd", "cmd.exe":
		call.Dialect = DialectCMD
		call.Body, ok = cmdLauncherBody(launcher)
	case "bash", "sh", "zsh", "dash", "ksh", "mksh":
		call.Dialect = DialectPOSIX
		call.Body, call.Trailing, ok = posixLauncherBody(launcher)
	default:
		return LauncherCall{}, false
	}
	return call, ok
}

// maxLauncherReadings bounds the successful operand and title readings one
// argv judges before the final launcher (each is a request of its own, and a
// launcher's script may hold launchers again). A wrapper chain with more is
// a crafted one: readings that do not fit are TRUNCATED, and the last launcher
// is still read (see ShellLauncherCalls, rel-1-0-10:GAP-0971).
const maxLauncherReadings = 4

// launcherStarts are the indexes of the launcher words an argv may run (see
// ShellLauncherCalls). Leading assignments are skipped. A word in an operand
// slot (after a wrapper flag or a start switch that takes one) or in the start
// title slot is read as the launcher when it names one, and as the operand or
// title all the same, so the walk goes on past it, however many there are
// (rel-1-0-10:GAP-0971). cmd's start takes its first quoted word as the
// window title and any other first word as the program: an argv carries no
// quotes, so the first word after start's switches is read both ways, and
// start has one title. command -v and -V only print. The walk reads up to
// MaxArgvItems words, the bound of the argv analysis itself: a wrapper chain
// the analysis reads whole (context-neutral wrappers spend no wrapper depth up
// to InlineChainWrappers, substrate-1:GAP-0334) is read whole here too, so the
// launcher at its end is found (rel-1-0-10:GAP-0970). open reports a walk that
// ran out of words still inside the wrapper chain: the command it runs is
// past the words read.
func launcherStarts(argv []string) (starts []int, open bool) {
	wrapper, afterFlag, titled := "", false, false
	for index := 0; index < len(argv) && index < MaxArgvItems; index++ {
		literal := argv[index]
		titleSlot := wrapper == "start" && !titled
		if literal != "" && launcherProgramWord(literal) {
			starts = append(starts, index)
			if !afterFlag && !titleSlot {
				return starts, false
			}
			if afterFlag {
				afterFlag = false
			} else {
				titled = true
			}
			continue
		}
		word := layoutWord{literal: literal, plain: true, assign: assignmentNameAt(literal, 0) != ""}
		name := ""
		if literal != "" {
			name = commandBase(literal)
		}
		switch {
		case name != "" && launcherWrapper(name):
			if (name == "command" || name == "builtin") && index+1 < len(argv) &&
				layoutOptions(argv[index+1]) && strings.ContainsAny(argv[index+1], "vV") {
				return starts, false
			}
			wrapper, afterFlag, titled = name, false, false
		case wrapper == "" && word.assign:
		case wrapper == "":
			return starts, false
		case launcherPrefix(word, wrapper):
			if wrapper == "start" && literal == "" {
				titled = true
			}
			afterFlag = launcherOperandFlag(word, wrapper)
		case afterFlag:
			afterFlag = false
		case titleSlot:
			titled = true
		default:
			return starts, false
		}
	}
	return starts, true
}

// launcherProgramWord reports a shell launcher program at any path.
func launcherProgramWord(word string) bool {
	switch launcherProgram(word) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe", "cmd", "cmd.exe",
		"bash", "sh", "zsh", "dash", "ksh", "mksh":
		return true
	}
	return false
}

// launcherProgram is the lower-case file name of a launcher at any path.
func launcherProgram(executable string) string {
	return strings.ToLower(path.Base(strings.ReplaceAll(executable, `\`, "/")))
}

// powerShellOptionIs reports that option (with its leading - or /) names the
// parameter full by an unambiguous prefix of at least min letters, as
// PowerShell reads parameter names.
func powerShellOptionIs(option, full string, min int) bool {
	if len(option) < 2 || (option[0] != '-' && option[0] != '/') {
		return false
	}
	name := strings.ToLower(option[1:])
	return len(name) >= min && strings.HasPrefix(full, name)
}

// powerShellLauncherBody is the script a powershell or pwsh argv runs. A
// -WorkingDirectory (-wd) with one value before the script is the move the
// script runs after: the body starts with `Set-Location -LiteralPath
// '<value>'; `, as the launcher reading of the same call as one command line
// (launcherWorkingDirectory) and of its argv (argvWorkingDirectory) read it,
// so the Codex shell argv ["pwsh", "-wd", <folder>, "-Command", <script>] is
// read as the string is (rel-1-0-10:GAP-0198); any other spelling of it has
// no body, as before.
func powerShellLauncherBody(argv []string) (string, bool) {
	location := ""
	join := func(words []string) (string, bool) {
		body, ok := joinPowerShellBody(words)
		return location + body, ok
	}
	for i := 1; i < len(argv); i++ {
		word := argv[i]
		if word == "" {
			return "", false
		}
		if word[0] != '-' && word[0] != '/' {
			return join(argv[i:])
		}
		switch {
		case workingDirectoryWord(word):
			move, ok := workingDirectoryMove(argv, i)
			if !ok || location != "" {
				return "", false
			}
			location = move
			i++
		case powerShellOptionIs(word, "command", 1):
			return join(argv[i+1:])
		case powerShellOptionIs(word, "noprofile", 3),
			powerShellOptionIs(word, "nologo", 3),
			powerShellOptionIs(word, "noninteractive", 4),
			powerShellOptionIs(word, "noexit", 4),
			powerShellOptionIs(word, "sta", 3),
			powerShellOptionIs(word, "mta", 3):
			continue
		case powerShellOptionIs(word, "executionpolicy", 2),
			powerShellOptionIs(word, "windowstyle", 1),
			powerShellOptionIs(word, "inputformat", 1),
			powerShellOptionIs(word, "outputformat", 1):
			i++
			if i >= len(argv) {
				return "", false
			}
		default:
			// -File, -EncodedCommand, -Version and every option not listed:
			// the body is not one fixed text.
			return "", false
		}
	}
	return "", false
}

// joinPowerShellBody joins the words PowerShell runs as one command line.
func joinPowerShellBody(words []string) (string, bool) {
	if len(words) == 0 || strings.TrimSpace(words[0]) == "" || words[0] == "-" {
		return "", false
	}
	for _, word := range words {
		if word == "" {
			// An empty word is passed differently across PowerShell versions.
			return "", false
		}
	}
	return strings.Join(words, " "), true
}

func cmdLauncherBody(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		option := strings.ToLower(argv[i])
		switch option {
		case "/c", "/k", "/r":
			words := argv[i+1:]
			if len(words) == 0 {
				return "", false
			}
			body := strings.TrimSpace(strings.Join(words, " "))
			// cmd strips a leading and a trailing quote of the command line
			// unless it takes the quoted text as a program path, which has
			// no operators to read either way.
			if len(body) >= 2 && body[0] == '"' && body[len(body)-1] == '"' {
				body = body[1 : len(body)-1]
			}
			if strings.TrimSpace(body) == "" {
				return "", false
			}
			return body, true
		default:
			// One cmd switch set with the psparse host reading
			// (rel-1-0-10:GAP-1708).
			if psparse.CmdStartupSwitch(option) {
				continue
			}
			return "", false
		}
	}
	return "", false
}

// maxLauncherTextWords bounds the words read from the head of a launcher
// command string: the argv walk's own bound, so a wrapper chain is read as
// far in a string as in an argv; a chain still open at it is TRUNCATED
// (rel-1-0-10:GAP-0971).
const maxLauncherTextWords = MaxArgvItems

// maxLauncherTextStatements bounds the statements of a command string read
// for a launcher; maxLauncherTextBytes the text: a launcher string past the
// 64 KiB command bound still has its launcher read (rel-1-0-10:GAP-0807),
// and the call's own reading is TRUNCATED at that bound all the same.
const (
	maxLauncherTextStatements = 16
	maxLauncherTextBytes      = 1 << 20
)

// ShellLauncherBodyOfText returns the script of a launcher written as one
// command string, such as `powershell.exe -Command '<script>'` or
// `cmd /c "<script>"` as the Codex shell tool sends it on a Windows host
// (rel-1-0-10:GAP-0735), read from the launcher's own grammar like
// ShellLauncherBody. See ShellLauncherCallOfText.
func ShellLauncherBodyOfText(text string) (body string, dialect Dialect, ok bool) {
	call, _, _, ok := ShellLauncherCallOfText(text)
	return call.Body, call.Dialect, ok
}

// ShellLauncherCallOfText is the first of ShellLauncherCallsOfText.
func ShellLauncherCallOfText(text string) (call LauncherCall, words []string, statement int, ok bool) {
	calls, words, statement, _, ok := ShellLauncherCallsOfText(text)
	if !ok {
		return LauncherCall{}, nil, 0, false
	}
	return calls[0], words, statement, true
}

// ShellLauncherCallsOfText reads the launchers a command string runs, in the
// first of its first statements that runs one, behind any wrapper
// ShellLauncherCalls reads (`echo x | xargs pwsh -c '...'`,
// `start "" powershell -Command '...'`): each statement is split into words as
// PowerShell splits it (single quotes, in which a doubled quote is one quote,
// and double quotes, in which a backtick quote or a doubled quote is one
// quote) up to its statement operator outside quotes (newline, ; | &). A
// redirection (< > >> 2> 2>&1 and its target) is no word: it is kept in
// LauncherCall.Redirects, since the launcher's script runs with it. A
// leading call operator & is skipped. words are the words of that statement
// and statement its index. cut is set when a statement read had a launcher
// reading past maxLauncherReadings, or its wrapper chain went on past the
// words read (ShellLauncherCalls): the caller treats the call as TRUNCATED
// (the one bound rule, rel-1-0-10:GAP-0971).
func ShellLauncherCallsOfText(text string) (calls []LauncherCall, words []string, statement int, cut, ok bool) {
	if text == "" || len(text) > maxLauncherTextBytes {
		return nil, nil, 0, false, false
	}
	from := 0
	for statement = 0; statement < maxLauncherTextStatements && from < len(text); statement++ {
		var next int
		var redirects []string
		words, redirects, next, ok = launcherTextWords(text, from)
		if next < 0 {
			return nil, nil, 0, false, false // unterminated quote
		}
		if ok {
			starts, open := launcherStarts(words)
			var skipped bool
			calls, skipped = launcherCallsAt(words, starts)
			cut = cut || skipped || open && len(words) >= maxLauncherTextWords
			if len(calls) > 0 {
				if len(redirects) > 0 {
					for i := range calls {
						if calls[i].Dialect == DialectCMD || calls[i].Dialect == DialectPowerShell {
							calls[i].Redirects = strings.Join(redirects, " ")
							calls[i].Body += " " + calls[i].Redirects
						}
					}
				}
				return calls, words, statement, cut, true
			}
		}
		from = next
	}
	return nil, nil, 0, cut, false
}

func launcherTextWords(text string, from int) ([]string, []string, int, bool) {
	var (
		words     []string
		redirects []string
		word      strings.Builder
		in        bool
	)
	flush := func() {
		if in {
			words = append(words, word.String())
			word.Reset()
			in = false
		}
	}
	i := from
	for i < len(text) && len(words) < maxLauncherTextWords {
		c := text[i]
		switch c {
		case ' ', '\t':
			flush()
			i++
		case '\n', '\r', ';', '|':
			flush()
			return words, redirects, launcherStatementEnd(text, i), len(words) > 0
		case '<', '>':
			start := i
			if in && i > from && text[i-1] >= '0' && text[i-1] <= '9' && strings.Trim(word.String(), "0123456789") == "" {
				// The descriptor of 2> or 1>> belongs to the redirection.
				start -= word.Len()
				word.Reset()
				in = false
			} else {
				flush()
			}
			end, ok := launcherRedirectEnd(text, i)
			if !ok {
				// A redirection the reader cannot finish (its target opens a
				// quote that never closes) ends the statement, as every
				// redirection did before the reader kept them: the words
				// and redirections before it are still read for a launcher,
				// so a launcher the statement runs is never lost to an
				// unreadable target (rel-1-0-10:GAP-0969).
				return words, redirects, launcherRedirectStatementEnd(text, i), len(words) > 0
			}
			redirects = append(redirects, text[start:end])
			i = end
		case '&':
			if len(words) == 0 && !in {
				i++ // the call operator before the program
				continue
			}
			flush()
			return words, redirects, launcherStatementEnd(text, i), len(words) > 0
		case '\'', '"':
			in = true
			end, ok := launcherQuoteEnd(text, i, &word)
			if !ok {
				return nil, nil, -1, false // unterminated quote
			}
			i = end
		default:
			in = true
			word.WriteByte(c)
			i++
		}
	}
	flush()
	if len(words) >= maxLauncherTextWords {
		// The statement goes on past the words read: the next one is not
		// looked for (the call's own reading has it).
		return words, redirects, len(text), len(words) > 0
	}
	return words, redirects, i, len(words) > 0
}

// launcherRedirectEnd is the end of the redirection whose operator starts at
// text[i]: the run of < and >, then a descriptor (&1, &-) or the target
// word, quoted as launcherTextWords quotes. ok is false for an unterminated
// quote.
func launcherRedirectEnd(text string, i int) (int, bool) {
	for i < len(text) && (text[i] == '<' || text[i] == '>') {
		i++
	}
	if i < len(text) && text[i] == '&' {
		j := i + 1
		for j < len(text) && (text[j] >= '0' && text[j] <= '9' || text[j] == '-') {
			j++
		}
		if j > i+1 {
			return j, true
		}
	}
	for i < len(text) && (text[i] == ' ' || text[i] == '\t') {
		i++
	}
	for i < len(text) {
		switch c := text[i]; c {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '<', '>':
			return i, true
		case '\'', '"':
			end, ok := launcherQuoteEnd(text, i, nil)
			if !ok {
				return 0, false
			}
			i = end
		default:
			i++
		}
	}
	return i, true
}

// launcherQuoteEnd is the index after the quoted span that opens at text[i]
// (a single or a double quote), split as PowerShell splits it: in single
// quotes a doubled quote is one quote; in double quotes a backtick escapes the
// next byte and a doubled quote is one quote. The span's text goes to word
// when word is not nil. ok is false for a quote that never closes. Words and
// redirection targets are read by this one scanner, so a target never ends
// where its word would not (rel-1-0-10:GAP-0969).
func launcherQuoteEnd(text string, i int, word *strings.Builder) (int, bool) {
	quote := text[i]
	write := func(c byte) {
		if word != nil {
			word.WriteByte(c)
		}
	}
	for i++; i < len(text); i++ {
		c := text[i]
		if quote == '"' && c == '`' && i+1 < len(text) {
			i++
			write(text[i])
			continue
		}
		if c == quote {
			if i+1 < len(text) && text[i+1] == quote {
				i++
				write(quote)
				continue
			}
			return i + 1, true
		}
		write(c)
	}
	return 0, false
}

// launcherRedirectStatementEnd is the start of the next statement after a
// redirection the reader cannot finish at text[i]: the operator run, its
// blanks and any statement operators after them, as the reader ended a
// statement at a redirection before it kept them (the target is then read as
// a statement of its own).
func launcherRedirectStatementEnd(text string, i int) int {
	for i < len(text) && (text[i] == '<' || text[i] == '>' || launcherStatementByte(text[i])) {
		i++
	}
	return i
}

// launcherStatementEnd is the index after the operator at text[i] (a run of
// ; | & and line breaks): the start of the next statement.
func launcherStatementEnd(text string, i int) int {
	for i < len(text) && launcherStatementByte(text[i]) {
		i++
	}
	return i
}

// launcherStatementByte reports a byte of a statement operator run: a line
// break, ; | & or a blank.
func launcherStatementByte(c byte) bool {
	switch c {
	case '\n', '\r', ';', '|', '&', ' ', '\t':
		return true
	}
	return false
}

// posixLauncherBody is the script word of a POSIX shell invoked with -c in
// any option cluster (-c, -lc, -ic, -xc, -o pipefail -c ...). Whether a
// startup file runs first does not matter here: it runs before the script,
// never instead of it.
func posixLauncherBody(argv []string) (string, bool, bool) {
	for i := 1; i < len(argv); i++ {
		word := argv[i]
		switch {
		case word == "--":
			return "", false, false
		case strings.HasPrefix(word, "--"):
			if word == "--rcfile" || word == "--init-file" {
				i++
			}
		case len(word) > 1 && (word[0] == '-' || word[0] == '+'):
			valued := 0
			command := false
			for _, letter := range word[1:] {
				switch letter {
				case 'c':
					command = true
				case 'o', 'O':
					valued++
				}
			}
			i += valued
			if command {
				if i+1 >= len(argv) || strings.TrimSpace(argv[i+1]) == "" {
					return "", false, false
				}
				return argv[i+1], i+2 < len(argv), true
			}
		default:
			// A script file or stdin: no script text in the argv.
			return "", false, false
		}
	}
	return "", false, false
}
