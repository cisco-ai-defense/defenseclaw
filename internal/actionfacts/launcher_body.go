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
}

// ShellLauncherCall reads the launcher an argv runs: argv[0], or the command
// a wrapper (sudo, env, nohup, timeout, nice, exec, xargs, start, wsl ...)
// runs after its options, their operands, assignments, durations, switches
// and a start title. The wrapper reading is the one the over-limit launcher
// screen uses (launcherWrapper, launcherPrefix, launcherFlag in
// host_launcher_scan.go), so the screen and this reader name the same
// launcher (rel-1-0-10:GAP-0805). Then ShellLauncherBody's grammar reads the
// script.
func ShellLauncherCall(argv []string) (LauncherCall, bool) {
	start, ok := launcherAt(argv)
	if !ok {
		return LauncherCall{}, false
	}
	call := LauncherCall{Start: start}
	launcher := argv[start:]
	if len(launcher) < 2 || strings.TrimSpace(launcher[0]) != launcher[0] || launcher[0] == "" {
		return LauncherCall{}, false
	}
	switch launcherProgram(launcher[0]) {
	case "powershell", "powershell.exe", "pwsh", "pwsh.exe":
		call.Dialect = DialectPowerShell
		call.Body, ok = powerShellLauncherBody(launcher)
	case "cmd", "cmd.exe":
		call.Dialect = DialectCMD
		call.Body, ok = cmdLauncherBody(launcher)
	case "bash", "sh", "zsh", "dash", "ksh", "mksh":
		call.Dialect = DialectPOSIX
		call.Body, ok = posixLauncherBody(launcher)
	default:
		return LauncherCall{}, false
	}
	return call, ok
}

// launcherAt is the index of the launcher word an argv runs (see
// ShellLauncherCall). Leading assignments are skipped; a word that follows a
// wrapper flag is read as the flag's operand unless it is a launcher (the
// screen reads it as both). command -v and -V only print.
func launcherAt(argv []string) (int, bool) {
	wrapper, afterFlag := "", false
	for index := 0; index < len(argv) && index < maxLauncherTextWords; index++ {
		literal := argv[index]
		if literal != "" && launcherProgramWord(literal) {
			return index, true
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
				return 0, false
			}
			wrapper, afterFlag = name, false
		case wrapper == "" && word.assign:
		case wrapper == "":
			return 0, false
		case launcherPrefix(word, wrapper):
			afterFlag = launcherFlag(word)
		case afterFlag:
			afterFlag = false
		default:
			return 0, false
		}
	}
	return 0, false
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

func powerShellLauncherBody(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		word := argv[i]
		if word == "" {
			return "", false
		}
		if word[0] != '-' && word[0] != '/' {
			return joinPowerShellBody(argv[i:])
		}
		switch {
		case powerShellOptionIs(word, "command", 1):
			return joinPowerShellBody(argv[i+1:])
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
			// -File, -EncodedCommand, -WorkingDirectory, -Version and every
			// option not listed: the body is not one fixed text.
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
		case "/d", "/q", "/s", "/a", "/u":
			continue
		default:
			if cmdSwitchWithValue(option) {
				continue
			}
			return "", false
		}
	}
	return "", false
}

// maxLauncherTextWords bounds the words read from the head of a launcher
// command string.
const maxLauncherTextWords = 64

// maxLauncherTextStatements bounds the statements of a command string read
// for a launcher.
const maxLauncherTextStatements = 16

// ShellLauncherBodyOfText returns the script of a launcher written as one
// command string, such as `powershell.exe -Command '<script>'` or
// `cmd /c "<script>"` as the Codex shell tool sends it on a Windows host
// (rel-1-0-10:GAP-0735), read from the launcher's own grammar like
// ShellLauncherBody. See ShellLauncherCallOfText.
func ShellLauncherBodyOfText(text string) (body string, dialect Dialect, ok bool) {
	call, _, _, ok := ShellLauncherCallOfText(text)
	return call.Body, call.Dialect, ok
}

// ShellLauncherCallOfText reads the first launcher a command string runs, in
// any of its first statements, behind any wrapper ShellLauncherCall reads
// (`echo x | xargs pwsh -c '...'`, `start "" powershell -Command '...'`):
// each statement is split into words as PowerShell splits it (single
// quotes, in which a doubled quote is one quote, and double quotes, in which
// a backtick quote or a doubled quote is one quote) up to its statement or
// redirect operator outside quotes (newline, ; | & < >). A leading call
// operator & is skipped. words are the words of that statement and
// statement its index.
func ShellLauncherCallOfText(text string) (call LauncherCall, words []string, statement int, ok bool) {
	if text == "" || len(text) > maxCommandBytes {
		return LauncherCall{}, nil, 0, false
	}
	from := 0
	for statement = 0; statement < maxLauncherTextStatements && from < len(text); statement++ {
		var next int
		words, next, ok = launcherTextWords(text, from)
		if next < 0 {
			return LauncherCall{}, nil, 0, false // unterminated quote
		}
		if ok {
			if call, ok = ShellLauncherCall(words); ok {
				return call, words, statement, true
			}
		}
		from = next
	}
	return LauncherCall{}, nil, 0, false
}

func launcherTextWords(text string, from int) ([]string, int, bool) {
	var (
		words []string
		word  strings.Builder
		in    bool
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
		case '\n', '\r', ';', '|', '<', '>':
			flush()
			return words, launcherStatementEnd(text, i), len(words) > 0
		case '&':
			if len(words) == 0 && !in {
				i++ // the call operator before the program
				continue
			}
			flush()
			return words, launcherStatementEnd(text, i), len(words) > 0
		case '\'':
			in = true
			i++
			for i < len(text) {
				if text[i] == '\'' {
					if i+1 < len(text) && text[i+1] == '\'' {
						word.WriteByte('\'')
						i += 2
						continue
					}
					break
				}
				word.WriteByte(text[i])
				i++
			}
			if i >= len(text) {
				return nil, -1, false // unterminated quote
			}
			i++
		case '"':
			in = true
			i++
			for i < len(text) {
				if text[i] == '`' && i+1 < len(text) {
					word.WriteByte(text[i+1])
					i += 2
					continue
				}
				if text[i] == '"' {
					if i+1 < len(text) && text[i+1] == '"' {
						word.WriteByte('"')
						i += 2
						continue
					}
					break
				}
				word.WriteByte(text[i])
				i++
			}
			if i >= len(text) {
				return nil, -1, false
			}
			i++
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
		return words, len(text), len(words) > 0
	}
	return words, i, len(words) > 0
}

// launcherStatementEnd is the index after the operator at text[i] (a run of
// ; | & < > and line breaks): the start of the next statement. A redirect
// target is a word of no launcher, so it is read as a statement that names
// none.
func launcherStatementEnd(text string, i int) int {
	for i < len(text) && strings.IndexByte("\n\r;|&<> \t", text[i]) >= 0 {
		i++
	}
	return i
}

// posixLauncherBody is the script word of a POSIX shell invoked with -c in
// any option cluster (-c, -lc, -ic, -xc, -o pipefail -c ...). Whether a
// startup file runs first does not matter here: it runs before the script,
// never instead of it.
func posixLauncherBody(argv []string) (string, bool) {
	for i := 1; i < len(argv); i++ {
		word := argv[i]
		switch {
		case word == "--":
			return "", false
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
					return "", false
				}
				return argv[i+1], true
			}
		default:
			// A script file or stdin: no script text in the argv.
			return "", false
		}
	}
	return "", false
}

// cmdSwitchWithValue reports a cmd startup switch with a valid value:
// /e:on, /e:off, /f:on, /f:off, /v:on, /v:off or /t:<one or two hex digits>.
// Any other value is not read.
func cmdSwitchWithValue(option string) bool {
	if len(option) < 4 || option[2] != ':' || option[0] != '/' {
		return false
	}
	value := option[3:]
	switch option[1] {
	case 'e', 'f', 'v':
		return value == "on" || value == "off"
	case 't':
		if len(value) > 2 {
			return false
		}
		for _, r := range value {
			if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
				return false
			}
		}
		return true
	}
	return false
}
