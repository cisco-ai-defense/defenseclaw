// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"path"
	"strings"
	"unicode/utf16"
)

// Windows hooks can run a POSIX shell while reporting a native Windows home.
// This resolver is shared by hook-side evidence and gateway action decisions.
func actionWindowsHome(home string) bool {
	home = strings.ReplaceAll(home, `\`, "/")
	return len(home) >= 3 && home[1] == ':' && home[2] == '/' || strings.HasPrefix(home, "//")
}

func actionWindowsPath(value, cwd, home string) (string, bool) {
	value = strings.TrimSpace(strings.ReplaceAll(value, `\`, "/"))
	if value == "" || strings.ContainsAny(value, "\x00\r\n`") {
		return "", false
	}
	lower := strings.ToLower(value)
	for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%", "$env:userprofile", "${env:userprofile}", "$home", "${home}", "~"} {
		if lower == prefix || strings.HasPrefix(lower, prefix+"/") {
			value = strings.ReplaceAll(home, `\`, "/") + value[len(prefix):]
			lower = strings.ToLower(value)
			break
		}
	}
	if strings.ContainsAny(value, "$%*?[]") {
		return "", false
	}
	if strings.HasPrefix(lower, "//?/unc/") {
		value = "//" + value[len("//?/unc/"):]
	} else if strings.HasPrefix(lower, "//?/") {
		value = value[len("//?/"):]
	}
	if strings.HasPrefix(strings.ToLower(value), "/cygdrive/") && len(value) >= 12 && value[11] == '/' {
		value = value[10:11] + ":" + value[11:]
	} else if len(value) >= 3 && value[0] == '/' && value[2] == '/' && asciiLetter(value[1]) {
		value = value[1:2] + ":" + value[2:]
	}
	if len(value) >= 2 && value[1] == ':' && (len(value) == 2 || value[2] != '/') {
		return "", false // drive-relative paths depend on mutable drive state
	}
	if !actionWindowsHome(value) {
		value = strings.TrimRight(strings.ReplaceAll(cwd, `\`, "/"), "/") + "/" + value
	}
	for _, part := range strings.Split(value, "/") {
		if strings.TrimRight(part, " ") == ".." || strings.Contains(part, "~") {
			return "", false // junction traversal and short names need file identity
		}
	}
	value = strings.ToLower(value)
	if strings.HasPrefix(value, "//") {
		return "/" + path.Clean(value), true
	}
	return path.Clean(value), true
}

func asciiLetter(value byte) bool {
	return value >= 'a' && value <= 'z' || value >= 'A' && value <= 'Z'
}

func actionWindowsProtected(value, cwd, home string, readOnly bool) (bool, bool) {
	resolved, ok := actionWindowsPath(value, cwd, home)
	if !ok {
		return false, false
	}
	root, ok := actionWindowsPath(home, cwd, home)
	if !ok {
		return false, false
	}
	names := []string{"authorized_keys", "authorized_keys2"}
	if readOnly {
		names = []string{"id_rsa", "id_ed25519", "id_ecdsa", "id_dsa"}
	}
	for _, name := range names {
		if resolved == root+"/.ssh/"+name {
			return true, true
		}
	}
	return false, true
}

// actionWindowsWords treats a quoted command body as one word and emits each
// redirection separately. An unclosed quote leaves the command unproved.
func actionWindowsWords(command string) ([]string, bool) {
	var words []string
	var word strings.Builder
	var quote byte
	flush := func() {
		if word.Len() > 0 {
			words = append(words, word.String())
			word.Reset()
		}
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			if c == quote {
				quote = 0
			} else {
				word.WriteByte(c)
			}
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
		case ' ', '\t', '\r', '\n':
			flush()
		case '>', '<', ';', '|', '&':
			if c == '>' && word.Len() == 1 && (word.String() == "1" || word.String() == "2") &&
				i+2 < len(command) && command[i+1] == '&' && command[i+2] >= '0' && command[i+2] <= '9' {
				word.WriteString(command[i : i+3])
				i += 2
				continue
			}
			flush()
			if i+1 < len(command) && command[i+1] == c && (c == '>' || c == '<' || c == '&' || c == '|') {
				words = append(words, command[i:i+2])
				i++
			} else {
				words = append(words, command[i:i+1])
			}
		default:
			word.WriteByte(c)
		}
	}
	flush()
	return words, quote == 0
}

func actionWindowsCommandDecision(command, cwd, home string, depth int) string {
	if command == "" || depth >= 8 || len(command) > MaxPayloadBytes {
		return "dynamic-command"
	}
	words, ok := actionWindowsWords(actionWindowsControlSource(command))
	if !ok || len(words) == 0 {
		return "shell-parse"
	}
	values := make(map[string]string)
	for start := 0; start < len(words); {
		end := start
		for end < len(words) && words[end] != ";" && words[end] != "|" && words[end] != "||" && words[end] != "&" && words[end] != "&&" {
			end++
		}
		if end > start {
			statement := words[start:end]
			if len(statement) == 3 && strings.HasPrefix(statement[0], "$") && statement[1] == "=" &&
				!strings.ContainsAny(statement[2], "$%`") {
				values[strings.ToLower(statement[0])] = statement[2]
				start = end + 1
				continue
			}
			if len(statement) == 5 && strings.HasPrefix(statement[0], "$") && statement[1] == "=" &&
				strings.EqualFold(statement[2], "Join-Path") {
				key := strings.ToLower(statement[0])
				delete(values, key)
				parent := statement[3]
				if value, known := values[strings.ToLower(parent)]; known {
					parent = value
				}
				child := statement[4]
				if !strings.HasPrefix(child, "/") && !actionWindowsHome(child) &&
					!strings.ContainsAny(child, "$%`*?[]") {
					if joined, known := actionWindowsPath(parent+"/"+child, cwd, home); known {
						values[key] = joined
					}
				}
				start = end + 1
				continue
			}
			for i, word := range statement {
				if value, known := values[strings.ToLower(word)]; known {
					statement[i] = value
				}
			}
			if reason := actionWindowsStatement(statement, cwd, home, depth); reason != "" {
				return reason
			}
		}
		start = end + 1
	}
	return ""
}

func actionWindowsStatement(words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	program := strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(words[0], `\`, "/")), ".exe"))
	for i := 1; i < len(words); i++ {
		if words[i] != ">" && words[i] != ">>" && words[i] != "<" && words[i] != "<<" {
			continue
		}
		if i+1 >= len(words) {
			return "dynamic-argument"
		}
		if protected, resolved := actionWindowsProtected(words[i+1], cwd, home, words[i] == "<"); protected ||
			!resolved && (words[i] != "<" || actionProgramMayWrite(program)) {
			return "dynamic-argument"
		}
	}
	if strings.ContainsAny(program, "$%`") || strings.HasPrefix(program, "(") {
		return "dynamic-command"
	}
	// This decision has no body proof for these sourced or directly launched
	// scripts and interpreter hosts. Fail closed on those forms.
	if program == "." || program == "source" {
		return "eval-source"
	}
	for _, extension := range []string{".ps1", ".psm1", ".cmd", ".bat", ".sh", ".bash", ".py", ".js", ".mjs", ".cjs", ".rb", ".pl", ".vbs", ".wsf"} {
		if strings.HasSuffix(program, extension) {
			return "interpreter-path"
		}
	}
	if program == "python" || strings.HasPrefix(program, "python3") || program == "py" ||
		program == "node" || program == "nodejs" || program == "ruby" ||
		program == "perl" || program == "php" || program == "awk" ||
		program == "gawk" || program == "mawk" || program == "nawk" ||
		program == "wscript" || program == "cscript" || program == "mshta" {
		return "interpreter-path"
	}
	if program == "eval" || program == "invoke-expression" || program == "iex" {
		return "eval-source"
	}
	if program == "cmd" {
		for i, word := range words[1:] {
			if strings.EqualFold(word, "/c") || strings.EqualFold(word, "/k") {
				if i+2 >= len(words) {
					return "nested-shell"
				}
				return actionWindowsCommandDecision(strings.Join(words[i+2:], " "), cwd, home, depth+1)
			}
		}
		return "nested-shell"
	}
	if program == "pwsh" || program == "powershell" {
		for i, word := range words[1:] {
			switch strings.ToLower(word) {
			case "-command", "-c":
				if i+2 >= len(words) {
					return "nested-shell"
				}
				return actionWindowsCommandDecision(strings.Join(words[i+2:], " "), cwd, home, depth+1)
			case "-encodedcommand", "-enc":
				if i+2 >= len(words) {
					return "nested-shell"
				}
				encoded, err := base64.StdEncoding.DecodeString(words[i+2])
				if err != nil || len(encoded)%2 != 0 || len(encoded) == 0 {
					return "nested-shell"
				}
				letters := make([]uint16, len(encoded)/2)
				for j := range letters {
					letters[j] = uint16(encoded[j*2]) | uint16(encoded[j*2+1])<<8
				}
				return actionWindowsCommandDecision(string(utf16.Decode(letters)), cwd, home, depth+1)
			case "-file":
				return "nested-shell" // file and arguments may contain commands
			}
		}
		return "nested-shell" // stdin or unknown option
	}
	if posixShellProgram(program) {
		for i, word := range words[1:] {
			if word == "-c" || strings.HasPrefix(word, "-") && strings.Contains(word, "c") {
				if i+2 >= len(words) {
					return "nested-shell"
				}
				return actionWindowsCommandDecision(strings.Join(words[i+2:], " "), cwd, home, depth+1)
			}
		}
		return "nested-shell"
	}
	if program == "git" {
		return actionGitDecision(words, cwd, home, depth+1)
	}
	if strings.Contains(" env nice ionice timeout stdbuf setsid chroot unshare nsenter flock sudo su script xargs find parallel busybox time nohup command exec ", " "+program+" ") {
		return actionWindowsWrapperDecision(program, words, cwd, home, depth+1)
	}
	writeCapable := actionProgramMayWrite(program) || strings.Contains(commandLike(words), ">")
	for i, word := range words[1:] {
		if word == ">" || word == ">>" || word == "<" || word == "<<" {
			continue
		}
		if i > 0 && (words[i] == ">" || words[i] == ">>" || words[i] == "<" || words[i] == "<<") {
			continue
		}
		if word == "<<<" || word == "@'" || word == `@"` {
			if writeCapable {
				return "dynamic-argument"
			}
		}
		if strings.HasPrefix(word, "-") && !strings.Contains(word, "/") {
			continue
		}
		if program == "echo" || program == "printf" || program == "write-output" {
			continue
		}
		if strings.ContainsAny(word, "/\\$%") || len(word) >= 2 && word[1] == ':' {
			readOnly := program == "cat" || program == "type" || program == "get-content" ||
				program == "get-childitem" || program == "grep"
			protected, resolved := actionWindowsProtected(word, cwd, home, readOnly)
			if protected || !resolved && writeCapable && actionWindowsPathPosition(program, i+1, words) &&
				!actionWindowsBoundedSourceGlob(program, i+1, words, word, cwd, home) {
				return "dynamic-argument"
			}
		}
	}
	return ""
}

func actionWindowsPathPosition(program string, index int, words []string) bool {
	switch program {
	case "echo", "printf", "write-output":
		return false
	case "add-content", "set-content", "out-file":
		for i := 1; i < index; i++ {
			if strings.EqualFold(words[i], "-Value") {
				return false
			}
		}
	}
	return true
}

func actionWindowsBoundedSourceGlob(program string, index int, words []string, word, cwd, home string) bool {
	if program != "compress-archive" || index < 2 || !strings.EqualFold(words[index-1], "-Path") ||
		!strings.HasSuffix(word, "/*") && !strings.HasSuffix(word, `\*`) {
		return false
	}
	prefix := word[:len(word)-1]
	resolved, ok := actionWindowsPath(prefix, cwd, home)
	if !ok {
		return false
	}
	protected, _ := actionWindowsProtected(prefix, cwd, home, true)
	return !protected && !strings.Contains(resolved, "/.ssh/")
}

func commandLike(words []string) string { return strings.Join(words, " ") }

func actionWindowsWrapperDecision(program string, words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	if program == "xargs" || program == "parallel" {
		return "dynamic-command" // stdin supplies an unreported child operand.
	}
	if program == "find" {
		for i, word := range words {
			if word != "-exec" && word != "-execdir" && word != "-ok" {
				continue
			}
			if i+1 >= len(words) || strings.Contains(strings.Join(words[i+1:], " "), "{}") {
				return "dynamic-command"
			}
			return actionWindowsStatement(words[i+1:], cwd, home, depth+1)
		}
		return ""
	}
	index := 1
	for index < len(words) && strings.HasPrefix(words[index], "-") {
		option := strings.ToLower(words[index])
		if option == "--" {
			index++
			break
		}
		if (program == "su" || program == "script" || program == "flock") &&
			(option == "-c" || option == "--command") {
			if index+1 >= len(words) {
				return "dynamic-command"
			}
			if program == "script" && index+2 < len(words) {
				if protected, _ := actionWindowsProtected(words[len(words)-1], cwd, home, false); protected {
					return "dynamic-argument"
				}
			}
			return actionWindowsCommandDecision(words[index+1], cwd, home, depth+1)
		}
		if program == "env" && (option == "-s" || option == "--split-string") {
			if index+1 >= len(words) {
				return "dynamic-command"
			}
			return actionWindowsCommandDecision(words[index+1], cwd, home, depth+1)
		}
		value := false
		known := false
		switch program {
		case "env":
			value = option == "-c" || option == "--chdir" || option == "-u" || option == "--unset"
			known = value || option == "-i" || option == "--ignore-environment" || option == "-v" || option == "-0" ||
				strings.HasPrefix(option, "--chdir=") || strings.HasPrefix(option, "--unset=")
		case "nice":
			value = option == "-n" || option == "--adjustment"
			known = value || strings.HasPrefix(option, "-n") || strings.HasPrefix(option, "--adjustment=")
		case "ionice":
			value = option == "-c" || option == "-n" || option == "-p" || option == "-P"
			known = value || option == "-t" || strings.Contains(option, "=")
		case "timeout":
			value = option == "-s" || option == "--signal" || option == "-k" || option == "--kill-after"
			known = value || option == "--foreground" || option == "--preserve-status" || option == "-v" || strings.Contains(option, "=")
		case "stdbuf":
			value = option == "-i" || option == "-o" || option == "-e"
			known = value || strings.HasPrefix(option, "-i") || strings.HasPrefix(option, "-o") || strings.HasPrefix(option, "-e")
		case "setsid":
			known = strings.Contains(" -c -f -w --ctty --fork --wait ", " "+option+" ")
		case "chroot":
			value = option == "--userspec" || option == "--groups"
			known = value || strings.Contains(option, "=")
		case "unshare", "nsenter":
			value = program == "nsenter" && (option == "-t" || option == "--target" || option == "-s" || option == "-g")
			known = value || strings.Contains(" -m -u -i -n -p -c -f -r --mount --uts --ipc --net --pid --user --cgroup --fork --map-root-user ", " "+option+" ") ||
				strings.HasPrefix(option, "--mount-proc")
		case "flock":
			value = option == "-w" || option == "--timeout" || option == "-e" || option == "--conflict-exit-code"
			known = value || strings.Contains(" -s -x -u -n -o -f --shared --exclusive --unlock --nonblock --close --no-fork ", " "+option+" ")
		case "sudo":
			value = strings.Contains(" -u -g -h -p -c -r -t --user --group --host --prompt --close-from --role --type ", " "+option+" ")
			known = value || strings.Contains(" -n -e -h -s -b -k -v --non-interactive --preserve-env ", " "+option+" ") ||
				strings.HasPrefix(option, "--user=") || strings.HasPrefix(option, "--group=")
		case "su":
			value = option == "-s" || option == "--shell" || option == "-g" || option == "--group"
			known = value || option == "-l" || option == "-m" || option == "-p" || option == "--login"
		case "script":
			known = option == "-q" || option == "-f" || option == "-e" || option == "--quiet" || option == "--flush"
		default:
			return "dynamic-command"
		}
		if !known {
			return "dynamic-command"
		}
		if value {
			if index+1 >= len(words) || words[index+1] == "" {
				return "dynamic-command"
			}
			if program == "env" && (option == "-c" || option == "--chdir") {
				resolved, ok := actionWindowsPath(words[index+1], cwd, home)
				if !ok {
					return "dynamic-command"
				}
				cwd = resolved
			}
			index += 2
		} else {
			if program == "env" && strings.HasPrefix(option, "--chdir=") {
				resolved, ok := actionWindowsPath(words[index][len("--chdir="):], cwd, home)
				if !ok {
					return "dynamic-command"
				}
				cwd = resolved
			}
			index++
		}
	}
	if program == "env" {
		for index < len(words) && strings.Contains(words[index], "=") && !strings.HasPrefix(words[index], "-") {
			index++
		}
	}
	if program == "flock" && index < len(words) {
		if protected, resolved := actionWindowsProtected(words[index], cwd, home, false); protected || !resolved {
			return "dynamic-argument"
		}
	}
	if program == "timeout" || program == "chroot" || program == "flock" {
		index++ // duration, new root, or lock file
	}
	if program == "su" {
		return "dynamic-command" // An implicit login shell reads external startup code.
	}
	if index >= len(words) || words[index] == "" {
		return "dynamic-command"
	}
	return actionWindowsStatement(words[index:], cwd, home, depth+1)
}

// actionWindowsControlSource turns PowerShell control syntax into statement
// boundaries, so each statement of a body is judged as if it runs: if,
// elseif, while, until and foreach with an inert header, else, try, catch,
// finally and do, switch with an inert header and simple case labels, the
// braces of their bodies, and the while or until of a do loop. A header that can run or assign something, or unbalanced text, keeps
// its spelling and so its strict decision.
func actionWindowsControlSource(command string) string {
	if !strings.Contains(command, "{") {
		return command
	}
	out := []byte(command)
	// control holds each open brace: 0 for a block left as written, 'c' for
	// a control body and 's' for a switch body, whose labels open bodies.
	var control []byte
	atStart := true
	var quote byte
	for i := 0; i < len(command); i++ {
		c := command[i]
		if quote != 0 {
			if c == quote {
				if i+1 < len(command) && command[i+1] == quote {
					i++
				} else {
					quote = 0
				}
			} else if quote == '"' && c == '`' {
				i++
			}
			continue
		}
		switch c {
		case '`':
			i++
			atStart = false
			continue
		case '\'', '"':
			quote = c
			atStart = false
			continue
		case ' ', '\t':
			continue
		case '\r', '\n', ';', '|', '&':
			atStart = true
			continue
		case '$':
			if i+1 < len(command) && command[i+1] == '{' {
				// ${name} is a variable, not a block.
				end := strings.IndexByte(command[i:], '}')
				if end < 0 {
					return command
				}
				i += end
				atStart = false
				continue
			}
		case '{':
			control = append(control, 0)
			atStart = true
			continue
		case '}':
			if len(control) == 0 {
				return command
			}
			if control[len(control)-1] != 0 {
				out[i] = ';'
			}
			control = control[:len(control)-1]
			atStart = true
			continue
		}
		if atStart {
			end, kind := actionWindowsControlHead(command, i)
			if end <= i && len(control) != 0 && control[len(control)-1] == 's' {
				end, kind = actionWindowsSwitchLabel(command, i), 'c'
			}
			if end > i {
				for j := i; j < end; j++ {
					if out[j] != '\r' && out[j] != '\n' {
						out[j] = ' '
					}
				}
				if kind != 0 {
					out[end-1] = ';'
					control = append(control, kind)
				}
				i = end - 1
				continue
			}
		}
		atStart = false
	}
	if quote != 0 || len(control) != 0 {
		return command
	}
	return string(out)
}

// actionWindowsControlHead returns the end of the control keyword and inert
// header at start: after the { of its body, with kind 'c' ('s' for a switch
// body), or, for the while or until of a do loop, at the end of its
// statement, with kind 0.
func actionWindowsControlHead(command string, start int) (end int, kind byte) {
	lower := strings.ToLower(command[start:])
	for _, keyword := range []string{"elseif", "else", "if", "while", "until", "foreach", "switch", "try", "catch", "finally", "do"} {
		next := start + len(keyword)
		if !strings.HasPrefix(lower, keyword) || next < len(command) &&
			!strings.ContainsRune(" \t\r\n({", rune(command[next])) {
			continue
		}
		index := actionWindowsSkipSpace(command, next)
		for keyword == "switch" && index+1 < len(command) && command[index] == '-' {
			// -Regex, -Wildcard, -Exact, -CaseSensitive
			option := index + 1
			for option < len(command) && asciiLetter(command[option]) {
				option++
			}
			if option == index+1 {
				return 0, 0
			}
			index = actionWindowsSkipSpace(command, option)
		}
		switch keyword {
		case "if", "elseif", "while", "until", "foreach", "switch":
			if index >= len(command) || command[index] != '(' {
				return 0, 0
			}
			closing := strings.IndexByte(command[index:], ')')
			if closing < 0 || !actionWindowsInertHeader(keyword, command[index+1:index+closing]) {
				return 0, 0
			}
			index = actionWindowsSkipSpace(command, index+closing+1)
		}
		if index < len(command) && command[index] == '{' {
			if keyword == "switch" {
				return index + 1, 's'
			}
			return index + 1, 'c'
		}
		if (keyword == "while" || keyword == "until") &&
			(index >= len(command) || strings.ContainsRune(";\r\n}", rune(command[index]))) {
			return index, 0
		}
		return 0, 0
	}
	return 0, 0
}

// actionWindowsSwitchLabel returns the end, after the { of its body, of a
// switch case whose label is a literal: a quoted string without expansion, a
// number or a bare word such as default. Any other label keeps its spelling.
func actionWindowsSwitchLabel(command string, start int) int {
	index := start
	if c := command[start]; c == '\'' || c == '"' {
		closing := strings.IndexByte(command[start+1:], c)
		if closing < 0 || strings.ContainsAny(command[start+1:start+1+closing], "$`") {
			return 0
		}
		index = start + closing + 2
	} else {
		for index < len(command) && (asciiLetter(command[index]) ||
			command[index] >= '0' && command[index] <= '9' || strings.ContainsRune("_.-", rune(command[index]))) {
			index++
		}
		if index == start {
			return 0
		}
	}
	index = actionWindowsSkipSpace(command, index)
	if index >= len(command) || command[index] != '{' {
		return 0
	}
	return index + 1
}

func actionWindowsSkipSpace(command string, index int) int {
	for index < len(command) && strings.ContainsRune(" \t\r\n", rune(command[index])) {
		index++
	}
	return index
}

// actionWindowsInertHeader reports a condition that runs no command: each
// token is a quoted string, a variable, a number or an operator (-eq, -not,
// !$x), separated by spaces or commas, and there is no subexpression, block, type, splat, redirect,
// assignment or statement. A command name anywhere, such as the collection of
// foreach ($n in Get-ChildItem ...), is not inert.
func actionWindowsInertHeader(keyword, header string) bool {
	if strings.ContainsAny(header, "(){}[]@`<>=|;&\r\n") {
		return false
	}
	var tokens []string
	for i := 0; i < len(header); {
		switch c := header[i]; c {
		case ' ', '\t', ',':
			i++
		case '\'', '"':
			end := i + 1
			for ; end < len(header); end++ {
				if header[end] != c {
					continue
				}
				if end+1 < len(header) && header[end+1] == c {
					end++ // a doubled quote
					continue
				}
				break
			}
			if end >= len(header) {
				return false
			}
			tokens = append(tokens, "'")
			i = end + 1
		default:
			end := i
			for end < len(header) && !strings.ContainsRune(" \t,", rune(header[end])) {
				end++
			}
			tokens = append(tokens, header[i:end])
			i = end
		}
	}
	if keyword == "foreach" {
		if len(tokens) < 3 || len(tokens[0]) < 2 || tokens[0][0] != '$' || !strings.EqualFold(tokens[1], "in") {
			return false
		}
		tokens = tokens[2:]
	}
	if len(tokens) == 0 {
		return false
	}
	for _, token := range tokens {
		if !actionWindowsInertToken(strings.TrimPrefix(token, "!")) {
			return false
		}
	}
	return true
}

// actionWindowsInertToken reports a quoted string ('), variable, number or
// operator such as -eq or -not.
func actionWindowsInertToken(token string) bool {
	switch {
	case token == "":
		return false
	case token == "'", token[0] == '$', token[0] >= '0' && token[0] <= '9':
		return true
	}
	return token[0] == '-' && len(token) > 1 && token[1] != '-'
}
