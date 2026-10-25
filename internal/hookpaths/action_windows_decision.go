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
	// Remove lexical traversal before asking the filesystem to expand a short
	// name. GetLongPathName cannot expand a nonexistent intermediate component.
	unc := strings.HasPrefix(value, "//")
	value = path.Clean(value)
	if unc {
		value = "/" + value
	}
	if strings.Contains(value, "~") {
		var expanded bool
		value, expanded = actionWindowsExpandShortPath(value)
		if !expanded {
			return "", false
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
// redirection separately, preserving an attached file descriptor. An unclosed
// quote leaves the command unproved.
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
			if c == '>' || c == '<' {
				fd := word.String()
				if len(fd) > 0 && strings.IndexFunc(fd, func(r rune) bool { return r < '0' || r > '9' }) == -1 {
					word.WriteByte(c)
					if i+1 < len(command) && command[i+1] == c {
						word.WriteByte(c)
						i++
					}
					flush()
					continue
				}
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

// actionPowerShellCode keeps quoted text and line boundaries while removing
// comments. Call it only for an explicit PowerShell dialect: cmd treats # as
// ordinary data, and an absent hint does not identify the shell.
func actionPowerShellCode(command string) string {
	code := []byte(command)
	var quote byte
	blockComment := false
	lineComment := false
	for i := 0; i < len(code); i++ {
		c := command[i]
		if lineComment {
			if c == '\n' || c == '\r' {
				lineComment = false
			} else {
				code[i] = ' '
			}
			continue
		}
		if blockComment {
			if i+1 < len(code) && c == '#' && command[i+1] == '>' {
				blockComment = false
				code[i], code[i+1] = ' ', ' '
				i++
				continue
			}
			if c != '\n' && c != '\r' {
				code[i] = ' '
			}
			continue
		}
		if quote == '\'' {
			if c == '\'' {
				if i+1 < len(code) && command[i+1] == '\'' {
					i++ // doubled quote is part of the literal
				} else {
					quote = 0
				}
			}
			continue
		}
		if c == '`' && i+1 < len(code) {
			i++ // PowerShell escape, including a literal # or quote
			continue
		}
		if quote == '"' {
			if c == '"' {
				quote = 0
			}
			continue
		}
		if c == '\'' || c == '"' {
			quote = c
			continue
		}
		commentStart := i == 0 || strings.ContainsRune(" \t\r\n,=;|&(){}[]", rune(command[i-1]))
		if commentStart && i+1 < len(code) && c == '<' && command[i+1] == '#' {
			blockComment = true
			code[i], code[i+1] = ' ', ' '
			i++
			continue
		}
		if c == '#' && commentStart {
			lineComment = true
			code[i] = ' '
		}
	}
	return string(code)
}

func actionWindowsLiteralDollars(command string, dialect string) string {
	var normalized strings.Builder
	normalized.Grow(len(command))
	if dialect != "powershell" {
		// Keep the pre-dialect Windows scan byte-for-byte for cmd and an
		// absent hint. A backtick has no escape meaning in cmd.
		singleQuoted := false
		for i := 0; i < len(command); i++ {
			if command[i] == '\'' {
				singleQuoted = !singleQuoted
			}
			if singleQuoted && command[i] == '$' {
				normalized.WriteByte('@')
			} else {
				normalized.WriteByte(command[i])
			}
		}
		return normalized.String()
	}
	var quote byte
	for i := 0; i < len(command); i++ {
		c := command[i]
		if c == '`' && quote != '\'' && i+1 < len(command) {
			if command[i+1] == '$' {
				normalized.WriteByte('@')
				i++
				continue
			}
			normalized.WriteByte(c)
			normalized.WriteByte(command[i+1])
			i++
			continue
		}
		if c == '\'' && quote == 0 {
			quote = '\''
		} else if c == '\'' && quote == '\'' {
			if i+1 < len(command) && command[i+1] == '\'' {
				normalized.WriteByte(c)
				normalized.WriteByte(c)
				i++
				continue
			}
			quote = 0
		} else if c == '"' && quote == 0 {
			quote = '"'
		} else if c == '"' && quote == '"' {
			quote = 0
		}
		if c == '$' && quote == '\'' {
			normalized.WriteByte('@')
		} else {
			normalized.WriteByte(c)
		}
	}
	return normalized.String()
}

func actionWindowsRedirectOperator(word string) string {
	switch word {
	case ">", ">>", "<", "<<":
		return word
	}
	i := 0
	for i < len(word) && word[i] >= '0' && word[i] <= '9' {
		i++
	}
	if i > 0 {
		switch word[i:] {
		case ">", ">>", "<", "<<":
			return word[i:]
		}
	}
	return ""
}

func actionWindowsCommandDecision(command, cwd, home string, depth int) string {
	if command == "" || depth >= 8 || len(command) > MaxPayloadBytes {
		return "dynamic-command"
	}
	words, ok := actionWindowsWords(command)
	if !ok || len(words) == 0 {
		return "shell-parse"
	}
	for _, statement := range actionWindowsResolvedStatements(words, cwd, home) {
		if reason := actionWindowsStatement(statement, cwd, home, depth); reason != "" {
			return reason
		}
	}
	return ""
}

// Keep bounded assignment resolution common to audit and enforcement. Only
// literal assignments and Join-Path children are substituted into commands.
func actionWindowsResolvedStatements(words []string, cwd, home string) [][]string {
	values := make(map[string]string)
	var statements [][]string
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
			statements = append(statements, statement)
		}
		start = end + 1
	}
	return statements
}

func actionWindowsStatement(words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	program := strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(words[0], `\`, "/")), ".exe"))
	for i := 1; i < len(words); i++ {
		redirect := actionWindowsRedirectOperator(words[i])
		if redirect == "" {
			continue
		}
		if i+1 >= len(words) {
			return "dynamic-argument"
		}
		if protected, resolved := actionWindowsProtected(words[i+1], cwd, home, redirect == "<"); protected ||
			!resolved && (redirect != "<" || actionProgramMayWrite(program)) {
			return "dynamic-argument"
		}
	}
	if strings.ContainsAny(program, "$%`") || strings.HasPrefix(program, "(") {
		return "dynamic-command"
	}
	// This audit decision has no body proof for sourced or directly launched
	// scripts and interpreter hosts, so it records uncertainty for them.
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
	writeCapable := actionProgramMayWrite(program)
	for i, word := range words[1:] {
		if actionWindowsRedirectOperator(word) != "" {
			continue
		}
		if i > 0 && actionWindowsRedirectOperator(words[i]) != "" {
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
			_, resolved := actionWindowsProtected(word, cwd, home, false)
			if !resolved && writeCapable {
				return "dynamic-argument"
			}
		}
	}
	return ""
}

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
