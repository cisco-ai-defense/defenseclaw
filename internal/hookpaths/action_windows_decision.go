// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"path"
	"slices"
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

// PowerShell's static File writers take the destination as their first
// argument. Inspect only executable statements and that destination: a
// protected path in the content argument or quoted command text is data.
func actionWindowsDotNetFileWrite(command, cwd, home string) bool {
	if command == "" || len(command) > MaxPayloadBytes {
		return false
	}
	start := 0
	var quote byte
	for i := 0; i <= len(command); i++ {
		if i == len(command) || quote == 0 && strings.ContainsRune(";|&\r\n", rune(command[i])) {
			if quote == 0 && actionWindowsDotNetFileStatement(command[start:i], cwd, home) {
				return true
			}
			start = i + 1
			continue
		}
		if command[i] == '`' && i+1 < len(command) {
			i++ // PowerShell's escape also keeps a separator inside this statement.
			continue
		}
		if quote != 0 {
			if command[i] == quote {
				quote = 0
			}
		} else if command[i] == '\'' || command[i] == '"' {
			quote = command[i]
		}
	}
	return false
}

func actionWindowsDotNetFileCommand(command, cwd, home string, depth int) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	if actionWindowsDotNetFileWrite(command, cwd, home) {
		return true
	}
	words, ok := actionWindowsWords(command)
	if !ok || len(words) < 3 {
		return false
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	switch program {
	case "cmd":
		for i := 1; i < len(words); i++ {
			option := strings.ToLower(words[i])
			if option == "/c" || option == "/k" {
				return i+1 < len(words) && actionWindowsDotNetFileCommand(strings.Join(words[i+1:], " "), cwd, home, depth+1)
			}
			if option != "/d" && option != "/s" && option != "/q" &&
				!strings.HasPrefix(option, "/v:") && !strings.HasPrefix(option, "/e:") && !strings.HasPrefix(option, "/f:") {
				return false
			}
		}
		return false
	case "env", "sudo":
		index := 1
		for index < len(words) {
			option := words[index]
			if option == "--" {
				index++
				break
			}
			if program == "env" {
				switch {
				case option == "-S" || option == "--split-string":
					return index+1 < len(words) && actionWindowsDotNetFileCommand(words[index+1], cwd, home, depth+1)
				case option == "-i" || option == "--ignore-environment" || option == "-v" || option == "-0":
					index++
				case option == "-u" || option == "--unset" || option == "-C" || option == "--chdir":
					if index+1 >= len(words) {
						return false
					}
					if option == "-C" || option == "--chdir" {
						var resolved bool
						cwd, resolved = actionWindowsPath(words[index+1], cwd, home)
						if !resolved {
							return false
						}
					}
					index += 2
				case strings.HasPrefix(option, "--chdir="):
					var resolved bool
					cwd, resolved = actionWindowsPath(strings.TrimPrefix(option, "--chdir="), cwd, home)
					if !resolved {
						return false
					}
					index++
				case strings.HasPrefix(option, "--unset=") || strings.HasPrefix(option, "-u") && len(option) > 2 ||
					strings.Contains(option, "=") && !strings.HasPrefix(option, "-"):
					index++
				case strings.HasPrefix(option, "-"):
					return false
				default:
					return actionWindowsDotNetFileCommand(strings.Join(words[index:], " "), cwd, home, depth+1)
				}
				continue
			}
			if option == "-l" || option == "-ll" || option == "--list" {
				return false
			}
			switch {
			case strings.Contains(" -u -g -h -p -C -r -t --user --group --host --prompt --close-from --role --type ", " "+option+" "):
				if index+1 >= len(words) {
					return false
				}
				index += 2
			case strings.Contains(" -n -E -H -S -b -k -K -v -i -s --login --shell --non-interactive --preserve-env ", " "+option+" ") ||
				strings.HasPrefix(option, "--user=") || strings.HasPrefix(option, "--group=") ||
				strings.HasPrefix(option, "--preserve-env=") ||
				len(option) > 2 && (strings.HasPrefix(option, "-u") || strings.HasPrefix(option, "-g")):
				index++
			case strings.HasPrefix(option, "-"):
				return false
			default:
				return actionWindowsDotNetFileCommand(strings.Join(words[index:], " "), cwd, home, depth+1)
			}
		}
		return index < len(words) && actionWindowsDotNetFileCommand(strings.Join(words[index:], " "), cwd, home, depth+1)
	}
	if program != "pwsh" && program != "powershell" {
		return false
	}
	for i := 1; i+1 < len(words); i++ {
		switch strings.ToLower(words[i]) {
		case "-command", "-c":
			return actionWindowsDotNetFileCommand(strings.Join(words[i+1:], " "), cwd, home, depth+1)
		case "-encodedcommand", "-enc":
			encoded, err := base64.StdEncoding.DecodeString(words[i+1])
			if err != nil || len(encoded) == 0 || len(encoded)%2 != 0 {
				return false
			}
			letters := make([]uint16, len(encoded)/2)
			for j := range letters {
				letters[j] = uint16(encoded[2*j]) | uint16(encoded[2*j+1])<<8
			}
			return actionWindowsDotNetFileCommand(string(utf16.Decode(letters)), cwd, home, depth+1)
		}
	}
	return false
}

func actionWindowsDotNetFileStatement(statement, cwd, home string) bool {
	statement = strings.TrimSpace(statement)
	if !strings.HasSuffix(statement, ")") {
		return false
	}
	lower := strings.ToLower(statement)
	for _, prefix := range []string{"[system.io.file]::", "[io.file]::"} {
		if !strings.HasPrefix(lower, prefix) {
			continue
		}
		call := statement[len(prefix):]
		open := strings.IndexByte(call, '(')
		if open < 0 {
			return false
		}
		method := strings.ToLower(strings.TrimSpace(call[:open]))
		switch method {
		case "appendalltext", "writealltext", "appendalllines", "writealllines",
			"writeallbytes", "appendtext", "createtext", "openwrite", "create":
		default:
			return false
		}
		args := strings.TrimSpace(call[open+1:])
		if args == "" {
			return false
		}
		var target string
		quoted := byte(0)
		if args[0] == '\'' || args[0] == '"' {
			quoted = args[0]
			end := 1
			for end < len(args) && args[end] != quoted && args[end] != '`' {
				end++
			}
			if end >= len(args) || args[end] != quoted {
				return false
			}
			target, args = args[1:end], strings.TrimSpace(args[end+1:])
		} else {
			end := strings.IndexAny(args, ",)")
			if end < 0 {
				return false
			}
			target, args = strings.TrimSpace(args[:end]), args[end:]
		}
		if args == "" || args[0] != ',' && args[0] != ')' ||
			(method == "appendalltext" || method == "writealltext" || method == "appendalllines" ||
				method == "writealllines" || method == "writeallbytes") && args[0] != ',' ||
			quoted == '\'' && strings.ContainsAny(target, "$%") ||
			quoted == '"' && strings.Contains(target, "%") {
			return false
		}
		protected, _ := actionWindowsProtected(target, cwd, home, false)
		return protected
	}
	return false
}

// A quoted nested command is one outer argument but contains its own target
// words. Inspect those words as paths; encoded PowerShell bodies are decoded
// with the same bounded UTF-16 form as the action parser.
func actionWindowsResolvedProtectedTarget(command, cwd, home string, depth int) bool {
	if depth >= 8 || len(command) > MaxPayloadBytes {
		return false
	}
	if actionWindowsDotNetFileWrite(command, cwd, home) {
		return true
	}
	words, ok := actionWindowsWords(command)
	if !ok || len(words) == 0 {
		return false
	}
	statements := actionWindowsResolvedStatements(words, cwd, home)
	if len(statements) != 1 || !slices.Equal(statements[0], words) {
		for _, statement := range statements {
			if actionWindowsResolvedProtectedTarget(strings.Join(statement, " "), cwd, home, depth+1) {
				return true
			}
		}
		return false
	}
	program := strings.TrimSuffix(strings.ToLower(programBase(words[0])), ".exe")
	// A redirect owns its destination regardless of the program's arguments.
	for i, word := range words {
		if (word == ">" || word == ">>") && i+1 < len(words) {
			if protected, _ := actionWindowsProtected(words[i+1], cwd, home, false); protected {
				return true
			}
		}
	}
	switch program {
	case "echo", "printf", "write-output", "cat", "type", "get-content", "get-childitem",
		"get-item", "get-acl", "get-filehash", "resolve-path", "test-path", "select-string",
		"grep", "rg", "head", "tail", "wc", "dir", "ls", "stat", "readlink", "diff", "cmp", "file", "findstr":
		return false
	}
	if program == "git" && len(words) > 1 {
		switch strings.ToLower(words[1]) {
		case "status", "diff", "log", "show":
			return false
		}
	}
	if program == "source" || program == "." {
		return false
	}
	if actionWindowsWrapperProgram(program) {
		return actionWindowsResolvedWrapperTarget(program, words, cwd, home, depth)
	}
	for _, extension := range []string{".ps1", ".psm1", ".cmd", ".bat", ".sh", ".bash", ".py", ".js", ".rb", ".pl"} {
		if strings.HasSuffix(program, extension) {
			return false // A script's argv is data, not its write target.
		}
	}
	if program == "python" || strings.HasPrefix(program, "python3") || program == "py" ||
		program == "node" || program == "nodejs" || program == "ruby" || program == "perl" ||
		program == "pwsh" || program == "powershell" || program == "sh" || program == "bash" ||
		program == "cmd" {
		for i, word := range words[1:] {
			switch strings.ToLower(word) {
			case "-c", "-e", "-command", "/c", "/k":
				if i+2 < len(words) {
					return actionWindowsResolvedProtectedTarget(strings.Join(words[i+2:], " "), cwd, home, depth+1)
				}
				return false
			case "-file":
				return false
			}
		}
		if program != "pwsh" && program != "powershell" {
			return false
		}
		for i, word := range words {
			if !strings.EqualFold(word, "-encodedcommand") && !strings.EqualFold(word, "-enc") || i+1 >= len(words) {
				continue
			}
			encoded, err := base64.StdEncoding.DecodeString(words[i+1])
			if err != nil || len(encoded)%2 != 0 || len(encoded) == 0 {
				return false
			}
			letters := make([]uint16, len(encoded)/2)
			for j := range letters {
				letters[j] = uint16(encoded[j*2]) | uint16(encoded[j*2+1])<<8
			}
			return actionWindowsResolvedProtectedTarget(string(utf16.Decode(letters)), cwd, home, depth+1)
		}
		return false
	}
	for i, word := range words {
		if actionWindowsPathPosition(program, i, words) {
			if program == "dd" {
				if !strings.HasPrefix(strings.ToLower(word), "of=") {
					continue
				}
				word = word[3:]
			}
			for _, token := range strings.FieldsFunc(word, func(r rune) bool {
				return r == ' ' || r == '\t' || r == '>' || r == '<' || r == ';' || r == '|' || r == '&' || r == '(' || r == ')' || r == '{' || r == '}' || r == '\'' || r == '"'
			}) {
				if protected, _ := actionWindowsProtected(token, cwd, home, false); protected {
					return true
				}
			}
		}
	}
	return false
}

func actionWindowsWrapperProgram(program string) bool {
	switch program {
	case "env", "nice", "ionice", "timeout", "stdbuf", "setsid", "chroot", "unshare", "nsenter",
		"flock", "sudo", "time", "nohup", "command", "exec", "busybox":
		return true
	}
	return false
}

// Unwrap only known option forms. The child is inspected as its own command,
// so a path in a wrapper option or environment assignment is never a target.
func actionWindowsResolvedWrapperTarget(program string, words []string, cwd, home string, depth int) bool {
	index := 1
	for index < len(words) {
		rawOption := words[index]
		option := strings.ToLower(rawOption)
		if option == "--" {
			index++
			break
		}
		if program == "env" {
			switch {
			case option == "-s" || option == "--split-string":
				return index+1 < len(words) && actionWindowsResolvedProtectedTarget(words[index+1], cwd, home, depth+1)
			case strings.HasPrefix(option, "--split-string="):
				return actionWindowsResolvedProtectedTarget(rawOption[len("--split-string="):], cwd, home, depth+1)
			case option == "-i" || option == "--ignore-environment" || option == "-v" || option == "-0" ||
				strings.HasPrefix(option, "--unset=") || strings.HasPrefix(option, "-u") && len(option) > 2:
				index++
			case option == "-u" || option == "--unset" || option == "-c" || option == "--chdir":
				if index+1 >= len(words) {
					return false
				}
				if option == "-c" || option == "--chdir" {
					var resolved bool
					cwd, resolved = actionWindowsPath(words[index+1], cwd, home)
					if !resolved {
						return false
					}
				}
				index += 2
			case strings.HasPrefix(option, "--chdir="):
				var resolved bool
				cwd, resolved = actionWindowsPath(strings.TrimPrefix(words[index], "--chdir="), cwd, home)
				if !resolved {
					return false
				}
				index++
			case strings.Contains(option, "=") && !strings.HasPrefix(option, "-"):
				index++
			case strings.HasPrefix(option, "-"):
				return index+1 < len(words) && actionWindowsResolvedProtectedTarget(strings.Join(words[index+1:], " "), cwd, home, depth+1)
			default:
				return actionWindowsResolvedProtectedTarget(strings.Join(words[index:], " "), cwd, home, depth+1)
			}
			continue
		}
		if !strings.HasPrefix(option, "-") {
			break
		}
		value, known := actionWindowsResolvedWrapperOption(program, rawOption)
		if !known || value && index+1 >= len(words) {
			return !known && index+1 < len(words) &&
				actionWindowsResolvedProtectedTarget(strings.Join(words[index+1:], " "), cwd, home, depth+1)
		}
		if program == "sudo" && (rawOption == "-D" || option == "--chdir") {
			var resolved bool
			cwd, resolved = actionWindowsPath(words[index+1], cwd, home)
			if !resolved {
				return false
			}
		}
		index++
		if value {
			index++
		}
	}
	if program == "env" {
		for index < len(words) && strings.Contains(words[index], "=") && !strings.HasPrefix(words[index], "-") {
			index++
		}
	}
	if program == "timeout" || program == "chroot" || program == "flock" {
		index++ // Duration, new root, or lock file is wrapper metadata.
	}
	return index < len(words) && actionWindowsResolvedProtectedTarget(strings.Join(words[index:], " "), cwd, home, depth+1)
}

func actionWindowsResolvedWrapperOption(program, option string) (value, known bool) {
	if program != "sudo" {
		option = strings.ToLower(option)
	}
	switch program {
	case "nice":
		return option == "-n" || option == "--adjustment", strings.HasPrefix(option, "-n") || strings.HasPrefix(option, "--adjustment") ||
			len(option) > 1 && option[0] == '-' && strings.Trim(option[1:], "0123456789") == ""
	case "ionice":
		value = option == "-c" || option == "-n" || option == "-p" || option == "-P"
		return value, value || option == "-t" || strings.Contains(option, "=") ||
			len(option) > 2 && strings.HasPrefix(option, "-c") && strings.Trim(option[2:], "0123456789") == ""
	case "timeout":
		value = option == "-s" || option == "--signal" || option == "-k" || option == "--kill-after"
		return value, value || option == "--foreground" || option == "--preserve-status" || option == "-v" || strings.Contains(option, "=")
	case "stdbuf":
		value = option == "-i" || option == "-o" || option == "-e"
		return value, value || strings.HasPrefix(option, "-i") || strings.HasPrefix(option, "-o") || strings.HasPrefix(option, "-e")
	case "setsid":
		return false, strings.Contains(" -c -f -w --ctty --fork --wait ", " "+option+" ")
	case "chroot":
		value = option == "--userspec" || option == "--groups"
		return value, value || strings.Contains(option, "=")
	case "unshare", "nsenter":
		value = program == "nsenter" && (option == "-t" || option == "--target" || option == "-s" || option == "-g")
		return value, value || strings.Contains(" -m -u -i -n -p -c -f -r --mount --uts --ipc --net --pid --user --cgroup --fork --map-root-user ", " "+option+" ") || strings.HasPrefix(option, "--mount-proc")
	case "flock":
		value = option == "-w" || option == "--timeout" || option == "-e" || option == "--conflict-exit-code"
		return value, value || strings.Contains(" -s -x -u -n -o -f --shared --exclusive --unlock --nonblock --close --no-fork ", " "+option+" ")
	case "sudo":
		if option == "-l" || option == "-ll" || option == "--list" {
			return false, false
		}
		value = strings.Contains(" -u -g -h -p -C -D -r -t --user --group --host --prompt --close-from --chdir --role --type ", " "+option+" ")
		return value, value || strings.Contains(" -n -E -H -S -b -k -K -v -i -s --login --shell --non-interactive --preserve-env ", " "+option+" ") ||
			strings.HasPrefix(option, "--user=") || strings.HasPrefix(option, "--group=") || strings.HasPrefix(option, "--preserve-env=") ||
			len(option) > 2 && (strings.HasPrefix(option, "-u") || strings.HasPrefix(option, "-g")) ||
			len(option) > 2 && option[0] == '-' && strings.Trim(option[1:], "nEHsbkKvi") == ""
	case "time":
		return option == "-f" || option == "--format", option == "-p" || option == "-f" || option == "--format" || strings.HasPrefix(option, "--format=")
	case "command":
		return false, option == "-p"
	case "exec":
		return option == "-a", option == "-a" || option == "-c" || option == "-l"
	case "nohup", "busybox":
		return false, false
	}
	return false, false
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
	case "copy-item", "copy", "cp", "cpi", "move-item", "move", "mv", "mi", "rni",
		"ln", "rsync", "install", "xcopy", "robocopy":
		if index == 0 || strings.HasPrefix(words[index], "-") {
			return false
		}
		sourceSeen, unknownOption := false, false
		for i := 1; i <= index; i++ {
			word := strings.ToLower(words[i])
			switch word {
			case "-destination", "-dest":
				return i+1 == index
			case "-path", "-literalpath":
				if i+1 == index {
					return false
				}
				i++
				sourceSeen = true
				continue
			case "-force", "-recurse", "-verbose", "-container", "-confirm", "-whatif", "-passthru":
				continue
			case "-exclude", "-filter", "-erroraction":
				if i+1 == index {
					return false
				}
				i++
				continue
			case "-t", "--target-directory":
				if program == "cp" || program == "mv" || program == "ln" || program == "install" {
					return i+1 == index
				}
			}
			if (program == "cp" || program == "mv" || program == "ln" || program == "rsync" || program == "install") &&
				len(word) > 1 && word[0] == '-' && strings.Trim(word[1:], "aAbBcCdDfFghHiIlLmMnNoOpPrRsStTuUvVxXzZ") == "" {
				continue
			}
			if (program == "xcopy" || program == "robocopy") && strings.HasPrefix(word, "/") {
				continue
			}
			if strings.HasPrefix(word, "-") {
				unknownOption = true
				continue
			}
			if i == index {
				if !unknownOption && (program == "cp" || program == "mv" || program == "ln" || program == "rsync" || program == "install" || program == "xcopy") {
					for _, next := range words[index+1:] {
						if next != "" && next[0] != '-' && (program != "xcopy" || next[0] != '/') {
							return false // A later positional operand is the destination.
						}
					}
				}
				return unknownOption || sourceSeen
			}
			sourceSeen = true
		}
		return false
	case "sed":
		for _, word := range words[1:] {
			if word == "-i" || strings.HasPrefix(word, "--in-place") {
				return index > 0 && !strings.HasPrefix(words[index], "-")
			}
		}
		return false
	case "invoke-webrequest", "iwr":
		return index > 0 && strings.EqualFold(words[index-1], "-OutFile")
	case "add-content", "set-content", "out-file":
		if index == 0 || strings.HasPrefix(words[index], "-") {
			return false
		}
		positionalPath, pathArray, unknownOption := false, false, false
		for i := 1; i <= index; i++ {
			word := strings.ToLower(words[i])
			if strings.HasPrefix(word, "-") {
				pathArray = false
				switch {
				case actionWindowsDataParameter(word):
					if i+1 == index {
						return false
					}
					i++ // Confirmed content or option value.
				case actionWindowsPathParameter(word):
					for i++; i <= index && i < len(words); i++ {
						if i == index {
							return true
						}
						if !strings.HasSuffix(words[i], ",") {
							break
						}
					}
					positionalPath = true
				case word == "-append" || word == "-force" || word == "-nonewline" ||
					word == "-passthru" || word == "-whatif" || word == "-confirm":
				default:
					unknownOption = true
				}
				continue
			}
			if i == index {
				return unknownOption || !positionalPath || pathArray
			}
			if !positionalPath || pathArray {
				positionalPath = true
				pathArray = strings.HasSuffix(words[i], ",")
			}
		}
		return false
	}
	return true
}

func actionWindowsDataParameter(word string) bool {
	return len(word) >= 3 && strings.HasPrefix("-value", word) ||
		len(word) >= 4 && strings.HasPrefix("-inputobject", word) ||
		strings.Contains(" -encoding -delimiter -stream -width ", " "+word+" ")
}

func actionWindowsPathParameter(word string) bool {
	return len(word) >= 3 && strings.HasPrefix("-path", word) ||
		len(word) >= 4 && strings.HasPrefix("-literalpath", word) ||
		len(word) >= 5 && strings.HasPrefix("-filepath", word)
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
