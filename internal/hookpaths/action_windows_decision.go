// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/base64"
	"path"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
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

// actionWindowsGrammar selects how actionWindowsScan reads a command.
type actionWindowsGrammar uint8

const (
	// actionWindowsPlainGrammar reads only ASCII quotes, with no comment and
	// no escape rule. A shell other than PowerShell (Git Bash, cmd) may run a
	// command sent from a Windows home, and it reads comments, smart quotes
	// and the backtick differently; a protected decision holds when either
	// reading finds the target (GAP-1500 refix 2).
	actionWindowsPlainGrammar actionWindowsGrammar = 1 << iota
	// actionWindowsLiteralDollar keeps a $ inside a single-quoted string or
	// an @'...'@ here-string from reading as a home variable ($ -> @).
	actionWindowsLiteralDollar
)

// actionWindowsScanResult is one reading of a command. quoted[i] reports a
// word whose first character is quoted (GAP-1473).
type actionWindowsScanResult struct {
	words   []string
	literal []bool
	quoted  []bool
	ok      bool
}

// actionWindowsWords treats a quoted command body as one word and emits each
// redirection separately, preserving an attached file descriptor. An unclosed
// quote leaves the command unproved. Quotes, escapes and comments follow
// PowerShell: ‘ ’ ‚ ‛ are single quotes and “ ” „ double quotes, like ' and ";
// outside single quotes a backtick escapes the next character (a quote, a
// blank, a # or a separator is then part of the word; a backtick at a line
// end continues the line); a # that starts a token comments out the rest of
// its line, and <# ... #> is a block comment. A PowerShell here-string (@' or
// @" at the end of its line) is one word, "@" + body + "@", and runs to the
// line that starts with its closing '@ or "@: a quote inside the body (It's,
// "x") does not end it. literal[i] reports a word that is exactly one
// @'...'@ here-string, whose body PowerShell does not expand ($ and the
// backtick are characters there).
func actionWindowsWords(command string) (words []string, literal []bool, ok bool) {
	scan := actionWindowsScan(command, 0)
	return scan.words, scan.literal, scan.ok
}

func actionWindowsScan(command string, grammar actionWindowsGrammar) (result actionWindowsScanResult) {
	plain := grammar&actionWindowsPlainGrammar != 0
	literalDollar := grammar&actionWindowsLiteralDollar != 0
	var word strings.Builder
	var quote byte
	hereLen := -1
	quoted := false // the current word has a quote, possibly an empty one
	startQuoted := false
	emit := func(value string, isLiteral, isQuoted bool) {
		result.words = append(result.words, value)
		result.literal = append(result.literal, isLiteral)
		result.quoted = append(result.quoted, isQuoted)
	}
	flush := func() {
		if word.Len() > 0 {
			emit(word.String(), word.Len() == hereLen, startQuoted)
			word.Reset()
		}
		hereLen = -1
		quoted = false
		startQuoted = false
	}
	quoteAt := func(i int) (byte, int) {
		if plain {
			if c := command[i]; c == '\'' || c == '"' {
				return c, 1
			}
			return 0, 0
		}
		return actionWindowsQuote(command, i)
	}
	// escaped writes the backtick at i and the character after it. With
	// literalDollar a backtick-escaped $ is literal text (GAP-1504).
	escaped := func(i int) int {
		if literalDollar && command[i+1] == '$' {
			word.WriteByte('@')
			return i + 1
		}
		_, size := utf8.DecodeRuneInString(command[i+1:])
		word.WriteString(command[i : i+1+size])
		return i + size
	}
	for i := 0; i < len(command); i++ {
		c := command[i]
		kind, size := quoteAt(i)
		if quote != 0 {
			switch {
			case kind == quote:
				quote = 0
				i += size - 1
			case !plain && quote == '"' && c == '`' && i+1 < len(command):
				i = escaped(i)
			case literalDollar && quote == '\'' && c == '$':
				word.WriteByte('@')
			default:
				if word.Len() == 0 {
					startQuoted = true
				}
				word.WriteByte(c)
			}
			continue
		}
		if !plain && c == '`' && i+1 < len(command) {
			if next := command[i+1]; next == '\r' || next == '\n' {
				// A line continuation is a blank.
				flush()
				i++
				if next == '\r' && i+1 < len(command) && command[i+1] == '\n' {
					i++
				}
				continue
			}
			i = escaped(i)
			continue
		}
		if !plain && word.Len() == 0 && !quoted && (i == 0 || strings.IndexByte(" \t\r\n;|&", command[i-1]) >= 0) {
			if c == '#' {
				end := strings.IndexAny(command[i:], "\r\n")
				if end < 0 {
					break
				}
				i += end - 1
				continue
			}
			if c == '<' && i+1 < len(command) && command[i+1] == '#' {
				end := strings.Index(command[i+2:], "#>")
				if end < 0 {
					return result
				}
				i += end + 3
				continue
			}
		}
		if kind != 0 {
			if word.String() == "@" {
				if bodyEnd, after, here, ok := actionWindowsHereStringEnd(command, i); here {
					if !ok {
						return result
					}
					body := command[i+size : bodyEnd]
					if literalDollar && kind == '\'' {
						body = strings.ReplaceAll(body, "$", "@")
					}
					word.WriteString(body)
					word.WriteByte('@')
					if kind == '\'' {
						hereLen = word.Len()
					}
					i = after - 1
					continue
				}
			}
			quote, quoted = kind, true
			i += size - 1
			continue
		}
		switch c {
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
				emit(command[i:i+2], false, false)
				i++
			} else {
				emit(command[i:i+1], false, false)
			}
		default:
			word.WriteByte(c)
		}
	}
	flush()
	result.ok = quote == 0
	return result
}

// actionWindowsHereStringEnd reads the here-string whose opening quote is at
// command[open] (after an @). A quote followed by nonblanks on its line is an
// ordinary quote. bodyEnd is the first byte of the closing marker, and after
// is the byte after it. PowerShell also accepts lone CR line ends and smart
// quote closing markers. An indented closer or no closer is unproved.
func actionWindowsHereStringEnd(command string, open int) (bodyEnd, after int, here, ok bool) {
	quote, size := actionWindowsQuote(command, open)
	newline := strings.IndexAny(command[open+size:], "\r\n")
	if quote == 0 || newline < 0 || strings.Trim(command[open+size:open+size+newline], " \t") != "" {
		return 0, 0, false, false
	}
	firstEnd := open + size + newline
	start := firstEnd + 1
	if command[firstEnd] == '\r' && start < len(command) && command[start] == '\n' {
		start++
	}
	for start <= len(command) {
		lineEnd := len(command)
		if next := strings.IndexAny(command[start:], "\r\n"); next >= 0 {
			lineEnd = start + next
		}
		line := command[start:lineEnd]
		if size := actionWindowsHereStringCloserLen(line, quote); size > 0 {
			return start, start + size, true, true
		}
		if actionWindowsHereStringCloserLen(strings.TrimLeft(line, " \t"), quote) > 0 {
			return 0, 0, true, false
		}
		if lineEnd == len(command) {
			break
		}
		start = lineEnd + 1
		if command[lineEnd] == '\r' && start < len(command) && command[start] == '\n' {
			start++
		}
	}
	return 0, 0, true, false
}

// actionWindowsQuote reports the quote that starts at command[i] and its
// length: PowerShell reads ‘ ’ ‚ ‛ as ' and “ ” „ as ".
func actionWindowsQuote(command string, i int) (kind byte, size int) {
	if c := command[i]; c == '\'' || c == '"' {
		return c, 1
	}
	if command[i] == 0xE2 && i+2 < len(command) && command[i+1] == 0x80 {
		switch command[i+2] {
		case 0x98, 0x99, 0x9A, 0x9B:
			return '\'', 3
		case 0x9C, 0x9D, 0x9E:
			return '"', 3
		}
	}
	return 0, 0
}

func actionWindowsHereStringCloserLen(line string, quote byte) int {
	if quote == '\'' {
		for _, closer := range [...]string{"'@", "‘@", "’@", "‚@", "‛@"} {
			if strings.HasPrefix(line, closer) {
				return len(closer)
			}
		}
	} else {
		for _, closer := range [...]string{"\"@", "“@", "”@", "„@"} {
			if strings.HasPrefix(line, closer) {
				return len(closer)
			}
		}
	}
	return 0
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
	words, literal, ok := actionWindowsWords(command)
	if !ok || len(words) == 0 {
		return "shell-parse"
	}
	spans := actionWindowsResolvedSpans(words, cwd, home)
	for i := 0; i < len(spans); i++ {
		span := spans[i]
		statement := span.words
		// A here-string piped into apply_patch (@'...'@ | apply_patch)
		// is the same envelope argument as apply_patch @'...'@.
		if _, piped := actionWindowsPipedPatch(words, statement, span.end); piped &&
			i+1 < len(spans) && spans[i+1].start == span.end+1 {
			if reason, judged := actionWindowsPatchDecision([]string{words[span.end+1], statement[0]}, literal[span.start], cwd, home); judged {
				if reason != "" {
					return reason
				}
				i++ // the apply_patch statement was judged with its envelope
				continue
			}
		}
		// apply_patch @'...'@ reads a literal envelope ($ and ` included).
		if len(statement) == 2 && literal[span.start+1] && isApplyPatchToolName(
			strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(statement[0], `\`, "/")), ".exe"))) {
			if reason, judged := actionWindowsPatchDecision(statement, true, cwd, home); judged {
				if reason != "" {
					return reason
				}
				continue
			}
		}
		if reason := actionWindowsStatement(statement, cwd, home, depth); reason != "" {
			return reason
		}
	}
	return ""
}

// actionWindowsResolvedSpan is one statement after assignment resolution and
// where it sits in the command words: words[start:end], end its separator.
type actionWindowsResolvedSpan struct {
	words      []string
	start, end int
}

// Keep bounded assignment resolution common to audit and enforcement. Only
// literal assignments and Join-Path children are substituted into commands.
func actionWindowsResolvedSpans(words []string, cwd, home string) []actionWindowsResolvedSpan {
	values := make(map[string]string)
	var spans []actionWindowsResolvedSpan
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
			spans = append(spans, actionWindowsResolvedSpan{words: statement, start: start, end: end})
		}
		start = end + 1
	}
	return spans
}

// actionWindowsPipedPatch reports a one-word statement piped into a bare
// apply_patch statement, and the index after that statement.
func actionWindowsPipedPatch(words, statement []string, end int) (int, bool) {
	if len(statement) != 1 || end+1 >= len(words) || words[end] != "|" {
		return 0, false
	}
	next := end + 2
	if next < len(words) && words[next] != ";" && words[next] != "|" && words[next] != "||" &&
		words[next] != "&" && words[next] != "&&" {
		return 0, false
	}
	program := strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(words[end+1], `\`, "/")), ".exe"))
	if !isApplyPatchToolName(program) {
		return 0, false
	}
	return next + 1, true
}

// actionWindowsPatchDecision judges an apply_patch that reads one envelope as
// its only argument, the way Copilot CLI on Windows sends a patch through its
// PowerShell tool (apply_patch @'...'@). Each directive path gets the same
// protected-file check as a redirect operand. The envelope word was read as a
// path before, so every patch naming an absolute or nested project file was
// denied as a dynamic argument. Any other form (more than one argument or
// envelope, a body PowerShell could expand: $ or a backtick outside a
// literal @'...'@ here-string, as in an @"..."@ one) is not judged here and
// keeps the generic word check.
func actionWindowsPatchDecision(words []string, literal bool, cwd, home string) (string, bool) {
	if len(words) != 2 {
		return "", false
	}
	envelope := strings.TrimSuffix(strings.TrimPrefix(words[1], "@"), "@")
	if !literal && strings.ContainsAny(envelope, "$`") || !strings.HasPrefix(strings.TrimSpace(envelope), patchBeginMarker) {
		return "", false
	}
	paths, envelopes, ok := patchEnvelopePaths(envelope)
	if !ok || envelopes != 1 || len(paths) == 0 {
		return "", false
	}
	for _, target := range paths {
		protected, resolved := actionWindowsProtected(target, cwd, home, false)
		if protected || !resolved {
			return "dynamic-argument", true
		}
	}
	return "", true
}

func actionWindowsStatement(words []string, cwd, home string, depth int) string {
	if depth >= 8 {
		return "dynamic-command"
	}
	program := strings.ToLower(strings.TrimSuffix(path.Base(strings.ReplaceAll(words[0], `\`, "/")), ".exe"))
	if isApplyPatchToolName(program) {
		if reason, judged := actionWindowsPatchDecision(words, false, cwd, home); judged {
			return reason
		}
	}
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
