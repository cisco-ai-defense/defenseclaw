// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import "strings"

// actionWindowsPrivateKeyRead is ActionPrivateKeyRead on a Windows home. The
// command is read as PowerShell and as a plain shell (Git Bash, cmd; GAP-1500
// refix 2). A statement is a reader after an assignment or a block keyword
// is set aside ($k = Get-Content key, do cat "$f"), and a Git Bash for loop
// binds its variable to each listed item (GAP-1780). The body of every
// expression the shell evaluates first, and the path of a .NET file read,
// is read as a command of its own: Write-Output (Get-Content key),
// "$(gc key)", [IO.File]::ReadAllText(key) (GAP-2397, GAP-1779).
func actionWindowsPrivateKeyRead(command, cwd, home string) bool {
	if actionWindowsKeyReadStatements(command, cwd, home) {
		return true
	}
	for _, plain := range []bool{false, true} {
		for _, body := range actionWindowsExpressionBodies(command, plain, false, nil) {
			if actionWindowsKeyReadStatements(body, cwd, home) {
				return true
			}
		}
	}
	return false
}

func actionWindowsKeyReadStatements(command, cwd, home string) bool {
	for _, grammar := range []actionWindowsGrammar{0, actionWindowsPlainGrammar} {
		scan := actionWindowsScan(command, grammar)
		if !scan.ok {
			// An unreadable command: each piece between separators is
			// read on its own, so a key read the misread quote hides is
			// still found (GAP-1779).
			for _, piece := range strings.FieldsFunc(command, func(r rune) bool {
				return strings.ContainsRune(";|&\r\n", r)
			}) {
				if actionPrivateKeyReadWords(actionWindowsReaderWords(strings.Fields(piece)), cwd, home, keyReadWindows, 0) {
					return true
				}
			}
			continue
		}
		// A reader after a directory change reads relative to it, in
		// any spelling of the drive (cd /c/Users/me && head .ssh/id_rsa,
		// GAP-1823). The previous directories stay candidates: cmd's cd
		// without /d does not switch the drive.
		words, start, dirs := scan.words, 0, []string{cwd}
		loops := make(map[string][]string)
		for i := 0; i <= len(words); i++ {
			if i < len(words) {
				switch words[i] {
				case ";", "&", "&&", "|", "||":
				default:
					continue
				}
			}
			statement := actionWindowsReaderWords(words[start:i])
			if len(statement) >= 3 && statement[0] == "for" && statement[2] == "in" {
				loops[statement[1]] = statement[3:]
			}
			for _, candidate := range actionWindowsLoopBindings(statement, loops) {
				for _, dir := range dirs {
					if actionPrivateKeyReadWords(candidate, dir, home, keyReadWindows, 0) {
						return true
					}
				}
			}
			if len(statement) == 2 && actionWindowsLocationProgram(statement[0]) && len(dirs) < 8 {
				if next, ok := actionWindowsPath(statement[1], dirs[len(dirs)-1], home); ok {
					dirs = append(dirs, next)
				}
			}
			start = i + 1
		}
	}
	return false
}

// actionWindowsReaderWords sets aside what precedes the program of a
// statement: block keywords (do, then, else, braces), a PowerShell
// assignment ($k = ..., [string]$k = ..., $k=...) and shell assignments
// (NAME=value).
func actionWindowsReaderWords(statement []string) []string {
	for len(statement) > 0 {
		word := statement[0]
		switch strings.ToLower(word) {
		case "do", "then", "else", "{", "}":
			statement = statement[1:]
			continue
		}
		if len(statement) >= 2 && actionWindowsVariableWord(word) {
			switch statement[1] {
			case "=", "+=", "??=":
				statement = statement[2:]
				continue
			}
		}
		if eq := strings.IndexByte(word, '='); eq > 0 && eq+1 < len(word) && actionWindowsVariableWord(word[:eq]) {
			return append([]string{word[eq+1:]}, statement[1:]...)
		}
		if eq := strings.IndexByte(word, '='); eq > 0 && actionShellName(word[:eq]) {
			statement = statement[1:]
			continue
		}
		break
	}
	return statement
}

// actionWindowsVariableWord reports a PowerShell variable reference with
// optional type casts: $k, ${k}, $script:k, [string]$k.
func actionWindowsVariableWord(word string) bool {
	for strings.HasPrefix(word, "[") {
		end := strings.IndexByte(word, ']')
		if end < 0 {
			return false
		}
		word = word[end+1:]
	}
	if len(word) < 2 || word[0] != '$' {
		return false
	}
	for _, r := range word[1:] {
		if r != '_' && r != ':' && r != '{' && r != '}' && (r < '0' || r > '9') && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}
	return true
}

func actionShellName(word string) bool {
	for i, r := range word {
		if r != '_' && (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') && (i == 0 || r < '0' || r > '9') {
			return false
		}
	}
	return word != ""
}

// actionWindowsLoopBindings returns the statement and, for each word that is
// exactly a bound loop variable ($f, ${f}), the statement with the variable
// replaced by each loop item.
func actionWindowsLoopBindings(statement []string, loops map[string][]string) [][]string {
	candidates := [][]string{statement}
	for index, word := range statement {
		if !strings.HasPrefix(word, "$") {
			continue
		}
		name := word[1:]
		if strings.HasPrefix(name, "{") && strings.HasSuffix(name, "}") {
			name = name[1 : len(name)-1]
		}
		for _, item := range loops[name] {
			if len(candidates) > 32 {
				return candidates
			}
			bound := append([]string(nil), statement...)
			bound[index] = item
			candidates = append(candidates, bound)
		}
	}
	return candidates
}

// actionWindowsExpressionBodies returns the bodies of the expressions a
// command evaluates before its statement runs, at every nesting level. In
// the PowerShell reading: (...), $(...) and @(...) outside quotes and $(...)
// inside a double-quoted string or an expandable @"..."@ here-string; the
// argument list of a .NET file read ([IO.File]::ReadAllText(path)) becomes
// "get-content <args>". In the plain reading (Git Bash): $(...) and a ( that
// starts a command. Single-quoted text, comments, literal here-strings,
// quoted-delimiter here-documents (<<'EOF') and text after an unterminated
// Git Bash backtick are not evaluated, so they yield nothing.
func actionWindowsExpressionBodies(text string, plain, hereBody bool, bodies []string) []string {
	type frame struct {
		open              int
		quote             byte
		quoteHere         bool
		reader, notSubexp bool
	}
	var stack []frame
	var quote byte
	var heredocs []actionHeredoc
	quoteHere := false
	if hereBody {
		quote, quoteHere = '"', true
	}
	escape := byte('`')
	if plain {
		escape = '\\'
	}
	for i := 0; i < len(text) && len(bodies) < 64; i++ {
		c := text[i]
		kind, size := byte(0), 1
		if plain {
			if c == '\'' || c == '"' {
				kind = c
			}
		} else if k, s := actionWindowsQuote(text, i); k != 0 {
			kind, size = k, s
		}
		switch quote {
		case '\'':
			if kind == '\'' {
				quote = 0
				i += size - 1
			}
			continue
		case '"':
			switch {
			case c == escape && i+1 < len(text):
				i++
			case plain && c == '`' && !actionPlainBacktickClosed(text, i+1):
				// Git Bash cannot parse the rest: nothing after it runs.
				return bodies
			case kind == '"' && !quoteHere:
				quote = 0
				i += size - 1
			case c == '$' && i+1 < len(text) && text[i+1] == '(':
				stack = append(stack, frame{open: i + 2, quote: '"', quoteHere: quoteHere})
				quote, quoteHere = 0, false
				i++
			}
			continue
		}
		if c == escape && i+1 < len(text) {
			i++
			continue
		}
		if plain && c == '`' && !actionPlainBacktickClosed(text, i+1) {
			return bodies
		}
		if kind != 0 {
			if !plain && i > 0 && text[i-1] == '@' {
				if bodyEnd, after, here, ok := actionWindowsHereStringEnd(text, i); here {
					if !ok {
						return bodies
					}
					if kind == '"' {
						bodies = actionWindowsExpressionBodies(text[i+size:bodyEnd], plain, true, bodies)
					}
					i = after - 1
					continue
				}
			}
			quote = kind
			i += size - 1
			continue
		}
		if c == '#' && (i == 0 || strings.IndexByte(" \t\r\n;|&(", text[i-1]) >= 0) {
			end := strings.IndexAny(text[i:], "\r\n")
			if end < 0 {
				break
			}
			i += end - 1
			continue
		}
		if !plain && c == '<' && i+1 < len(text) && text[i+1] == '#' {
			end := strings.Index(text[i+2:], "#>")
			if end < 0 {
				break
			}
			i += end + 3
			continue
		}
		if c == '<' && i+1 < len(text) && text[i+1] == '<' && (i == 0 || text[i-1] != '<') {
			if doc, after, ok := actionQuotedHeredoc(text, i+2); ok {
				heredocs = append(heredocs, doc)
				i = after - 1
				continue
			}
		}
		if c == '\n' && len(heredocs) > 0 {
			i = actionSkipHeredocBodies(text, i+1, heredocs) - 1
			heredocs = nil
			continue
		}
		switch c {
		case '(':
			f := frame{open: i + 1}
			if plain {
				prev := strings.TrimRight(text[:i], " \t")
				f.notSubexp = !(i > 0 && text[i-1] == '$' || prev == "" ||
					strings.IndexByte(";|&(\r\n", prev[len(prev)-1]) >= 0)
			} else {
				f.reader = actionWindowsFileReadMethod(text[:i])
			}
			stack = append(stack, f)
		case ')':
			if len(stack) == 0 {
				continue
			}
			f := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if !f.notSubexp {
				body := text[f.open:i]
				if f.reader {
					body = "get-content " + strings.ReplaceAll(body, ",", " ")
				}
				bodies = append(bodies, body)
			}
			quote, quoteHere = f.quote, f.quoteHere
		}
	}
	return bodies
}

// actionHeredoc is a pending here-document whose delimiter was quoted
// (<<'EOF', << "EOF", <<\EOF, <<-'EOF'): the shell does not expand its body.
type actionHeredoc struct {
	delim     string
	stripTabs bool
}

// actionQuotedHeredoc reads the delimiter word after a << operator at start
// and reports it only when part of it is quoted. An unquoted delimiter's body
// is expanded, so it stays scanned (GAP-2397 review row RV2-1).
func actionQuotedHeredoc(text string, start int) (actionHeredoc, int, bool) {
	var doc actionHeredoc
	j := start
	if j < len(text) && text[j] == '<' {
		return doc, 0, false
	}
	if j < len(text) && text[j] == '-' {
		doc.stripTabs = true
		j++
	}
	for j < len(text) && (text[j] == ' ' || text[j] == '\t') {
		j++
	}
	var word strings.Builder
	quoted := false
	for j < len(text) && strings.IndexByte(" \t\r\n;|&<>()", text[j]) < 0 {
		switch c := text[j]; c {
		case '\'', '"':
			end := strings.IndexByte(text[j+1:], c)
			if end < 0 {
				return doc, 0, false
			}
			word.WriteString(text[j+1 : j+1+end])
			quoted = true
			j += end + 2
		case '\\':
			quoted = true
			if j+1 < len(text) {
				word.WriteByte(text[j+1])
			}
			j += 2
		default:
			word.WriteByte(c)
			j++
		}
	}
	doc.delim = word.String()
	if !quoted || doc.delim == "" {
		return doc, 0, false
	}
	return doc, min(j, len(text)), true
}

// actionSkipHeredocBodies returns the offset after the delimiter line of
// each pending here-document, read in order from start (the line after the
// operator). A body without its delimiter runs to the end of the text.
func actionSkipHeredocBodies(text string, start int, docs []actionHeredoc) int {
	pos := start
	for _, doc := range docs {
		for pos < len(text) {
			end := strings.IndexByte(text[pos:], '\n')
			next := len(text)
			line := text[pos:]
			if end >= 0 {
				line, next = text[pos:pos+end], pos+end+1
			}
			line = strings.TrimSuffix(line, "\r")
			if doc.stripTabs {
				line = strings.TrimLeft(line, "\t")
			}
			pos = next
			if line == doc.delim {
				break
			}
		}
	}
	return pos
}

// actionPlainBacktickClosed reports whether a Git Bash backtick command
// substitution opened just before from has its closing backtick. Without it
// the shell stops with a syntax error and runs nothing after the backtick.
func actionPlainBacktickClosed(text string, from int) bool {
	for j := from; j < len(text); j++ {
		switch text[j] {
		case '\\':
			j++
		case '`':
			return true
		}
	}
	return false
}

// actionWindowsFileReadMethod reports a .NET static method call that reads a
// file's content ([System.IO.File]::ReadAllText( and its kin) just before an
// opening parenthesis.
func actionWindowsFileReadMethod(prefix string) bool {
	lower := strings.ToLower(strings.TrimRight(prefix, " \t"))
	for _, method := range []string{"::readalltext", "::readallbytes", "::readalllines", "::readlines", "::openread", "::opentext"} {
		if strings.HasSuffix(lower, method) {
			return true
		}
	}
	return false
}
