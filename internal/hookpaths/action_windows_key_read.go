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
// quoted-delimiter here-documents (<<'EOF', Git Bash reading only, at command
// level: not inside ${...}, $((...)) or a[...]), a PowerShell stop-parsing
// tail (--%) and text after an unterminated Git Bash backtick are not
// evaluated, so they yield nothing. PowerShell has no here-documents: in its
// reading a << is a parse error and nothing after it is read (RV5-1, RV5-2).
func actionWindowsExpressionBodies(text string, plain, hereBody bool, bodies []string) []string {
	type frame struct {
		open              int
		quote             byte
		quoteHere         bool
		reader, notSubexp bool
		// arith is a Git Bash $(( or (( arithmetic frame: a << there
		// is a shift, not a here-document (RV5-2).
		arith bool
	}
	var stack []frame
	var quote byte
	var heredocs []actionHeredoc
	lines := &HeredocLines{}
	// braces counts the open ${...} parameter expansions and subscript the
	// open name[...] subscripts of the Git Bash reading: a << there is
	// pattern or arithmetic text, not a here-document (RV5-2).
	// arith counts the open arithmetic frames.
	braces, subscript, arith := 0, 0, 0
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
			case !plain && c == '$' && i+1 < len(text) && text[i+1] == '$':
				i++
			case !plain && c == '$' && i+1 < len(text) && text[i+1] == '{':
				// "${C:\Users\me\.ssh\id_ed25519}" reads the file
				// through the FileSystem provider (GAP-2409).
				if end := actionWindowsBracedVariableEnd(text, i+2); end > 0 {
					if body, ok := actionWindowsProviderPathRead(text[i+2 : end]); ok {
						bodies = append(bodies, body)
					}
				}
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
		if !plain && c == '-' && strings.HasPrefix(text[i:], "--%") &&
			(i == 0 || strings.IndexByte(" \t", text[i-1]) >= 0) &&
			(i+3 == len(text) || strings.IndexByte(" \t\r\n", text[i+3]) >= 0) {
			// The PowerShell stop-parsing token: the rest of the line, up
			// to a pipe, goes verbatim to a native program; PowerShell
			// evaluates none of it, and the next line runs (RV5-1).
			end := strings.IndexAny(text[i:], "\r\n|")
			if end < 0 {
				break
			}
			i += end - 1
			continue
		}
		if !plain && c == '$' && i+1 < len(text) && text[i+1] == '$' {
			// $$ is one variable token: a { after it opens a script
			// block, not a braced variable name, and ForEach-Object $${...}
			// runs that block (RV7-1).
			i++
			continue
		}
		if !plain && c == '$' && i+1 < len(text) && text[i+1] == '{' {
			// A PowerShell braced variable name (${a<<b}, ${a'b}) is
			// text up to its first unescaped }; nothing in it is
			// evaluated. An unterminated one is scanned on (RV6-1). A
			// provider-qualified name (${C:\Users\me\.ssh\id_ed25519})
			// reads that item's content (GAP-2409).
			if end := actionWindowsBracedVariableEnd(text, i+2); end > 0 {
				if body, ok := actionWindowsProviderPathRead(text[i+2 : end]); ok {
					bodies = append(bodies, body)
				}
				i = end
				continue
			}
		}
		if !plain && c == '<' && i+1 < len(text) && text[i+1] == '<' &&
			(i == 0 || strings.IndexByte(" \t\r\n;|&(){}", text[i-1]) >= 0) {
			// PowerShell has no here-documents: a << that starts a token
			// outside a string, a comment, a braced variable name or a
			// stop-parsing tail is a parse error, so PowerShell runs
			// nothing of the command (RV5-1). A << inside a bareword
			// (a<<b, a#<<) is text and the scan goes on (RV6-1).
			return bodies
		}
		if plain {
			switch {
			case c == '$' && i+1 < len(text) && text[i+1] == '{':
				braces++
				i++
				continue
			case c == '{' && braces > 0:
				braces++
			case c == '}' && braces > 0:
				braces--
			case c == '[' && i > 0 && actionShellName(text[i-1:i]):
				subscript++
			case c == ']' && subscript > 0:
				subscript--
			case c == '\n':
				subscript = 0
			}
		}
		if plain && c == '<' && i+1 < len(text) && text[i+1] == '<' && (i == 0 || text[i-1] != '<') &&
			braces == 0 && subscript == 0 && arith == 0 {
			if doc, after, ok := actionQuotedHeredoc(text, i+2); ok {
				doc.level = len(stack)
				heredocs = append(heredocs, doc)
				if doc.quoted {
					i = after - 1
					continue
				}
			}
		}
		if c == '\n' && len(heredocs) > 0 && len(stack) <= heredocs[0].level {
			// The bodies start after the line that ends the command: a
			// newline inside a $(...) opened after the operator is still
			// command text (cat <<'A' $(echo x<newline>...), RV5-2).
			i = actionSkipHeredocBodies(text, i+1, heredocs, lines) - 1
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
				f.arith = !f.notSubexp && i+1 < len(text) && text[i+1] == '('
				if f.arith {
					arith++
				}
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
			if f.arith {
				arith--
			}
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
	// quoted is false for an unquoted delimiter (<<EOF): its body is
	// expanded and must stay scanned (RV4-1).
	quoted bool
	// level is the expression nesting of the operator.
	level int
}

// actionQuotedHeredoc reads the delimiter word after a << operator at start
// and reports every pending here-document, with quoted set when part of the
// delimiter is quoted. An unquoted delimiter's body is expanded, so it stays
// scanned (GAP-2397 review rows RV2-1, RV4-1).
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
		case '$':
			// $'EOF' (ANSI-C) and $"EOF" (locale) quoting: quote removal
			// drops the $, so bash ends the body at the line EOF (RV3-1).
			if j+1 < len(text) && (text[j+1] == '\'' || text[j+1] == '"') {
				j++
				continue
			}
			word.WriteByte(c)
			j++
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
	if doc.delim == "" {
		return doc, 0, false
	}
	doc.quoted = quoted
	return doc, min(j, len(text)), true
}

// actionSkipHeredocBodies returns the offset after the delimiter line of
// each pending here-document, read in order from start (the line after the
// operator). When a delimiter line is never found (a malformed here-document
// or a delimiter spelling this reading does not model) it returns start, so
// the rest stays scanned: over-block, never under-block (RV3-1). It also
// returns start when any pending here-document is unquoted, because its
// expanded body lies on these lines (cat <<B; cat <<'A', RV4-1).
func actionSkipHeredocBodies(text string, start int, docs []actionHeredoc, lines *HeredocLines) int {
	for _, doc := range docs {
		if !doc.quoted {
			return start
		}
	}
	pos := start
	for _, doc := range docs {
		// lines finds the delimiter line in time linear in text over all
		// the bodies of one reading (GAP-2557).
		_, lineEnd, found := lines.Next(text, doc.delim, doc.stripTabs, pos)
		if !found {
			return start
		}
		pos = min(lineEnd+1, len(text))
	}
	return pos
}

// actionWindowsBracedVariableEnd returns the index of the } that ends a
// PowerShell braced variable name whose text starts at from (after ${), or
// -1 when it is not terminated. A backtick escapes the next character.
func actionWindowsBracedVariableEnd(text string, from int) int {
	for i := from; i < len(text); i++ {
		switch text[i] {
		case '`':
			i++
		case '}':
			return i
		}
	}
	return -1
}

// actionWindowsProviderPathRead returns "get-content '<path>'" (double
// quotes when the path has an apostrophe) for a
// PowerShell braced variable name that is a provider path (${C:\f},
// ${Temp:\f}, ${c:f}): PowerShell reads the variable from that drive, so a
// FileSystem drive yields the file's content. Scope modifiers and the
// env, variable, function and alias drives name no file.
func actionWindowsProviderPathRead(name string) (string, bool) {
	colon := strings.IndexByte(name, ':')
	if colon <= 0 || colon+1 >= len(name) {
		return "", false
	}
	switch strings.ToLower(name[:colon]) {
	case "global", "local", "script", "private", "using", "workflow",
		"env", "variable", "function", "alias":
		return "", false
	}
	path := strings.ReplaceAll(strings.ReplaceAll(name, "``", "\x00"), "`", "")
	path = strings.ReplaceAll(path, "\x00", "`")
	switch {
	case strings.ContainsAny(path, "\r\n"):
		return "", false
	case !strings.Contains(path, "'"):
		return "get-content '" + path + "'", true
	case !strings.ContainsAny(path, "\"$`"):
		return "get-content \"" + path + "\"", true
	}
	return "", false
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
	// Lower only the tail the method names can match: lowering the whole
	// prefix for every ( made a long command quadratic (RV14-2 class).
	trimmed := strings.TrimRight(prefix, " \t")
	if len(trimmed) > 32 {
		trimmed = trimmed[len(trimmed)-32:]
	}
	lower := strings.ToLower(trimmed)
	for _, method := range []string{"::readalltext", "::readallbytes", "::readalllines", "::readlines", "::openread", "::opentext"} {
		if strings.HasSuffix(lower, method) {
			return true
		}
	}
	return false
}
