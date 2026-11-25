// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "strings"

// The writers the hook config registration reader did not list
// (rel-1-0-10:GAP-0506): a sqlite3 call that changes its database file and
// git config --file FILE NAME VALUE write that file. They are modeled here,
// so a write of a protected member by them is the Known write the plain
// spelling is.

// sqlRole is what one SQL text does to the database it runs on.
type sqlRole int

const (
	sqlReads   sqlRole = iota // every statement only reads
	sqlWrites                 // a statement changes the database
	sqlUnknown                // a statement or dot-command the closed reading does not accept
)

// sqliteOperands models sqlite3 [OPTIONS] FILENAME [SQL...]: the database
// file is written when a statement changes it, read when every statement
// only reads (or -readonly opened it), and has an unknown role when the SQL
// comes from standard input or the closed reading does not accept it. An
// in-memory database names no file.
func sqliteOperands(ps []Word, ctx posCtx, mk func(Word, Role) operand) []operand {
	if len(ps) == 0 || ps[0].Static && (ps[0].Value == ":memory:" || ps[0].Value == "") {
		return nil
	}
	role, known := sqlReads, len(ps) > 1
	for _, s := range ps[1:] {
		if !s.Static {
			known = false
			break
		}
		switch r := sqlTextRole(s.Value); r {
		case sqlUnknown:
			known = false
		case sqlWrites:
			role = sqlWrites
		}
	}
	readOnly := hasWordFold(ctx.words, "-readonly") || hasWordFold(ctx.words, "--readonly")
	switch {
	case !known:
		op := mk(ps[0], RoleWrite)
		op.roleUncertain = true
		return []operand{op}
	case role == sqlWrites && !readOnly:
		return []operand{mk(ps[0], RoleWrite)}
	}
	return []operand{mk(ps[0], RoleRead)}
}

// sqlTextRole reads one SQL argument: its statements split at semicolons
// outside quotes and comments. A dot-command (.shell, .output, .import ...)
// is unknown.
func sqlTextRole(text string) sqlRole {
	if strings.HasPrefix(strings.TrimSpace(text), ".") || len(text) > maxGrammarSource {
		return sqlUnknown
	}
	role := sqlReads
	var stmt strings.Builder
	flush := func() bool {
		r := sqlStatementRole(stmt.String())
		stmt.Reset()
		if r == sqlUnknown {
			return false
		}
		if r == sqlWrites {
			role = sqlWrites
		}
		return true
	}
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case c == '\'' || c == '"' || c == '`' || c == '[':
			end := c
			if c == '[' {
				end = ']'
			}
			j := strings.IndexByte(text[i+1:], end)
			if j < 0 {
				return sqlUnknown
			}
			stmt.WriteString(" ? ") // a literal or a quoted name is no keyword
			i += j + 1
		case c == '-' && i+1 < len(text) && text[i+1] == '-':
			j := strings.IndexByte(text[i:], '\n')
			if j < 0 {
				i = len(text)
			} else {
				i += j
			}
			stmt.WriteByte(' ')
		case c == '/' && i+1 < len(text) && text[i+1] == '*':
			j := strings.Index(text[i+2:], "*/")
			if j < 0 {
				return sqlUnknown
			}
			i += j + 3
			stmt.WriteByte(' ')
		case c == ';':
			if !flush() {
				return sqlUnknown
			}
		default:
			stmt.WriteByte(c)
		}
	}
	if !flush() {
		return sqlUnknown
	}
	return role
}

// sqlStatementRole reads one statement by its keywords.
func sqlStatementRole(stmt string) sqlRole {
	words := strings.FieldsFunc(strings.ToUpper(stmt), func(r rune) bool {
		return (r < 'A' || r > 'Z') && (r < '0' || r > '9') && r != '_'
	})
	if len(words) == 0 {
		return sqlReads
	}
	has := func(names ...string) bool {
		for _, w := range words {
			for _, n := range names {
				if w == n {
					return true
				}
			}
		}
		return false
	}
	switch words[0] {
	case "SELECT", "VALUES", "EXPLAIN":
		return sqlReads
	case "WITH":
		if has("INSERT", "UPDATE", "DELETE", "REPLACE") {
			return sqlWrites
		}
		return sqlReads
	case "PRAGMA":
		if strings.ContainsAny(stmt, "=(") {
			return sqlUnknown // a pragma with a value can change the file
		}
		return sqlReads
	case "BEGIN", "COMMIT", "END", "ROLLBACK", "SAVEPOINT", "RELEASE":
		return sqlReads
	case "INSERT", "UPDATE", "DELETE", "REPLACE", "CREATE", "DROP", "ALTER", "REINDEX", "ANALYZE":
		return sqlWrites
	case "VACUUM":
		if has("INTO") {
			return sqlUnknown // VACUUM INTO writes another file
		}
		return sqlWrites
	}
	return sqlUnknown // ATTACH, DETACH and anything else
}

// gitConfigFile reads git config --file FILE (also -f FILE, --file=FILE):
// file is the file the call names, role whether it reads or writes it. ok is
// false when the call names no file, or a form the reading does not accept
// (a scope option beside it, --edit, --blob, a relative file under -C or
// --git-dir, an unlisted option).
func gitConfigFile(args []Word) (file Word, role Role, ok bool) {
	i := 0
	relativeBase := false
	for ; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return Word{}, RoleNone, false
		}
		if !strings.HasPrefix(a.Value, "-") {
			break
		}
		switch a.Value {
		case "-C", "--git-dir", "--work-tree":
			relativeBase = true
			i++
		case "-c", "--namespace", "--exec-path", "--super-prefix", "--config-env":
			i++
		}
	}
	if i >= len(args) || args[i].Value != "config" {
		return Word{}, RoleNone, false
	}
	var have bool
	write, read, words := false, false, 0
	for i++; i < len(args); i++ {
		a := args[i]
		if !a.Static {
			return Word{}, RoleNone, false
		}
		v := a.Value
		switch {
		case v == "--file" || v == "-f":
			if i+1 >= len(args) || have {
				return Word{}, RoleNone, false
			}
			i++
			file, have = args[i], true
		case strings.HasPrefix(v, "--file="):
			if have {
				return Word{}, RoleNone, false
			}
			file, have = Word{Value: strings.TrimPrefix(v, "--file="), Static: true, Quoted: a.Quoted}, true
		case v == "--unset" || v == "--unset-all" || v == "--add" || v == "--replace-all" ||
			v == "--rename-section" || v == "--remove-section":
			write = true
		case v == "--get" || v == "--get-all" || v == "--get-regexp" || v == "--get-urlmatch" ||
			v == "--list" || v == "-l" || v == "--get-color" || v == "--get-colorbool":
			read = true
		case v == "--type" || v == "--default" || v == "--comment" || v == "--value":
			i++
		case strings.HasPrefix(v, "--type=") || strings.HasPrefix(v, "--default=") || strings.HasPrefix(v, "--comment=") ||
			strings.HasPrefix(v, "--value="):
		case v == "--bool" || v == "--int" || v == "--bool-or-int" || v == "--path" || v == "--expiry-date" ||
			v == "--show-origin" || v == "--show-scope" || v == "--name-only" || v == "-z" || v == "--null" ||
			v == "--includes" || v == "--no-includes" || v == "--fixed-value" || v == "--no-type":
		case strings.HasPrefix(v, "-"):
			return Word{}, RoleNone, false // a scope option, --edit, --blob or an unlisted option
		default:
			if words == 0 {
				switch v {
				case "get", "list":
					read = true
					continue
				case "set", "unset", "rename-section", "remove-section":
					write = true
					continue
				case "edit":
					return Word{}, RoleNone, false
				}
			}
			words++
		}
	}
	if !have || file.Value == "" || read && write ||
		relativeBase && !strings.HasPrefix(file.Value, "/") && !strings.HasPrefix(file.Value, "~") {
		return Word{}, RoleNone, false
	}
	if write || !read && words >= 2 {
		return file, RoleWrite, true
	}
	if read || words == 1 {
		return file, RoleRead, true
	}
	return Word{}, RoleNone, false
}

// hasGitFileOption reports a --file option (also --file=) of a git call.
func hasGitFileOption(args []Word) bool {
	for _, a := range args {
		if a.Static && (a.Value == "--file" || strings.HasPrefix(a.Value, "--file=")) {
			return true
		}
	}
	return false
}

// gitFileOptionValue is the static value of the one --file option of a git
// call (git commit --file MSG): false when there is none, more than one or a
// dynamic one.
func gitFileOptionValue(args []Word) (Word, bool) {
	var file Word
	n := 0
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a.Static && a.Value == "--file":
			if i+1 >= len(args) || !args[i+1].Static {
				return Word{}, false
			}
			i++
			file, n = args[i], n+1
		case a.Static && strings.HasPrefix(a.Value, "--file="):
			file, n = Word{Value: strings.TrimPrefix(a.Value, "--file="), Static: true, Quoted: a.Quoted}, n+1
		}
	}
	return file, n == 1 && file.Value != ""
}

// emitOperand emits the effect of one operand a model outside the row's
// positional roles names (git config --file FILE).
func (w *walker) emitOperand(op operand, origin Origin, cond bool, dialect Dialect, depth int) {
	if e := w.effectForOperand(op, Program{}, origin, cond, false, false, false, dialect, depth); e != nil {
		w.emit(*e)
	}
}

// edReading is what an ed script on standard input does to the file it
// edits: writesFile for a w / wq / W with no file name (the edited file),
// writes for the files a w names. ok is false for a script the closed
// reading does not accept (g / v command lists, ! commands, e / E / f / r,
// an unknown command, a text block left open).
type edReading struct {
	writesFile bool
	writes     []string
	ok         bool
}

// readEdScript reads an ed command script line by line: an address (line
// numbers, . $ , ; + -, marks, /re/ and ?re? searches), then one command.
func readEdScript(s string) edReading {
	var rd edReading
	if len(s) > maxGrammarSource {
		return rd
	}
	lines := strings.Split(s, "\n")
	for i := 0; i < len(lines); i++ {
		line := strings.TrimLeft(lines[i], " \t")
		j := 0
	addr:
		for j < len(line) {
			switch c := line[j]; {
			case strings.IndexByte("0123456789.,;$+- \t", c) >= 0:
				j++
			case c == '\'':
				j += 2
			case c == '/' || c == '?':
				k := j + 1
				for k < len(line) && line[k] != c {
					if line[k] == '\\' {
						k++
					}
					k++
				}
				if k >= len(line) {
					return edReading{}
				}
				j = k + 1
			default:
				break addr
			}
		}
		if j >= len(line) {
			continue // an address alone moves to (and prints) a line
		}
		rest := line[j+1:]
		switch line[j] {
		case 'p', 'n', 'l', '=', 'd', 'j', 'u', 'h', 'H', 'P', 'q', 'Q', 'z':
			if strings.TrimSpace(strings.TrimLeft(rest, "0123456789pnl")) != "" {
				return edReading{}
			}
		case 'k':
			if len(strings.TrimSpace(rest)) != 1 {
				return edReading{}
			}
		case 'm', 't':
			if strings.Trim(rest, "0123456789.,;$+- \t") != "" {
				return edReading{}
			}
		case 'a', 'i', 'c':
			if strings.TrimSpace(rest) != "" {
				return edReading{}
			}
			for i++; i < len(lines) && lines[i] != "."; i++ {
			}
			if i >= len(lines) {
				return edReading{}
			}
		case 's':
			if rest == "" || strings.ContainsRune(" \n", rune(rest[0])) {
				return edReading{}
			}
			d := rest[0]
			parts, k := 0, 1
			for ; k < len(rest) && parts < 2; k++ {
				if rest[k] == '\\' {
					k++
					continue
				}
				if rest[k] == d {
					parts++
				}
			}
			if parts < 2 || strings.Trim(rest[k:], "gpnl0123456789") != "" {
				return edReading{}
			}
		case 'w', 'W':
			rest = strings.TrimPrefix(rest, "q")
			name := strings.TrimSpace(rest)
			switch {
			case name == "":
				rd.writesFile = true
			case strings.HasPrefix(name, "!") || strings.ContainsAny(name, "$`"):
				return edReading{}
			default:
				rd.writes = append(rd.writes, name)
			}
		default:
			return edReading{} // g v G V ! e E f r x and anything unknown
		}
	}
	rd.ok = true
	return rd
}

// edOperands models ed [-s] [-p PROMPT] FILE with its script on standard
// input: FILE is written when the script writes it, read when the script
// only edits and quits, and of an unknown role when the script is not on a
// static standard input or the reading does not accept it.
func (w *walker) edOperands(ps []Word, mk func(Word, Role) operand) []operand {
	if len(ps) != 1 {
		return []operand{{role: RoleWrite, roleUncertain: true}}
	}
	rd := readEdScript(w.edStdin)
	if !w.edStdinOK || !rd.ok {
		op := mk(ps[0], RoleWrite)
		op.roleUncertain = true
		return []operand{op}
	}
	role := RoleRead
	if rd.writesFile {
		role = RoleWrite
	}
	out := []operand{mk(ps[0], role)}
	for _, name := range rd.writes {
		out = append(out, operand{value: name, static: true, quoted: true, role: RoleWrite})
	}
	return out
}
