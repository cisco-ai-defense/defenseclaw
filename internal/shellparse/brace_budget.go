// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package shellparse

import (
	"strconv"
	"strings"
)

// MaxBraceFields and MaxBraceBytes bound the words, and the bytes, that the
// brace expansions of one command produce. A shell reader that expands a
// word (expand.Fields) builds every field in memory: a one-word range of
// 10^8 elements pinned a per-user gateway at a 2 GiB memory cap and, with no
// cap, hung its host (rel-1-0-6 GAP-0187; GAP-0568). The cost is computed
// from the text before anything expands. No ordinary command comes near it:
// mkdir -p src/{a,b,c}/{x,y} is 6 words.
const (
	MaxBraceFields = 1 << 16
	MaxBraceBytes  = 4 << 20
)

// BraceExpansionTooLarge reports whether the brace expansions of command
// would produce more than MaxBraceFields words or MaxBraceBytes bytes, in
// one linear pass over the text. A {a,b} list counts its alternatives, a
// {x..y[..s]} range of integers or single letters its elements, adjacent
// and nested groups multiply, and a word counts its fields times its
// length. Quoted and escaped braces do not expand; a brace that cannot
// expand counts once. The estimate never undercounts a word the shell
// expands, so a command it passes cannot blow up a reader.
//
// ONE BOUND RULE: the one text this pass leaves uncounted is the body of a
// quoted here-document whose command is data-only (see braceScan); a comment
// never hides text, and a body that a shell may run is counted like code.
func BraceExpansionTooLarge(command string) bool {
	if !strings.Contains(command, "<<") {
		over, _ := braceScan(command, false)
		return over
	}
	over, shellFed := braceScan(command, true)
	if over || !shellFed {
		return over
	}
	over, _ = braceScan(command, false)
	return over
}

// braceScan is the counting pass. With skipBodies it leaves out the bodies of
// quoted here-documents (rel-1-0-10:GAP-0018), and reports in shellFed
// whether some word of the text outside those bodies and the comments could
// hand a body to a shell reader (braceStatement.feed): the caller then counts
// again with no body left out.
func braceScan(command string, skipBodies bool) (over, shellFed bool) {
	var fields, bytes float64
	var heredocs []heredocDelimiter
	var statement braceStatement
	for start := 0; start < len(command); {
		// A here-document body is data the shell does not brace-expand: a
		// script or JSON text sent to python3 - <<'PY' held thousands of
		// comma lists that made the whole call "over the reading bound" and
		// every such call an ACTION-COMPOUND-LIMIT alert (rel-1-0-10:GAP-0018).
		// The operator is found outside quotes and comments (words are
		// consumed whole), and the bodies begin at the next newline.
		if command[start] == '<' && strings.HasPrefix(command[start:], "<<") && !strings.HasPrefix(command[start:], "<<<") {
			if delimiter, next, ok := heredocOperator(command, start); ok {
				if skipBodies {
					heredocs = append(heredocs, delimiter)
				}
				statement.redirected = false
				start = next
				continue
			}
		}
		if command[start] == '\n' && len(heredocs) > 0 {
			start = skipHeredocBodies(command, start+1, heredocs)
			heredocs = heredocs[:0]
			statement.reset()
			continue
		}
		// A comment runs to the end of the line, whatever quotes it holds
		// (an apostrophe in a comment must not swallow the next lines), and
		// its text still counts: a comment never stops the counting.
		if command[start] == '#' {
			end := len(command)
			if i := strings.IndexByte(command[start:], '\n'); i >= 0 {
				end = start + i
			}
			for _, word := range strings.FieldsFunc(command[start:end], func(r rune) bool {
				return r == ' ' || r == '\t' || r == '\r' || r == ';' || r == '&' || r == '|' ||
					r == '<' || r == '>' || r == '(' || r == ')'
			}) {
				n := wordBraceFields(word)
				fields += n
				bytes += n * float64(len(word))
			}
			if fields > MaxBraceFields || bytes > MaxBraceBytes {
				return true, shellFed
			}
			start = end
			continue
		}
		end := wordEnd(command, start)
		if end > start {
			word := command[start:end]
			n := wordBraceFields(word)
			fields += n
			bytes += n * float64(len(word))
			if fields > MaxBraceFields || bytes > MaxBraceBytes {
				return true, shellFed
			}
			if end < len(command) && (command[end] == '<' || command[end] == '>') && allDigits(word) {
				// 2>file: a descriptor, not a word of the command.
			} else if statement.feed(word) {
				shellFed = true
			}
			start = end
			continue
		}
		switch command[start] {
		case ';', '&', '|', '(', ')', '\n':
			statement.reset()
		case '<', '>':
			statement.redirected = true
		}
		start++
	}
	return false, shellFed
}

func allDigits(word string) bool {
	for i := 0; i < len(word); i++ {
		if word[i] < '0' || word[i] > '9' {
			return false
		}
	}
	return word != ""
}

// braceStatement follows the simple command the scan is in, so a word that
// could make a shell run a here-document is known: a program that reads its
// standard input as shell text, or a program word the text does not name.
type braceStatement struct {
	// command is false once the first word of the statement has been read.
	started bool
	// wrapped: the statement began with a word that runs another command (a
	// wrapper or a reserved word), so every later word may be the program.
	wrapped bool
	// redirected: the next word is the target of a redirect, not a word of
	// the command.
	redirected bool
}

func (s *braceStatement) reset() { *s = braceStatement{} }

// feed reads one word and reports whether it could hand a here-document to a
// shell. It is true when the word (or one blank-separated field of its
// quoted text) is a program that runs its input as shell text, or a program
// word whose value is not in the text ($VAR, command substitution) at a
// position where a program may stand. It over-reports on purpose: a false
// answer leaves a body uncounted, a true one only counts it.
func (s *braceStatement) feed(word string) bool {
	if s.redirected {
		s.redirected = false
		return false
	}
	value, dynamic := unquoteBraceWord(word)
	programPosition := !s.started || s.wrapped
	if !s.started && braceAssignment(word) {
		return false
	}
	s.started = true
	hit := false
	for _, field := range strings.Fields(value) {
		base := field
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		base = strings.TrimSuffix(strings.ToLower(base), ".exe")
		if shellStdinProgram(base) || programPosition && (base == "." || base == "source") {
			hit = true
		}
		if programPosition && braceWrapper(base) {
			s.wrapped = true
		}
	}
	if programPosition && dynamic {
		hit = true
	}
	return hit
}

// shellStdinProgram: the programs that run text on their standard input as a
// shell program, or hand it to a shell: the shells, the evaluators, and the
// programs that start one for the text they read (xargs, ssh, su, at, chroot).
func shellStdinProgram(base string) bool {
	switch base {
	case "sh", "bash", "zsh", "dash", "ksh", "mksh", "ash", "csh", "tcsh", "fish", "rbash", "busybox",
		"eval", "exec", "xargs", "ssh", "su", "at", "batch", "chroot", "nsenter", "script", "sg", "runuser":
		return true
	}
	return false
}

// braceWrapper: the words after which the program of a command may follow.
func braceWrapper(base string) bool {
	switch base {
	case "sudo", "doas", "env", "command", "nohup", "time", "nice", "ionice", "timeout", "stdbuf", "setsid", "builtin",
		"if", "then", "else", "elif", "while", "until", "do", "!", "{":
		return true
	}
	return false
}

// braceAssignment reports a leading NAME=value word.
func braceAssignment(word string) bool {
	eq := strings.IndexByte(word, '=')
	if eq <= 0 {
		return false
	}
	for i := 0; i < eq; i++ {
		c := word[i]
		if c != '_' && (c < 'a' || c > 'z') && (c < 'A' || c > 'Z') && (i == 0 || c < '0' || c > '9') {
			return false
		}
	}
	return true
}

// unquoteBraceWord removes the quotes and escapes of a word and reports
// whether it holds a parameter or a command substitution outside single
// quotes (a value the text does not spell).
func unquoteBraceWord(word string) (string, bool) {
	var out strings.Builder
	var quote byte
	dynamic := false
	for i := 0; i < len(word); i++ {
		c := word[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			} else {
				out.WriteByte(c)
			}
		case c == '\\':
			if i+1 < len(word) {
				i++
				out.WriteByte(word[i])
			}
		case quote == '"':
			if c == '"' {
				quote = 0
			} else {
				if c == '$' || c == '`' {
					dynamic = true
				}
				out.WriteByte(c)
			}
		case c == '\'' || c == '"':
			quote = c
		default:
			if c == '$' || c == '`' {
				dynamic = true
			}
			out.WriteByte(c)
		}
	}
	return out.String(), dynamic
}

// wordEnd returns the end of the shell word that starts at i: the first
// unquoted blank or operator byte. Quotes and escapes stay in the word.
func wordEnd(command string, i int) int {
	var quote byte
	for ; i < len(command); i++ {
		c := command[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ' ' || c == '\t' || c == '\n' || c == ';' || c == '&' || c == '|' ||
			c == '<' || c == '>' || c == '(' || c == ')':
			return i
		}
	}
	// A trailing backslash escapes past the end.
	return min(i, len(command))
}

// wordBraceFields is the number of fields word expands to: the product of
// its unquoted brace groups.
func wordBraceFields(word string) float64 {
	n, _ := braceSequence(word, 0, false)
	return n
}

// braceSequence reads word from i up to the end, or (inGroup) up to an
// unquoted , or } of the enclosing group, and returns the product of the
// brace groups in it and where it stopped.
func braceSequence(word string, i int, inGroup bool) (float64, int) {
	product := 1.0
	var quote byte
	for i < len(word) {
		c := word[i]
		switch {
		case quote == '\'':
			if c == '\'' {
				quote = 0
			}
		case c == '\\':
			i++
		case quote == '"':
			if c == '"' {
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case inGroup && (c == ',' || c == '}'):
			return product, i
		case c == '$' && i+1 < len(word) && word[i+1] == '{':
			// ${...} is a parameter, not a brace group.
			i = skipGroup(word, i+2)
			continue
		case c == '{':
			count, next := braceGroup(word, i)
			product *= count
			if product > MaxBraceFields*MaxBraceBytes {
				product = MaxBraceFields * MaxBraceBytes
			}
			i = next
			continue
		}
		i++
	}
	return product, i
}

// braceGroup reads the group that opens at word[open] and returns its field
// count and the index after it. A group with no closing brace, or one with
// neither a top-level comma nor a valid range, counts once.
func braceGroup(word string, open int) (float64, int) {
	if count, end, ok := braceRange(word, open); ok {
		return count, end
	}
	sum := 0.0
	alternatives := 0
	i := open + 1
	for i < len(word) {
		n, stop := braceSequence(word, i, true)
		sum += n
		alternatives++
		if stop >= len(word) {
			return 1, len(word)
		}
		if word[stop] == '}' {
			if alternatives < 2 {
				return n, stop + 1
			}
			return sum, stop + 1
		}
		i = stop + 1
	}
	return 1, len(word)
}

// braceRange reads {x..y} or {x..y..s} at word[open], with integer or
// single-letter ends, and returns its element count.
func braceRange(word string, open int) (float64, int, bool) {
	close := open + 1
	for close < len(word) && word[close] != '}' && close-open <= 64 {
		close++
	}
	if close >= len(word) || word[close] != '}' {
		return 0, 0, false
	}
	parts := splitDots(word[open+1 : close])
	if len(parts) != 2 && len(parts) != 3 {
		return 0, 0, false
	}
	step := 1.0
	if len(parts) == 3 {
		s, err := strconv.ParseInt(parts[2], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		if s < 0 {
			s = -s
		}
		if s > 1 {
			step = float64(s)
		}
	}
	if lo, err := strconv.ParseInt(parts[0], 10, 64); err == nil {
		hi, err := strconv.ParseInt(parts[1], 10, 64)
		if err != nil {
			return 0, 0, false
		}
		span := float64(hi) - float64(lo)
		if span < 0 {
			span = -span
		}
		return span/step + 1, close + 1, true
	}
	if len(parts[0]) == 1 && len(parts[1]) == 1 {
		span := float64(parts[1][0]) - float64(parts[0][0])
		if span < 0 {
			span = -span
		}
		return span/step + 1, close + 1, true
	}
	return 0, 0, false
}

// splitDots splits a range body at "..".
func splitDots(body string) []string {
	var parts []string
	start := 0
	for i := 0; i+1 < len(body); i++ {
		if body[i] == '.' && body[i+1] == '.' {
			parts = append(parts, body[start:i])
			start = i + 2
			i++
		}
	}
	return append(parts, body[start:])
}

// skipGroup returns the index after the } that closes a ${ opened before i.
func skipGroup(word string, i int) int {
	depth := 1
	for ; i < len(word); i++ {
		switch word[i] {
		case '{':
			depth++
		case '}':
			if depth--; depth == 0 {
				return i + 1
			}
		}
	}
	return i
}

// heredocDelimiter is the end marker of a here-document and whether leading
// tabs of its lines are ignored (<<-).
type heredocDelimiter struct {
	word    string
	dashTab bool
	// quoted: the delimiter is quoted or escaped, so the body is literal text.
	// An unquoted body expands dollar-paren and backticks, which run commands.
	quoted bool
}

// heredocOperator reads the << or <<- at i and the delimiter word after it.
// It returns the position after the delimiter word.
func heredocOperator(command string, i int) (heredocDelimiter, int, bool) {
	j := i + 2
	var delimiter heredocDelimiter
	if j < len(command) && command[j] == '-' {
		delimiter.dashTab = true
		j++
	}
	for j < len(command) && (command[j] == ' ' || command[j] == '\t') {
		j++
	}
	end := wordEnd(command, j)
	if end <= j {
		return delimiter, 0, false
	}
	var word strings.Builder
	for k := j; k < end; k++ {
		switch c := command[k]; c {
		case '\'', '"':
			delimiter.quoted = true
		case '\\':
			delimiter.quoted = true
			if k+1 < end {
				k++
				word.WriteByte(command[k])
			}
		default:
			word.WriteByte(c)
		}
	}
	if word.Len() == 0 {
		return delimiter, 0, false
	}
	delimiter.word = word.String()
	return delimiter, end, true
}

// skipHeredocBodies returns the position after the bodies of delimiters,
// which start at from (the line after the operators). A body ends at a line
// equal to its delimiter; an unterminated body runs to the end of the text,
// as the shell reads it.
func skipHeredocBodies(command string, from int, delimiters []heredocDelimiter) int {
	for _, delimiter := range delimiters {
		if !delimiter.quoted {
			// An unquoted body runs $( ) and backticks: it is counted as code.
			return from
		}
	}
	pos := from
	for _, delimiter := range delimiters {
		for pos < len(command) {
			lineEnd := strings.IndexByte(command[pos:], '\n')
			line := command[pos:]
			next := len(command)
			if lineEnd >= 0 {
				line = command[pos : pos+lineEnd]
				next = pos + lineEnd + 1
			}
			if delimiter.dashTab {
				line = strings.TrimLeft(line, "\t")
			}
			line = strings.TrimSuffix(line, "\r")
			pos = next
			if line == delimiter.word {
				break
			}
		}
	}
	return pos
}
