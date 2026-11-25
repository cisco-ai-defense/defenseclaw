// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package awkprog reads the text of an awk program far enough to say what
// shell commands it runs (rel-1-0-10:GAP-0499). Awk starts a shell command
// through three channels: system(EXPR), print or printf ... | EXPR (and the
// gawk |& coprocess form), and EXPR | getline. The readers of the hook path
// judge a command the program runs exactly as if the hook had run it
// directly, so a program whose command expression is a string literal (or a
// concatenation of literals) hands them that command text, and a program
// whose command is built from anything else is reported as dynamic: the
// callers answer it at the unknown tier of the pack, never as an allow.
//
// The scan is a tokenizer, not a pattern over raw text: strings, regular
// expression literals and comments are data, and || is a logical operator.
// It is linear in the program text, which the hook payload bound already
// limits, and keeps no state between calls.
package awkprog

import (
	"strings"
)

// Kind is the channel through which a program starts a command.
type Kind uint8

// The three channels of an awk program.
const (
	// System is system(EXPR).
	System Kind = iota + 1
	// PrintPipe is print or printf ... | EXPR (also |&).
	PrintPipe
	// GetlinePipe is EXPR | getline (also |&).
	GetlinePipe
)

// String is the channel's audit name.
func (k Kind) String() string {
	switch k {
	case System:
		return "system"
	case PrintPipe:
		return "print-pipe"
	case GetlinePipe:
		return "getline-pipe"
	}
	return "unknown"
}

// DynamicReason is the audit reason of a program that runs a command the
// scan cannot read: the command is built from a field, a variable or any
// other expression, or the program text is not one awk accepts.
const DynamicReason = "awk_command_dynamic"

// Channel is one place a program starts a shell command.
type Channel struct {
	Kind Kind
	// Commands are the command texts the channel can run when its expression
	// is a string literal or a concatenation of literals: the whole
	// concatenation, and for an unparenthesized concatenation before
	// | getline also its last literal alone (POSIX leaves the precedence of
	// that form unspecified, and one awk reads the shorter command).
	Commands []string
	// Dynamic reports that the command is not fully known: it is built from
	// something other than literals.
	Dynamic bool
}

// Program is what the scan found.
type Program struct {
	Channels []Channel
	// Directive reports a gawk @ directive (@include, @load): more code the
	// scan does not read.
	Directive bool
	// Truncated reports a program longer than MaxProgramBytes: the scan read
	// the text before the cap and nothing after it, so the program counts as
	// one that runs a command it cannot read (the one bound rule).
	Truncated bool
	// Malformed reports a string or regular expression literal with no end
	// awk accepts, so the program does not run as this scan reads it. Every
	// awk refuses such a program at its syntax check and runs nothing; the
	// scan may still disagree with an awk about where a literal ends, so the
	// program counts as a command it cannot read when its text holds a word
	// or a pipe that starts one (Commands).
	Malformed bool
	// channelText: the text holds system, getline, a pipe or an @ directive.
	channelText bool
	// Outputs are the files a print or printf statement redirects into
	// (print ... > "file", >> "file") when the target is a string literal or
	// a concatenation of literals. Awk opens the file itself, so the call
	// writes it as a shell redirect would (rel-1-0-10:GAP-1239). A target
	// built from anything else is not listed.
	Outputs []Output
}

// Output is a file a print or printf statement redirects into.
type Output struct {
	// Target is the file name as awk opens it: no ~ or variable expansion.
	Target string
	// Append is the >> form; > truncates the file when awk first opens it.
	Append bool
	// RecordInput proves that this is the sole action of an unguarded record
	// program, and print (or printf "%s", $0) sends the input record.
	RecordInput bool
}

// Redirect is the shell command that writes Target as the print redirect
// does: the null command with the same redirection, the target single-quoted
// so the shell reads it as the literal awk opens.
func (o Output) Redirect() string {
	operator := ">"
	if o.Append {
		operator = ">>"
	}
	return ": " + operator + " '" + strings.ReplaceAll(o.Target, "'", `'\''`) + "'"
}

// RedirectInput is the plain shell reading of an unguarded awk record
// action that sends static input files to a literal network redirect.
func (o Output) RedirectInput(inputs []string) string {
	if len(inputs) == 0 {
		return o.Redirect()
	}
	operator := ">"
	if o.Append {
		operator = ">>"
	}
	var b strings.Builder
	b.WriteString("cat")
	for _, input := range inputs {
		b.WriteString(" '")
		b.WriteString(strings.ReplaceAll(input, "'", `'\''`))
		b.WriteByte(39)
	}
	b.WriteByte(' ')
	b.WriteString(operator)
	b.WriteString(" '")
	b.WriteString(strings.ReplaceAll(o.Target, "'", `'\''`))
	b.WriteByte(39)
	return b.String()
}

// RunsCommand reports a program with a command channel, a directive that
// loads more code, or text the scan cannot read to its end.
func (p Program) RunsCommand() bool {
	return len(p.Channels) > 0 || p.Directive || p.Malformed || p.Truncated
}

// Commands are the static command texts of every channel, and whether some
// command of the program is not fully known.
func (p Program) Commands() (commands []string, dynamic bool) {
	for _, c := range p.Channels {
		commands = append(commands, c.Commands...)
		dynamic = dynamic || c.Dynamic
	}
	return commands, dynamic || p.Directive || p.Truncated || p.Malformed && p.channelText
}

type tokenKind uint8

const (
	tokString  tokenKind = iota + 1 // a string literal; text is its value
	tokRegex                        // a regular expression literal
	tokWord                         // an identifier, keyword, builtin or number
	tokPunct                        // an operator or delimiter
	tokNewline                      // a statement-ending newline
)

type token struct {
	kind tokenKind
	text string
}

// MaxProgramBytes bounds the program text one scan reads. The scan is linear
// in the text for ordinary programs and worse for a flood of tokens with no
// delimiter, so a longer program is cut here and reported Truncated.
const MaxProgramBytes = 64 << 10

// Parse scans the program text for its command channels.
func Parse(code string) Program {
	var p Program
	if len(code) > MaxProgramBytes {
		code, p.Truncated = code[:MaxProgramBytes], true
	}
	p.channelText = strings.ContainsAny(code, "|@") || strings.Contains(code, "system") || strings.Contains(code, "getline")
	tokens := tokenize(code, &p)
	match := matchParens(tokens)
	for i, t := range tokens {
		switch {
		case t.kind == tokWord && t.text == "system":
			p.addSystem(tokens, match, i)
		case t.kind == tokWord && (t.text == "print" || t.text == "printf"):
			p.addPrintPipe(tokens, match, i)
		case t.kind == tokPunct && (t.text == "|" || t.text == "|&"):
			if i+1 < len(tokens) && tokens[i+1].kind == tokWord && tokens[i+1].text == "getline" {
				p.addGetline(tokens, match, i)
			}
		}
	}
	// A pipe that no print statement or getline owns is not valid awk, and
	// no awk runs it as a command; it is still a command effect for the
	// callers that only ask whether one exists.
	owned := 0
	for _, c := range p.Channels {
		if c.Kind != System {
			owned++
		}
	}
	pipes := 0
	for _, t := range tokens {
		if t.kind == tokPunct && (t.text == "|" || t.text == "|&") {
			pipes++
		}
	}
	for ; owned < pipes; owned++ {
		p.Channels = append(p.Channels, Channel{Kind: PrintPipe, Dynamic: true})
	}
	return p
}

// WordByte reports a byte of an awk name or number.
func WordByte(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_'
}

// Blank steps over a blank or a backslash-newline continuation. Awk reads
// both as a blank: neither ends a statement nor opens a literal.
func Blank(code string, i *int) bool {
	switch code[*i] {
	case ' ', '\t', '\r':
		return true
	case '\\':
		next := *i + 1
		if next < len(code) && code[next] == '\r' {
			next++
		}
		if next < len(code) && code[next] == '\n' {
			*i = next
			return true
		}
	}
	return false
}

// DataEnd finds the awk data that starts at code[i]: a string, a regular
// expression literal (a slash where regexOK says awk cannot divide, from the
// Slash state of the tokens before it) or a comment. It returns the index of
// the data's last byte; a comment ends before its newline, which still ends
// the statement. found is false when code[i] starts no data. ok is false when
// the data has no end awk accepts, so the program does not run as this scan
// reads it.
func DataEnd(code string, i int, regexOK bool) (end int, found, ok bool) {
	switch c := code[i]; {
	case c == '"':
		for j := i + 1; j < len(code); j++ {
			switch code[j] {
			case '\\':
				j++
			case '"':
				return j, true, true
			}
		}
		return len(code) - 1, true, false
	case c == '#':
		if newline := strings.IndexByte(code[i:], '\n'); newline >= 0 {
			return i + newline - 1, true, true
		}
		return len(code) - 1, true, true
	case c == '/' && regexOK:
		end, ok := regexEnd(code, i)
		return end, true, ok
	}
	return i, false, true
}

// regexEnd returns the index of the slash that closes the regular
// expression literal opening at code[start]. A slash inside a bracket
// expression belongs to it, as gawk and mawk read it; an awk that ends the
// literal there rejects its unclosed bracket and runs nothing. [:class:],
// [.symbol.] and [=equivalent=] close with their own pair, not the first ].
// ok is false for a literal that does not close on its line.
func regexEnd(code string, start int) (int, bool) {
	bracket := false
	for i := start + 1; i < len(code); i++ {
		c := code[i]
		switch {
		case c == '\n':
			return i, false
		case c == '\\':
			if i+1 < len(code) && code[i+1] == '\n' {
				return i + 1, false
			}
			i++
		case bracket && c == '[' && i+1 < len(code) && strings.IndexByte(":.=", code[i+1]) >= 0:
			closer := string(code[i+1]) + "]"
			if end := strings.Index(code[i+2:], closer); end >= 0 && !strings.Contains(code[i+2:i+2+end], "\n") {
				i += 2 + end + 1
			}
		case bracket && c == ']':
			bracket = false
		case c == '[':
			bracket = true
			if i+1 < len(code) && code[i+1] == '^' {
				i++
			}
			if i+1 < len(code) && code[i+1] == ']' {
				i++
			}
		case !bracket && c == '/':
			return i, true
		}
	}
	return len(code) - 1, false
}

// regexKeywords are the words after which a slash opens a regular
// expression, not a division.
var regexKeywords = map[string]bool{
	"print": true, "printf": true, "return": true, "in": true, "case": true, "do": true, "else": true,
}

// Slash tells whether a "/" divides or opens a regular expression literal.
// POSIX awk lexers decide it by the previous significant token: a slash after
// an operand (a name, a number, a string, a regular expression, a closing
// bracket, a closing parenthesis that does not end an if, while or for header,
// or a postfix ++ or --) divides, and after anything else (an operator, a
// delimiter, a keyword that takes an expression, a header's closing
// parenthesis) it opens a regular expression. A scan that reads a regular
// expression as a division, or the reverse, reads a different program than
// awk runs, so every scanner of program text feeds one Slash. The zero value
// is the start of a program.
type Slash struct {
	operand bool
	header  bool
	headers []bool
}

// RegexOK reports that a slash here opens a regular expression literal.
func (s *Slash) RegexOK() bool { return !s.operand }

// Word notes a name, keyword, builtin or number.
func (s *Slash) Word(word string) {
	s.operand = !regexKeywords[word]
	s.header = word == "if" || word == "while" || word == "for"
}

// Data notes a string or a regular expression literal.
func (s *Slash) Data() {
	s.operand = true
	s.header = false
}

// Punct notes an operator or delimiter ("\n" for a newline).
func (s *Slash) Punct(text string) {
	switch text {
	case "(":
		s.headers = append(s.headers, s.header)
		s.operand = false
	case ")":
		header := false
		if n := len(s.headers); n > 0 {
			header = s.headers[n-1]
			s.headers = s.headers[:n-1]
		}
		s.operand = !header
	case "]":
		s.operand = true
	case "++", "--":
		// Postfix after an operand, prefix otherwise: either way the state
		// stays.
	default:
		s.operand = false
	}
	s.header = false
}

// Feed notes the token that starts at code[i] for a scanner that walks the
// bytes itself: it must call Feed once at the first byte of a word and once
// at each other byte that is not part of a string, regular expression or
// comment, and note those with Data.
func (s *Slash) Feed(code string, i int) {
	c := code[i]
	switch {
	case WordByte(c):
		if i > 0 && WordByte(code[i-1]) {
			return
		}
		j := i + 1
		for j < len(code) && WordByte(code[j]) {
			j++
		}
		s.Word(code[i:j])
	case (c == '+' || c == '-') && i+1 < len(code) && code[i+1] == c:
		s.Punct(code[i : i+2])
	case (c == '+' || c == '-') && i > 0 && code[i-1] == c && (i < 2 || code[i-2] != c):
		// The second byte of a ++ or -- Feed already noted.
	default:
		s.Punct(string(c))
	}
}

var punct3 = []string{"**=", "..."}
var punct2 = []string{"||", "&&", "|&", "++", "--", "+=", "-=", "*=", "/=", "%=", "^=", "**", "==", "!=", "<=", ">=", "!~", ">>"}

func tokenize(code string, p *Program) []token {
	var tokens []token
	var slash Slash
	for i := 0; i < len(code); i++ {
		c := code[i]
		if Blank(code, &i) {
			continue
		}
		if end, found, ok := DataEnd(code, i, slash.RegexOK()); found {
			if !ok {
				p.Malformed = true
				return tokens
			}
			switch c {
			case '"':
				tokens = append(tokens, token{tokString, awkString(code[i+1 : end])})
				slash.Data()
			case '/':
				tokens = append(tokens, token{tokRegex, ""})
				slash.Data()
			}
			i = end
			continue
		}
		switch {
		case c == '\n':
			tokens = append(tokens, token{kind: tokNewline})
			slash.Punct("\n")
		case c == '@':
			p.Directive = true
			slash.Punct("@")
		case WordByte(c):
			start := i
			for i+1 < len(code) && WordByte(code[i+1]) {
				i++
			}
			tokens = append(tokens, token{tokWord, code[start : i+1]})
			slash.Word(code[start : i+1])
		default:
			text := string(c)
			for _, candidates := range [][]string{punct3, punct2} {
				for _, candidate := range candidates {
					if strings.HasPrefix(code[i:], candidate) {
						text = candidate
						break
					}
				}
				if len(text) > 1 {
					break
				}
			}
			i += len(text) - 1
			tokens = append(tokens, token{tokPunct, text})
			slash.Punct(text)
		}
	}
	return tokens
}

// awkString is the value of an awk string literal body: \" \\ \/ and the
// C escapes, up to three octal digits, and two hex digits after \x. An
// unknown escape keeps its character, as gawk does.
func awkString(body string) string {
	if !strings.Contains(body, "\\") {
		return body
	}
	var b strings.Builder
	for i := 0; i < len(body); i++ {
		c := body[i]
		if c != '\\' || i+1 >= len(body) {
			b.WriteByte(c)
			continue
		}
		i++
		switch e := body[i]; {
		case e == 'n':
			b.WriteByte('\n')
		case e == 't':
			b.WriteByte('\t')
		case e == 'r':
			b.WriteByte('\r')
		case e == 'a':
			b.WriteByte(7)
		case e == 'b':
			b.WriteByte(8)
		case e == 'f':
			b.WriteByte(12)
		case e == 'v':
			b.WriteByte(11)
		case e == '\n':
		case e >= '0' && e <= '7':
			v, n := 0, 0
			for n < 3 && i < len(body) && body[i] >= '0' && body[i] <= '7' {
				v = v*8 + int(body[i]-'0')
				i++
				n++
			}
			i--
			b.WriteByte(byte(v))
		case e == 'x' && i+1 < len(body) && hexValue(body[i+1]) >= 0:
			v, n := 0, 0
			for n < 2 && i+1 < len(body) && hexValue(body[i+1]) >= 0 {
				v = v*16 + hexValue(body[i+1])
				i++
				n++
			}
			b.WriteByte(byte(v))
		default:
			b.WriteByte(e)
		}
	}
	return b.String()
}

func hexValue(c byte) int {
	switch {
	case c >= '0' && c <= '9':
		return int(c - '0')
	case c >= 'a' && c <= 'f':
		return int(c-'a') + 10
	case c >= 'A' && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}

// matchParens maps each ( token to its ) and back; an unmatched one maps to
// -1.
func matchParens(tokens []token) []int {
	match := make([]int, len(tokens))
	var stack []int
	for i, t := range tokens {
		match[i] = -1
		if t.kind != tokPunct {
			continue
		}
		switch t.text {
		case "(":
			stack = append(stack, i)
		case ")":
			if n := len(stack); n > 0 {
				match[i], match[stack[n-1]] = stack[n-1], i
				stack = stack[:n-1]
			}
		}
	}
	return match
}

// literalConcat is the value of tokens when they are string literals and
// parenthesized groups of such (a concatenation by juxtaposition), and
// whether they are. An empty run is not a command.
func literalConcat(tokens []token, match []int, from, to int) (value string, parts int, ok bool) {
	var b strings.Builder
	for i := from; i < to; i++ {
		t := tokens[i]
		switch {
		case t.kind == tokString:
			b.WriteString(t.text)
			parts++
		case t.kind == tokPunct && t.text == "(" && match[i] > i && match[i] < to:
			inner, n, innerOK := literalConcat(tokens, match, i+1, match[i])
			if !innerOK {
				return "", 0, false
			}
			b.WriteString(inner)
			parts += n
			i = match[i]
		default:
			return "", 0, false
		}
	}
	return b.String(), parts, parts > 0
}

func (p *Program) addSystem(tokens []token, match []int, i int) {
	open := i + 1
	if open >= len(tokens) || tokens[open].kind != tokPunct || tokens[open].text != "(" || match[open] < 0 {
		p.Channels = append(p.Channels, Channel{Kind: System, Dynamic: true})
		return
	}
	value, _, ok := literalConcat(tokens, match, open+1, match[open])
	p.Channels = append(p.Channels, staticOrDynamic(System, value, ok))
}

func staticOrDynamic(kind Kind, value string, ok bool) Channel {
	if !ok {
		return Channel{Kind: kind, Dynamic: true}
	}
	return Channel{Kind: kind, Commands: []string{value}}
}

// addPrintPipe reads the statement a print or printf at tokens[i] starts: a
// pipe outside parentheses sends the output to the command that follows it,
// to the end of the statement, and a > or >> outside parentheses sends it to
// the file that follows (Outputs; inside parentheses > is a comparison).
func (p *Program) addPrintPipe(tokens []token, match []int, i int) {
	depth := 0
	for j := i + 1; j < len(tokens); j++ {
		t := tokens[j]
		switch {
		case t.kind == tokNewline:
			if depth == 0 && !continuesLine(tokens[j-1]) {
				return
			}
		case t.kind != tokPunct:
		case t.text == "(" || t.text == "[":
			depth++
		case t.text == ")" || t.text == "]":
			if depth == 0 {
				return
			}
			depth--
		case depth == 0 && (t.text == ";" || t.text == "}"):
			return
		case depth == 0 && (t.text == "|" || t.text == "|&"):
			if j+1 < len(tokens) && tokens[j+1].kind == tokWord && tokens[j+1].text == "getline" {
				return // a getline pipe: addGetline reads it.
			}
			end := j + 1
			for end < len(tokens) && !statementEnd(tokens[end]) {
				end++
			}
			value, _, ok := literalConcat(tokens, match, j+1, end)
			p.Channels = append(p.Channels, staticOrDynamic(PrintPipe, value, ok))
			return
		case depth == 0 && (t.text == ">" || t.text == ">>"):
			end := j + 1
			for end < len(tokens) && !statementEnd(tokens[end]) {
				end++
			}
			if value, _, ok := literalConcat(tokens, match, j+1, end); ok && value != "" {
				p.Outputs = append(p.Outputs, Output{Target: value, Append: t.text == ">>",
					RecordInput: unguardedRecordOutput(tokens, i, j, end)})
			}
			return
		}
	}
}

// unguardedRecordOutput proves the only record action copies $0 to the
// redirect. A BEGIN/END block, condition, function, or second statement does
// not prove that the call sends an input file's contents.
func unguardedRecordOutput(tokens []token, printAt, redirectAt, end int) bool {
	if len(tokens) < 5 || tokens[0].text != "{" || tokens[0].kind != tokPunct ||
		tokens[len(tokens)-1].text != "}" || tokens[len(tokens)-1].kind != tokPunct ||
		printAt != 1 || end != len(tokens)-1 {
		return false
	}
	args := tokens[printAt+1 : redirectAt]
	if tokens[printAt].text == "print" {
		return len(args) == 0 || len(args) == 2 &&
			args[0].kind == tokPunct && args[0].text == "$" &&
			args[1].kind == tokWord && args[1].text == "0"
	}
	return tokens[printAt].text == "printf" && len(args) == 4 &&
		args[0].kind == tokString && args[0].text == "%s" &&
		args[1].kind == tokPunct && args[1].text == "," &&
		args[2].kind == tokPunct && args[2].text == "$" &&
		args[3].kind == tokWord && args[3].text == "0"
}

func continuesLine(t token) bool {
	return t.kind == tokPunct && (t.text == "," || t.text == "&&" || t.text == "||" || t.text == "{")
}

func statementEnd(t token) bool {
	return t.kind == tokNewline || t.kind == tokPunct && (t.text == ";" || t.text == "}" || t.text == ")")
}

// operandStart is the start of the expression that ends at tokens[end-1]: the
// token after the nearest operator of lower precedence than the pipe, an
// opening parenthesis or a statement delimiter.
func operandStart(tokens []token, match []int, end int) int {
	j := end - 1
	for j >= 0 {
		t := tokens[j]
		if t.kind == tokNewline {
			break
		}
		if t.kind == tokPunct {
			switch t.text {
			case ";", "{", "}", "(", ",", "=", "+=", "-=", "*=", "/=", "%=", "^=", "**=", "&&", "||", "?", ":", "~", "!~":
				return j + 1
			case ")":
				if match[j] >= 0 {
					j = match[j] - 1
					continue
				}
				return j + 1
			}
		}
		if t.kind == tokWord && t.text == "in" {
			return j + 1
		}
		j--
	}
	return j + 1
}

// addGetline reads cmd | getline, with the pipe at tokens[i].
func (p *Program) addGetline(tokens []token, match []int, i int) {
	start := operandStart(tokens, match, i)
	value, parts, ok := literalConcat(tokens, match, start, i)
	channel := Channel{Kind: GetlinePipe}
	switch {
	case ok:
		channel.Commands = []string{value}
		if parts > 1 {
			// The last literal alone: one awk binds getline to it.
			last := i - 1
			if tokens[last].kind == tokString {
				channel.Commands = append(channel.Commands, tokens[last].text)
			} else if tokens[last].kind == tokPunct && tokens[last].text == ")" && match[last] >= 0 {
				if tail, _, tailOK := literalConcat(tokens, match, match[last], i); tailOK {
					channel.Commands = append(channel.Commands, tail)
				}
			}
		}
	default:
		channel.Dynamic = true
		// A literal run right before the pipe may still be the command.
		k := i
		for k > start && (tokens[k-1].kind == tokString || tokens[k-1].kind == tokPunct && tokens[k-1].text == ")" && match[k-1] >= 0) {
			if tokens[k-1].kind == tokString {
				k--
			} else {
				k = match[k-1]
			}
		}
		if tail, _, tailOK := literalConcat(tokens, match, k, i); tailOK {
			channel.Commands = []string{tail}
		}
	}
	p.Channels = append(p.Channels, channel)
}
