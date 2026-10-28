// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// provenPowerShellStateWrite judges the PowerShell reading of a Windows-home
// command for the state-write proof (GAP-2414). Codex names its PowerShell
// tool Bash and shell_command may run PowerShell, and one statement the
// parser does not model (” | Out-File, an expression, a .NET call) leaves
// the whole command partial, so a write of DefenseClaw state next to it had
// no proof. Each statement and pipeline element that names DefenseClaw is
// read as a PowerShell command of its own, and each file an expression
// writes (a redirect target, a provider-path variable assignment
// ${C:\...} = x, the path of a .NET file write) is read as the write
// Set-Content -LiteralPath <target> it is. Only a twin whose own reading
// proves the mutation of active state counts. The caller has already seen a
// DefenseClaw state mention.
func provenPowerShellStateWrite(request trustedActionRequest) bool {
	home := request.Input.ActiveHome
	if len(home) < 2 || home[1] != ':' {
		return false
	}
	switch request.Input.DialectHint {
	case "", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell:
	default:
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !strings.Contains(strings.ToLower(command), "defenseclaw") {
		return false
	}
	forms, ok := powerShellStateWriteForms(command)
	if !ok {
		return false
	}
	// Bound the twins a crafted command can ask for; past the bound the
	// state-naming command counts as the write (over-block, RV10-3).
	const maxForms = 128
	if len(forms) > maxForms {
		return true
	}
	for _, form := range forms {
		input := request.Input
		input.Command, input.Args, input.Argv = form, nil, nil
		input.DialectHint = actionfacts.DialectPowerShell
		twin := request
		twin.Input = input
		if provenStateMutationPath(actionfacts.Analyze(input), twin) {
			return true
		}
	}
	return false
}

// powerShellStateWriteForms returns the PowerShell twins of command that
// name DefenseClaw (see provenPowerShellStateWrite), deduplicated. ok is
// false when PowerShell cannot parse the command: a < that starts a token
// is a parse error there (a Git Bash here-document or input redirect), so
// nothing runs in that reading.
func powerShellStateWriteForms(command string) ([]string, bool) {
	scan := psStateScan{runes: []rune(command)}
	scan.code(0, false)
	if scan.parseError {
		return nil, false
	}
	seen := map[string]bool{}
	var forms []string
	add := func(form string) {
		form = strings.TrimSpace(form)
		if form == "" || seen[form] || !strings.Contains(strings.ToLower(form), "defenseclaw") {
			return
		}
		seen[form] = true
		forms = append(forms, form)
	}
	for _, piece := range scan.pieces {
		add(piece)
	}
	for _, target := range scan.targets {
		add("Set-Content -LiteralPath " + target + " -Value x")
	}
	return forms, true
}

// psStateScan reads a command in the PowerShell grammar: strings (also the
// typographic quotes PowerShell accepts), here-strings, comments, backtick
// escapes, the --% stop-parsing tail, $(...) inside double quotes and
// braced variable names.
type psStateScan struct {
	runes      []rune
	pieces     []string
	targets    []string
	parseError bool
}

func psSingleQuote(r rune) bool {
	return r == '\'' || r == '\u2018' || r == '\u2019' || r == '\u201a' || r == '\u201b'
}

func psDoubleQuote(r rune) bool {
	return r == '"' || r == '\u201c' || r == '\u201d' || r == '\u201e'
}

func psTokenBreak(r rune) bool {
	return r == ' ' || r == '\t' || r == '\r' || r == '\n' || strings.ContainsRune(";|&(){}", r)
}

// tokenStart reports whether index i starts a token.
func (s *psStateScan) tokenStart(i int) bool {
	return i == 0 || psTokenBreak(s.runes[i-1])
}

// code scans statements from i to the end, or to the ) that closes the
// enclosing ( when nested, and returns the index after it. Every statement
// and pipeline element becomes a piece; a nested (...), $(...) or @(...)
// body is a piece of its own.
func (s *psStateScan) code(i int, nested bool) int {
	r := s.runes
	var cur strings.Builder
	flush := func() {
		if strings.TrimSpace(cur.String()) != "" {
			s.pieces = append(s.pieces, cur.String())
		}
		cur.Reset()
	}
	for i < len(r) && !s.parseError {
		c := r[i]
		switch {
		case c == '`':
			cur.WriteRune(c)
			if i+1 < len(r) {
				cur.WriteRune(r[i+1])
			}
			i += 2
		case c == '\n' || c == ';' || c == '|' || c == '&' || c == '{' || c == '}':
			flush()
			i++
		case c == ')':
			flush()
			if nested {
				return i + 1
			}
			i++
		case c == '(':
			method := strings.ToLower(strings.TrimRight(cur.String(), " \t"))
			flush()
			end := s.code(i+1, true)
			if write := psFileWriteMethod(method); write != nil && end-1 > i+1 {
				args := psSplitArguments(string(r[i+1 : end-1]))
				for _, index := range write {
					if index < len(args) && args[index] != "" {
						s.targets = append(s.targets, args[index])
					}
				}
			}
			i = end
		case c == '#' && s.tokenStart(i):
			for i < len(r) && r[i] != '\n' {
				i++
			}
		case c == '<' && i+1 < len(r) && r[i+1] == '#':
			end := strings.Index(string(r[i+2:]), "#>")
			if end < 0 {
				return len(r)
			}
			i += 2 + len([]rune(string(r[i+2:])[:end])) + 2
		case c == '<' && s.tokenStart(i):
			s.parseError = true
			return len(r)
		case c == '-' && s.tokenStart(i) && i+2 < len(r) && r[i+1] == '-' && r[i+2] == '%':
			for i < len(r) && r[i] != '\n' {
				cur.WriteRune(r[i])
				i++
			}
		case c == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && s.hereStringOpen(i+2):
			end := s.hereString(i)
			cur.WriteString(string(r[i:end]))
			i = end
		case psSingleQuote(c):
			end := s.singleQuoted(i)
			cur.WriteString(string(r[i:end]))
			i = end
		case psDoubleQuote(c):
			end := s.doubleQuoted(i)
			cur.WriteString(string(r[i:end]))
			i = end
		case c == '$' && i+1 < len(r) && r[i+1] == '{':
			end := i + 2
			for end < len(r) && r[end] != '}' {
				if r[end] == '`' {
					end++
				}
				end++
			}
			if end >= len(r) {
				cur.WriteString(string(r[i:]))
				i = len(r)
				continue
			}
			name := string(r[i+2 : end])
			cur.WriteString(string(r[i : end+1]))
			i = end + 1
			if target, ok := psProviderPathLiteral(name); ok && s.assignmentAt(i) {
				s.targets = append(s.targets, target)
			}
		case c == '>':
			cur.WriteRune(c)
			i++
			if i < len(r) && r[i] == '>' {
				cur.WriteRune(r[i])
				i++
			}
			if i < len(r) && r[i] == '&' {
				continue
			}
			for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
				cur.WriteRune(r[i])
				i++
			}
			start := i
			switch {
			case i < len(r) && psSingleQuote(r[i]):
				i = s.singleQuoted(i)
			case i < len(r) && psDoubleQuote(r[i]):
				i = s.doubleQuoted(i)
			default:
				for i < len(r) && !psTokenBreak(r[i]) && r[i] != '<' && r[i] != '>' {
					if r[i] == '`' {
						i++
					}
					i++
				}
				if i > len(r) {
					i = len(r)
				}
			}
			if i > start {
				target := string(r[start:i])
				cur.WriteString(target)
				s.targets = append(s.targets, target)
			}
		default:
			cur.WriteRune(c)
			i++
		}
	}
	flush()
	return len(r)
}

// assignmentAt reports an assignment or increment operator after optional
// blanks at i: = (not ==), +=, -=, *=, /=, %=, ??=, ++ or --.
func (s *psStateScan) assignmentAt(i int) bool {
	r := s.runes
	for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
		i++
	}
	rest := string(r[i:])
	for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "??=", "++", "--"} {
		if strings.HasPrefix(rest, op) {
			return true
		}
	}
	return strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "==")
}

// hereStringOpen reports that only blanks follow @' or @" to the end of the
// line, as a here-string header requires.
func (s *psStateScan) hereStringOpen(i int) bool {
	for ; i < len(s.runes); i++ {
		switch s.runes[i] {
		case ' ', '\t', '\r':
		case '\n':
			return true
		default:
			return false
		}
	}
	return false
}

// hereString returns the index after the here-string that starts at i (@'
// or @"): its body ends at a line that starts with the closing quote and @.
// An expandable body runs its $(...) subexpressions.
func (s *psStateScan) hereString(i int) int {
	r := s.runes
	expandable := psDoubleQuote(r[i+1])
	j := i + 2
	for j < len(r) && r[j] != '\n' {
		j++
	}
	lineStart := true
	for j < len(r) {
		if lineStart && j+1 < len(r) && r[j+1] == '@' &&
			(expandable && psDoubleQuote(r[j]) || !expandable && psSingleQuote(r[j])) {
			return j + 2
		}
		lineStart = r[j] == '\n'
		if expandable && r[j] == '`' {
			j += 2
			continue
		}
		if expandable && r[j] == '$' && j+1 < len(r) && r[j+1] == '(' {
			j = s.code(j+2, true)
			lineStart = false
			continue
		}
		j++
	}
	return len(r)
}

// singleQuoted returns the index after the single-quoted string at i; a
// doubled quote is an escaped one.
func (s *psStateScan) singleQuoted(i int) int {
	r := s.runes
	for j := i + 1; j < len(r); j++ {
		if psSingleQuote(r[j]) {
			if j+1 < len(r) && psSingleQuote(r[j+1]) {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(r)
}

// doubleQuoted returns the index after the double-quoted string at i. A
// backtick or a doubled quote escapes; a $(...) subexpression runs.
func (s *psStateScan) doubleQuoted(i int) int {
	r := s.runes
	for j := i + 1; j < len(r); j++ {
		switch {
		case r[j] == '`':
			j++
		case r[j] == '$' && j+1 < len(r) && r[j+1] == '(':
			j = s.code(j+2, true) - 1
		case psDoubleQuote(r[j]):
			if j+1 < len(r) && psDoubleQuote(r[j+1]) {
				j++
				continue
			}
			return j + 1
		}
	}
	return len(r)
}

// psFileWriteMethod returns the argument positions a .NET file call writes,
// replaces or removes when prefix (lower case) ends with its name.
func psFileWriteMethod(prefix string) []int {
	for _, method := range []struct {
		name string
		args []int
	}{
		{"::writealltext", []int{0}}, {"::writeallbytes", []int{0}}, {"::writealllines", []int{0}},
		{"::appendalltext", []int{0}}, {"::appendalllines", []int{0}}, {"::appendtext", []int{0}},
		{"::createtext", []int{0}}, {"::create", []int{0}}, {"::openwrite", []int{0}},
		{"::delete", []int{0}}, {"::move", []int{0, 1}}, {"::copy", []int{1}},
		{"::replace", []int{0, 1, 2}}, {"streamwriter]::new", []int{0}},
	} {
		if strings.HasSuffix(prefix, method.name) {
			return method.args
		}
	}
	return nil
}

// psSplitArguments splits a .NET argument list at its top-level commas; an
// argument that is not one string or bare word is returned empty.
func psSplitArguments(text string) []string {
	r := []rune(text)
	scan := psStateScan{runes: r}
	var args []string
	depth, start := 0, 0
	for i := 0; i <= len(r); i++ {
		if i < len(r) {
			switch {
			case psSingleQuote(r[i]):
				i = scan.singleQuoted(i) - 1
				continue
			case psDoubleQuote(r[i]):
				i = scan.doubleQuoted(i) - 1
				continue
			case r[i] == '(' || r[i] == '[' || r[i] == '{':
				depth++
				continue
			case r[i] == ')' || r[i] == ']' || r[i] == '}':
				depth--
				continue
			case r[i] != ',' || depth != 0:
				continue
			}
		}
		arg := strings.TrimSpace(string(r[start:i]))
		if strings.ContainsAny(arg, "()[]{} \t\r\n") && !psQuotedWord(arg) {
			arg = ""
		}
		args = append(args, arg)
		start = i + 1
	}
	return args
}

func psQuotedWord(arg string) bool {
	r := []rune(arg)
	if len(r) < 2 {
		return false
	}
	scan := psStateScan{runes: r}
	switch {
	case psSingleQuote(r[0]):
		return scan.singleQuoted(0) == len(r)
	case psDoubleQuote(r[0]):
		return scan.doubleQuoted(0) == len(r)
	}
	return false
}

// psProviderPathLiteral returns a single-quoted PowerShell literal of the
// file a braced variable name names on a drive (${C:\f}, ${c:/f}): the env,
// variable, function and alias drives and the scope modifiers name none.
func psProviderPathLiteral(name string) (string, bool) {
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
	if strings.ContainsAny(path, "\r\n") {
		return "", false
	}
	return "'" + strings.ReplaceAll(path, "'", "''") + "'", true
}
