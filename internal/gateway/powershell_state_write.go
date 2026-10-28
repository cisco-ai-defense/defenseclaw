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
	forms, bounded, ok := powerShellStateWriteForms(command)
	if !ok {
		return false
	}
	// Bound the twins a crafted command can ask for and the text the
	// reading copies; past a bound the state-naming command counts as the
	// write (over-block, RV10-3, RV14-2).
	const maxForms = 128
	if bounded || len(forms) > maxForms {
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

// psStateScanMaxRunes bounds the text the PowerShell reading copies into
// pieces and argument lists; psNestedShellDepth bounds powershell -Command
// bodies read inside each other. Ordinary commands stay far below both; a
// crafted command past one is judged the write (RV14-2).
const (
	psStateScanMaxRunes = 1 << 20
	psNestedShellDepth  = 3
)

// powerShellStateWriteForms returns the PowerShell twins of command that
// name DefenseClaw (see provenPowerShellStateWrite), deduplicated. A
// powershell or pwsh -Command body is read as PowerShell too. bounded
// reports a command past the reading bounds. ok is false when PowerShell
// cannot parse the command: a < that starts a token is a parse error there
// (a Git Bash here-document or input redirect), so nothing runs in that
// reading.
func powerShellStateWriteForms(command string) (forms []string, bounded, ok bool) {
	seen := map[string]bool{}
	bounded, ok = psCollectStateWriteForms(command, 0, seen, &forms)
	return forms, bounded, ok
}

func psCollectStateWriteForms(command string, depth int, seen map[string]bool, forms *[]string) (bool, bool) {
	scan := psStateScan{runes: []rune(command)}
	scan.code(0, false)
	if scan.overBound {
		return true, true
	}
	if scan.parseError {
		return false, false
	}
	add := func(form string) {
		form = strings.TrimSpace(form)
		if form == "" || seen[form] || !strings.Contains(strings.ToLower(form), "defenseclaw") ||
			psOutputOnly(form) {
			return
		}
		seen[form] = true
		*forms = append(*forms, form)
	}
	for _, piece := range scan.pieces {
		add(piece)
		body, nested := psNestedShellBody(piece)
		if !nested || !strings.Contains(strings.ToLower(body), "defenseclaw") {
			continue
		}
		if depth >= psNestedShellDepth {
			return true, true
		}
		// A body PowerShell cannot parse runs nothing; only its bound counts.
		if bounded, _ := psCollectStateWriteForms(body, depth+1, seen, forms); bounded {
			return true, true
		}
	}
	for _, target := range scan.targets {
		add("Set-Content -LiteralPath " + target + " -Value x")
	}
	return false, true
}

// psOutputOnly reports a statement whose command only writes to the output
// streams (Write-Host "defenseclaw step 3"); its own reading cannot mutate
// state, and a redirect of it is judged as its own target, so it is not a
// twin and does not count toward the bound (checker it14 B40).
func psOutputOnly(form string) bool {
	word := form
	if index := strings.IndexAny(form, " \t\r\n"); index >= 0 {
		word = form[:index]
	}
	switch strings.ToLower(word) {
	case "write-host", "write-output", "echo", "write", "write-verbose",
		"write-debug", "write-warning", "write-information", "write-error":
		return true
	}
	return false
}

// psWord is one whitespace-separated word of a PowerShell statement.
type psWord struct {
	start  int // rune index in the statement
	text   string
	quoted bool
}

// psWords splits a statement into words at blanks outside quotes.
func psWords(statement string) []psWord {
	r := []rune(statement)
	scan := psStateScan{runes: r}
	var words []psWord
	for i := 0; i < len(r); {
		if r[i] == ' ' || r[i] == '\t' || r[i] == '\r' || r[i] == '\n' {
			i++
			continue
		}
		start := i
		for i < len(r) && r[i] != ' ' && r[i] != '\t' && r[i] != '\r' && r[i] != '\n' {
			switch {
			case r[i] == '`':
				i += 2
			case psSingleQuote(r[i]):
				i = scan.singleQuoted(i)
			case psDoubleQuote(r[i]):
				i = scan.doubleQuoted(i)
			default:
				i++
			}
		}
		if i > len(r) {
			i = len(r)
		}
		words = append(words, psWord{start: start, text: string(r[start:i]),
			quoted: psSingleQuote(r[start]) || psDoubleQuote(r[start])})
	}
	return words
}

// psUnquote removes the outer quotes of one quoted word as PowerShell does
// when it passes it to a program: a doubled quote and a backtick escape
// become the character.
func psUnquote(word string) string {
	r := []rune(word)
	if len(r) < 2 || !psQuotedWord(word) {
		return word
	}
	single := psSingleQuote(r[0])
	var out []rune
	for i := 1; i < len(r)-1; i++ {
		switch {
		case single && psSingleQuote(r[i]) && i+1 < len(r)-1 && psSingleQuote(r[i+1]):
			out = append(out, r[i])
			i++
		case !single && r[i] == '`' && i+1 < len(r)-1:
			out = append(out, r[i+1])
			i++
		case !single && psDoubleQuote(r[i]) && i+1 < len(r)-1 && psDoubleQuote(r[i+1]):
			out = append(out, r[i])
			i++
		default:
			out = append(out, r[i])
		}
	}
	return string(out)
}

// psNestedShellBody returns the script a powershell or pwsh call in
// statement runs with -Command (or as its first positional argument), after
// the outer shell's quote removal: powershell -Command "Set-Content STATE x"
// writes state as the inner Set-Content does (checker it14, GAP-2414).
func psNestedShellBody(statement string) (string, bool) {
	words := psWords(statement)
	if len(words) == 0 {
		return "", false
	}
	program := strings.ToLower(psUnquote(words[0].text))
	if index := strings.LastIndexAny(program, `\/`); index >= 0 {
		program = program[index+1:]
	}
	program = strings.TrimSuffix(program, ".exe")
	if program != "powershell" && program != "pwsh" {
		return "", false
	}
	body := func(rest []psWord) string {
		if len(rest) == 1 {
			return psUnquote(rest[0].text)
		}
		parts := make([]string, 0, len(rest))
		for _, word := range rest {
			parts = append(parts, psUnquote(word.text))
		}
		return strings.Join(parts, " ")
	}
	for k := 1; k < len(words); k++ {
		lower := strings.ToLower(words[k].text)
		if words[k].quoted || !strings.HasPrefix(lower, "-") {
			return body(words[k:]), true
		}
		name, _, _ := strings.Cut(lower, ":")
		switch {
		case name == "-c" || len(name) >= 4 && strings.HasPrefix("-command", name):
			if k+1 >= len(words) {
				return "", false
			}
			return body(words[k+1:]), true
		case name == "-f" || len(name) >= 3 && strings.HasPrefix("-file", name),
			name == "-e" || name == "-ec" || len(name) >= 3 && strings.HasPrefix("-encodedcommand", name):
			return "", false
		case psShellValueOption(name):
			k++
		}
	}
	return "", false
}

// psShellValueOption reports a powershell/pwsh option that takes the next
// word as its value.
func psShellValueOption(name string) bool {
	switch name {
	case "-ep", "-ex", "-exec", "-if", "-inp", "-of", "-o", "-w", "-win",
		"-config", "-wd", "-settings", "-v", "-version", "-psconsolefile",
		"-custompipename", "-configurationname", "-settingsfile",
		"-workingdirectory", "-inputformat", "-outputformat":
		return true
	}
	return len(name) >= 5 && (strings.HasPrefix("-executionpolicy", name) ||
		strings.HasPrefix("-windowstyle", name))
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
	overBound  bool
	copied     int
}

// account adds n copied runes and reports the reading still within bound.
func (s *psStateScan) account(n int) bool {
	s.copied += n
	if s.copied > psStateScanMaxRunes {
		s.overBound = true
	}
	return !s.overBound
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
	var cur []rune
	flush := func() {
		if strings.TrimSpace(string(cur)) != "" && s.account(len(cur)) {
			s.pieces = append(s.pieces, string(cur))
		}
		cur = cur[:0]
	}
	for i < len(r) && !s.parseError && !s.overBound {
		c := r[i]
		switch {
		case c == '`':
			cur = append(cur, c)
			if i+1 < len(r) {
				cur = append(cur, r[i+1])
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
			tail := cur
			if len(tail) > 32 {
				tail = tail[len(tail)-32:]
			}
			method := strings.ToLower(strings.TrimRight(string(tail), " \t"))
			flush()
			end := s.code(i+1, true)
			if s.overBound {
				return len(r)
			}
			if write := psFileWriteMethod(method); write != nil && end-1 > i+1 && s.account(end-1-i) {
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
			// A block comment ends at the first #>; one pass over the
			// runes (RV14-2). An unterminated one runs to the end.
			j := i + 2
			for j+1 < len(r) && (r[j] != '#' || r[j+1] != '>') {
				j++
			}
			i = j + 2
			if i > len(r) {
				i = len(r)
			}
		case c == '<' && s.tokenStart(i):
			s.parseError = true
			return len(r)
		case c == '-' && s.tokenStart(i) && i+2 < len(r) && r[i+1] == '-' && r[i+2] == '%':
			for i < len(r) && r[i] != '\n' {
				cur = append(cur, r[i])
				i++
			}
		case c == '@' && i+1 < len(r) && (psSingleQuote(r[i+1]) || psDoubleQuote(r[i+1])) && s.hereStringOpen(i+2):
			end := s.hereString(i)
			if s.overBound {
				return len(r)
			}
			cur = append(cur, r[i:end]...)
			i = end
		case psSingleQuote(c):
			end := s.singleQuoted(i)
			cur = append(cur, r[i:end]...)
			i = end
		case psDoubleQuote(c):
			end := s.doubleQuoted(i)
			if s.overBound {
				return len(r)
			}
			cur = append(cur, r[i:end]...)
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
				cur = append(cur, r[i:]...)
				i = len(r)
				continue
			}
			name := string(r[i+2 : end])
			cur = append(cur, r[i:end+1]...)
			i = end + 1
			if target, ok := psProviderPathLiteral(name); ok && s.assignmentAt(i) {
				s.targets = append(s.targets, target)
			}
		case c == '>':
			// The redirect target is judged as its own write (below); the
			// piece keeps only the command, so a stream redirect such as
			// 2>$null or 2>&1 does not leave the cmdlet's own reading
			// partial (checker it14 class rows).
			if len(cur) > 0 && i > 0 && strings.ContainsRune("123456*", r[i-1]) && s.tokenStart(i-1) {
				cur = cur[:len(cur)-1]
			}
			i++
			if i < len(r) && r[i] == '>' {
				i++
			}
			if i < len(r) && r[i] == '&' {
				i++
				for i < len(r) && r[i] >= '0' && r[i] <= '9' {
					i++
				}
				continue
			}
			for i < len(r) && (r[i] == ' ' || r[i] == '\t') {
				i++
			}
			start := i
			switch {
			case i < len(r) && psSingleQuote(r[i]):
				i = s.singleQuoted(i)
			case i < len(r) && psDoubleQuote(r[i]):
				i = s.doubleQuoted(i)
				if s.overBound {
					return len(r)
				}
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
				if target := string(r[start:i]); !strings.EqualFold(target, "$null") {
					s.targets = append(s.targets, target)
				}
			}
		default:
			cur = append(cur, c)
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
	// Compare runes in place: converting the rest of the command for every
	// braced variable made the reading quadratic (RV14-2).
	at := func(op string) bool {
		k := i
		for _, c := range op {
			if k >= len(r) || r[k] != c {
				return false
			}
			k++
		}
		return true
	}
	for _, op := range []string{"+=", "-=", "*=", "/=", "%=", "??=", "++", "--"} {
		if at(op) {
			return true
		}
	}
	return at("=") && !at("==")
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
			if s.overBound {
				return len(r)
			}
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
			if s.overBound {
				return len(r)
			}
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
