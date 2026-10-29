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
	proven := func(form string) bool {
		input := request.Input
		input.Command, input.Args, input.Argv = form, nil, nil
		input.DialectHint = actionfacts.DialectPowerShell
		twin := request
		twin.Input = input
		return provenStateMutationPath(actionfacts.Analyze(input), twin)
	}
	const maxVariants = 256
	variants := 0
	for _, form := range forms {
		if proven(form) {
			return true
		}
		// PowerShell takes any unique parameter prefix (-ErrorA, -Verb,
		// -Fo), and the reader leaves an unknown parameter partial, which
		// dropped the proof. A mutator's prefixes are resolved; one that
		// stays unknown or ambiguous is read without it, alone and with
		// its value, and any reading that writes state is the write
		// (over-block, checker it15 RV15-2).
		forms, bounded := psParameterReadings(form)
		variants += len(forms)
		if bounded || variants > maxVariants {
			return true
		}
		for _, variant := range forms {
			if proven(variant) {
				return true
			}
		}
	}
	return false
}

// psMutatorCmdlet reports a cmdlet or alias that writes, renames, moves,
// copies over, empties or removes the item its path parameters name.
func psMutatorCmdlet(word string) bool {
	switch strings.ToLower(word) {
	case "rename-item", "rni", "ren", "move-item", "mi", "mv", "move",
		"copy-item", "cpi", "cp", "copy", "remove-item", "ri", "rm", "rmdir",
		"rd", "del", "erase", "clear-content", "clc", "set-content", "sc",
		"add-content", "ac", "out-file", "new-item", "ni", "clear-item", "cli",
		"set-item", "si", "tee-object", "tee":
		return true
	}
	return false
}

// psKnownParameters are the full parameter names of the mutator cmdlets
// and the common parameters, and their aliases; a prefix that matches one
// of them only is that parameter, as PowerShell binds it.
var psKnownParameters = []string{
	"Path", "LiteralPath", "PSPath", "LP", "Destination", "NewName", "Force",
	"Recurse", "Value", "Encoding", "NoNewline", "PassThru", "Filter",
	"Include", "Exclude", "Credential", "WhatIf", "Confirm", "Stream",
	"ItemType", "Type", "Name", "InputObject", "Append", "NoClobber", "Width",
	"FilePath", "Target", "UseTransaction", "Container", "ToSession",
	"FromSession", "AsByteStream", "Delimiter", "Wait", "ReadCount",
	"ErrorAction", "ErrorVariable", "WarningAction", "WarningVariable",
	"InformationAction", "InformationVariable", "OutVariable", "OutBuffer",
	"PipelineVariable", "Verbose", "Debug", "ProgressAction", "ea", "ev",
	"wa", "wv", "infa", "iv", "ov", "ob", "pv", "vb", "db", "proga", "wi", "cf",
}

// psSwitchParameter reports a known switch parameter (no value of its own).
func psSwitchParameter(name string) bool {
	switch strings.ToLower(name) {
	case "force", "recurse", "nonewline", "passthru", "whatif", "confirm",
		"append", "noclobber", "usetransaction", "container", "asbytestream",
		"wait", "verbose", "debug", "wi", "cf", "vb", "db":
		return true
	}
	return false
}

// psParameterReadings returns the readings of a mutator statement with
// abbreviated parameters: one with every unique prefix spelled out, and,
// for each parameter that stays unknown or ambiguous, that reading without
// it and without it and its value. Nothing is returned for a statement
// whose parameters are all known. bounded reports too many to read.
func psParameterReadings(form string) ([]string, bool) {
	budget := &psBudget{}
	words := psWords(form, budget)
	if budget.over {
		return nil, true
	}
	if len(words) < 2 || !psMutatorCmdlet(words[0].text) {
		return nil, false
	}
	texts := make([]string, len(words))
	var unknown []int
	changed := false
	for k, word := range words {
		texts[k] = word.text
		if k == 0 || word.quoted || len(word.text) < 2 || word.text[0] != '-' {
			continue
		}
		c := word.text[1]
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
			continue
		}
		name, value, hasValue := strings.Cut(word.text[1:], ":")
		full := ""
		matches := 0
		for _, known := range psKnownParameters {
			if strings.EqualFold(known, name) {
				full, matches = known, 1
				break
			}
			if len(name) <= len(known) && strings.EqualFold(known[:len(name)], name) {
				full = known
				matches++
			}
		}
		switch {
		case matches == 1 && hasValue:
			// -Name:value binds as -Name value, and a switch bound to
			// anything but $true is off; the readers know only the spaced
			// form, so the colon form dropped the proof (checker it16
			// RV16-1).
			texts[k] = "-" + full
			if psSwitchParameter(full) {
				if !strings.EqualFold(value, "$true") && value != "1" {
					texts[k] = ""
				}
			} else if value != "" {
				texts[k] += " " + value
			}
			changed = true
		case matches == 1 && strings.EqualFold(full, name):
		case matches == 1:
			texts[k] = "-" + full
			changed = true
		default:
			unknown = append(unknown, k)
		}
	}
	const maxUnknown = 8
	if len(unknown) > maxUnknown {
		return nil, true
	}
	var readings []string
	without := func(skip, count int) string {
		parts := make([]string, 0, len(texts))
		for k, text := range texts {
			if text != "" && (k < skip || k >= skip+count) {
				parts = append(parts, text)
			}
		}
		return strings.Join(parts, " ")
	}
	if changed {
		readings = append(readings, without(len(texts), 0))
	}
	for _, k := range unknown {
		readings = append(readings, without(k, 1))
		if k+1 < len(texts) {
			readings = append(readings, without(k, 2))
		}
	}
	return readings, false
}

// psStateScanMaxRunes bounds the text the PowerShell reading copies into
// pieces and argument lists; psNestedShellDepth bounds powershell -Command
// bodies read inside each other. Ordinary commands stay far below both; a
// crafted command past one is judged the write (RV14-2).
const (
	psStateScanMaxRunes = 1 << 20
	psStateScanMaxSteps = 1 << 22
	psNestedShellDepth  = 3
)

// psBudget is the one copy and work budget of a whole reading: the
// command, every word split, every unquote and every nested shell body
// share it, so balanced nesting cannot multiply the work (checker it15
// RV15-1). Past it the reading is bounded.
type psBudget struct {
	copied, steps int
	over          bool
}

func (b *psBudget) step() bool {
	b.steps++
	if b.steps > psStateScanMaxSteps {
		b.over = true
	}
	return !b.over
}

func newPSScan(runes []rune, budget *psBudget) *psStateScan {
	if budget == nil {
		budget = &psBudget{}
	}
	return &psStateScan{runes: runes, budget: budget}
}

// powerShellStateWriteForms returns the PowerShell twins of command that
// name DefenseClaw (see provenPowerShellStateWrite), deduplicated. A
// powershell or pwsh -Command body is read as PowerShell too. bounded
// reports a command past the reading bounds. ok is false when PowerShell
// cannot parse the command: a < that starts a token is a parse error there
// (a Git Bash here-document or input redirect), so nothing runs in that
// reading.
func powerShellStateWriteForms(command string) (forms []string, bounded, ok bool) {
	seen := map[string]bool{}
	budget := &psBudget{}
	bounded, ok = psCollectStateWriteForms(command, 0, seen, &forms, budget)
	return forms, bounded, ok
}

func psCollectStateWriteForms(command string, depth int, seen map[string]bool, forms *[]string, budget *psBudget) (bool, bool) {
	scan := newPSScan([]rune(command), budget)
	scan.code(0, false)
	if scan.overBound() {
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
		body, nested := psNestedShellBody(piece, budget)
		if budget.over {
			return true, true
		}
		if !nested || !strings.Contains(strings.ToLower(body), "defenseclaw") {
			continue
		}
		if depth >= psNestedShellDepth {
			return true, true
		}
		// A body PowerShell cannot parse runs nothing; only its bound counts.
		if bounded, _ := psCollectStateWriteForms(body, depth+1, seen, forms, budget); bounded {
			return true, true
		}
	}
	for _, body := range scan.bodies {
		if !strings.Contains(strings.ToLower(body), "defenseclaw") {
			continue
		}
		if depth >= psNestedShellDepth {
			return true, true
		}
		if bounded, _ := psCollectStateWriteForms(body, depth+1, seen, forms, budget); bounded {
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
func psWords(statement string, budget *psBudget) []psWord {
	r := []rune(statement)
	scan := newPSScan(r, budget)
	var words []psWord
	for i := 0; i < len(r) && scan.budget.step(); {
		if r[i] == ' ' || r[i] == '\t' || r[i] == '\r' || r[i] == '\n' {
			i++
			continue
		}
		start := i
		for i < len(r) && r[i] != ' ' && r[i] != '\t' && r[i] != '\r' && r[i] != '\n' && scan.budget.step() {
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
func psUnquote(word string, budget *psBudget) string {
	r := []rune(word)
	if len(r) < 2 || !psQuotedWord(word, budget) {
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
func psNestedShellBody(statement string, budget *psBudget) (string, bool) {
	// Only a statement that names a shell or a string runner is split into
	// words (checker it15 RV15-1: every piece was tokenized).
	lower := strings.ToLower(statement)
	if !strings.Contains(lower, "powershell") && !strings.Contains(lower, "pwsh") &&
		!strings.Contains(lower, "iex") && !strings.Contains(lower, "invoke-expression") {
		return "", false
	}
	words := psWords(statement, budget)
	if len(words) == 0 || budget.over {
		return "", false
	}
	body := func(rest []psWord) string {
		if len(rest) == 1 {
			return psUnquote(rest[0].text, budget)
		}
		parts := make([]string, 0, len(rest))
		for _, word := range rest {
			parts = append(parts, psUnquote(word.text, budget))
		}
		return strings.Join(parts, " ")
	}
	program := psProgramName(psUnquote(words[0].text, budget))
	switch program {
	case "iex", "invoke-expression":
		// Invoke-Expression runs its string in this session as a -Command
		// body (checker it15 RV15-2).
		for k := 1; k < len(words); k++ {
			name, value, _ := strings.Cut(words[k].text, ":")
			name = strings.ToLower(name)
			if !words[k].quoted && strings.HasPrefix(name, "-") {
				if len(name) >= 2 && strings.HasPrefix("-command", name) {
					// -Command:'...' binds the string in the same word
					// (checker it16 RV16-2).
					if value != "" {
						return body([]psWord{{text: value}}), true
					}
					if k+1 < len(words) {
						return body(words[k+1 : k+2]), true
					}
				}
				continue
			}
			return body(words[k : k+1]), true
		}
		return "", false
	case "start-process", "saps", "start":
		return psStartProcessShellBody(words, budget)
	case "powershell", "pwsh":
	default:
		return "", false
	}
	return psShellArgumentsBody(words, body)
}

// psProgramName is the lower-case command name of a program word, without
// its directory and .exe.
func psProgramName(word string) string {
	program := strings.ToLower(word)
	if index := strings.LastIndexAny(program, `\/`); index >= 0 {
		program = program[index+1:]
	}
	return strings.TrimSuffix(program, ".exe")
}

// psPipedInvokeBody returns the string a pipeline element runs when it is
// Invoke-Expression (iex) and the element before it is one string:
// 'Clear-Content STATE' | iex runs Clear-Content (checker it16 RV16-2).
func psPipedInvokeBody(from, element string, budget *psBudget) (string, bool) {
	word := strings.TrimSpace(element)
	if index := strings.IndexAny(word, " \t\r\n"); index >= 0 {
		word = word[:index]
	}
	if program := psProgramName(word); program != "iex" && program != "invoke-expression" {
		return "", false
	}
	from = strings.TrimSpace(from)
	if !psQuotedWord(from, budget) {
		return "", false
	}
	return psUnquote(from, budget), true
}

// psStartProcessStatement reports a statement (so far) whose command is
// Start-Process or one of its aliases; only its first word is read.
func psStartProcessStatement(cur []rune) bool {
	k := 0
	for k < len(cur) && (cur[k] == ' ' || cur[k] == '\t' || cur[k] == '\r') {
		k++
	}
	end := k
	for end < len(cur) && end-k <= len("start-process") && cur[end] != ' ' && cur[end] != '\t' {
		end++
	}
	switch strings.ToLower(string(cur[k:end])) {
	case "start-process", "saps", "start":
		return true
	}
	return false
}

// psJoinListWords joins the words of a comma list written with blanks
// ('-c', 'x' or "-c" ,"x") and of a (...) or @(...) array into one word, as
// PowerShell binds them to one parameter (checker it16 RV16-2).
func psJoinListWords(words []psWord, budget *psBudget) []psWord {
	out := make([]psWord, 0, len(words))
	for k := 0; k < len(words); k++ {
		word := words[k]
		depth := psParenDelta(word.text, budget)
		for k+1 < len(words) && budget.step() &&
			(strings.HasSuffix(word.text, ",") || strings.HasPrefix(words[k+1].text, ",") || depth > 0) {
			k++
			word.text += " " + words[k].text
			depth += psParenDelta(words[k].text, budget)
		}
		out = append(out, word)
	}
	return out
}

// psParenDelta is the count of ( minus ) of word outside its strings.
func psParenDelta(word string, budget *psBudget) int {
	r := []rune(word)
	scan := newPSScan(r, budget)
	delta := 0
	for i := 0; i < len(r) && budget.step(); i++ {
		switch {
		case r[i] == '`':
			i++
		case psSingleQuote(r[i]):
			i = scan.singleQuoted(i) - 1
		case psDoubleQuote(r[i]):
			i = scan.doubleQuoted(i) - 1
		case r[i] == '(':
			delta++
		case r[i] == ')':
			delta--
		}
	}
	return delta
}

// psArrayBody returns the elements of a (...) or @(...) array literal, or
// text itself.
func psArrayBody(text string) string {
	t := strings.TrimPrefix(strings.TrimSpace(text), "@")
	if len(t) >= 2 && t[0] == '(' && t[len(t)-1] == ')' {
		return t[1 : len(t)-1]
	}
	return text
}

// psStartProcessShellBody returns the script a Start-Process of powershell
// or pwsh runs: its -ArgumentList (a string or a comma list, joined with
// spaces as Start-Process does) is the shell's argument line (checker it15
// RV15-2).
func psStartProcessShellBody(words []psWord, budget *psBudget) (string, bool) {
	words = psJoinListWords(words, budget)
	var file, arguments string
	var positional []string
	for k := 1; k < len(words); k++ {
		name, value, hasValue := strings.Cut(strings.ToLower(words[k].text), ":")
		if words[k].quoted || !strings.HasPrefix(name, "-") || len(name) < 2 {
			positional = append(positional, words[k].text)
			continue
		}
		if !hasValue && psStartProcessSwitch(name) {
			continue
		}
		if !hasValue {
			if k+1 >= len(words) {
				break
			}
			k++
			value = words[k].text
		} else {
			value = words[k].text[len(name)+1:]
		}
		switch {
		case strings.HasPrefix("-filepath", name), name == "-pspath", name == "-path":
			file = value
		case len(name) >= 2 && strings.HasPrefix("-argumentlist", name), name == "-args":
			arguments = value
		}
	}
	if file == "" && len(positional) > 0 {
		file, positional = positional[0], positional[1:]
	}
	if arguments == "" && len(positional) > 0 {
		arguments = positional[0]
	}
	program := psProgramName(psUnquote(file, budget))
	if program != "powershell" && program != "pwsh" || arguments == "" {
		return "", false
	}
	var parts []string
	for _, part := range psSplitArguments(psArrayBody(arguments), budget) {
		if part == "" {
			return "", false
		}
		parts = append(parts, psUnquote(part, budget))
	}
	line := strings.Join(parts, " ")
	inner := psWords("powershell "+line, budget)
	return psShellArgumentsBody(inner, func(rest []psWord) string {
		texts := make([]string, 0, len(rest))
		for _, word := range rest {
			texts = append(texts, psUnquote(word.text, budget))
		}
		return strings.Join(texts, " ")
	})
}

// psStartProcessSwitch reports a Start-Process switch parameter (no value).
func psStartProcessSwitch(name string) bool {
	for _, full := range []string{"-wait", "-nonewwindow", "-passthru", "-usenewenvironment", "-loaduserprofile"} {
		if len(name) >= 3 && strings.HasPrefix(full, name) {
			return true
		}
	}
	return false
}

// psShellArgumentsBody returns the -Command body of a powershell or pwsh
// call whose words (program first) are words.
func psShellArgumentsBody(words []psWord, body func([]psWord) string) (string, bool) {
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
	bodies     []string // strings piped into Invoke-Expression
	parseError bool
	budget     *psBudget
}

func (s *psStateScan) overBound() bool { return s.budget.over }

// account adds n copied runes and reports the reading still within bound.
func (s *psStateScan) account(n int) bool {
	s.budget.copied += n
	if s.budget.copied > psStateScanMaxRunes {
		s.budget.over = true
	}
	return !s.budget.over
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
	var last, pipedFrom string
	flush := func() {
		text := string(cur)
		if strings.TrimSpace(text) != "" && s.account(len(cur)) {
			s.pieces = append(s.pieces, text)
			if pipedFrom != "" {
				if body, ok := psPipedInvokeBody(pipedFrom, text, s.budget); ok {
					s.bodies = append(s.bodies, body)
				}
			}
		}
		last, pipedFrom = text, ""
		cur = cur[:0]
	}
	for i < len(r) && !s.parseError && s.budget.step() {
		c := r[i]
		switch {
		case c == '`':
			cur = append(cur, c)
			if i+1 < len(r) {
				cur = append(cur, r[i+1])
			}
			i += 2
		case c == '|':
			// A string piped into Invoke-Expression runs as its body
			// (checker it16 RV16-2).
			flush()
			if i+1 < len(r) && r[i+1] == '|' {
				i += 2
				continue
			}
			pipedFrom = last
			i++
		case c == '\n' || c == ';' || c == '&' || c == '{' || c == '}':
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
			// A Start-Process statement keeps its (...) and @(...)
			// argument arrays, so the -ArgumentList it runs is read
			// (checker it16 RV16-2); the body is still scanned as a piece.
			keep := psStartProcessStatement(cur)
			if !keep {
				flush()
			}
			end := s.code(i+1, true)
			if s.overBound() {
				return len(r)
			}
			if keep && s.account(end-i) {
				cur = append(cur, r[i:end]...)
			}
			if write := psFileWriteMethod(method); write != nil && end-1 > i+1 && s.account(end-1-i) {
				args := psSplitArguments(string(r[i+1:end-1]), s.budget)
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
			for j+1 < len(r) && (r[j] != '#' || r[j+1] != '>') && s.budget.step() {
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
			if s.overBound() {
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
			if s.overBound() {
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
				if s.overBound() {
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
	for j < len(r) && s.budget.step() {
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
			if s.overBound() {
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
	for j := i + 1; j < len(r) && s.budget.step(); j++ {
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
	for j := i + 1; j < len(r) && s.budget.step(); j++ {
		switch {
		case r[j] == '`':
			j++
		case r[j] == '$' && j+1 < len(r) && r[j+1] == '(':
			j = s.code(j+2, true) - 1
			if s.overBound() {
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
func psSplitArguments(text string, budget *psBudget) []string {
	r := []rune(text)
	scan := newPSScan(r, budget)
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
		if strings.ContainsAny(arg, "()[]{} \t\r\n") && !psQuotedWord(arg, budget) {
			arg = ""
		}
		args = append(args, arg)
		start = i + 1
	}
	return args
}

func psQuotedWord(arg string, budget *psBudget) bool {
	r := []rune(arg)
	if len(r) < 2 {
		return false
	}
	scan := newPSScan(r, budget)
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
