// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path"
	"strconv"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The .NET file opens the shared PowerShell write reader reads besides the
// static writes of psFileWriteMethod (rel-1-0-10:GAP-1138): File.Open and the
// FileStream constructors, whose FileMode and FileAccess decide whether they
// write; the StreamWriter constructors, over a path or a stream variable; and
// the FileInfo opens, of a FileInfo variable, a [IO.FileInfo] cast or a
// (Get-Item f) group. A read-only open (FileMode Open with FileAccess Read)
// writes nothing. An open whose mode, access or path is known only at run
// time may write: its twin is the unknown tier, never the write.

// psOpenTarget is the twin parameter (-LiteralPath 'f' or -Path f) of a file
// a .NET open writes; unknown when it may write it only.
type psOpenTarget struct {
	param   string
	unknown bool
}

// psOpenVerdict is what a .NET open does to its file.
type psOpenVerdict int

const (
	psOpenRead psOpenVerdict = iota
	psOpenWrite
	psOpenUnknown
)

// The kinds of .NET calls psDotNetCalls lists.
const (
	psCallOpen     = "open"     // (path, FileMode[, FileAccess, ...])
	psCallWriter   = "writer"   // (path or stream, ...)
	psCallFileInfo = "fileinfo" // (path)
)

// psDotNetCalls are the .NET calls (lower-case suffix of the text before
// their argument list) that open a file by its path: the static method,
// [T]::new and New-Object T(...).
var psDotNetCalls = []struct{ suffix, kind string }{
	{"file]::open", psCallOpen}, {"filestream]::new", psCallOpen}, {"io.filestream", psCallOpen},
	{"streamwriter]::new", psCallWriter}, {"io.streamwriter", psCallWriter},
	{"fileinfo]::new", psCallFileInfo}, {"io.fileinfo", psCallFileInfo},
}

// psFileInfoOpens are the FileInfo instance methods that open the file:
// true for the ones that always write, false for Open(FileMode[,
// FileAccess]).
var psFileInfoOpens = map[string]bool{
	"openwrite": true, "appendtext": true, "createtext": true, "create": true, "open": false,
}

// psFileModes and psFileAccesses are the System.IO.FileMode and FileAccess
// names, by value.
var (
	psFileModes    = []string{"", "createnew", "create", "open", "openorcreate", "truncate", "append"}
	psFileAccesses = []string{"", "read", "write", "readwrite"}
)

// dotNetCall reads the .NET call whose argument list runs from the ( at
// open to end: method is the lower-case text before it, statement the
// statement so far, receiver the body of the (...) group the method is
// called on, if any.
func (s *psStateScan) dotNetCall(method, statement, receiver string, open, end int) {
	write := psFileWriteMethod(method)
	kind := ""
	for _, call := range psDotNetCalls {
		if strings.HasSuffix(method, call.suffix) {
			kind = call.kind
			break
		}
	}
	file, always := "", false
	if write == nil && kind == "" {
		dot := strings.LastIndexByte(method, '.')
		if dot < 0 {
			return
		}
		name := method[dot+1:]
		var ok bool
		if always, ok = psFileInfoOpens[name]; !ok {
			return
		}
		if file = s.fileInfoOf(statement, name, receiver); file == "" {
			return
		}
	}
	var args []string
	if end-1 > open+1 && s.account(end-1-open) {
		if text := string(s.runes[open+1 : end-1]); strings.TrimSpace(text) != "" {
			args = psSplitArgumentTexts(text, s.budget)
		}
	}
	variable, _ := psAssignment(statement)
	switch {
	case write != nil:
		for _, index := range write {
			if index < len(args) {
				s.addOpen(args[index], psOpenWrite)
			}
		}
		s.bindStream(variable, args)
	case kind != "":
		s.dotNetConstruct(kind, variable, args)
	default:
		verdict := psOpenWrite
		if !always {
			verdict = psOpenVerdictOf(args, 0)
		}
		if verdict != psOpenRead {
			s.opens = append(s.opens, psOpenTarget{file, verdict == psOpenUnknown})
		}
		if variable != "" {
			s.bind(&s.streams, variable, file)
		}
	}
}

// dotNetConstruct reads a call of kind (psDotNetCalls) with args, whose
// result is assigned to variable ("" for none).
func (s *psStateScan) dotNetConstruct(kind, variable string, args []string) {
	switch kind {
	case psCallOpen:
		if verdict := psOpenVerdictOf(args, 1); verdict != psOpenRead && len(args) > 0 {
			s.addOpen(args[0], verdict)
		}
		s.bindStream(variable, args)
	case psCallWriter:
		if len(args) == 0 {
			return
		}
		if stream, ok := s.streams[strings.ToLower(strings.TrimPrefix(args[0], "$"))]; ok && strings.HasPrefix(args[0], "$") {
			s.opens = append(s.opens, psOpenTarget{param: stream})
			return
		}
		s.addOpen(args[0], psOpenWrite)
	case psCallFileInfo:
		if variable != "" && len(args) > 0 && args[0] != "" && psLiteralArgument(args[0], s.budget) {
			s.bind(&s.fileInfos, variable, "-LiteralPath "+args[0])
		}
	}
}

// addOpen adds the file of a .NET path argument that verdict writes or may
// write: a literal one as its twin, any other as a path known only at run
// time.
func (s *psStateScan) addOpen(arg string, verdict psOpenVerdict) {
	switch {
	case arg == "":
	case psLiteralArgument(arg, s.budget):
		s.opens = append(s.opens, psOpenTarget{"-LiteralPath " + arg, verdict == psOpenUnknown})
	default:
		s.dynamicPaths = append(s.dynamicPaths, arg)
	}
}

// bindStream records variable as the stream of the file args[0] opens.
func (s *psStateScan) bindStream(variable string, args []string) {
	if variable != "" && len(args) > 0 && args[0] != "" && psLiteralArgument(args[0], s.budget) {
		s.bind(&s.streams, variable, "-LiteralPath "+args[0])
	}
}

func (s *psStateScan) bind(vars *map[string]string, variable, param string) {
	if *vars == nil {
		*vars = map[string]string{}
	}
	(*vars)[variable] = param
}

// fileInfoOf returns the twin parameter of the FileInfo the method name is
// called on: the (...) group receiver, else the variable before .name in
// statement; "" when it is not a known FileInfo.
func (s *psStateScan) fileInfoOf(statement, name, receiver string) string {
	if receiver != "" {
		return psFileInfoExpression(receiver, s.budget)
	}
	before := strings.ToLower(strings.TrimRight(statement, " \t"))
	before, ok := strings.CutSuffix(before, "."+name)
	if !ok {
		return ""
	}
	k := len(before)
	for k > 0 && psVariableNameByte(before[k-1]) {
		k--
	}
	if k == 0 || k == len(before) || before[k-1] != '$' {
		return ""
	}
	return s.fileInfos[before[k:]]
}

// dotNetStatement reads a statement that binds a FileInfo or opens a file
// without an argument list in parentheses: New-Object T -ArgumentList a, b
// (or T a, b), $f = Get-Item f and $f = [IO.FileInfo]'f'.
func (s *psStateScan) dotNetStatement(text string) {
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "new-object") && !strings.Contains(lower, "fileinfo") &&
		!strings.Contains(lower, "get-item") && !strings.Contains(lower, "gi ") {
		return
	}
	variable, rest := psAssignment(text)
	words := psJoinListWords(psWords(rest, s.budget), s.budget)
	if len(words) == 0 || s.budget.over {
		return
	}
	if !strings.EqualFold(words[0].text, "new-object") {
		if variable != "" {
			if file := psFileInfoExpression(rest, s.budget); file != "" {
				s.bind(&s.fileInfos, variable, file)
			}
		}
		return
	}
	typeName, arguments := psNewObjectParts(words)
	typeName = strings.TrimPrefix(strings.Trim(strings.ToLower(psUnquote(typeName, s.budget)), "[]"), "system.")
	var args []string
	if strings.TrimSpace(arguments) != "" {
		args = psSplitArgumentTexts(psArrayBody(arguments), s.budget)
	}
	for _, call := range psDotNetCalls {
		if strings.HasPrefix(call.suffix, "io.") && typeName == call.suffix {
			s.dotNetConstruct(call.kind, variable, args)
			return
		}
	}
}

// psNewObjectParts returns the type name (-TypeName or the first positional
// word) and the argument list (-ArgumentList, -Args or the second positional
// word) of a New-Object call whose words (comma lists joined) are words.
func psNewObjectParts(words []psWord) (typeName, arguments string) {
	var positional []string
	for k := 1; k < len(words); k++ {
		word := words[k].text
		if words[k].quoted || len(word) < 2 || word[0] != '-' {
			positional = append(positional, word)
			continue
		}
		name, value, joined := strings.Cut(strings.ToLower(word[1:]), ":")
		if strings.HasPrefix("strict", name) {
			continue
		}
		if joined {
			value = word[len(name)+2:]
		} else if k+1 < len(words) {
			k++
			value = words[k].text
		}
		switch {
		case strings.HasPrefix("typename", name):
			typeName = value
		case strings.HasPrefix("argumentlist", name), name == "args":
			arguments = value
		}
	}
	if typeName == "" && len(positional) > 0 {
		typeName, positional = positional[0], positional[1:]
	}
	if arguments == "" && len(positional) > 0 {
		arguments = positional[0]
	}
	return typeName, arguments
}

// psFileInfoExpression returns the twin parameter of the file an expression
// evaluates to as a FileInfo: a [IO.FileInfo] cast of a literal,
// [IO.FileInfo]::new(literal) or Get-Item (gi) of one path; "" otherwise.
func psFileInfoExpression(text string, budget *psBudget) string {
	text = strings.TrimSpace(text)
	lower := strings.ToLower(text)
	for _, cast := range []string{"[system.io.fileinfo]", "[io.fileinfo]"} {
		if !strings.HasPrefix(lower, cast) || len(text) < len(cast) {
			continue
		}
		value := strings.TrimSpace(text[len(cast):])
		if inner, ok := strings.CutPrefix(strings.ToLower(value), "::new("); ok && strings.HasSuffix(inner, ")") {
			args := psSplitArgumentTexts(value[len("::new("):len(value)-1], budget)
			if len(args) != 1 {
				return ""
			}
			value = args[0]
		}
		if value == "" || !psLiteralArgument(value, budget) {
			return ""
		}
		return "-LiteralPath " + value
	}
	words := psWords(text, budget)
	if len(words) < 2 || budget.over {
		return ""
	}
	if program := strings.ToLower(words[0].text); program != "get-item" && program != "gi" {
		return ""
	}
	param := ""
	for k := 1; k < len(words); k++ {
		word := words[k].text
		if words[k].quoted || len(word) < 2 || word[0] != '-' {
			if param != "" {
				return ""
			}
			param = "-Path " + word
			continue
		}
		name := strings.ToLower(word[1:])
		if strings.HasPrefix("force", name) && len(name) >= 2 {
			continue
		}
		if k+1 >= len(words) {
			return ""
		}
		k++
		switch {
		case name == "lp" || name == "pspath" || strings.HasPrefix("literalpath", name):
			param = "-LiteralPath " + words[k].text
		case len(name) >= 2 && strings.HasPrefix("path", name):
			param = "-Path " + words[k].text
		}
	}
	if param == "" || !psLiteralArgument(param[strings.IndexByte(param, ' ')+1:], budget) {
		return ""
	}
	return param
}

// psOpenVerdictOf is what a .NET open whose FileMode is args[mode] and
// FileAccess (when given) args[mode+1] does to its file: only FileMode Open
// with FileAccess Read reads; a mode or access known only at run time may
// write.
func psOpenVerdictOf(args []string, mode int) psOpenVerdict {
	if mode >= len(args) {
		return psOpenUnknown
	}
	switch name, ok := psEnumWord(args[mode], "filemode", psFileModes); {
	case !ok:
		return psOpenUnknown
	case name != "open" || mode+1 >= len(args):
		// Every other mode creates, truncates or appends; Open without an
		// access opens for ReadWrite.
		return psOpenWrite
	}
	switch name, ok := psEnumWord(args[mode+1], "fileaccess", psFileAccesses); {
	case !ok:
		return psOpenUnknown
	case name == "read":
		return psOpenRead
	}
	return psOpenWrite
}

// psEnumWord returns the name (lower case) of a System.IO enum value spelled
// as a string, a number or [IO.<enum>]::Name; false when it is known only at
// run time or names no value of names.
func psEnumWord(arg, enum string, names []string) (string, bool) {
	word := strings.TrimSpace(arg)
	if word != "" && (psSingleQuote([]rune(word)[0]) || psDoubleQuote([]rune(word)[0])) {
		if strings.ContainsAny(word, "$`") && !psSingleQuote([]rune(word)[0]) {
			return "", false
		}
		word = strings.TrimSpace(psUnquote(word, nil))
	} else {
		lower := strings.ToLower(word)
		for _, prefix := range []string{"[system.io." + enum + "]::", "[io." + enum + "]::"} {
			if rest, ok := strings.CutPrefix(lower, prefix); ok {
				word = rest
				break
			}
		}
	}
	word = strings.ToLower(word)
	if n, err := strconv.Atoi(word); err == nil {
		if n > 0 && n < len(names) {
			return names[n], true
		}
		return "", false
	}
	for _, name := range names[1:] {
		if word == name {
			return name, true
		}
	}
	return "", false
}

// psAssignment returns the lower-case name of the variable a statement
// assigns ($name = ...) and the text after the =; "" and the statement when
// it assigns none.
func psAssignment(statement string) (variable, rest string) {
	t := strings.TrimLeft(statement, " \t\r\n")
	if !strings.HasPrefix(t, "$") {
		return "", statement
	}
	j := 1
	for j < len(t) && psVariableNameByte(t[j]) {
		j++
	}
	k := j
	for k < len(t) && (t[k] == ' ' || t[k] == '\t') {
		k++
	}
	if j == 1 || k >= len(t) || t[k] != '=' || k+1 < len(t) && t[k+1] == '=' {
		return "", statement
	}
	return strings.ToLower(t[1:j]), t[k+1:]
}

func psVariableNameByte(c byte) bool {
	return c == '_' || c < 0x80 && (unicode.IsLetter(rune(c)) || unicode.IsDigit(rune(c)))
}

// psDynamicPathReadings returns the twins of the files a .NET path argument
// known only at run time may name ((Resolve-Path 'f').Path, (Join-Path $HOME
// 'f')): each string in it and each bare word of it, also in home when the
// text spells the home.
func psDynamicPathReadings(text, home string, budget *psBudget) []string {
	r := []rune(text)
	scan := newPSScan(r, budget)
	lower := strings.ToLower(text)
	inHome := home != "" && (strings.Contains(lower, "$home") || strings.Contains(lower, "$env:userprofile") ||
		strings.Contains(lower, "${home}") || strings.Contains(lower, "~"))
	separator := `\`
	if strings.HasPrefix(home, "/") {
		separator = "/"
	}
	var forms []string
	for i := 0; i < len(r) && budget.step(); {
		if strings.ContainsRune(" \t\r\n()[]{},;+", r[i]) {
			i++
			continue
		}
		start := i
		quoted := psSingleQuote(r[i]) || psDoubleQuote(r[i])
		switch {
		case psSingleQuote(r[i]):
			i = scan.singleQuoted(i)
		case psDoubleQuote(r[i]):
			i = scan.doubleQuoted(i)
		default:
			for i < len(r) && !strings.ContainsRune(" \t\r\n()[]{},;+", r[i]) && budget.step() {
				i++
			}
		}
		word := string(r[start:min(i, len(r))])
		if quoted {
			forms = append(forms, "Set-Content "+psHomeLiteralParam("-LiteralPath "+word, home)+" -Value x")
			if value := psUnquote(word, budget); inHome && value != "" && !strings.ContainsAny(value[:1], `\/`) &&
				!(len(value) >= 2 && value[1] == ':') {
				forms = append(forms, "Set-Content -LiteralPath "+
					managed.PowerShellLiteral(strings.TrimRight(home, `\/`)+separator+strings.TrimLeft(value, `\/`))+" -Value x")
			}
		} else if word != "" && word[0] != '-' && strings.ContainsAny(word, `\/`) {
			forms = append(forms, "Set-Content -Path "+word+" -Value x")
		}
	}
	return forms
}

// psHomeLiteralParam returns a -LiteralPath "$HOME/f" twin parameter (or a
// -Path one with no wildcard) as -LiteralPath with the home written out
// ('<home>/f'): PowerShell's $HOME is a constant, and
// the literal twin is proven as the same path spelled out is, where the
// state proof left the expanded one unproven under a Linux or macOS home
// (rel-1-0-10:GAP-1138). Any other parameter is returned as it is.
func psHomeLiteralParam(param, home string) string {
	value, ok := strings.CutPrefix(param, "-LiteralPath ")
	pattern := false
	if !ok {
		// A -Path names the same file when it has no wildcard.
		value, pattern = strings.CutPrefix(param, "-Path ")
	}
	if !ok && !pattern || home == "" || len(value) < 2 || !psDoubleQuote([]rune(value)[0]) ||
		pattern && strings.ContainsAny(value, "*?[]") {
		return param
	}
	r := []rune(value)
	if !psDoubleQuote(r[len(r)-1]) {
		return param
	}
	inner := string(r[1 : len(r)-1])
	lower := strings.ToLower(inner)
	for _, anchor := range []string{"${home}", "$home"} {
		rest, ok := strings.CutPrefix(lower, anchor)
		if !ok || rest == "" || rest[0] != '/' && rest[0] != '\\' {
			continue
		}
		rest = inner[len(anchor):]
		if strings.ContainsAny(rest, "$`\"\u201c\u201d\u201e") || strings.ContainsFunc(rest, unicode.IsControl) {
			return param
		}
		return "-LiteralPath " + managed.PowerShellLiteral(strings.TrimRight(home, `\/`)+rest)
	}
	return param
}

// psPOSIXWriteTwin returns the arguments of the file write tool's write of
// the literal file a twin (Set-Content -LiteralPath <file> -Value x) names,
// under a Linux or macOS home, read in cwd; false for any other form, home or
// file.
func psPOSIXWriteTwin(form, home, cwd string) (json.RawMessage, bool) {
	value, ok := strings.CutPrefix(form, "Set-Content -LiteralPath ")
	if !ok || !strings.HasPrefix(home, "/") || !strings.HasPrefix(cwd, "/") {
		return nil, false
	}
	if value, ok = strings.CutSuffix(value, " -Value x"); !ok || value == "" {
		return nil, false
	}
	first := []rune(value)[0]
	switch {
	case psSingleQuote(first):
	case psDoubleQuote(first):
		if strings.ContainsAny(value, "$`") {
			return nil, false
		}
	default:
		if strings.ContainsAny(value, "$`~'\"()[]{}*? \t") {
			return nil, false
		}
	}
	file := value
	if psSingleQuote(first) || psDoubleQuote(first) {
		if !psQuotedWord(value, nil) {
			return nil, false
		}
		file = psUnquote(value, nil)
	}
	if file == "" || strings.HasPrefix(file, "~") || strings.ContainsFunc(file, unicode.IsControl) {
		return nil, false
	}
	if !strings.HasPrefix(file, "/") {
		file = path.Join(cwd, file)
	}
	args, err := json.Marshal(map[string]string{"file_path": file, "content": "x"})
	return args, err == nil
}
