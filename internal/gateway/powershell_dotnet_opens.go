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
// static writes of psFileWriteMethod (rel-1-0-10:GAP-1138): File.Open,
// File.OpenHandle and the FileStream constructors, whose FileMode and
// FileAccess decide whether they write; the StreamWriter constructors, over a
// path or a stream variable; and the FileInfo opens and writes (Delete,
// CopyTo, MoveTo, Replace) of a FileInfo variable (also a typed one), a
// [IO.FileInfo] cast, a [IO.FileInfo]::new(f) or New-Object IO.FileInfo
// result, or a (Get-Item f) or (Get-ChildItem f) group. A read-only open
// (FileMode Open with FileAccess Read) writes nothing. An open whose mode,
// access or path is known only at run time may write: its twin is the
// unknown tier, never the write. So is a FileInfo write on a receiver the
// reader cannot place (a pipeline item, any other call result or variable)
// and a System.IO call it does not classify: every file the command spells
// may be the one written (rel-1-0-10:GAP-1230).

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
	psCallHandle   = "handle"   // (path[, FileMode[, FileAccess, ...]]): Open and Read by default
	psCallWriter   = "writer"   // (path or stream, ...)
	psCallFileInfo = "fileinfo" // (path)
)

// psDotNetCalls are the .NET calls (lower-case suffix of the text before
// their argument list) that open a file by its path: the static method,
// [T]::new and New-Object T(...).
var psDotNetCalls = []struct{ suffix, kind string }{
	{"file]::open", psCallOpen}, {"file]::openhandle", psCallHandle},
	{"filestream]::new", psCallOpen}, {"io.filestream", psCallOpen},
	{"streamwriter]::new", psCallWriter}, {"io.streamwriter", psCallWriter},
	{"fileinfo]::new", psCallFileInfo}, {"io.fileinfo", psCallFileInfo},
}

// psFileInfoMethod is what a FileInfo instance method does to the files it
// names.
type psFileInfoMethod struct {
	// receiver: the method writes (or removes) the FileInfo's own file;
	// mode: it opens it with the FileMode and FileAccess of its arguments.
	receiver, mode bool
	// arguments are the positions of the paths it writes.
	arguments []int
	// placedOnly: the name is too common on other types (String.Replace)
	// for a receiver the reader cannot place to count.
	placedOnly bool
	// stream: the method returns a stream (or writer) of the file.
	stream bool
}

// psFileInfoMethods are the FileInfo instance methods that open or write a
// file: the opens, Delete, and CopyTo, MoveTo and Replace, which write the
// files their arguments name (MoveTo and Replace also remove their own).
var psFileInfoMethods = map[string]psFileInfoMethod{
	"openwrite": {receiver: true, stream: true}, "appendtext": {receiver: true, stream: true},
	"createtext": {receiver: true, stream: true}, "create": {receiver: true, stream: true},
	"open": {mode: true, stream: true}, "delete": {receiver: true},
	"copyto": {arguments: []int{0}}, "moveto": {receiver: true, arguments: []int{0}},
	"replace": {receiver: true, arguments: []int{0, 1}, placedOnly: true},
}

// psReceiver is what a method is called on when it is not a variable: the
// body of the (...) group, or the result of the call that group is the
// argument list of (file: the twin parameter of the FileInfo it returns, ""
// when not known).
type psReceiver struct {
	text, file string
	call       bool
}

// psFileModes and psFileAccesses are the System.IO.FileMode and FileAccess
// names, by value.
var (
	psFileModes    = []string{"", "createnew", "create", "open", "openorcreate", "truncate", "append"}
	psFileAccesses = []string{"", "read", "write", "readwrite"}
)

// dotNetCall reads the .NET call whose argument list runs from the ( at
// open to end: method is the lower-case text before it, statement the
// statement so far, receiver what the method is called on when it is not a
// variable (nil for none). It returns the twin parameter of the FileInfo the
// call returns, "" for none known.
func (s *psStateScan) dotNetCall(method, statement string, receiver *psReceiver, open, end int) string {
	write := psFileWriteMethod(method)
	kind := ""
	for _, call := range psDotNetCalls {
		if strings.HasSuffix(method, call.suffix) {
			kind = call.kind
			break
		}
	}
	args := func() []string {
		if end-1 > open+1 && s.account(end-1-open) {
			if text := string(s.runes[open+1 : end-1]); strings.TrimSpace(text) != "" {
				return psSplitArgumentTexts(text, s.budget)
			}
		}
		return nil
	}
	variable, _, _ := psTypedAssignment(statement)
	switch {
	case write != nil:
		args := args()
		for _, index := range write {
			if index < len(args) {
				s.addOpen(args[index], psOpenWrite)
			}
		}
		s.bindStream(variable, args)
	case kind != "":
		args := args()
		s.dotNetConstruct(kind, variable, args)
		if kind == psCallFileInfo && len(args) == 1 && args[0] != "" && psLiteralArgument(args[0], s.budget) {
			return "-LiteralPath " + args[0]
		}
	case s.newObjectArguments(statement, args):
	case s.unclassifiedIOCall(statement, open, end):
	default:
		dot := strings.LastIndexByte(method, '.')
		if dot < 0 {
			return ""
		}
		name := method[dot+1:]
		if effect, ok := psFileInfoMethods[name]; ok {
			s.fileInfoMethod(name, effect, statement, receiver, variable, args())
		}
	}
	return ""
}

// fileInfoMethod reads the FileInfo instance method name (effect) called
// with args on receiver (or the variable before .name in statement), whose
// result is assigned to variable.
func (s *psStateScan) fileInfoMethod(name string, effect psFileInfoMethod, statement string, receiver *psReceiver, variable string, args []string) {
	file := s.fileInfoOf(statement, name, receiver)
	if file == "" {
		// A receiver the reader cannot place: an Open without a FileMode
		// and Replace are calls of other types (a connection, a string).
		if effect.placedOnly || effect.mode && len(args) == 0 {
			return
		}
		for _, index := range effect.arguments {
			if index < len(args) {
				s.addOpen(args[index], psOpenUnknown)
			}
		}
		if effect.receiver || effect.mode {
			s.unplaced = true
		}
		return
	}
	for _, index := range effect.arguments {
		if index < len(args) && !strings.EqualFold(args[index], "$null") {
			s.addOpen(args[index], psOpenWrite)
		}
	}
	verdict := psOpenWrite
	switch {
	case effect.mode:
		verdict = psOpenVerdictOf(args, 0)
	case !effect.receiver:
		return
	}
	if verdict != psOpenRead {
		s.opens = append(s.opens, psOpenTarget{file, verdict == psOpenUnknown})
	}
	if variable != "" && effect.stream {
		s.bind(&s.streams, variable, file)
	}
}

// dotNetConstruct reads a call of kind (psDotNetCalls) with args, whose
// result is assigned to variable ("" for none).
func (s *psStateScan) dotNetConstruct(kind, variable string, args []string) {
	switch kind {
	case psCallOpen, psCallHandle:
		verdict := psOpenVerdictOf(args, 1)
		if kind == psCallHandle {
			verdict = psHandleVerdictOf(args)
		}
		if verdict != psOpenRead && len(args) > 0 {
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
		if variable == "" {
			return
		}
		if len(args) > 0 && args[0] != "" && psLiteralArgument(args[0], s.budget) {
			s.bind(&s.fileInfos, variable, "-LiteralPath "+args[0])
			return
		}
		// A FileInfo of a path known only at run time is not placed.
		delete(s.fileInfos, variable)
	}
}

// newObjectArguments reads a (...) or @(...) group at open..end that is
// the argument list of the New-Object statement before it (New-Object T
// -ArgumentList @(f, m)); false when it is not one.
func (s *psStateScan) newObjectArguments(statement string, args func() []string) bool {
	text := strings.TrimSuffix(strings.TrimRight(statement, " \t"), "@")
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "new-object") {
		return false
	}
	variable, _, rest := psTypedAssignment(text)
	words := psJoinListWords(psWords(rest, s.budget), s.budget)
	if len(words) < 2 || s.budget.over || !strings.EqualFold(words[0].text, "new-object") {
		return false
	}
	typeName, arguments := psNewObjectParts(words)
	if typeName == "" || arguments != "" {
		return false
	}
	// The group is the argument list only when the statement ends with the
	// type name or an -ArgumentList (-Args) parameter.
	last := strings.ToLower(words[len(words)-1].text)
	name := strings.TrimPrefix(last, "-")
	if last != strings.ToLower(typeName) && (name == last || !strings.HasPrefix("argumentlist", name) && name != "args") {
		return false
	}
	s.dotNetNewObject(variable, typeName, args())
	return true
}

// dotNetNewObject reads New-Object typeName with args, whose result is
// assigned to variable.
func (s *psStateScan) dotNetNewObject(variable, typeName string, args []string) {
	typeName = psNewObjectType(typeName, s.budget)
	for _, call := range psDotNetCalls {
		if strings.HasPrefix(call.suffix, "io.") && typeName == call.suffix {
			s.dotNetConstruct(call.kind, variable, args)
			return
		}
	}
}

// psNewObjectType is the lower-case name of a New-Object type without its
// System. namespace.
func psNewObjectType(typeName string, budget *psBudget) string {
	return strings.TrimPrefix(strings.Trim(strings.ToLower(psUnquote(typeName, budget)), "[]"), "system.")
}

// psIOType is the lower-case System.IO type (io.file) a static call
// ([System.IO.File]::Name) before its argument list is made on, and the
// lower-case method name; false for any other call.
func psIOType(statement string) (typeName, name string, ok bool) {
	lower := strings.ToLower(strings.TrimRight(statement, " \t"))
	colons := strings.LastIndex(lower, "]::")
	if colons < 0 {
		return "", "", false
	}
	open := strings.LastIndexByte(lower[:colons], '[')
	if open < 0 {
		return "", "", false
	}
	typeName = strings.TrimPrefix(strings.TrimSpace(lower[open+1:colons]), "system.")
	name = lower[colons+3:]
	if !strings.HasPrefix(typeName, "io.") || name == "" || strings.ContainsAny(name, " \t.[]()") {
		return "", "", false
	}
	return typeName, name, true
}

// psIOReadOnly reports a System.IO static call (lower case) that writes no
// file: the Path methods, the constructors (the FileStream and
// StreamWriter ones are read before, by their FileMode and path), and the
// reads, lookups and listings.
func psIOReadOnly(typeName, name string) bool {
	if typeName == "io.path" || name == "new" {
		return true
	}
	for _, prefix := range []string{"get", "read", "enumerate", "exists", "openread", "opentext", "resolvelinktarget", "setcurrentdirectory"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

// unclassifiedIOCall reads a System.IO static call at open..end the reader
// does not classify (File.SetAttributes, File.CreateSymbolicLink,
// ZipFile.ExtractToDirectory, ...): every path its arguments spell may be
// one it writes, the unknown tier (rel-1-0-10:GAP-1230). False for any other
// call and for a read-only one.
func (s *psStateScan) unclassifiedIOCall(statement string, open, end int) bool {
	typeName, name, ok := psIOType(statement)
	if !ok {
		return false
	}
	if !psIOReadOnly(typeName, name) && end-1 > open+1 && s.account(end-1-open) {
		s.dynamicPaths = append(s.dynamicPaths, string(s.runes[open+1:end-1]))
	}
	return true
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
// called on: the receiver, else the variable before .name in statement; ""
// when the reader cannot place it.
func (s *psStateScan) fileInfoOf(statement, name string, receiver *psReceiver) string {
	switch {
	case receiver != nil && receiver.call:
		return receiver.file
	case receiver != nil:
		return psFileInfoExpression(receiver.text, s.budget)
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
// (or T a, b), $f = Get-Item f, $f = Get-ChildItem f, $f = [IO.FileInfo]'f'
// and [IO.FileInfo]$f = 'f'.
func (s *psStateScan) dotNetStatement(text string) {
	lower := strings.ToLower(text)
	if !strings.Contains(lower, "new-object") && !strings.Contains(lower, "fileinfo") &&
		!strings.Contains(lower, "get-item") && !strings.Contains(lower, "gi ") &&
		!strings.Contains(lower, "get-childitem") && !strings.Contains(lower, "gci ") &&
		!strings.Contains(lower, "dir ") && !strings.Contains(lower, "ls ") {
		return
	}
	variable, typeName, rest := psTypedAssignment(text)
	words := psJoinListWords(psWords(rest, s.budget), s.budget)
	if len(words) == 0 || s.budget.over {
		return
	}
	if !strings.EqualFold(words[0].text, "new-object") {
		if variable == "" {
			return
		}
		file := psFileInfoExpression(rest, s.budget)
		if file == "" && psFileInfoType(typeName) {
			// A variable typed [IO.FileInfo] converts what it is given.
			file = psFileInfoExpression("[IO.FileInfo]"+strings.TrimSpace(rest), s.budget)
		}
		if file != "" {
			s.bind(&s.fileInfos, variable, file)
		}
		return
	}
	typeName, arguments := psNewObjectParts(words)
	var args []string
	if strings.TrimSpace(arguments) != "" {
		args = psSplitArgumentTexts(psArrayBody(arguments), s.budget)
	}
	s.dotNetNewObject(variable, typeName, args)
}

// psFileInfoType reports the type literal [IO.FileInfo] ([System.IO.FileInfo]),
// lower case.
func psFileInfoType(typeName string) bool {
	return typeName == "[io.fileinfo]" || typeName == "[system.io.fileinfo]"
}

// psNewObjectParts returns the type name (-TypeName or the first positional
// word) and the argument list (-ArgumentList, -Args, the second positional
// word or the (...) glued to the type name) of a New-Object call whose words
// (comma lists joined) are words.
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
	if open := strings.IndexByte(typeName, '('); open > 0 && strings.HasSuffix(typeName, ")") && arguments == "" {
		// New-Object IO.FileInfo('f'): the argument list is glued on.
		typeName, arguments = typeName[:open], typeName[open:]
	}
	if arguments == "" && len(positional) > 0 {
		arguments = positional[0]
	}
	return typeName, arguments
}

// psFileInfoExpression returns the twin parameter of the file an expression
// evaluates to as a FileInfo: a [IO.FileInfo] cast of a literal,
// [IO.FileInfo]::new(literal), New-Object IO.FileInfo of a literal, or
// Get-Item (gi) or Get-ChildItem (gci, dir, ls) of one path; "" otherwise.
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
		if value == "" || strings.HasPrefix(value, "::") || !psLiteralArgument(value, budget) {
			return ""
		}
		return "-LiteralPath " + value
	}
	words := psWords(text, budget)
	if len(words) < 2 || budget.over {
		return ""
	}
	program := strings.ToLower(words[0].text)
	if program == "new-object" {
		typeName, arguments := psNewObjectParts(psJoinListWords(words, budget))
		if psNewObjectType(typeName, budget) != "io.fileinfo" {
			return ""
		}
		args := psSplitArgumentTexts(psArrayBody(arguments), budget)
		if len(args) != 1 || args[0] == "" || !psLiteralArgument(args[0], budget) {
			return ""
		}
		return "-LiteralPath " + args[0]
	}
	children := false
	switch program {
	case "get-item", "gi":
	case "get-childitem", "gci", "dir", "ls":
		children = true
	default:
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
		if strings.HasPrefix("force", name) && len(name) >= 2 || children && name == "file" {
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
		case children:
			// A filter, a recursion or any other selection of children
			// leaves the file unplaced.
			return ""
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

// psHandleVerdictOf is what File.OpenHandle(path[, FileMode[, FileAccess,
// ...]]) does to its file: FileMode Open and FileAccess Read by default, so
// only an Open with no access or FileAccess Read reads.
func psHandleVerdictOf(args []string) psOpenVerdict {
	if len(args) < 2 {
		return psOpenRead
	}
	if len(args) == 2 {
		switch name, ok := psEnumWord(args[1], "filemode", psFileModes); {
		case !ok:
			return psOpenUnknown
		case name == "open":
			return psOpenRead
		}
		return psOpenWrite
	}
	return psOpenVerdictOf(args, 1)
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

// psTypedAssignment returns the lower-case name of the variable a statement
// assigns ($name = ... or [T]$name = ...), the lower-case type literal it is
// constrained to ("" for none; the last when there are several) and the text
// after the =; "", "" and the statement when it assigns none.
func psTypedAssignment(statement string) (variable, typeName, rest string) {
	t := strings.TrimLeft(statement, " \t\r\n")
	for strings.HasPrefix(t, "[") {
		depth, end := 0, -1
		for k := 0; k < len(t) && end < 0; k++ {
			switch t[k] {
			case '[':
				depth++
			case ']':
				if depth--; depth == 0 {
					end = k
				}
			}
		}
		if end < 0 {
			return "", "", statement
		}
		typeName = strings.ToLower(strings.ReplaceAll(t[:end+1], " ", ""))
		t = strings.TrimLeft(t[end+1:], " \t")
	}
	if !strings.HasPrefix(t, "$") {
		return "", "", statement
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
		return "", "", statement
	}
	return strings.ToLower(t[1:j]), typeName, t[k+1:]
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
				(len(value) < 2 || value[1] != ':') {
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
