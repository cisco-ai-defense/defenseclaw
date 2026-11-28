// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"path"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/defenseclaw/defenseclaw/internal/asciifold"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The .NET file opens the shared PowerShell write reader reads besides the
// static writes of psFileWriteMethod (rel-1-0-10:GAP-1138): File.Open,
// File.OpenHandle and the FileStream constructors, whose FileMode and
// FileAccess decide whether they write; the StreamWriter constructors, over a
// path or a stream variable; and the FileInfo opens and writes (Delete,
// CopyTo, MoveTo, Replace) of a FileInfo variable (also a typed one), a
// [IO.FileInfo] cast, a [IO.FileInfo]::new(f) or New-Object IO.FileInfo
// result, a (Get-Item f) or (Get-ChildItem f) group (each path of a path
// array), or the pipeline item of a ForEach-Object block such a command, read
// whole, feeds. A read-only open (FileMode Open with FileAccess Read) writes
// nothing. An open whose mode, access or path is known only at run time may
// write: its twin is the unknown tier, never the write. So is a FileInfo
// write on a receiver the reader cannot place (any other pipeline item, call
// result or variable, a variable with an assignment the reader does not
// place, and any variable of a command that may bind one by a name built at
// run time) and a System.IO call it does not classify: every file the
// command spells may be the one written (rel-1-0-10:GAP-1230, GAP-1257,
// GAP-1275, GAP-1276, GAP-1277). A Get-ChildItem result of a folder is its
// children, and a Get-Item result of one is a DirectoryInfo whose Delete and
// MoveTo take what it holds: such a write may write every file the folder
// holds, the unknown tier (rel-1-0-10:GAP-1257).

// psOpenTarget is the twin parameter (-LiteralPath 'f' or -Path f) of a file
// a .NET open writes; unknown when it may write it only. folder reports an
// open that also writes every file the path holds when it is a folder (the
// unknown tier: psFolderTwin).
type psOpenTarget struct {
	param           string
	unknown, folder bool
}

// psFileInfo is the FileInfo (or DirectoryInfo) the reader places a receiver
// at: params are the twin parameters of its paths (one per element of a
// path array, none when not placed), kind what the receiver is of them, and
// maybe the earlier bindings of a variable it may still be (a binding in a
// block or a branch need not have run): their writes are the unknown tier
// (rel-1-0-10:GAP-1277, GAP-1278).
type psFileInfo struct {
	params []string
	kind   psFileInfoKind
	maybe  []psFileInfo
}

// placed reports a receiver the reader places.
func (f psFileInfo) placed() bool { return len(f.params) > 0 }

// unsure is the reading of a receiver the reader places but may be wrong
// about (a run-time name may bind it, or a use may re-bind it): not placed,
// each of its readings a maybe (rel-1-0-10:GAP-1301).
func (f psFileInfo) unsure() psFileInfo {
	if !f.placed() {
		return f
	}
	return psFileInfo{maybe: psReadings(psFileInfo{}, []psFileInfo{f})}
}

// same reports a reading of the same paths, of the same kind, as g.
func (f psFileInfo) same(g psFileInfo) bool {
	return f.kind == g.kind && slices.Equal(f.params, g.params)
}

// psReadings returns every reading the bindings may be (each placed binding
// and each of its maybes), once each, in reading order, without the
// readings that are the same as placed: a binding that is the same file as
// the receiver's own reading can change nothing (rel-1-0-10:GAP-1315).
func psReadings(placed psFileInfo, bindings []psFileInfo) []psFileInfo {
	var readings []psFileInfo
	var add func(f psFileInfo)
	add = func(f psFileInfo) {
		if f.placed() {
			reading := psFileInfo{params: f.params, kind: f.kind}
			if !placed.placed() || !reading.same(placed) {
				if !slices.ContainsFunc(readings, reading.same) {
					readings = append(readings, reading)
				}
			}
		}
		for _, maybe := range f.maybe {
			add(maybe)
		}
	}
	for _, binding := range bindings {
		add(binding)
	}
	return readings
}

// psLiteralFileInfo is the FileInfo of the literal .NET path argument arg.
func psLiteralFileInfo(arg string) psFileInfo {
	return psFileInfo{params: []string{"-LiteralPath " + arg}}
}

// psFileInfoKind is what a placed receiver is of its path.
type psFileInfoKind int

const (
	// psFileInfoFile: a FileInfo of the path ([IO.FileInfo], New-Object).
	psFileInfoFile psFileInfoKind = iota
	// psFileInfoItem: the item at the path (Get-Item), a DirectoryInfo
	// when it is a folder.
	psFileInfoItem
	// psFileInfoChildren: the item when the path is a file, else every
	// item in the folder (Get-ChildItem): a method runs on each.
	psFileInfoChildren
)

// writesFolder reports a receiver write (name, a psFileInfoMethods name) that
// may write every file the path holds: any write of a Get-ChildItem result,
// and a DirectoryInfo Delete or MoveTo of a Get-Item one.
func (f psFileInfo) writesFolder(name string) bool {
	return f.kind == psFileInfoChildren || f.kind == psFileInfoItem && (name == "delete" || name == "moveto")
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
// argument list of (file: the FileInfo it returns, unplaced when not known).
type psReceiver struct {
	text string
	file psFileInfo
	call bool
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
// variable (nil for none). It returns the FileInfo the call returns,
// unplaced for none known.
func (s *psStateScan) dotNetCall(method, statement string, receiver *psReceiver, open, end int) psFileInfo {
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
			return psLiteralFileInfo(args[0])
		}
	case s.newObjectArguments(statement, args):
	case s.unclassifiedIOCall(statement, open, end):
	default:
		dot := strings.LastIndexByte(method, '.')
		if dot < 0 {
			return psFileInfo{}
		}
		name := method[dot+1:]
		if effect, ok := psFileInfoMethods[name]; ok {
			s.fileInfoMethod(name, effect, statement, receiver, variable, args(), open)
		}
	}
	return psFileInfo{}
}

// fileInfoMethod reads the FileInfo instance method name (effect) called
// with args on receiver (or the variable before .name in statement), whose
// result is assigned to variable; its argument list opens at rune index open.
func (s *psStateScan) fileInfoMethod(name string, effect psFileInfoMethod, statement string, receiver *psReceiver, variable string, args []string, open int) {
	file := s.fileInfoOf(statement, name, receiver, open)
	if !file.placed() {
		// A receiver the reader knows nothing of: an Open without a
		// FileMode and Replace are calls of other types (a connection, a
		// string), and an Open with a literal read mode reads whatever file
		// it is (rel-1-0-10:GAP-1258). A receiver the reader placed but is
		// not sure of (file.maybe) is a FileInfo it may still be: its
		// Replace is read as Delete's and CopyTo's are, never as nothing
		// (rel-1-0-10:GAP-1301).
		if effect.placedOnly && len(file.maybe) == 0 || effect.mode && (len(args) == 0 || psOpenVerdictOf(args, 0) == psOpenRead) {
			return
		}
		for _, index := range effect.arguments {
			if index < len(args) {
				s.addOpen(args[index], psOpenUnknown)
			}
		}
		if effect.receiver || effect.mode {
			s.unplaced = true
			s.maybeOpens(file, name)
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
		for _, param := range file.params {
			s.opens = append(s.opens, psOpenTarget{param, verdict == psOpenUnknown, file.writesFolder(name)})
		}
		s.maybeOpens(file, name)
	}
	if variable != "" && effect.stream && len(file.params) == 1 && len(file.maybe) == 0 {
		s.bind(&s.streams, variable, file.params[0])
	}
}

// maybeOpens adds the files of the readings the receiver file may be
// (file.maybe) that the FileInfo method name writes, as the unknown tier.
func (s *psStateScan) maybeOpens(file psFileInfo, name string) {
	for _, maybe := range file.maybe {
		for _, param := range maybe.params {
			s.opens = append(s.opens, psOpenTarget{param, true, maybe.writesFolder(name)})
		}
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
		// A FileInfo of a path known only at run time is not placed: its
		// assignment leaves the variable unplaced (variableFileInfo).
		if len(args) > 0 && args[0] != "" && psLiteralArgument(args[0], s.budget) {
			s.bindFileInfo(variable, psLiteralFileInfo(args[0]))
		}
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
		s.opens = append(s.opens, psOpenTarget{param: "-LiteralPath " + arg, unknown: verdict == psOpenUnknown})
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

// bindFileInfo records a binding of variable, in reading order: placed, or
// a copy of a variable the reader is not sure of (no params, its readings
// as maybes).
func (s *psStateScan) bindFileInfo(variable string, file psFileInfo) {
	if s.fileInfos == nil {
		s.fileInfos = map[string][]psFileInfo{}
	}
	s.fileInfos[variable] = append(s.fileInfos[variable], file)
}

// fileInfoOf returns the FileInfo the method name, whose argument list opens
// at rune index at, is called on: the receiver, else the variable before
// .name in statement (variableFileInfo; the pipeline item of the
// ForEach-Object block being read, for $_ and $PSItem); unplaced when the
// reader cannot place it, and unsure (psFileInfo.unsure) when the command
// may bind a variable by a name built at run time (rel-1-0-10:GAP-1257,
// GAP-1276, GAP-1301).
func (s *psStateScan) fileInfoOf(statement, name string, receiver *psReceiver, at int) psFileInfo {
	switch {
	case receiver != nil && receiver.call:
		return receiver.file
	case receiver != nil:
		return psFileInfoExpression(receiver.text, s.budget)
	}
	before := strings.ToLower(strings.TrimRight(statement, " \t"))
	before, ok := strings.CutSuffix(before, "."+name)
	if !ok {
		return psFileInfo{}
	}
	k := len(before)
	for k > 0 && psVariableNameByte(before[k-1]) {
		k--
	}
	if k == 0 || k == len(before) || before[k-1] != '$' {
		return psFileInfo{}
	}
	variable := before[k:]
	var file psFileInfo
	if variable == "_" || variable == "psitem" {
		if s.item.placed() {
			s.itemUses++
		}
		file = s.item
	} else {
		file = s.variableFileInfo(variable, at)
	}
	if s.dynamicVariables() {
		return file.unsure()
	}
	return file
}

// psVariableCount is what psVariableUses reads of one variable in the whole
// command.
type psVariableCount struct {
	assignments int
	rebinds     bool
}

// lowerText returns the command in lower case, read once; false past the
// reading bounds.
func (s *psStateScan) lowerText() (string, bool) {
	if s.lower == "" && s.account(len(s.runes)) {
		s.lower = strings.ToLower(string(s.runes))
	}
	return s.lower, !s.budget.over
}

// dynamicVariables reports a command that may bind a variable by a name
// built at run time (psDynamicVariableWrite), read once; also past the
// reading bounds.
func (s *psStateScan) dynamicVariables() bool {
	if s.dynamic == 0 {
		s.dynamic = 1
		if lower, ok := s.lowerText(); !ok || psDynamicVariableWrite(lower, s.budget) {
			s.dynamic = 2
		}
	}
	return s.dynamic == 2
}

// variableFileInfo returns the FileInfo the variable (lower case) is when a
// method whose argument list opens at rune index at is called on it: the
// binding read last, and the earlier ones it may still be (maybe). It is
// unsure (psFileInfo.unsure: every binding a maybe) when an assignment of it
// before the call is one the reader does not place, when one after the call
// may run before it (the call is in a block, which may run again, or a trap
// block may run first), and when a use may bind it otherwise
// (psVariableUses). A plain read of the variable binds nothing
// (rel-1-0-10:GAP-1257, GAP-1278, GAP-1301).
func (s *psStateScan) variableFileInfo(variable string, at int) psFileInfo {
	bindings := s.fileInfos[variable]
	lower, ok := s.lowerText()
	if len(bindings) == 0 || !ok {
		return psFileInfo{}
	}
	count, ok := s.uses[variable]
	if !ok {
		count.assignments, count.rebinds = psVariableUses(lower, variable)
		if s.uses == nil {
			s.uses = map[string]psVariableCount{}
		}
		s.uses[variable] = count
	}
	unsure := psFileInfo{maybe: psReadings(psFileInfo{}, bindings)}
	if count.rebinds || at > len(s.runes) || !s.account(at) {
		return unsure
	}
	before, _ := psVariableUses(strings.ToLower(string(s.runes[:at])), variable)
	if before != len(bindings) || count.assignments > before && (s.braces > 0 || psHasWord(lower, "trap")) {
		return unsure
	}
	// The binding read last, and every other reading it may still be: the
	// earlier bindings and what the last one may be (a copy of a variable
	// with earlier bindings), less the readings of the same file.
	last := bindings[len(bindings)-1]
	file := psFileInfo{params: last.params, kind: last.kind}
	file.maybe = psReadings(file, append(append([]psFileInfo(nil), bindings[:len(bindings)-1]...), last.maybe...))
	return file
}

// psHasWord reports the lower-case word in text (lower case), not part of a
// longer name, a parameter or a variable.
func psHasWord(text, word string) bool {
	for k := 0; k < len(text); {
		j := strings.Index(text[k:], word)
		if j < 0 {
			return false
		}
		start, end := k+j, k+j+len(word)
		k = end
		if (start == 0 || !psCommandWordByte(text[start-1]) && text[start-1] != '$') && (end == len(text) || !psCommandWordByte(text[end])) {
			return true
		}
	}
	return false
}

// psCommandWordByte reports a byte of a command or parameter name.
func psCommandWordByte(c byte) bool { return psVariableNameByte(c) || c == '-' }

// psDynamicMarkers are the lower-case texts of the APIs, drives and
// commands that can bind a variable by a name known only at run time.
var psDynamicMarkers = []string{"psvariable", "sessionstate", "variable:", "scriptblock", "invokecommand", "invoke-expression", "powershell]::"}

// psVariableCmdlets are the commands that bind (or return the PSVariable
// of) a variable they name, with whether they set it; the short aliases are
// read in command position only.
var psVariableCmdlets = map[string]bool{
	"set-variable": true, "new-variable": true, "get-variable": false,
	"set": true, "sv": true, "nv": true, "gv": false,
}

// psItemCmdlets are the provider commands that can write a variable: drive
// item, or its content, at a path built at run time, and Tee-Object, whose
// -Variable can be one.
var psItemCmdlets = map[string]bool{
	"set-item": true, "si": true, "new-item": true, "ni": true, "copy-item": true, "cpi": true, "copy": true, "cp": true,
	"move-item": true, "mi": true, "move": true, "mv": true, "rename-item": true, "rni": true, "ren": true,
	"set-content": true, "sc": true, "add-content": true, "ac": true, "tee-object": true, "tee": true,
}

// psAliasCmdlets make an alias, which can name a variable command (sal q
// sv) the reader does not read as one.
var psAliasCmdlets = map[string]bool{"set-alias": true, "sal": true, "new-alias": true, "nal": true, "import-alias": true, "ipal": true}

// psDynamicVariableWrite reports a command (lower case) that may bind a
// variable by a name the reader cannot read as text: the PSVariable and
// SessionState APIs, the variable: drive, a script block made of text,
// Invoke-Expression (iex), [PowerShell]::Create (which may run in this
// runspace), an alias made by the command, a .Value assignment (of a PSVariable from
// Get-Variable or Get-Item), Set-Variable, New-Variable or Get-Variable with
// a name that is not one plain name (psVariableCmdletLiteral), an
// -OutVariable (or another common variable parameter) of one, a provider
// item command at a path built at run time (the variable: drive) and a call
// of a command whose name is known only at run time (& $c, & (...)). A
// variable a command names literally is read by psVariableUses
// (rel-1-0-10:GAP-1276).
func psDynamicVariableWrite(lower string, budget *psBudget) bool {
	for _, marker := range psDynamicMarkers {
		if strings.Contains(lower, marker) {
			return true
		}
	}
	for k := 0; k < len(lower); {
		j := strings.Index(lower[k:], ".value")
		if j < 0 {
			break
		}
		k += j + len(".value")
		if (k == len(lower) || !psVariableNameByte(lower[k])) && psAssignmentNext(lower[k:]) {
			return true
		}
	}
	for k := 0; k < len(lower); k++ {
		if !budget.step() {
			return true
		}
		c := lower[k]
		if k > 0 && (psCommandWordByte(lower[k-1]) || strings.IndexByte("$.:/\\", lower[k-1]) >= 0) {
			continue
		}
		switch {
		case c == '&' && k+1 < len(lower) && lower[k+1] == '&':
			k++
			continue
		case c == '&' || c == '.' && psCommandPosition(lower, k):
			if psRunTimeCall(lower[k+1:], budget) {
				return true
			}
			continue
		case !psCommandWordByte(c):
			continue
		}
		start, end := k, k
		for end < len(lower) && psCommandWordByte(lower[end]) {
			end++
		}
		word, rest := lower[start:end], lower[end:]
		k = end - 1
		setter, cmdlet := psVariableCmdlets[word]
		switch {
		case word == "iex", psAliasCmdlets[word] && psCommandPosition(lower, start):
			return true
		case cmdlet && (len(word) > 3 || psCommandPosition(lower, start)):
			if !psVariableCmdletLiteral(rest, setter, budget) {
				return true
			}
		case psItemCmdlets[word] && psCommandPosition(lower, start):
			if strings.ContainsAny(psStatementRest(rest), "($@") {
				return true
			}
		case psCommonVariableParameter(word):
			if !psPlainVariableName(strings.TrimPrefix(psFirstWord(strings.TrimLeft(rest, ": \t")), "+")) {
				return true
			}
		}
	}
	return false
}

// psRunTimeCall reports the text after a call operator (& or .) that runs a
// command whose name is known only at run time ($c, (...)), or a string
// naming a variable command (psVariableCmdlets) the name of whose variable
// is not plain, or a provider item command at a path built at run time.
func psRunTimeCall(rest string, budget *psBudget) bool {
	rest = strings.TrimLeft(rest, " \t")
	switch {
	case rest == "":
		return false
	case rest[0] == '$' || rest[0] == '(':
		return true
	case rest[0] != '\'' && rest[0] != '"':
		return false
	}
	end := strings.IndexByte(rest[1:], rest[0])
	if end < 0 {
		return true
	}
	name, args := rest[1:1+end], rest[2+end:]
	if setter, ok := psVariableCmdlets[name]; ok {
		return !psVariableCmdletLiteral(args, setter, budget)
	}
	return psItemCmdlets[name] && strings.ContainsAny(psStatementRest(args), "($@")
}

// psCommandPosition reports index k of text in command position: after the
// start, a statement or pipeline break, a ( or { or an =.
func psCommandPosition(text string, k int) bool {
	j := k - 1
	for j >= 0 && (text[j] == ' ' || text[j] == '\t') {
		j--
	}
	return j < 0 || strings.IndexByte(";|&({}=\r\n", text[j]) >= 0
}

// psAssignmentNext reports an assignment operator (=, not ==, or a compound
// one) after optional blanks at the start of text.
func psAssignmentNext(text string) bool {
	t := strings.TrimLeft(text, " \t")
	return strings.HasPrefix(t, "=") && !strings.HasPrefix(t, "==") ||
		len(t) > 1 && t[1] == '=' && strings.IndexByte("+-*/%?", t[0]) >= 0
}

// psStatementRest is text up to the end of its statement or pipeline
// element.
func psStatementRest(text string) string {
	if end := strings.IndexAny(text, ";|}\r\n"); end >= 0 {
		return text[:end]
	}
	return text
}

// psFirstWord is the first argument word of text (psArgumentWordEnd).
func psFirstWord(text string) string {
	return text[:psArgumentWordEnd(text, 0, &psBudget{})]
}

// psCommonVariableParameter reports a common parameter (lower case) that
// names a variable it binds: -OutVariable, -PipelineVariable,
// -ErrorVariable, -WarningVariable and -InformationVariable, their aliases
// and unambiguous prefixes.
func psCommonVariableParameter(word string) bool {
	switch word {
	case "-ov", "-pv", "-ev", "-wv", "-iv":
		return true
	}
	for _, parameter := range []struct {
		name string
		min  int
	}{{"-outvariable", 5}, {"-pipelinevariable", 5}, {"-errorvariable", 7}, {"-warningvariable", 9}, {"-informationvariable", 13}} {
		if len(word) >= parameter.min && strings.HasPrefix(parameter.name, word) {
			return true
		}
	}
	return false
}

// psPlainVariableName reports one variable name (lower case), also quoted
// or with a scope: no wildcard, expression or variable.
func psPlainVariableName(word string) bool {
	if len(word) >= 2 && (word[0] == '\'' || word[0] == '"') && word[len(word)-1] == word[0] {
		word = word[1 : len(word)-1]
	}
	if word == "" {
		return false
	}
	for i := 0; i < len(word); i++ {
		if !psVariableNameByte(word[i]) && word[i] != ':' {
			return false
		}
	}
	return true
}

// psArgumentWordEnd returns the index after the argument word of text that
// starts at k: through its strings, escapes and (...), [...] and {...}
// groups, to a blank or a statement break outside them.
func psArgumentWordEnd(text string, k int, budget *psBudget) int {
	depth := 0
	for k < len(text) && budget.step() {
		c := text[k]
		switch {
		case c == '`':
			k += 2
			continue
		case c == '\'' || c == '"':
			end := k + 1
			for end < len(text) && text[end] != c {
				if c == '"' && text[end] == '`' {
					end++
				}
				end++
			}
			k = end + 1
			continue
		case c == '(' || c == '[' || c == '{':
			depth++
		case c == ')' || c == ']' || c == '}':
			if depth == 0 {
				return k
			}
			depth--
		case depth == 0 && strings.IndexByte(" \t;|&\r\n", c) >= 0:
			return k
		}
		k++
	}
	return min(k, len(text))
}

// psVariableCmdletLiteral reports that the Set-Variable, New-Variable or
// Get-Variable call (setter: one of the first two) whose arguments (lower
// case) start at text names one plain variable (psPlainVariableName): by
// -Name or its first positional word. Besides it only the value (-Value, or
// the positional word after the name of a setter), -Scope, -Option,
// -Visibility, -Description and the switches may follow; any other
// parameter (-Include, -Exclude) or word leaves it not literal.
func psVariableCmdletLiteral(text string, setter bool, budget *psBudget) bool {
	var words []string
	for k := 0; k < len(text) && budget.step(); {
		c := text[k]
		if c == ' ' || c == '\t' {
			k++
			continue
		}
		if strings.IndexByte(";|&)}\r\n", c) >= 0 {
			break
		}
		end := max(psArgumentWordEnd(text, k, budget), k+1)
		words = append(words, text[k:end])
		k = end
	}
	named := false
	for _, word := range words {
		if name, _, _ := psParameterWord(word); name != "" && strings.HasPrefix("name", name) {
			named = true
		}
	}
	names, positional := 0, 0
	for k := 0; k < len(words); k++ {
		name, value, glued := psParameterWord(words[k])
		if name == "" {
			switch {
			case !named && positional == 0:
				if !psPlainVariableName(words[k]) {
					return false
				}
				names++
			case !setter || positional > 1 || named && positional > 0:
				return false
			}
			positional++
			continue
		}
		takes := func() (string, bool) {
			if glued && value != "" {
				return value, true
			}
			if k+1 < len(words) {
				k++
				return words[k], true
			}
			return "", false
		}
		switch {
		case strings.HasPrefix("name", name):
			if word, ok := takes(); !ok || !psPlainVariableName(word) {
				return false
			}
			names++
		case strings.HasPrefix("scope", name),
			setter && (strings.HasPrefix("value", name) || strings.HasPrefix("visibility", name) ||
				strings.HasPrefix("option", name) || strings.HasPrefix("description", name)):
			if _, ok := takes(); !ok {
				return false
			}
		case psVariableCmdletSwitch(name):
		default:
			return false
		}
	}
	return names == 1
}

// psParameterWord splits a parameter word (-name or -name:value, lower case)
// into its name and glued value; name is "" for any other word.
func psParameterWord(word string) (name, value string, glued bool) {
	if len(word) < 2 || word[0] != '-' || word[1] < 'a' || word[1] > 'z' {
		return "", "", false
	}
	name, value, glued = strings.Cut(word[1:], ":")
	return name, value, glued
}

// psVariableCmdletSwitch reports a switch (lower-case name or prefix) of
// the variable cmdlets and the common switches.
func psVariableCmdletSwitch(name string) bool {
	for _, full := range []string{"force", "passthru", "valueonly", "whatif", "confirm", "verbose", "debug"} {
		if len(name) >= 2 && strings.HasPrefix(full, name) {
			return true
		}
	}
	return false
}

// psVariableUses reads every use of the variable name in text (both lower
// case): assignments counts $name = ... (also [T]$name = ...); rebinds
// reports a use that may bind it otherwise: a compound or multiple
// assignment, a foreach variable, a [ref] or parameter ($name after [, ( or
// ,), a braced, scoped or splatted spelling, and the bare name (Set-Variable
// name, -OutVariable name, variable:name). A member use ($name.Open, also a
// file name.txt), a path segment, a -name and a plain read ($name as an
// argument or in a string) are not (rel-1-0-10:GAP-1278).
func psVariableUses(text, name string) (assignments int, rebinds bool) {
	for k := 0; k < len(text); {
		j := strings.Index(text[k:], name)
		if j < 0 {
			break
		}
		start, end := k+j, k+j+len(name)
		k = end
		if start > 0 && psVariableNameByte(text[start-1]) || end < len(text) && (psVariableNameByte(text[end]) || text[end] == '.') {
			continue
		}
		var before byte
		if start > 0 {
			before = text[start-1]
		}
		if before != '$' {
			if before != 0 && strings.IndexByte(`/\.-`, before) >= 0 {
				continue
			}
			return assignments, true
		}
		var prefix byte
		if start > 1 {
			prefix = text[start-2]
		}
		rest := strings.TrimLeft(text[end:], " \t")
		switch {
		case strings.HasPrefix(rest, "=") && !strings.HasPrefix(rest, "=="):
			assignments++
			continue
		case len(rest) > 1 && rest[1] == '=' && strings.IndexByte("+-*/%?", rest[0]) >= 0,
			strings.HasPrefix(rest, "??="), strings.HasPrefix(rest, ","),
			prefix == ']' || prefix == '(' || prefix == ',',
			strings.HasPrefix(rest, "in") && (len(rest) == 2 || !psVariableNameByte(rest[2])):
			return assignments, true
		}
	}
	return assignments, false
}

// openBlock reads the { at i, after the statement text, of a pipeline
// element fed by pipedFrom: the block of a ForEach-Object fed by Get-Item or
// Get-ChildItem of known paths places its pipeline item there, only when
// whole, that feeding element read whole (no group, block or call cut it,
// and no pipeline fed it), is that command (rel-1-0-10:GAP-1275). A block
// inside that one may bind the item: it is unplaced from there to the end of
// the block (rel-1-0-10:GAP-1257).
func (s *psStateScan) openBlock(statement, pipedFrom string, whole bool, i int) {
	s.braces++
	if s.itemDepth != 0 {
		s.item = psFileInfo{}
		return
	}
	switch strings.ToLower(strings.TrimSpace(statement)) {
	case "foreach-object", "%", "foreach":
	default:
		return
	}
	if !whole || strings.TrimSpace(pipedFrom) == "" {
		return
	}
	if item := psFileInfoExpression(pipedFrom, s.budget); item.placed() {
		s.item, s.itemDepth, s.itemOpen, s.itemUses = item, s.braces, i+1, 0
	}
}

// closeBlock reads the } at i. At the end of a block that placed its
// pipeline item, a write on that item is unplaced (fail closed) when the
// block may bind the item ($_ = ..., Set-Variable _ ...) or is not the
// process block of its ForEach-Object (another block or a parameter
// follows: the first of several blocks is the begin block).
func (s *psStateScan) closeBlock(i int) {
	if s.itemDepth != 0 && s.braces == s.itemDepth {
		if s.itemUses > 0 && !s.itemBlockSound(i) {
			s.unplaced = true
		}
		s.item, s.itemDepth, s.itemOpen, s.itemUses = psFileInfo{}, 0, 0, 0
	}
	if s.braces > 0 {
		s.braces--
	}
}

// itemBlockSound reports that the block from s.itemOpen to the } at end
// binds neither $_ nor $PSItem and is the only block of its ForEach-Object.
func (s *psStateScan) itemBlockSound(end int) bool {
	if end < s.itemOpen || !s.account(end-s.itemOpen) {
		return false
	}
	body := strings.ToLower(string(s.runes[s.itemOpen:end]))
	for _, name := range []string{"_", "psitem"} {
		if assignments, rebinds := psVariableUses(body, name); assignments > 0 || rebinds {
			return false
		}
	}
	k := end + 1
	for k < len(s.runes) && (s.runes[k] == ' ' || s.runes[k] == '\t') {
		k++
	}
	return k >= len(s.runes) || !strings.ContainsRune("{-`", s.runes[k])
}

// psFolderTwin returns the twin of the write of every file the path of the
// twin parameter param holds when it is a folder (Remove-Item -Recurse of
// it), for a -Path with wildcards of the folder before the first one; "" when
// that is the working directory or the root.
func psFolderTwin(param, home string) string {
	flag, value, ok := strings.Cut(param, " ")
	if !ok || value == "" {
		return ""
	}
	if flag == "-Path" {
		r := []rune(value)
		open, closing, inner := "", "", value
		if len(r) >= 2 && (psSingleQuote(r[0]) && psSingleQuote(r[len(r)-1]) || psDoubleQuote(r[0]) && psDoubleQuote(r[len(r)-1])) {
			open, closing, inner = string(r[0]), string(r[len(r)-1]), string(r[1:len(r)-1])
		}
		if wild := strings.IndexAny(inner, "*?["); wild >= 0 {
			cut := strings.LastIndexAny(inner[:wild], `/\`)
			if cut <= 0 {
				return ""
			}
			value = open + inner[:cut] + closing
		}
	}
	return "Remove-Item " + psHomeLiteralParam(flag+" "+value, home) + " -Recurse -Force"
}

// dotNetStatement reads a statement that binds a FileInfo or opens a file
// without an argument list in parentheses: New-Object T -ArgumentList a, b
// (or T a, b), $f = Get-Item f, $f = Get-ChildItem f, $f = [IO.FileInfo]'f'
// and [IO.FileInfo]$f = 'f'; and $f = $g, a copy of a FileInfo variable
// (copyFileInfo). start is the rune index the statement starts at, and
// whole reports a statement that ends there (no pipeline, block or call
// takes the value further).
func (s *psStateScan) dotNetStatement(text string, start int, whole bool) {
	if whole && s.copyFileInfo(text, start) {
		return
	}
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
		if !file.placed() && psFileInfoType(typeName) {
			// A variable typed [IO.FileInfo] converts what it is given.
			file = psFileInfoExpression("[IO.FileInfo]"+strings.TrimSpace(rest), s.budget)
		}
		if file.placed() {
			s.bindFileInfo(variable, file)
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

// psFileInfoExpression returns the FileInfo an expression evaluates to: a
// copyFileInfo reads a statement $f = $g ([T]$f = $g) that copies the
// FileInfo variable g: f is bound to what g is there (variableFileInfo at
// start), so a copy, also of f itself ($f = $f) or through a chain of
// copies ($g = $f; $f = $g), keeps f placed at the same file and changes
// which file it is only when g may be another one. False for any other
// statement, and for a g the reader binds to no FileInfo: such an
// assignment leaves f unplaced, as before (rel-1-0-10:GAP-1257, GAP-1315).
func (s *psStateScan) copyFileInfo(text string, start int) bool {
	if len(s.fileInfos) == 0 {
		return false
	}
	variable, _, rest := psTypedAssignment(text)
	source, ok := strings.CutPrefix(strings.TrimSpace(rest), "$")
	if variable == "" || !ok || source == "" {
		return false
	}
	for k := 0; k < len(source); k++ {
		if !psVariableNameByte(source[k]) {
			return false
		}
	}
	source = strings.ToLower(source)
	if len(s.fileInfos[source]) == 0 {
		return false
	}
	file := s.variableFileInfo(source, start)
	if !file.placed() && len(file.maybe) == 0 {
		return false
	}
	s.bindFileInfo(variable, file)
	return true
}

// [IO.FileInfo] cast of a literal, [IO.FileInfo]::new(literal), New-Object
// IO.FileInfo of a literal (psFileInfoFile), Get-Item or gi of known paths
// (psFileInfoItem), or Get-ChildItem, gci, dir or ls of known paths
// (psFileInfoChildren); unplaced otherwise.
func psFileInfoExpression(text string, budget *psBudget) psFileInfo {
	text = strings.TrimSpace(text)
	lower := asciifold.Lower(text)
	for _, cast := range []string{"[system.io.fileinfo]", "[io.fileinfo]"} {
		if !strings.HasPrefix(lower, cast) || len(text) < len(cast) {
			continue
		}
		value := strings.TrimSpace(text[len(cast):])
		if inner, ok := strings.CutPrefix(strings.ToLower(value), "::new("); ok && strings.HasSuffix(inner, ")") {
			args := psSplitArgumentTexts(value[len("::new("):len(value)-1], budget)
			if len(args) != 1 {
				return psFileInfo{}
			}
			value = args[0]
		}
		if value == "" || strings.HasPrefix(value, "::") || !psLiteralArgument(value, budget) {
			return psFileInfo{}
		}
		return psLiteralFileInfo(value)
	}
	words := psWords(text, budget)
	if len(words) < 2 || budget.over {
		return psFileInfo{}
	}
	program := strings.ToLower(words[0].text)
	if program == "new-object" {
		typeName, arguments := psNewObjectParts(psJoinListWords(words, budget))
		if psNewObjectType(typeName, budget) != "io.fileinfo" {
			return psFileInfo{}
		}
		args := psSplitArgumentTexts(psArrayBody(arguments), budget)
		if len(args) != 1 || args[0] == "" || !psLiteralArgument(args[0], budget) {
			return psFileInfo{}
		}
		return psLiteralFileInfo(args[0])
	}
	children := false
	switch program {
	case "get-item", "gi":
	case "get-childitem", "gci", "dir", "ls":
		children = true
	default:
		return psFileInfo{}
	}
	// A comma list written with blanks ('a', 'b') is one path array.
	words = psJoinListWords(words, budget)
	flag, value := "", ""
	for k := 1; k < len(words); k++ {
		word := words[k].text
		if words[k].quoted || len(word) < 2 || word[0] != '-' {
			if flag != "" {
				return psFileInfo{}
			}
			flag, value = "-Path", word
			continue
		}
		name := strings.ToLower(word[1:])
		if strings.HasPrefix("force", name) && len(name) >= 2 || children && name == "file" {
			continue
		}
		if k+1 >= len(words) {
			return psFileInfo{}
		}
		k++
		switch {
		case name == "lp" || name == "pspath" || strings.HasPrefix("literalpath", name):
			flag, value = "-LiteralPath", words[k].text
		case len(name) >= 2 && strings.HasPrefix("path", name):
			flag, value = "-Path", words[k].text
		case children:
			// A filter, a recursion or any other selection of children
			// leaves the file unplaced.
			return psFileInfo{}
		}
	}
	if flag == "" {
		return psFileInfo{}
	}
	// A path array (a, b) is each of its paths; one the reader cannot read
	// leaves the result unplaced (rel-1-0-10:GAP-1277).
	file := psFileInfo{kind: psFileInfoItem}
	if children {
		file.kind = psFileInfoChildren
	}
	for _, element := range psSplitArgumentTexts(value, budget) {
		if element == "" || !psLiteralArgument(element, budget) {
			return psFileInfo{}
		}
		file.params = append(file.params, flag+" "+element)
	}
	return file
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
	lower := asciifold.Lower(inner)
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
