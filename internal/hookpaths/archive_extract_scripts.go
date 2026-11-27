// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/effects"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
	"github.com/defenseclaw/defenseclaw/internal/textlower"
)

// The archive extractions of interpreter code and PowerShell
// (rel-1-0-10:GAP-1173): what they write is read as the shell extractions
// are (ReadArchiveExtractions): the folder, a member the call names, and the
// whole archive whose members the archive itself tells.

var (
	// pythonArchiveOpen is a call that opens an archive file by name.
	pythonArchiveOpen = lazyregexp.New(`\b(?:tarfile\.open|tarfile\.TarFile|zipfile\.ZipFile|TarFile|ZipFile)\s*\(`)
	// pythonArchiveExtract is an extraction call: a TarFile or ZipFile
	// extractall or extract, or shutil.unpack_archive.
	pythonArchiveExtract = lazyregexp.New(`\.(?:extractall|extract)\s*\(|\b(?:shutil\.)?unpack_archive\s*\(`)
	// pythonExpandUser is os.path.expanduser of one argument.
	pythonExpandUser = lazyregexp.New(`^(?:os\.path\.)?expanduser\s*\(([\s\S]*)\)$`)
)

// pythonArchiveExtractions reads the archive extractions of python -c code.
// A folder is the path argument (cwd when there is none); a literal string
// or os.path.expanduser of one is read, any other value is not. The archive
// is the one archive file the code opens by a literal name (tarfile.open,
// zipfile.ZipFile), or the first argument of shutil.unpack_archive. An
// extract call names its member; an extractall with members= tells none.
func pythonArchiveExtractions(code, cwd, home string, read *archiveExtractionScan) {
	if !strings.Contains(code, "extract") && !strings.Contains(code, "unpack_archive") {
		return
	}
	archive, format, opened := "", archiveFormat(0), 0
	for _, loc := range pythonArchiveOpen.FindAllStringIndex(code, -1) {
		if !pythonExecutableCodePosition(code, loc[0]) {
			continue
		}
		opened++
		call, fixed := literalBoundedCall(code, loc[1]-1)
		if !fixed {
			continue
		}
		keyword := "name"
		if strings.Contains(code[loc[0]:loc[1]], "ZipFile") {
			keyword = "file"
		}
		if name, ok := pythonArchivePath(literalCallArgument(literalCallArgs(call), 0, keyword), cwd, home); ok {
			archive, format = name, archiveTar
			if keyword == "file" {
				format = archiveZip
			}
		}
	}
	if opened != 1 {
		// No archive, or more than one: which one an extraction reads is not
		// read from the code.
		archive = ""
	}
	module := strings.Contains(code, "tarfile") || strings.Contains(code, "zipfile")
	for _, loc := range pythonArchiveExtract.FindAllStringIndex(code, -1) {
		if !pythonExecutableCodePosition(code, loc[0]) {
			continue
		}
		name := strings.TrimSpace(strings.TrimPrefix(code[loc[0]:loc[1]-1], "."))
		call, fixed := literalBoundedCall(code, loc[1]-1)
		if !fixed {
			continue
		}
		args := literalCallArgs(call)
		whole := ArchiveWhole{}
		position, keyword := 0, "path"
		switch name {
		case "extractall", "extract":
			if !module {
				continue
			}
			whole.Archive, whole.format = archive, format
			if name == "extract" {
				position = 1
			}
		default: // unpack_archive
			if !strings.Contains(code, "shutil") {
				continue
			}
			position, keyword = 1, "extract_dir"
			if source, ok := pythonArchivePath(literalCallArgument(args, 0, "filename"), cwd, home); ok {
				whole.Archive, whole.format = source, archiveAny
			}
		}
		folder := cwd
		if value := literalCallArgument(args, position, keyword); value != "" {
			placed, ok := pythonArchivePath(value, cwd, home)
			if !ok {
				continue
			}
			folder = placed
		}
		read.paths = append(read.paths, folder)
		switch {
		case name == "extract":
			member, ok := literalPythonString(literalCallArgument(args, 0, "member"))
			if !ok {
				read.unknown = append(read.unknown, folder)
				continue
			}
			read.paths = append(read.paths, archiveMemberPath(folder, member))
		case name == "extractall" && literalCallArgument(args, 1, "members") != "":
			read.unknown = append(read.unknown, folder)
		case whole.Archive != "":
			whole.Folder = folder
			read.whole = append(read.whole, whole)
		}
	}
}

// pythonArchivePath places one Python path argument: a literal string, or
// os.path.expanduser of one (~ is the home), in cwd.
func pythonArchivePath(arg, cwd, home string) (string, bool) {
	arg = strings.TrimSpace(arg)
	expand := false
	if match := pythonExpandUser.FindStringSubmatch(arg); match != nil {
		arg, expand = strings.TrimSpace(match[1]), true
	}
	value, ok := literalPythonString(arg)
	if !ok || value == "" {
		return "", false
	}
	if expand && home != "" && (value == "~" || strings.HasPrefix(value, "~/") || strings.HasPrefix(value, `~\`)) {
		value = home + value[1:]
	}
	return filepath.Clean(OperandPath(value, cwd)), true
}

// powerShellArchiveExtractions reads the PowerShell archive extractions of
// a command that names one: Expand-Archive (-Path or -LiteralPath, the
// -DestinationPath folder, the current folder when there is none; -WhatIf
// writes nothing) and [System.IO.Compression.ZipFile]::ExtractToDirectory
// (source, folder), or the ZipFileExtensions form (archive object, folder).
// A path is a literal, or a string of literals and the home variables ($HOME,
// $env:USERPROFILE, $env:HOME); the cmdlet also reads ~ and FileSystem::.
// With windowsShell a native tar, unzip or 7z call is read too
// (psNativeArchiveCall). Input past the parser's bounds is TRUNCATED.
func powerShellArchiveExtractions(command, cwd, home string, windowsShell bool, read *archiveExtractionScan) {
	text, lower := command, textlower.Lower(command)
	native := windowsShell && psNativeExtractorWord.MatchString(lower)
	if !native && !strings.Contains(lower, "expand-archive") && !strings.Contains(lower, "extracttodirectory") || !filepath.IsAbs(cwd) {
		return
	}
	script, _ := psparse.Parse(command, psparse.Options{Dialect: psparse.DialectUnknown})
	for _, diagnostic := range script.Diagnostics {
		switch diagnostic.Reason {
		case psparse.ReasonTruncated:
			read.trunc.Hit(bounded.Bytes)
		case psparse.ReasonDepthLimit:
			read.trunc.Hit(bounded.Depth)
		}
	}
	add := func(archive, folder string, known bool) {
		read.paths = append(read.paths, folder)
		if known {
			// A command that names the archive more than once may write it
			// before the extraction opens it (rel-1-0-10:GAP-1224).
			staged := strings.Count(lower, strings.ToLower(filepath.Base(archive))) > 1
			read.whole = append(read.whole, ArchiveWhole{Folder: folder, Archive: archive, format: archiveZip, staged: staged})
		}
	}
	psparse.WalkCommands(script, func(command *psparse.Command) {
		name, ok := psparse.LiteralString(command.Name)
		if !ok {
			return
		}
		name = strings.ToLower(name)
		if native {
			if program, ok := psNativeExtractor(name); ok {
				psNativeArchiveCall(command, program, cwd, home, text, read)
				return
			}
			if base := strings.TrimSuffix(name[strings.LastIndexAny(name, `\/`)+1:], ".exe"); base == "cmd" {
				psCmdArchiveCall(command, cwd, home, text, read)
				return
			}
		}
		name = strings.TrimPrefix(name, `microsoft.powershell.archive\`)
		if name != "expand-archive" {
			return
		}
		values, whatIf := psExpandArchiveValues(command)
		if whatIf {
			return
		}
		folder := cwd
		if destination, given := values[psArchiveParamDestination]; given {
			placed, ok := psArchivePath(destination, cwd, home, true)
			if !ok {
				return
			}
			folder = placed
		}
		source, given := values[psArchiveParamLiteralPath]
		if !given {
			source, given = values[psArchiveParamPath]
		}
		archive, known := "", false
		if given {
			archive, known = psArchivePath(source, cwd, home, true)
		}
		add(archive, folder, known)
	})
	psparse.WalkInvokes(script, func(call *psparse.Invoke) {
		if !call.Static || !strings.EqualFold(call.Name, "ExtractToDirectory") || len(call.Args) < 2 {
			return
		}
		target, ok := call.Target.(*psparse.TypeExpr)
		if !ok {
			return
		}
		typeName := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(target.Name)), "system.")
		switch typeName {
		case "io.compression.zipfile", "io.compression.zipfileextensions":
		default:
			return
		}
		folder, ok := psArchivePath(call.Args[1], cwd, home, false)
		if !ok {
			return
		}
		archive, known := psArchivePath(call.Args[0], cwd, home, false)
		add(archive, folder, known && typeName == "io.compression.zipfile")
	})
}

// psExpandArchiveParameterSpec lists the Expand-Archive parameters, one
// entry each: the name, then its aliases after "=", with "!" ahead of a
// switch. The first four entries are the ones the binding reads
// (psArchiveParam*). It is one string read once, not a word literal per
// name: TestGAP0749BoundedSweepReadsEveryFormAndStaysInBudget sweeps every
// word literal of the package through Resolve.
const psExpandArchiveParameterSpec = "path literalpath=pspath,lp destinationpath !whatif=wi " +
	"erroraction=ea errorvariable=ev warningaction=wa warningvariable=wv informationaction=infa " +
	"informationvariable=iv outvariable=ov outbuffer=ob pipelinevariable=pv progressaction=proga " +
	"!force !passthru !confirm=cf !verbose=vb !debug=db"

// The Expand-Archive parameters the binding reads, by their entry in
// psExpandArchiveParameterSpec.
const (
	psArchiveParamPath = iota
	psArchiveParamLiteralPath
	psArchiveParamDestination
	psArchiveParamWhatIf
)

// psArchiveParameter is one entry of psExpandArchiveParameterSpec.
type psArchiveParameter struct {
	entry  int
	valued bool
}

// psExpandArchiveNames maps every name and alias of
// psExpandArchiveParameterSpec to its entry.
var psExpandArchiveNames = func() map[string]psArchiveParameter {
	names := map[string]psArchiveParameter{}
	for entry, field := range strings.Fields(psExpandArchiveParameterSpec) {
		parameter := psArchiveParameter{entry: entry, valued: !strings.HasPrefix(field, "!")}
		name, aliases, _ := strings.Cut(strings.TrimPrefix(field, "!"), "=")
		names[name] = parameter
		for _, alias := range strings.Split(aliases, ",") {
			if alias != "" {
				names[alias] = parameter
			}
		}
	}
	return names
}()

// psExpandArchiveValues binds the path parameters of one Expand-Archive
// call, by psArchiveParam* entry: path, literalpath and destinationpath
// (named, or the first two positional arguments). whatIf reports -WhatIf.
func psExpandArchiveValues(command *psparse.Command) (values map[int]psparse.Expr, whatIf bool) {
	values = map[int]psparse.Expr{}
	var positional []psparse.Expr
	for i := 0; i < len(command.Elements); i++ {
		element := command.Elements[i]
		parameter, named := element.(*psparse.Parameter)
		if !named {
			switch value := element.(type) {
			case *psparse.Arg:
				positional = append(positional, value.Value)
			case psparse.Expr:
				positional = append(positional, value)
			}
			continue
		}
		known, ok := psUniqueParameter(strings.ToLower(parameter.Name))
		if ok && known.entry == psArchiveParamWhatIf {
			// -WhatIf:$false writes as no -WhatIf does.
			off := false
			if variable, ok := parameter.Colon.(*psparse.Variable); parameter.HasColon && ok {
				off = strings.EqualFold(variable.Name, "false")
			}
			whatIf = whatIf || !off
			continue
		}
		if !ok || !known.valued {
			continue
		}
		var value psparse.Expr
		if parameter.HasColon {
			value = parameter.Colon
		} else if i+1 < len(command.Elements) {
			i++
			switch next := command.Elements[i].(type) {
			case *psparse.Arg:
				value = next.Value
			case psparse.Expr:
				value = next
			}
		}
		if value != nil {
			values[known.entry] = value
		}
	}
	for _, entry := range []int{psArchiveParamPath, psArchiveParamDestination} {
		if len(positional) == 0 {
			break
		}
		if _, given := values[entry]; given || entry == psArchiveParamPath && values[psArchiveParamLiteralPath] != nil {
			continue
		}
		values[entry], positional = positional[0], positional[1:]
	}
	return values, whatIf
}

// psUniqueParameter is the Expand-Archive parameter a name, an alias or a
// unique prefix of one spells; ok is false when it spells none or several.
func psUniqueParameter(name string) (psArchiveParameter, bool) {
	if parameter, ok := psExpandArchiveNames[name]; ok {
		return parameter, true
	}
	var found psArchiveParameter
	matches := 0
	for known, parameter := range psExpandArchiveNames {
		if strings.HasPrefix(known, name) && (matches == 0 || parameter.entry != found.entry) {
			found, matches = parameter, matches+1
		}
	}
	return found, matches == 1
}

// psNativeExtractorWord is a native extractor program word in a command's
// lower-case text: the gate of the PowerShell reading of native calls, so a
// command that only spells tar inside another word (Start-Process, $target)
// is not parsed again.
var psNativeExtractorWord = lazyregexp.New(`(?:^|[\s;&|(){}'"\\/])(?:bsdtar|gtar|tar|unzip|7z[ar]?)(?:\.exe)?(?:$|[\s;&|)'"])`)

// psNativeExtractor is the extractor a PowerShell command name runs: tar,
// bsdtar, gtar, unzip or 7z, by its base name with or without a folder and
// .exe (tar.exe, C:\Windows\System32\tar.exe).
func psNativeExtractor(name string) (string, bool) {
	base := strings.TrimSuffix(name[strings.LastIndexAny(name, `\/`)+1:], ".exe")
	switch base {
	case "tar", "bsdtar", "gtar", "unzip", "7z", "7za", "7zr":
		return base, true
	}
	return "", false
}

// psNativeArchiveCall reads a native extractor call of a PowerShell command
// with the words PowerShell hands the program (rel-1-0-10:GAP-1633): a
// parameter token as written (-xf, -C), a literal, a home variable or a
// string of literal runs and home variables (psNativeWord); any other value
// is a word with no static spelling. The words after --% are passed as they
// are written. A whole archive the text before the call names (a Copy-Item
// onto it) is staged (psNativeArchiveWords).
func psNativeArchiveCall(command *psparse.Command, program, cwd, home, text string, read *archiveExtractionScan) {
	words, static := psNativeArchiveCallWords(command, program, home)
	if len(command.Redirs) == 0 && archiveListing(words, static) {
		start, end := command.Span()
		read.listings = append(read.listings, archiveListingSpan{text: text, start: start, end: end})
		return
	}
	psNativeArchiveWords(command, words, static, cwd, text, read)
}

// psNativeArchiveCallWords are the words PowerShell hands the native
// extractor program of command (psNativeArchiveCall): the program, then each
// element read by psNativeWord, then the --% words as written.
func psNativeArchiveCallWords(command *psparse.Command, program, home string) (words []string, static []bool) {
	words, static = []string{program}, []bool{true}
	add := func(word string, known bool) {
		if !known {
			word = ""
		}
		words, static = append(words, word), append(static, known)
	}
	for _, element := range command.Elements {
		switch value := element.(type) {
		case *psparse.Parameter:
			// -C:value reaches the program as one word this reading does
			// not split.
			add(value.Raw, !value.HasColon)
		case *psparse.Arg:
			add(psNativeWord(value.Value, home))
		case psparse.Expr:
			add(psNativeWord(value, home))
		}
	}
	for _, field := range strings.Fields(command.StopParsing) {
		add(psSlashWord(field), true)
	}
	return words, static
}

// psArchiveCallWords are the words PowerShell hands the native extractor of
// text, one call (GAP-1634): -C $env:USERPROFILE\.defenseclaw is that folder
// of the home, where the POSIX reading of the same text has a word with no
// static spelling, so the extraction could write anywhere and any word could
// be an option. They are read only for a Windows home (a drive path): there
// the agent's shell is PowerShell and these spellings are its own. ok is
// false for any other home, a text that is not one clean extractor call of
// program, or a word with no static spelling here either.
func psArchiveCallWords(text, program, home string) (words []string, static []bool, ok bool) {
	if len(home) < 3 || home[1] != ':' || !strings.ContainsAny(text, `$\`) {
		return nil, nil, false
	}
	script, _ := psparse.Parse(text, psparse.Options{Dialect: psparse.DialectUnknown})
	if script == nil || len(script.Diagnostics) > 0 {
		return nil, nil, false
	}
	calls := 0
	psparse.WalkCommands(script, func(command *psparse.Command) {
		calls++
		name, named := psparse.LiteralString(command.Name)
		if !named {
			return
		}
		if found, extractor := psNativeExtractor(strings.ToLower(name)); extractor && found == program {
			words, static = psNativeArchiveCallWords(command, program, home)
		}
	})
	if calls != 1 || len(words) == 0 || slices.Contains(static, false) {
		return nil, nil, false
	}
	return words, static, true
}

// psNativeArchiveWords reads the words of one native extractor call. A whole
// archive the text before the call names may be written there first (a
// Copy-Item onto it) and is staged, as the POSIX reading has it
// (archiveStagedBefore, rel-1-0-10:GAP-1224); a mention after the call (a
// Remove-Item of it) is not, nor is one in a tar listing of it (textBefore,
// rel-1-0-10:GAP-1662). A call the text cannot place is read as staged.
func psNativeArchiveWords(call psparse.Node, words []string, static []bool, cwd, text string, read *archiveExtractionScan) {
	psArchiveWordsAfter(words, static, cwd, read.textBeforeCall(call, text), read)
}

// textBeforeCall is textBefore at the start of a PowerShell call; a call
// the text cannot place has all of it before.
func (read *archiveExtractionScan) textBeforeCall(call psparse.Node, text string) string {
	at, _ := call.Span()
	if at < 0 || at > len(text) {
		at = len(text)
	}
	return read.textBefore(text, at)
}

// psArchiveWordsAfter reads the words of one native extractor call that
// before (with its listings blanked) precedes: a whole archive before names
// is staged.
func psArchiveWordsAfter(words []string, static []bool, cwd, before string, read *archiveExtractionScan) {
	first := len(read.whole)
	archiveCallExtractions(words, static, cwd, read)
	if first == len(read.whole) {
		return
	}
	before = strings.ToLower(before)
	for index := first; index < len(read.whole); index++ {
		if strings.Contains(before, strings.ToLower(filepath.Base(read.whole[index].Archive))) {
			read.whole[index].staged = true
		}
	}
}

// psCmdArchiveCall reads cmd /c (or /k) running native extractors from a
// PowerShell command. The words after /c are the command line cmd gets (a
// word that holds a blank quoted, as PowerShell hands it, and cmd's outer
// quotes removed); it is split into statements by the cmd statement splitter
// (effects.CmdStatements), so `copy /y a.tar ok.tar && tar -xf ok.tar -C
// %USERPROFILE%` reads its tar call, staged by the copy before it, and a
// statement after an extractor is not read as its members
// (rel-1-0-10:GAP-1667). A statement's words are split at blanks, and
// %USERPROFILE% or %HOMEDRIVE%%HOMEPATH% at the start of a word is the home,
// as cmd expands it (rel-1-0-10:GAP-1633). A value with no static spelling,
// or a word before /c that is not a cmd startup switch
// (psparse.CmdStartupSwitch, the one cmd switch set: rel-1-0-10:GAP-1708),
// leaves the call unread.
func psCmdArchiveCall(command *psparse.Command, cwd, home, text string, read *archiveExtractionScan) {
	var body []string
	inBody := false
	for _, element := range command.Elements {
		var word string
		var ok bool
		switch value := element.(type) {
		case *psparse.Parameter:
			word, ok = value.Raw, !value.HasColon
		case *psparse.Arg:
			word, ok = psPathText(value.Value, home)
		case psparse.Expr:
			word, ok = psPathText(value, home)
		}
		if !ok {
			return
		}
		if inBody {
			if word == "" || strings.ContainsAny(word, " \t") {
				word = `"` + word + `"`
			}
			body = append(body, word)
			continue
		}
		switch lower := strings.ToLower(word); {
		case lower == "/c" || lower == "/k":
			inBody = true
		case psparse.CmdStartupSwitch(lower):
		default:
			return
		}
	}
	line := strings.Join(body, " ")
	if strings.HasPrefix(line, `"`) {
		if last := strings.LastIndex(line, `"`); last > 0 {
			line = line[1:last] + line[last+1:]
		}
	}
	before := read.textBeforeCall(command, text)
	for _, statement := range effects.CmdStatements(line) {
		words, static, extractor := cmdArchiveStatementWords(statement, home)
		switch {
		case !extractor:
		case archiveListing(words, static):
			// A listing reads the archive: it does not stage it
			// (rel-1-0-10:GAP-1662).
			continue
		default:
			psArchiveWordsAfter(words, static, cwd, before, read)
		}
		before += " " + statement
	}
}

// cmdArchiveStatementWords is one cmd statement as the words of a native
// extractor call: its quotes removed and split at blanks, with the home
// variables read (psCmdArchiveCall). extractor is false when the statement
// does not run tar, unzip or 7z.
func cmdArchiveStatementWords(statement, home string) (words []string, static []bool, extractor bool) {
	fields := strings.Fields(strings.ReplaceAll(statement, `"`, ""))
	if len(fields) == 0 {
		return nil, nil, false
	}
	program, ok := psNativeExtractor(strings.ToLower(fields[0]))
	if !ok {
		return nil, nil, false
	}
	words, static = []string{program}, []bool{true}
	for _, field := range fields[1:] {
		if home != "" {
			for _, prefix := range []string{"%userprofile%", "%homedrive%%homepath%"} {
				if len(field) >= len(prefix) && strings.EqualFold(field[:len(prefix)], prefix) &&
					(len(field) == len(prefix) || field[len(prefix)] == '\\' || field[len(prefix)] == '/') {
					field = home + field[len(prefix):]
					break
				}
			}
		}
		if strings.Contains(field, "%") {
			// Another variable: no static spelling.
			words, static = append(words, ""), append(static, false)
			continue
		}
		words, static = append(words, psSlashWord(field)), append(static, true)
	}
	return words, static, true
}

// psNativeWord is one PowerShell value as the word a native program gets:
// psPathText, with ~ at its start read as the home (as the cmdlet paths
// have it) and, on a POSIX gateway judging a Windows hook call, the
// backslash read as the separator it is there.
func psNativeWord(value psparse.Expr, home string) (string, bool) {
	text, ok := psPathText(value, home)
	if !ok {
		return "", false
	}
	if home != "" && (text == "~" || strings.HasPrefix(text, `~\`) || strings.HasPrefix(text, "~/")) {
		text = home + text[1:]
	}
	return psSlashWord(text), true
}

// psSlashWord reads a backslash as the separator on a POSIX gateway; a
// Windows gateway's filepath reads both.
func psSlashWord(text string) string {
	if filepath.Separator == '/' {
		return strings.ReplaceAll(text, `\`, "/")
	}
	return text
}

// psArchivePath places one PowerShell path value in cwd: a literal, a home
// variable, or a string of literal runs and home variables. cmdlet reads
// the provider forms (~, FileSystem::) a cmdlet path takes and a .NET call
// does not.
func psArchivePath(value psparse.Expr, cwd, home string, cmdlet bool) (string, bool) {
	text, ok := psPathText(value, home)
	if !ok {
		return "", false
	}
	if cmdlet {
		for _, provider := range []string{`microsoft.powershell.core\filesystem::`, "filesystem::"} {
			if len(text) > len(provider) && strings.EqualFold(text[:len(provider)], provider) {
				text = text[len(provider):]
				break
			}
		}
		if home != "" && (text == "~" || strings.HasPrefix(text, `~\`) || strings.HasPrefix(text, "~/")) {
			text = home + text[1:]
		}
		// A provider path takes the backslash as its separator on every
		// host, as PowerShell on Linux and macOS reads it too
		// (rel-1-0-10:GAP-1633).
		text = psSlashWord(text)
	}
	return filepath.Clean(OperandPath(text, cwd)), true
}

// psPathText is the text of one PowerShell value: a literal, a home
// variable, or a string of literal runs and home variables.
func psPathText(value psparse.Expr, home string) (string, bool) {
	text, ok := psparse.LiteralString(value)
	switch expression := value.(type) {
	case *psparse.Variable:
		if !psHomeVariable(expression) || home == "" {
			return "", false
		}
		text, ok = home, true
	case *psparse.StringLit:
		if !ok && !expression.Static {
			var built strings.Builder
			// A bare word PowerShell fuses from adjacent atoms
			// ($env:USERPROFILE\.defenseclaw) has each atom as a part: a
			// literal atom is its text (rel-1-0-10:GAP-1633).
			for _, part := range expression.Parts {
				literal, isLiteral := psparse.LiteralString(part.Expr)
				switch {
				case part.Expr == nil:
					built.WriteString(part.Lit)
				case home != "" && psHomeVariable(part.Expr):
					built.WriteString(home)
				case isLiteral:
					built.WriteString(literal)
				default:
					return "", false
				}
			}
			text, ok = built.String(), true
		}
	}
	if !ok || text == "" {
		return "", false
	}
	return text, true
}

// psHomeVariable reports $HOME, $env:USERPROFILE or $env:HOME.
func psHomeVariable(expression psparse.Expr) bool {
	variable, ok := expression.(*psparse.Variable)
	if !ok || variable.Splat {
		return false
	}
	switch strings.ToLower(variable.Scope) {
	case "":
		return strings.EqualFold(variable.Name, "home")
	case "env":
		return strings.EqualFold(variable.Name, "userprofile") || strings.EqualFold(variable.Name, "home")
	}
	return false
}
