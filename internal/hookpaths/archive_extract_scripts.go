// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
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
// Input past the parser's bounds is TRUNCATED.
func powerShellArchiveExtractions(command, cwd, home string, read *archiveExtractionScan) {
	lower := strings.ToLower(command)
	if !strings.Contains(lower, "expand-archive") && !strings.Contains(lower, "extracttodirectory") || !filepath.IsAbs(cwd) {
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
			read.whole = append(read.whole, ArchiveWhole{Folder: folder, Archive: archive, format: archiveZip})
		}
	}
	psparse.WalkCommands(script, func(command *psparse.Command) {
		name, ok := psparse.LiteralString(command.Name)
		if !ok {
			return
		}
		name = strings.ToLower(name)
		name = strings.TrimPrefix(name, `microsoft.powershell.archive\`)
		if name != "expand-archive" {
			return
		}
		values, whatIf := psExpandArchiveValues(command)
		if whatIf {
			return
		}
		folder := cwd
		if destination, given := values["destinationpath"]; given {
			placed, ok := psArchivePath(destination, cwd, home, true)
			if !ok {
				return
			}
			folder = placed
		}
		source, given := values["literalpath"]
		if !given {
			source, given = values["path"]
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

// psExpandArchiveParameters are the Expand-Archive parameters and aliases
// with a value, and the switches; a unique prefix names one, as PowerShell
// binds it.
var (
	psExpandArchiveValued = []string{"path", "literalpath", "pspath", "lp", "destinationpath",
		"erroraction", "ea", "errorvariable", "ev", "warningaction", "wa", "warningvariable", "wv",
		"informationaction", "infa", "informationvariable", "iv", "outvariable", "ov", "outbuffer", "ob",
		"pipelinevariable", "pv", "progressaction", "proga"}
	psExpandArchiveSwitches = []string{"force", "passthru", "whatif", "wi", "confirm", "cf", "verbose", "vb", "debug", "db"}
)

// psExpandArchiveValues binds the path parameters of one Expand-Archive
// call: path, literalpath and destinationpath (named, or the first two
// positional arguments). whatIf reports -WhatIf.
func psExpandArchiveValues(command *psparse.Command) (values map[string]psparse.Expr, whatIf bool) {
	values = map[string]psparse.Expr{}
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
		name := psUniqueParameter(strings.ToLower(parameter.Name))
		switch name {
		case "pspath", "lp":
			name = "literalpath"
		case "wi":
			name = "whatif"
		}
		if name == "whatif" {
			// -WhatIf:$false writes as no -WhatIf does.
			off := false
			if variable, ok := parameter.Colon.(*psparse.Variable); parameter.HasColon && ok {
				off = strings.EqualFold(variable.Name, "false")
			}
			whatIf = whatIf || !off
			continue
		}
		valued := false
		for _, known := range psExpandArchiveValued {
			valued = valued || known == name
		}
		if !valued {
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
			values[name] = value
		}
	}
	for _, name := range []string{"path", "destinationpath"} {
		if len(positional) == 0 {
			break
		}
		if _, given := values[name]; given || name == "path" && values["literalpath"] != nil {
			continue
		}
		values[name], positional = positional[0], positional[1:]
	}
	return values, whatIf
}

// psUniqueParameter is the Expand-Archive parameter a name or unique prefix
// spells, or the name itself when it spells none or several.
func psUniqueParameter(name string) string {
	found, matches := "", 0
	for _, list := range [][]string{psExpandArchiveValued, psExpandArchiveSwitches} {
		for _, known := range list {
			if known == name {
				return name
			}
			if strings.HasPrefix(known, name) {
				found, matches = known, matches+1
			}
		}
	}
	if matches == 1 {
		return found
	}
	return name
}

// psArchivePath places one PowerShell path value in cwd: a literal, a home
// variable, or a string of literal runs and home variables. cmdlet reads
// the provider forms (~, FileSystem::) a cmdlet path takes and a .NET call
// does not.
func psArchivePath(value psparse.Expr, cwd, home string, cmdlet bool) (string, bool) {
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
			for _, part := range expression.Parts {
				switch {
				case part.Expr == nil:
					built.WriteString(part.Lit)
				case home != "" && psHomeVariable(part.Expr):
					built.WriteString(home)
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
	}
	return filepath.Clean(OperandPath(text, cwd)), true
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
