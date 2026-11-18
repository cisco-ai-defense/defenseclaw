// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/shellparse"
	"mvdan.cc/sh/v3/syntax"
)

// maxTargetDirectoryForms bounds the moves and copies the target-directory
// reading spells out; past it the state-naming command counts as the write
// (over-block, as powerShellWriteReading does past its bounds).
const maxTargetDirectoryForms = 64

// provenTargetDirectoryStateWrite is the POSIX (Git Bash) reading of the GNU
// target-directory form of a Windows-home shell call for the state-write
// proof (rel-1-0-10:GAP-1250). mv, cp, install and ln with -t DIR, -tDIR, a
// short cluster that ends in or holds t, or --target-directory[=]DIR put
// each source operand at DIR/<its base name>. The ActionFacts POSIX reading
// leaves a drive home it does not spell ("$HOME\x", 'C:\x') partial, a call
// the dialect selection places in PowerShell (C:/x, "C:\x") is not read as
// POSIX at all, and PowerShell refuses -t. Once the PowerShell reading no
// longer took the folder of -t for a moved source (rel-1-0-10:GAP-1209), no
// reading proved mv -t <state folder> config.yaml. Each word is read as Git
// Bash makes it (literal and quoted text, a leading ~ and a plain $HOME as
// the drive home, an MSYS mount /c/... as C:/..., a glob that matches
// nothing as written), and each source is judged as the move or copy it is,
// Move-Item or Copy-Item -LiteralPath <source> -Destination <DIR>\<base>,
// through the state proof the PowerShell readings use (drive,
// mixed-separator and home spellings, links, the resolved write targets of
// the hook). A new entry that is no state file (mv -t <state folder>
// notes.txt) stays allowed. A source whose name the call does not fix ("$F",
// $(ls x), a glob) may be any entry its base name allows: when that may be
// a state entry of the folder (the detector config in the state root), the
// call is the unknown tier (unknown), never an allow; "$F.txt" may be no
// state name and stays a new entry (rel-1-0-10:GAP-1260). The PowerShell
// tool runs only PowerShell, which refuses the form, so its calls are not
// read.
func provenTargetDirectoryStateWrite(request trustedActionRequest) (written, unknown bool) {
	home := request.Input.ActiveHome
	if len(home) < 2 || home[1] != ':' || strings.EqualFold(strings.TrimSpace(request.Input.Tool), "powershell") {
		return false, false
	}
	switch request.Input.DialectHint {
	case "", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell:
	default:
		return false, false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !strings.Contains(command, "-") {
		return false, false
	}
	reading, bounded := targetDirectoryForms(command, home)
	if bounded {
		return true, false
	}
	proven := func(form string) bool {
		input := request.Input
		input.Command, input.Args, input.Argv = form, nil, nil
		input.DialectHint = actionfacts.DialectPowerShell
		twin := request
		twin.Input = input
		return provenStateMutationPath(actionfacts.Analyze(input), twin)
	}
	for _, form := range reading.forms {
		if proven(form) {
			return true, false
		}
	}
	// A source of unknown name may land on each state name its base name
	// may be: the copy onto it goes through the same proof (links and
	// spellings of the folder).
	for _, landing := range reading.unknownLandings {
		if proven("Copy-Item -LiteralPath " + managed.PowerShellLiteral(targetDirectoryUnknownSource) +
			" -Destination " + managed.PowerShellLiteral(landing)) {
			return false, true
		}
	}
	return false, false
}

// targetDirectoryUnknownSource stands for a source whose name the call does
// not fix in the probe of its folder: a relative name in the call's directory
// that names no state.
const targetDirectoryUnknownSource = "defenseclaw-unknown-source"

// targetDirectoryReading is what targetDirectoryForms reads of a command:
// the PowerShell move or copy of each source with a fixed base name, and
// each place DIR\<name> a source of unknown name may land on.
type targetDirectoryReading struct {
	forms           []string
	unknownLandings []string
}

// targetDirectoryForms spells each source of every mv, cp, install or ln
// call of command that gives a target directory as the PowerShell move or
// copy of that source onto DIR\<base>, and the places a source of unknown
// name may land on (targetDirectoryUnknownNames). bounded is true past
// maxTargetDirectoryForms.
func targetDirectoryForms(command, home string) (reading targetDirectoryReading, bounded bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return reading, false
	}
	// xargsStaticValue reads a rooted slash home; the drive home is spelled
	// as its drive view (/C:/Users/x) and read back as the drive path.
	view := "/" + strings.ReplaceAll(strings.TrimRight(home, `\/`), `\`, "/")
	// An operand, or the value of --target-directory=, read back from the
	// drive view, with an MSYS mount spelled as its drive.
	drivePath := func(text string) string {
		if strings.HasPrefix(text, "/") && actionfacts.DriveSlashPath(text[1:]) {
			text = text[1:]
		}
		return actionfacts.MSYSDrivePath(text)
	}
	syntax.Walk(file, func(node syntax.Node) bool {
		if bounded {
			return false
		}
		call, ok := node.(*syntax.CallExpr)
		if !ok || len(call.Args) < 3 {
			return true
		}
		program, ok := xargsStaticValue(call.Args[0], view)
		if !ok {
			return true
		}
		cmdlet := targetDirectoryCmdlet(program)
		if cmdlet == "" {
			return true
		}
		words := make([]string, len(call.Args)-1)
		named := make([]bool, len(words))
		for index, arg := range call.Args[1:] {
			words[index], named[index] = targetDirectoryWord(arg, view)
		}
		dir, sources, unknown, given := targetDirectoryOperands(words, named)
		if !given || dir == "" || strings.Contains(dir, "\x00") {
			return true
		}
		dir = strings.TrimRight(drivePath(dir), `\/`)
		add := func(list *[]string, item string) bool {
			if slices.Contains(*list, item) {
				return true
			}
			if len(reading.forms)+len(reading.unknownLandings) >= maxTargetDirectoryForms {
				bounded = true
				return false
			}
			*list = append(*list, item)
			return true
		}
		for _, source := range sources {
			source = drivePath(source)
			base := path.Base(strings.TrimRight(strings.ReplaceAll(source, `\`, "/"), "/"))
			if base == "." || base == ".." || base == "/" {
				continue
			}
			if !add(&reading.forms, cmdlet+" -LiteralPath "+managed.PowerShellLiteral(source)+
				" -Destination "+managed.PowerShellLiteral(dir+`\`+base)) {
				return false
			}
		}
		for _, index := range unknown {
			fixed, names := targetDirectoryUnknownNames(call.Args[index+1], view)
			if fixed != "" {
				// "$D/config.yaml": whatever the folder, the base is fixed.
				if !add(&reading.forms, cmdlet+" -LiteralPath "+managed.PowerShellLiteral(fixed)+
					" -Destination "+managed.PowerShellLiteral(dir+`\`+fixed)) {
					return false
				}
				continue
			}
			for _, name := range names {
				if !add(&reading.unknownLandings, dir+`\`+name) {
					return false
				}
			}
		}
		return true
	})
	return reading, bounded
}

// targetDirectoryWord is the argument Git Bash makes of one word after the
// program word of a target-directory call (view is the drive view of the
// home), and named, whether it names exactly one entry. A word with a glob
// character Bash would expand (//?/C:/x, the Windows long-path prefix) is
// passed as written when it matches nothing: it is read as written for the
// folder, and as a source it may name any entry (rel-1-0-10:GAP-1260). Any
// other word with no fixed value ("$F", $(ls x)) is unknown: "\x00", after
// the literal text of an option it starts with (--suffix="$S" stays an
// option, -t"$D" a folder of unknown name).
func targetDirectoryWord(word *syntax.Word, view string) (text string, named bool) {
	value, globbed, ok := shellWordLiteralValue(word, view)
	switch {
	case ok && !globbed:
		return value, true
	case ok:
		return value, false
	}
	if lit, isLit := word.Parts[0].(*syntax.Lit); isLit && strings.HasPrefix(lit.Value, "-") {
		return lit.Value + "\x00", false
	}
	return "\x00", false
}

// targetDirectoryUnknownNames reads a source word whose name the call does
// not fix ("$F", "$F.txt", $(ls x), a glob, a brace list) as the pattern of
// its base name: a fixed base when the base is known anyway ("$D/config.yaml",
// fixed), else the state names directly under ~/.defenseclaw it may match and
// one name it surely matches (notes*.txt: notes.txt), so that a folder in
// the state tree where every entry is state is read too. "$F.txt" may be no
// state name in the state root and adds only F.txt-shaped names
// (rel-1-0-10:GAP-1260).
func targetDirectoryUnknownNames(word *syntax.Word, view string) (fixed string, names []string) {
	base := targetDirectoryBasePattern(word, view)
	if base == "" {
		return "", nil
	}
	instance, meta := "", false
	for at := 0; at < len(base); at++ {
		switch char := base[at]; char {
		case '\\':
			if at+1 < len(base) {
				at++
				instance += base[at : at+1]
			}
		case '*':
			meta = true
		case '?':
			meta, instance = true, instance+"x"
		case '[':
			// A class: the instance is not spelled.
			meta, instance = true, "\x00"+instance
		default:
			instance += string(char)
		}
	}
	if !meta {
		if instance == "." || instance == ".." {
			return "", nil
		}
		return instance, nil
	}
	lowered := strings.ToLower(base)
	for _, name := range activeDefenseClawStateNames {
		if matched, err := path.Match(lowered, strings.ToLower(name)); err == nil && matched {
			names = append(names, name)
		}
	}
	if instance != "" && !strings.Contains(instance, "\x00") && instance != "." && instance != ".." &&
		!slices.Contains(names, instance) {
		names = append(names, instance)
	}
	return "", names
}

// targetDirectoryBasePattern is the base name of a source word as a
// path.Match pattern: literal and quoted text escaped (a backslash of
// quoted text is a Windows separator), an unquoted glob kept, and any
// expansion with no fixed value (or a brace list) as *. An expansion may
// hold a separator, so the base after an expansion is * and the text after
// it. "" when the word has no base (a trailing separator only).
func targetDirectoryBasePattern(word *syntax.Word, view string) string {
	var pattern strings.Builder
	literal := func(text string) {
		for _, char := range text {
			switch {
			case char == '\\':
				pattern.WriteByte('/')
			case strings.ContainsRune(`*?[]`, char):
				pattern.WriteByte('\\')
				pattern.WriteRune(char)
			default:
				pattern.WriteRune(char)
			}
		}
	}
	const unknown = "\x00"
	for index, part := range word.Parts {
		switch typed := part.(type) {
		case *syntax.Lit:
			value := typed.Value
			if index == 0 && strings.HasPrefix(value, "~") {
				if value != "~" && !strings.HasPrefix(value, "~/") {
					pattern.WriteString(unknown)
					value = strings.TrimLeft(value, "~")
					if at := strings.IndexByte(value, '/'); at >= 0 {
						value = value[at:]
					} else {
						value = ""
					}
				} else {
					literal(view)
					value = value[1:]
				}
			}
			for at := 0; at < len(value); at++ {
				switch char := value[at]; {
				case char == '\\':
					if at+1 < len(value) {
						at++
						literal(value[at : at+1])
					}
				case char == '*' || char == '?':
					pattern.WriteByte(char)
				case char == '[' && strings.IndexByte(value[at+1:], ']') >= 0:
					end := at + 1 + strings.IndexByte(value[at+1:], ']')
					class := value[at : end+1]
					if strings.HasPrefix(class, "[!") {
						class = "[^" + class[2:]
					}
					pattern.WriteString(class)
					at = end
				case char == '{' && strings.IndexByte(value[at+1:], '}') >= 0:
					// A brace list may be any of its words.
					pattern.WriteString(unknown)
					at += 1 + strings.IndexByte(value[at+1:], '}')
				default:
					literal(value[at : at+1])
				}
			}
		case *syntax.SglQuoted:
			if typed.Dollar {
				pattern.WriteString(unknown)
				continue
			}
			literal(typed.Value)
		case *syntax.DblQuoted:
			for _, inner := range typed.Parts {
				switch quoted := inner.(type) {
				case *syntax.Lit:
					literal(xargsDoubleQuotedText(quoted.Value))
				case *syntax.ParamExp:
					if xargsPlainHome(quoted) {
						literal(view)
					} else {
						pattern.WriteString(unknown)
					}
				default:
					pattern.WriteString(unknown)
				}
			}
		case *syntax.ParamExp:
			if xargsPlainHome(typed) {
				literal(view)
			} else {
				pattern.WriteString(unknown)
			}
		default:
			pattern.WriteString(unknown)
		}
	}
	text := strings.TrimRight(pattern.String(), "/")
	// The last separator outside an escape, and the last expansion.
	separator, expansion := -1, strings.LastIndex(text, unknown)
	for at := 0; at < len(text); at++ {
		if text[at] == '\\' {
			at++
			continue
		}
		if text[at] == '/' {
			separator = at
		}
	}
	if separator > expansion {
		return text[separator+1:]
	}
	if expansion >= 0 {
		return "*" + strings.ReplaceAll(text[expansion+len(unknown):], unknown, "*")
	}
	return text
}

// targetDirectoryCmdlet is the PowerShell cmdlet a GNU writer of the
// target-directory form is judged as: Move-Item for mv (the source goes),
// Copy-Item for cp, install and ln (ln makes DIR/<base> a new link to the
// source: the same new entry). "" for any other program.
func targetDirectoryCmdlet(program string) string {
	name := strings.ToLower(program[strings.LastIndexAny(program, `\/`)+1:])
	switch strings.TrimSuffix(name, ".exe") {
	case "mv":
		return "Move-Item"
	case "cp", "install", "ln":
		return "Copy-Item"
	}
	return ""
}

// targetDirectoryOperands reads the words after the program word of a cp,
// mv, install or ln call with actionfacts.CopyOperandRoles: the folder a
// target-directory option gives (given is false when none does: the
// destination is then the last operand, no -t form), the source operands
// that name one entry (named), and the indexes of the source operands that
// may name any entry (unknown). The value of a separate -S, -m, -o or -g
// option (or of its long name) is no source.
func targetDirectoryOperands(words []string, named []bool) (dir string, sources []string, unknown []int, given bool) {
	destination, attached, option := actionfacts.CopyOperandRoles(words)
	// With no target-directory option the destination is the last operand,
	// so one more operand moves it; the folder of -t stays.
	probe, probeAttached, _ := actionfacts.CopyOperandRoles(append(words[:len(words):len(words)], "\x00"))
	switch {
	case attached != "":
		dir, given = attached, true
	case destination >= 0 && probe == destination && probeAttached == "":
		dir, given = words[destination], true
	default:
		return "", nil, nil, false
	}
	optionsDone := false
	for index := 0; index < len(words); index++ {
		word := words[index]
		if option[index] {
			if word == "--" {
				optionsDone = true
			}
			if !optionsDone && targetDirectoryValuedOption(word) {
				index++
			}
			continue
		}
		if index == destination || word == "" {
			continue
		}
		if !named[index] {
			unknown = append(unknown, index)
			continue
		}
		sources = append(sources, word)
	}
	return dir, sources, unknown, given
}

// targetDirectoryValuedOption reports an option word whose value is the next
// word: a short cluster that ends in S, m, o or g (-S, -bS, -m) or the long
// suffix, mode, owner, group and strip-program options without "=".
func targetDirectoryValuedOption(word string) bool {
	if name, long := strings.CutPrefix(word, "--"); long {
		if name == "" || strings.Contains(name, "=") {
			return false
		}
		for _, valued := range []string{"suffix", "mode", "owner", "group", "strip-program"} {
			if strings.HasPrefix(valued, name) {
				return true
			}
		}
		return false
	}
	for position := 1; position < len(word); position++ {
		if strings.IndexByte("Smogt", word[position]) >= 0 {
			return word[position] != 't' && position == len(word)-1
		}
	}
	return false
}
