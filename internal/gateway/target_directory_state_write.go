// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path"
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
// the drive home, an MSYS mount /c/... as C:/...), and each source is judged
// as the move or copy it is, Move-Item or Copy-Item -LiteralPath <source>
// -Destination <DIR>\<base>, through the state proof the PowerShell readings
// use (drive, mixed-separator and home spellings, links, the resolved write
// targets of the hook). A new entry that is no state file (mv -t <state
// folder> notes.txt) stays allowed. The PowerShell tool runs only
// PowerShell, which refuses the form, so its calls are not read.
func provenTargetDirectoryStateWrite(request trustedActionRequest) bool {
	home := request.Input.ActiveHome
	if len(home) < 2 || home[1] != ':' || strings.EqualFold(strings.TrimSpace(request.Input.Tool), "powershell") {
		return false
	}
	switch request.Input.DialectHint {
	case "", actionfacts.DialectPOSIX, actionfacts.DialectPowerShell:
	default:
		return false
	}
	command, known := trustedBashCommandInput(request.Input)
	if !known || !strings.Contains(command, "-") {
		return false
	}
	forms, bounded := targetDirectoryForms(command, home)
	if bounded {
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

// targetDirectoryForms spells each source of every mv, cp, install or ln
// call of command that gives a target directory as the PowerShell move or
// copy of that source onto DIR\<base>. bounded is true past
// maxTargetDirectoryForms.
func targetDirectoryForms(command, home string) (forms []string, bounded bool) {
	file, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(shellparse.Reader(command), "")
	if err != nil {
		return nil, false
	}
	// xargsStaticValue reads a rooted slash home; the drive home is spelled
	// as its drive view (/C:/Users/x) and read back as the drive path.
	view := "/" + strings.ReplaceAll(strings.TrimRight(home, `\/`), `\`, "/")
	value := func(word *syntax.Word) (string, bool) {
		return xargsStaticValue(word, view)
	}
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
		program, ok := value(call.Args[0])
		if !ok {
			return true
		}
		cmdlet := targetDirectoryCmdlet(program)
		if cmdlet == "" {
			return true
		}
		words := make([]string, len(call.Args)-1)
		static := make([]bool, len(words))
		for index, arg := range call.Args[1:] {
			// A word with no static value is an operand of unknown name:
			// it names no source, and as the folder it places nothing.
			words[index], static[index] = value(arg)
			if !static[index] {
				words[index] = "\x00"
			}
		}
		dir, sources, given := targetDirectoryOperands(words, static)
		if !given || dir == "" {
			return true
		}
		dir = drivePath(dir)
		for _, source := range sources {
			source = drivePath(source)
			base := path.Base(strings.TrimRight(strings.ReplaceAll(source, `\`, "/"), "/"))
			if base == "." || base == ".." || base == "/" {
				continue
			}
			if len(forms) >= maxTargetDirectoryForms {
				bounded = true
				return false
			}
			landing := strings.TrimRight(dir, `\/`) + `\` + base
			forms = append(forms, cmdlet+" -LiteralPath "+managed.PowerShellLiteral(source)+
				" -Destination "+managed.PowerShellLiteral(landing))
		}
		return true
	})
	return forms, bounded
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
// destination is then the last operand, no -t form) and the source operands
// with a static value. The value of a separate -S, -m, -o or -g option (or
// of its long name) is no source.
func targetDirectoryOperands(words []string, static []bool) (dir string, sources []string, given bool) {
	destination, attached, option := actionfacts.CopyOperandRoles(words)
	// With no target-directory option the destination is the last operand,
	// so one more operand moves it; the folder of -t stays.
	probe, probeAttached, _ := actionfacts.CopyOperandRoles(append(words[:len(words):len(words)], "\x00"))
	switch {
	case attached != "":
		dir, given = attached, true
	case destination >= 0 && probe == destination && probeAttached == "":
		if !static[destination] {
			return "", nil, false
		}
		dir, given = words[destination], true
	default:
		return "", nil, false
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
		if index == destination || !static[index] || word == "" {
			continue
		}
		sources = append(sources, word)
	}
	return dir, sources, given
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
