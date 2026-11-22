// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/psparse"
)

// maxPowerShellLinkCommands bounds the commands of a PowerShell call that the
// link twin reads. A longer call keeps the opaque link reading.
const maxPowerShellLinkCommands = 64

// powerShellDirectoryChangers change what a relative operand names, which the
// twin does not follow.
var powerShellDirectoryChangers = []string{"set-location", "sl", "cd", "chdir", "push-location", "pushd", "pop-location", "popd"}

// powerShellLinkTwin reads the links a PowerShell call makes the way the shell
// link reader reads ln and mv: New-Item -ItemType SymbolicLink | Junction |
// HardLink with a static -Path and -Target (or -Value), and Move-Item with
// static operands, become `ln -s TARGET NAME` and `mv SOURCE DESTINATION`, in
// call order. The twin text is what commandLinksRead reads instead of the
// opaque reading, so a link whose target is protected state, a link made in
// a protected name, and a write through a moved link keep the verdict they
// have as a POSIX link (rel-1-0-10:GAP-0749, the Windows twin of GAP-0571).
//
// ok is false, and the call keeps the opaque reading, unless every
// link-making text of the call is such a New-Item that was read: every
// -ItemType link text opaqueLink finds is a read link call, every New-Item
// spelling, the ni alias too, is a read call (a link spelled another way, -Ty
// or an en dash, is found by its call: rel-1-0-10:GAP-0849), no other link
// API, directory change, copy, rename or archive command is in the call, and
// no operand is dynamic.
func powerShellLinkTwin(command, cwd, home string) (twin string, ok bool) {
	plainTexts := 0
	for _, match := range opaqueLink.FindAllString(command, -1) {
		if !strings.HasPrefix(strings.ToLower(match), "-itemtype") {
			return "", false
		}
		plainTexts++
	}
	spellings := len(newItemSpellingIndexes(command))
	if plainTexts == 0 && spellings == 0 {
		return "", false
	}
	facts := analyzeAtHookFolder(actionfacts.Input{Tool: "PowerShell", Command: command, DialectHint: actionfacts.DialectPowerShell, CWD: cwd, ActiveHome: home})
	if facts.Parse.Dialect != actionfacts.DialectPowerShell || len(facts.Commands) == 0 || len(facts.Commands) > maxPowerShellLinkCommands {
		return "", false
	}
	var lines []string
	links, plainLinks, newItems := 0, 0, 0
	for _, command := range facts.Commands {
		if command.Kind != "" && command.Kind != actionfacts.CommandKindProcess {
			continue
		}
		if !command.ArgvComplete || command.Effect != actionfacts.EffectExecute || len(command.Argv) == 0 {
			return "", false
		}
		program := strings.ToLower(command.Argv[0])
		if slices.Contains(powerShellDirectoryChangers, program) {
			return "", false
		}
		switch program {
		case "new-item", "ni":
			newItems++
			flavor, name, target, isLink, read := powerShellNewItemLink(command.Argv[1:])
			if !read {
				return "", false
			}
			if !isLink {
				continue
			}
			links++
			if opaqueLink.MatchString(strings.Join(command.Argv, " ")) {
				plainLinks++
			}
			option := "-s"
			if flavor == "hardlink" {
				option = ""
			}
			lines = append(lines, strings.TrimSpace("ln "+option)+" -- '"+target+"' '"+name+"'")
		case "move-item", "mv", "move", "mi":
			source, destination, read := powerShellMoveOperands(command.Argv[1:])
			if !read {
				return "", false
			}
			lines = append(lines, "mv -- '"+source+"' '"+destination+"'")
		default:
			// Any other command that copies or moves (Copy-Item, Rename-Item,
			// an archive tool) can carry a link to another name.
			if slices.Contains(command.Operations, actionfacts.OperationCopy) || slices.Contains(command.Operations, actionfacts.OperationMove) {
				return "", false
			}
		}
	}
	if links == 0 || plainLinks != plainTexts || newItems != spellings {
		return "", false
	}
	return strings.Join(lines, "\n"), true
}

// powerShellStaticOperand reports an operand that names one fixed path: no
// expansion, subexpression, wildcard, quote or separator, and not empty.
func powerShellStaticOperand(word string) bool {
	if word == "" || strings.ContainsAny(word, actionWindowsMoveUnsafe) || strings.HasPrefix(word, "-") {
		return false
	}
	if runtime.GOOS != "windows" {
		// The ln and mv twin is read with this host's path rules: a drive path
		// or a backslash is not a path here, so the call keeps the opaque
		// reading (a Windows spelling is read on a Windows host).
		return !strings.Contains(word, `\`) && (len(word) < 2 || word[1] != ':')
	}
	return true
}

// powerShellNewItemLink reads the operands of a New-Item call. Its words
// bind as PowerShell binds them (psparse.NewItemParameters: any unique
// prefix, any dash form, any case, -Name:value), so every spelling of a link
// reads as the plain one (rel-1-0-10:GAP-0849). read is false for a
// parameter that binds to no New-Item parameter or to more than one, or for
// an operand this reading does not know; isLink is false for a call that
// makes no link (a file or a folder).
func powerShellNewItemLink(args []string) (flavor, name, target string, isLink, read bool) {
	itemType := ""
	for index := 0; index < len(args); index++ {
		param, inline, colon, isParameter, known := psparse.NewItemParameters.BindWord(args[index])
		if !isParameter {
			if strings.HasPrefix(args[index], "-") || name != "" || !powerShellStaticOperand(args[index]) {
				return "", "", "", false, false
			}
			name = args[index]
			continue
		}
		if !known {
			return "", "", "", false, false
		}
		value := func() (string, bool) {
			if colon && inline != "" {
				return inline, true
			}
			if index+1 >= len(args) {
				return "", false
			}
			index++
			return args[index], true
		}
		switch param.Name {
		case "itemtype":
			word, ok := value()
			if !ok || strings.ContainsAny(word, actionWindowsMoveUnsafe) {
				return "", "", "", false, false
			}
			itemType = strings.ToLower(word)
		case "path":
			word, ok := value()
			if !ok || !powerShellStaticOperand(word) || name != "" {
				return "", "", "", false, false
			}
			name = word
		case "value":
			word, ok := value()
			if !ok || !powerShellStaticOperand(word) || target != "" {
				return "", "", "", false, false
			}
			target = word
		case "force":
			if colon {
				return "", "", "", false, false
			}
		default:
			return "", "", "", false, false
		}
	}
	switch itemType {
	case "symboliclink", "junction":
		flavor = "symboliclink"
	case "hardlink":
		flavor = "hardlink"
	default:
		// A file or a folder, or an item type this reading does not know: only
		// an item type that is not a link may be skipped.
		return "", "", "", false, itemType == "" || itemType == "file" || itemType == "directory"
	}
	if name == "" || target == "" {
		return "", "", "", false, false
	}
	return flavor, name, target, true, true
}

// powerShellMoveOperands reads Move-Item with only -Force and -PassThru, one
// source and one destination, positional or named.
func powerShellMoveOperands(args []string) (source, destination string, read bool) {
	var positional []string
	for index := 0; index < len(args); index++ {
		arg := strings.ToLower(args[index])
		next := func() (string, bool) {
			if index+1 >= len(args) || !powerShellStaticOperand(args[index+1]) {
				return "", false
			}
			index++
			return args[index], true
		}
		switch {
		case arg == "-force" || arg == "-passthru":
		case arg == "-path" || arg == "-literalpath":
			word, ok := next()
			if !ok || source != "" {
				return "", "", false
			}
			source = word
		case arg == "-destination":
			word, ok := next()
			if !ok || destination != "" {
				return "", "", false
			}
			destination = word
		case !strings.HasPrefix(arg, "-") && powerShellStaticOperand(args[index]):
			positional = append(positional, args[index])
		default:
			return "", "", false
		}
	}
	if source == "" && len(positional) > 0 {
		source, positional = positional[0], positional[1:]
	}
	if destination == "" && len(positional) > 0 {
		destination, positional = positional[0], positional[1:]
	}
	if source == "" || destination == "" || len(positional) != 0 {
		return "", "", false
	}
	return source, destination, true
}
