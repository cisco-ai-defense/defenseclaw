// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"runtime"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
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
// link-making text of the call is such a New-Item that was read: the link
// count equals the count of link-making spellings, no other link API,
// directory change, copy, rename or archive command is in the call, and no
// operand is dynamic.
func powerShellLinkTwin(command, cwd, home string) (twin string, ok bool) {
	matches := opaqueLink.FindAllString(command, -1)
	if len(matches) == 0 {
		return "", false
	}
	for _, match := range matches {
		if !strings.HasPrefix(strings.ToLower(match), "-itemtype") {
			return "", false
		}
	}
	facts := actionfacts.Analyze(actionfacts.Input{Tool: "PowerShell", Command: command, DialectHint: actionfacts.DialectPowerShell, CWD: cwd, ActiveHome: home})
	if facts.Parse.Dialect != actionfacts.DialectPowerShell || len(facts.Commands) == 0 || len(facts.Commands) > maxPowerShellLinkCommands {
		return "", false
	}
	var lines []string
	links := 0
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
			flavor, name, target, isLink, read := powerShellNewItemLink(command.Argv[1:])
			if !read {
				return "", false
			}
			if !isLink {
				continue
			}
			links++
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
	if links == 0 || links != len(matches) {
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

// powerShellNewItemLink reads the operands of a New-Item call. read is false
// for an option or operand this reading does not know; isLink is false for a
// call that makes no link (a file or a folder).
func powerShellNewItemLink(args []string) (flavor, name, target string, isLink, read bool) {
	itemType := ""
	for index := 0; index < len(args); index++ {
		arg := strings.ToLower(args[index])
		value := func() (string, bool) {
			if index+1 >= len(args) {
				return "", false
			}
			index++
			return args[index], true
		}
		switch {
		case arg == "-itemtype" || arg == "-type":
			word, ok := value()
			if !ok || strings.ContainsAny(word, actionWindowsMoveUnsafe) {
				return "", "", "", false, false
			}
			itemType = strings.ToLower(word)
		case arg == "-path" || arg == "-literalpath":
			word, ok := value()
			if !ok || !powerShellStaticOperand(word) || name != "" {
				return "", "", "", false, false
			}
			name = word
		case arg == "-target" || arg == "-value":
			word, ok := value()
			if !ok || !powerShellStaticOperand(word) || target != "" {
				return "", "", "", false, false
			}
			target = word
		case arg == "-force":
		case !strings.HasPrefix(arg, "-") && name == "":
			if !powerShellStaticOperand(args[index]) {
				return "", "", "", false, false
			}
			name = args[index]
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
