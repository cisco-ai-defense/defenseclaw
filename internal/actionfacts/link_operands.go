// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

// lnOptions is the option grammar of ln (GNU coreutils and BSD/macOS).
func lnOptions(argv []string) ownedPOSIXOptionParse {
	return parseOwnedPOSIXOptions(
		argv,
		exactOptionSet("-S", "--suffix", "-t", "--target-directory"),
		exactOptionSet(
			"-b", "--backup", "-d", "-F", "--directory", "-f", "--force",
			"-h", "-i", "--interactive", "-L", "--logical", "-n",
			"--no-dereference", "-P", "--physical", "-r", "--relative",
			"-s", "--symbolic", "-T", "--no-target-directory", "-v",
			"--verbose", "-w",
		),
		exactOptionSet("--help", "--version"),
	)
}

// lnLayout is what one ln call names: the link targets and either the one
// link name (link) or the directory the links land in (directory).
type lnLayout struct {
	targets         []string
	link, directory string
	complete        bool
}

func lnLayoutOf(parsed ownedPOSIXOptionParse) lnLayout {
	layout := lnLayout{targets: parsed.positionals, complete: parsed.complete}
	directory, into := parsed.values["-t"]
	if !into {
		directory, into = parsed.values["--target-directory"]
	}
	_, noTargetDirectory := parsed.seen["-T"]
	if _, long := parsed.seen["--no-target-directory"]; long {
		noTargetDirectory = true
	}
	switch {
	case len(layout.targets) == 0 || into && (directory == "" || noTargetDirectory):
		layout.complete = false
		layout.targets = nil
	case into:
		layout.directory = directory
	case len(layout.targets) == 1:
		layout.directory = "."
	case len(layout.targets) > 2:
		if noTargetDirectory {
			layout.complete = false
			layout.targets = nil
			break
		}
		layout.directory = layout.targets[len(layout.targets)-1]
		layout.targets = layout.targets[:len(layout.targets)-1]
	default:
		name := layout.targets[1]
		layout.targets = layout.targets[:1]
		if strings.HasSuffix(name, "/") && !noTargetDirectory {
			layout.directory = name
		} else {
			layout.link = name
		}
	}
	return layout
}

// LinkTargets returns what an ln argv points its links at (not the link
// names); nil when the call has no complete operand layout.
func LinkTargets(argv []string) []string {
	layout := lnLayoutOf(lnOptions(argv))
	if !layout.complete {
		return nil
	}
	return append([]string(nil), layout.targets...)
}

// classifyPOSIXLink reads ln: `ln [opts] TARGET LINK`, `ln [opts] TARGET`
// (a link named after TARGET in the cwd), `ln [opts] TARGET... DIR/` and
// `ln [opts] -t DIR TARGET...`. Each link name the call creates or
// replaces is a write (GAP-1774: `ln -sf X ~/.defenseclaw/config.yaml`
// replaces the file with a link). A TARGET is only what the link points
// at: nothing is read or written there, so a link elsewhere that points at
// protected state writes nothing protected. For `ln TARGET LINK` the write
// is LINK; the owner of a protected directory judges a link that lands in
// it (LinkTargets).
func classifyPOSIXLink(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	parsed := lnOptions(command.Argv)
	if parsed.preview {
		command.Effect = EffectPreview
		return
	}
	layout := lnLayoutOf(parsed)
	if !layout.complete {
		out.markPartial(IssueUnknownOperandGrammar)
	}
	if len(layout.targets) == 0 {
		return
	}
	addOperation(command, OperationWrite)
	if layout.link != "" {
		appendCommandPath(out, command, PathAccessWrite, layout.link)
		return
	}
	for _, target := range layout.targets {
		name := path.Base(strings.TrimRight(target, "/"))
		if name == "" || name == "/" || name == "." || name == ".." {
			out.markPartial(IssueUnknownOperandGrammar)
			continue
		}
		if layout.directory == "." {
			appendCommandPath(out, command, PathAccessWrite, name)
			continue
		}
		appendCommandPath(out, command, PathAccessWrite, strings.TrimRight(layout.directory, "/")+"/"+name)
	}
}

// LinkTargetReads are the files the ln calls of f point their links at, as
// read path facts placed and resolved as every operand fact is: a link to a
// protected file is judged as the plain read of that file
// (substrate-1:GAP-0706, ruling T6-LEAD10 2026-11-27). The facts of the
// call keep only the link name (classifyPOSIXLink); these are for the path
// rules alone. A relative target of a symbolic link names a file in the
// folder of the link, so it is read there; that of a hard link in the
// command's folder. A call without a complete operand layout gives none.
func (f Facts) LinkTargetReads() []PathFact {
	var paths []PathFact
	for _, command := range f.Commands {
		if command.Program != "ln" || command.Dialect != DialectPOSIX && command.Dialect != DialectArgv {
			continue
		}
		parsed := lnOptions(command.Argv)
		if parsed.preview {
			continue
		}
		layout := lnLayoutOf(parsed)
		if !layout.complete {
			continue
		}
		folder := layout.directory
		if layout.link != "" {
			folder = path.Dir(layout.link)
		}
		symbolic := lnSymbolic(command.Argv)
		for _, target := range layout.targets {
			value := target
			if symbolic && folder != "." && folder != "" && !strings.HasPrefix(target, "/") &&
				!strings.HasPrefix(target, "~") && !strings.HasPrefix(target, "$") {
				value = strings.TrimRight(folder, "/") + "/" + target
			}
			if value == "" || value == "-" {
				continue
			}
			paths = append(paths, PathFact{CommandID: command.ID, Access: PathAccessRead, Flavor: pathFlavor(value), Value: value})
		}
	}
	if len(paths) == 0 {
		return nil
	}
	return normalizePathFactsForCommandsInShell(paths, f.CWD, f.ActiveHome, f.Commands, false)
}

// lnSymbolic reports an ln argv that makes symbolic links (-s, --symbolic,
// or -s in a cluster of switches before the operands).
func lnSymbolic(argv []string) bool {
	for _, arg := range argv[min(1, len(argv)):] {
		if arg == "--" {
			return false
		}
		if arg == "--symbolic" {
			return true
		}
		if !strings.HasPrefix(arg, "-") || strings.HasPrefix(arg, "--") {
			continue
		}
		for _, letter := range arg[1:] {
			if letter == 's' {
				return true
			}
			if letter == 'S' || letter == 't' {
				break // the rest is the value of the option
			}
		}
	}
	return false
}
