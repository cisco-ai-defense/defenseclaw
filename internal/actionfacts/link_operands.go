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
