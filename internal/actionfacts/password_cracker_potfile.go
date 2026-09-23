// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"strings"
)

var canonicalPasswordCrackerPotfiles = [...]string{
	".john/john.pot",
	".local/share/hashcat/hashcat.potfile",
	".hashcat/hashcat.potfile",
}

// classifyCanonicalPasswordCrackerPotfileRead promotes existing exact file
// reads to the existing credential-read operation. It deliberately creates no
// parallel potfile fact: the owning command and its normalized PathFact remain
// the resource identity.
//
// The proof accepts only an unconditional command-owned content-read PathFact
// for a canonical potfile under trusted ActiveHome or /root. This permits safe
// transforms and sibling commands while rejecting dynamic paths, traversal,
// metadata/list operations, writes, conditional-only branches, and lookalikes.
func classifyCanonicalPasswordCrackerPotfileRead(facts *Facts) {
	if facts == nil {
		return
	}
	for commandIndex := range facts.Commands {
		command := &facts.Commands[commandIndex]
		if !(hasFactOperation(*command, OperationRead) ||
			hasFactOperation(*command, OperationSearch)) ||
			command.ControlFlowUncertain ||
			hasAnyArgument(command.Argv, "--help", "--version") {
			continue
		}
		for _, file := range facts.Paths {
			if file.CommandID != command.ID || file.Access != PathAccessRead ||
				file.Flavor != PathFlavorPOSIX ||
				!canonicalPasswordCrackerPotfilePath(*facts, file) {
				continue
			}
			if command.Effect == EffectExecute ||
				exactTrustedHomeTildePotfileCatRead(*facts, *command, file) {
				addOperation(command, OperationCredentialRead)
				break
			}
		}
	}
}

// exactTrustedHomeTildePotfileCatRead admits the one bounded POSIX expansion
// that ActionFacts already resolves from trusted ActiveHome. Generic shell
// parsing remains partial because it cannot expand arbitrary words; this
// helper accepts only a direct cat of one unquoted, wildcard-free ~/ path and
// only when the parser reports the expected dynamic-word and unsupported-argv
// diagnostics produced by that one expansion.
func exactTrustedHomeTildePotfileCatRead(
	facts Facts,
	command CommandFact,
	file PathFact,
) bool {
	if facts.Parse.Status != StatusPartial ||
		len(facts.Parse.Issues) != 2 ||
		!containsIssue(facts.Parse.Issues, IssueDynamicWord) ||
		!containsIssue(facts.Parse.Issues, IssueUnsupportedConstruct) ||
		facts.ActiveHome == "" || !strings.HasPrefix(facts.ActiveHome, "/") ||
		command.Dialect != DialectPOSIX || command.Program != "cat" ||
		command.Effect != EffectUncertain || command.ArgvComplete ||
		command.ControlFlowUncertain || command.ControlFlowOperator != ControlFlowOperatorNone ||
		command.ParentCommandID != 0 ||
		command.Kind != CommandKindProcess || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || len(command.Argv) != 2 ||
		command.Argv[0] != command.Executable || command.Argv[1] != "" ||
		len(command.Arguments) != 2 ||
		!exactCaseSensitivePOSIXProgram(&command, "cat") {
		return false
	}

	executable := command.Arguments[0]
	target := command.Arguments[1]
	return executable.Value == command.Executable && !executable.Expands &&
		executable.StaticGlob == "" && target.Value == "" && target.Expands &&
		target.Quote == QuoteNone && target.StaticGlob == file.Value &&
		strings.HasPrefix(file.Value, "~/") &&
		!strings.ContainsAny(file.Value, "*?[")
}

func canonicalPasswordCrackerPotfilePath(facts Facts, file PathFact) bool {
	if file.Value == "" || file.Resolved == "" ||
		containsPOSIXTraversalSegment(file.Value) {
		return false
	}

	for _, relative := range canonicalPasswordCrackerPotfiles {
		rootTarget := path.Join("/root", relative)
		if file.Resolved == rootTarget && file.Value == rootTarget {
			return true
		}
		if facts.ActiveHome == "" || !strings.HasPrefix(facts.ActiveHome, "/") {
			continue
		}
		homeTarget := path.Join(facts.ActiveHome, relative)
		if file.Resolved == homeTarget &&
			(file.Value == homeTarget || file.Value == relative ||
				file.Value == "~/"+relative) {
			return true
		}
	}
	return false
}

func containsPOSIXTraversalSegment(value string) bool {
	for _, segment := range strings.Split(value, "/") {
		if segment == ".." {
			return true
		}
	}
	return false
}
