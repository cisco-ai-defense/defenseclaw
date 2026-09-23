// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// windowsClassifyFSUtil owns only the exact non-interactive operation that
// deletes an NTFS USN change journal. Other fsutil verbs remain unsupported
// because their operand grammars and security effects are unrelated.
func windowsClassifyFSUtil(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !exactWindowsUSNJournalDeleteArguments(args) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationDelete)
	windowsAddOperation(command, OperationConfigChange)
}

func exactWindowsUSNJournalDeleteArguments(args []windowsWord) bool {
	if len(args) != 4 {
		return false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote != QuoteNone {
			return false
		}
	}
	return strings.EqualFold(args[0].value, "usn") &&
		strings.EqualFold(args[1].value, "deletejournal") &&
		strings.EqualFold(args[2].value, "/d") &&
		exactWindowsDriveVolume(args[3].value)
}

func exactWindowsDriveVolume(value string) bool {
	return len(value) == 2 &&
		((value[0] >= 'A' && value[0] <= 'Z') ||
			(value[0] >= 'a' && value[0] <= 'z')) &&
		value[1] == ':'
}

// ExactWindowsUSNJournalDelete proves one unconditional top-level fsutil
// invocation that deletes the USN journal for one literal drive volume.
func ExactWindowsUSNJournalDelete(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD &&
		facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.PipelineID != 0 ||
			command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
			len(command.Redirects) != 0 || !command.ArgvComplete ||
			(command.Program != "fsutil" && command.Program != "fsutil.exe") ||
			!hasFactOperation(command, OperationDelete) ||
			!hasFactOperation(command, OperationConfigChange) ||
			len(command.Arguments) != 5 {
			continue
		}
		args := make([]windowsWord, 0, 4)
		for _, argument := range command.Arguments[1:] {
			args = append(args, windowsWord{
				value:    argument.Value,
				quote:    argument.Quote,
				expands:  argument.Expands,
				wildcard: strings.ContainsAny(argument.Value, "*?"),
			})
		}
		if exactWindowsUSNJournalDeleteArguments(args) {
			return true
		}
	}
	return false
}
