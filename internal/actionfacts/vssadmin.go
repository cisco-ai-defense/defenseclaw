// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// windowsClassifyVSSAdmin owns only the exact destructive grammar used to
// remove every Volume Shadow Copy. Other vssadmin verbs and scoped deletes are
// intentionally left partial instead of being promoted to generic delete
// authority.
func windowsClassifyVSSAdmin(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !exactWindowsVSSDeleteAllArguments(args) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationDelete)
	// The second operation distinguishes recovery-state destruction from an
	// ordinary filesystem delete in CEL without exposing raw argv matching.
	windowsAddOperation(command, OperationConfigChange)
}

func exactWindowsVSSDeleteAllArguments(args []windowsWord) bool {
	if len(args) != 4 || !strings.EqualFold(args[0].value, "delete") ||
		!strings.EqualFold(args[1].value, "shadows") {
		return false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote != QuoteNone {
			return false
		}
	}
	return strings.EqualFold(args[2].value, "/all") &&
		strings.EqualFold(args[3].value, "/quiet") ||
		strings.EqualFold(args[2].value, "/quiet") &&
			strings.EqualFold(args[3].value, "/all")
}

// ExactWindowsVSSDeleteAllShadows proves one unconditional, top-level
// vssadmin invocation that deletes every shadow copy without prompting.
func ExactWindowsVSSDeleteAllShadows(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD &&
		facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.PipelineID != 0 ||
			command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
			len(command.Redirects) != 0 || !command.ArgvComplete ||
			(command.Program != "vssadmin" && command.Program != "vssadmin.exe") ||
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
		if exactWindowsVSSDeleteAllArguments(args) {
			return true
		}
	}
	return false
}
