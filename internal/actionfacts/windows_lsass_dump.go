// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// windowsClassifyLSASSDump owns only a static ProcDump invocation whose target
// is LSASS and whose output is an absolute .dmp path. Other process dumps stay
// partial: process-memory collection is dual-use, while LSASS memory contains
// reusable authentication material.
func windowsClassifyLSASSDump(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	output, ok := exactWindowsProcDumpLSASSArguments(args)
	if !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationCredentialRead)
	windowsAddOperation(command, OperationWrite)
	builder.addPath(command.ID, PathAccessWrite, output)
}

func exactWindowsProcDumpLSASSArguments(args []windowsWord) (string, bool) {
	if len(args) < 3 || len(args) > 4 {
		return "", false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote == QuoteMixed {
			return "", false
		}
	}
	index := 0
	if strings.EqualFold(args[index].value, "-accepteula") {
		if args[index].quote != QuoteNone {
			return "", false
		}
		index++
	}
	if len(args)-index != 3 || args[index].quote != QuoteNone ||
		(!strings.EqualFold(args[index].value, "-ma") &&
			!strings.EqualFold(args[index].value, "-mm")) ||
		args[index+1].quote != QuoteNone ||
		(!strings.EqualFold(args[index+1].value, "lsass") &&
			!strings.EqualFold(args[index+1].value, "lsass.exe")) {
		return "", false
	}
	output, ok := windowsCanonicalPathFactValue(args[index+2].value)
	if !ok || !strings.HasSuffix(strings.ToLower(output), ".dmp") {
		return "", false
	}
	parsed := parseWindowsPath(output)
	if !parsed.absolute || parsed.unresolved {
		return "", false
	}
	return output, true
}

// ExactWindowsLSASSMemoryDump proves one unconditional, top-level ProcDump
// command with a literal LSASS target and exact absolute dump destination.
func ExactWindowsLSASSMemoryDump(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD &&
		facts.Parse.Dialect != DialectPowerShell &&
		facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 || command.PipelineID != 0 ||
			command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
			len(command.Redirects) != 0 || command.Effect != EffectExecute ||
			!command.ArgvComplete ||
			(command.Program != "procdump" && command.Program != "procdump.exe") ||
			!hasFactOperation(command, OperationCredentialRead) ||
			!hasFactOperation(command, OperationWrite) ||
			len(command.Arguments) < 4 || len(command.Arguments) > 5 {
			continue
		}
		args := make([]windowsWord, 0, len(command.Arguments)-1)
		for _, argument := range command.Arguments[1:] {
			args = append(args, windowsWord{
				value:    argument.Value,
				quote:    argument.Quote,
				expands:  argument.Expands,
				wildcard: argument.StaticGlob != "" || strings.ContainsAny(argument.Value, "*?"),
			})
		}
		if _, ok := exactWindowsProcDumpLSASSArguments(args); ok {
			return true
		}
	}
	return false
}

// ExactWindowsLSASSMemoryDumpDetection accepts the enforceable ProcDump proof
// above plus two bounded PowerShell subgraphs whose process identity is exact:
// Comsvcs MiniDump with an inline Get-Process LSASS PID, and Get-Process LSASS
// piped directly to Out-Minidump. These additional forms are detection-only
// because their output path or imported function authority may be dynamic.
func ExactWindowsLSASSMemoryDumpDetection(facts Facts) bool {
	if ExactWindowsLSASSMemoryDump(facts) || facts.Parse.Dialect != DialectPowerShell {
		return ExactWindowsLSASSMemoryDump(facts)
	}
	for _, command := range facts.Commands {
		if exactWindowsComsvcsLSASSDump(command) {
			return true
		}
	}
	for _, source := range facts.Commands {
		if source.Program != "get-process" || source.PipelineID == 0 ||
			source.ParentCommandID != 0 || source.ControlFlowUncertain ||
			source.Effect != EffectExecute || !source.ArgvComplete ||
			len(source.Argv) != 2 || !strings.EqualFold(source.Argv[1], "lsass") ||
			!staticArguments(source.Arguments) {
			continue
		}
		for _, sink := range facts.Commands {
			if sink.Program != "out-minidump" || sink.PipelineID != source.PipelineID ||
				sink.ParentCommandID != 0 || sink.ControlFlowUncertain ||
				sink.Effect != EffectExecute || !sink.ArgvComplete ||
				len(sink.Argv) != 1 || !staticArguments(sink.Arguments) {
				continue
			}
			for _, flow := range facts.DataFlows {
				if flow.FromCommandID == source.ID && flow.ToCommandID == sink.ID &&
					flow.From == DataStdout && flow.To == DataStdin {
					return true
				}
			}
		}
	}
	return false
}

func exactWindowsComsvcsLSASSDump(command CommandFact) bool {
	if command.Program != "rundll32" && command.Program != "rundll32.exe" ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || len(command.Arguments) != 7 {
		return false
	}
	arguments := command.Arguments
	for index, argument := range arguments {
		if argument.StaticGlob != "" || argument.Quote == QuoteMixed ||
			argument.Expands && index != 5 {
			return false
		}
	}
	library := strings.ToLower(strings.ReplaceAll(arguments[1].Value, `\`, "/"))
	output := strings.ToLower(arguments[5].Value)
	return strings.HasSuffix(library, "/comsvcs.dll,") &&
		strings.EqualFold(arguments[2].Value, "MiniDump") &&
		strings.EqualFold(arguments[3].Value, "(Get-Process") &&
		strings.EqualFold(arguments[4].Value, "lsass).id") &&
		strings.HasSuffix(output, ".dmp") &&
		strings.EqualFold(arguments[6].Value, "full")
}
