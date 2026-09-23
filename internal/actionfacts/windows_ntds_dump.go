// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// windowsClassifyNTDSIFMDump owns one closed ntdsutil Install From Media
// grammar. A full IFM export contains the Active Directory database and
// registry material needed for offline credential extraction.
func windowsClassifyNTDSIFMDump(command *CommandFact, args []windowsWord, builder *windowsFactBuilder) {
	output, ok := exactWindowsNTDSIFMArguments(args)
	if !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationCredentialRead)
	windowsAddOperation(command, OperationWrite)
	builder.addPath(command.ID, PathAccessWrite, output)
}

func exactWindowsNTDSIFMArguments(args []windowsWord) (string, bool) {
	if len(args) != 5 {
		return "", false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain || arg.quote == QuoteMixed {
			return "", false
		}
	}
	activate := strings.ToLower(strings.Join(strings.Fields(args[0].value), " "))
	if activate != "ac i ntds" && activate != "activate instance ntds" {
		return "", false
	}
	if !strings.EqualFold(strings.TrimSpace(args[1].value), "ifm") ||
		!strings.EqualFold(strings.TrimSpace(args[3].value), "q") ||
		!strings.EqualFold(strings.TrimSpace(args[4].value), "q") {
		return "", false
	}
	fields := strings.Fields(strings.TrimSpace(args[2].value))
	if len(fields) != 3 || !strings.EqualFold(fields[0], "create") ||
		!strings.EqualFold(fields[1], "full") {
		return "", false
	}
	output, ok := windowsCanonicalPathFactValue(fields[2])
	if !ok {
		return "", false
	}
	parsed := parseWindowsPath(output)
	if !parsed.absolute || parsed.unresolved {
		return "", false
	}
	return output, true
}

// ExactWindowsNTDSIFMDump proves one unconditional, top-level, static full
// Active Directory IFM export to an absolute destination.
func ExactWindowsNTDSIFMDump(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		(facts.Parse.Dialect != DialectCMD && facts.Parse.Dialect != DialectPowerShell &&
			facts.Parse.Dialect != DialectArgv) || len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || command.Effect != EffectExecute ||
		!command.ArgvComplete || (command.Program != "ntdsutil" && command.Program != "ntdsutil.exe") ||
		!hasFactOperation(command, OperationCredentialRead) ||
		!hasFactOperation(command, OperationWrite) || len(command.Arguments) != 6 {
		return false
	}
	args := make([]windowsWord, 0, 5)
	for _, argument := range command.Arguments[1:] {
		args = append(args, windowsWord{
			value:    argument.Value,
			quote:    argument.Quote,
			expands:  argument.Expands,
			wildcard: argument.StaticGlob != "" || strings.ContainsAny(argument.Value, "*?"),
		})
	}
	_, ok := exactWindowsNTDSIFMArguments(args)
	return ok
}
