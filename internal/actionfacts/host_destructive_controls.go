// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "slices"

func classifyPOSIXHostHalt(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if command.ArgvComplete && len(command.Argv) == 2 &&
		staticArguments(command.Arguments) &&
		(command.Argv[1] == "-p" || command.Argv[1] == "-r") {
		addOperation(command, OperationConfigChange)
		return
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

// classifyMacOSUnifiedLog owns only the closed destructive form of the macOS
// unified logging CLI. Other `log` subcommands remain unsupported because
// their argument grammars are unrelated to this proof.
func classifyMacOSUnifiedLog(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	if exactMacOSUnifiedLogEraseArgv(command.Argv) &&
		staticArguments(command.Arguments) {
		addOperation(command, OperationDelete)
		addOperation(command, OperationPolicyBypass)
		return
	}
	out.markPartial(IssueUnknownOperandGrammar)
}

// ExactMacOSUnifiedLogErase proves one direct `log erase --all` invocation or
// the same exact invocation through sudo. Queries, TTL-only maintenance,
// dynamic arguments, wrappers, redirects, pipelines, and conditional commands
// are rejected.
func ExactMacOSUnifiedLogErase(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if command.Program != "log" || !command.ArgvComplete ||
			!staticArguments(command.Arguments) ||
			!exactMacOSUnifiedLogEraseArgv(command.Argv) ||
			command.ControlFlowUncertain || command.PipelineID != 0 ||
			command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
			len(command.Redirects) != 0 {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if len(command.Wrappers) != 1 || command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" || len(parent.Argv) != 4 ||
				parent.Argv[1] != "log" ||
				!exactMacOSUnifiedLogEraseArgv(parent.Argv[1:]) {
				continue
			}
			return true
		}
	}
	return false
}

func exactMacOSUnifiedLogEraseArgv(argv []string) bool {
	return len(argv) == 3 && argv[0] == "log" && argv[1] == "erase" &&
		argv[2] == "--all"
}

// ExactLinuxMagicSysRqDestruction proves a literal write of one destructive
// Magic SysRq key to the kernel trigger. The bounded key set covers immediate
// reboot, poweroff, crash, and process-wide TERM/KILL. Merely enabling SysRq,
// writing a non-destructive key, or using dynamic shell data is not enough.
func ExactLinuxMagicSysRqDestruction(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX {
		return false
	}
	for _, command := range facts.Commands {
		if exactLinuxMagicSysRqCommand(command) {
			return true
		}
	}
	return false
}

func exactLinuxMagicSysRqCommand(command CommandFact) bool {
	if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
		command.PipelineID != 0 || command.Kind != CommandKindProcess ||
		command.Effect != EffectExecute || command.Program != "echo" ||
		!command.ArgvComplete || len(command.Wrappers) != 0 ||
		len(command.Argv) != 2 || !staticArguments(command.Arguments) ||
		len(command.Redirects) != 1 {
		return false
	}
	switch command.Argv[1] {
	case "b", "o", "c", "e", "i":
	default:
		return false
	}
	redirect := command.Redirects[0]
	return !redirect.Expands && redirect.FD == 1 &&
		redirect.Access == PathAccessWrite &&
		redirect.Target == "/proc/sysrq-trigger"
}

// ExactPOSIXHostHalt proves one direct halt invocation that requests either a
// power-off or reboot. A bare halt, generic shutdown/reboot aliases, delayed
// forms, wrappers, redirects, pipelines, and conditional execution are not
// included because the available public benign corpus collides on those wider
// command families.
func ExactPOSIXHostHalt(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
			command.PipelineID != 0 || command.Kind != CommandKindProcess ||
			(command.Effect != EffectExecute && command.Effect != EffectUncertain) ||
			command.Program != "halt" || !command.ArgvComplete ||
			len(command.Wrappers) != 0 || len(command.Argv) != 2 ||
			!staticArguments(command.Arguments) || len(command.Redirects) != 0 {
			continue
		}
		if command.Argv[1] == "-p" || command.Argv[1] == "-r" {
			return true
		}
	}
	return false
}

// ExactPOSIXSystemLogDestruction proves one closed, literal operation that
// destroys a canonical host security log. Application logs, rotated logs,
// dynamic paths, append operations, bounded journal vacuuming, wrappers other
// than exact option-free sudo, pipelines, and conditional execution are
// excluded. Stderr may be redirected only to /dev/null. Two additional closed
// forms are accepted: an exact destructive operation followed only by literal
// `true` (failure suppression does not make the first operation conditional),
// and an immutable-bit removal followed by truncation of the same observed
// rotated audit log.
func ExactPOSIXSystemLogDestruction(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	if exactPOSIXSystemLogDestructionIgnoringFailure(facts) ||
		exactRotatedAuditLogUnlockTruncate(facts) {
		return true
	}
	for _, command := range facts.Commands {
		if exactJournalWildcardDelete(command) {
			return true
		}
		if !exactPOSIXSystemLogDestructionCommand(command) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if exactPOSIXSystemLogShellWrapper(facts, command) {
			return true
		}
		if len(command.Wrappers) != 1 ||
			command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				parent.ControlFlowUncertain || parent.ParentCommandID != 0 ||
				parent.PipelineID != 0 || parent.Kind != CommandKindProcess ||
				parent.Effect != EffectExecute || len(parent.Wrappers) != 0 ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" ||
				len(parent.Argv) != len(command.Argv)+1 ||
				!slices.Equal(parent.Argv[1:], command.Argv) ||
				!onlyDiscardedStderr(parent.Redirects) {
				continue
			}
			return true
		}
	}
	return false
}

func exactPOSIXSystemLogDestructionIgnoringFailure(facts Facts) bool {
	var topLevel []int
	for index, command := range facts.Commands {
		if command.ParentCommandID == 0 {
			topLevel = append(topLevel, index)
		}
	}
	if len(topLevel) != 2 {
		return false
	}
	first := facts.Commands[topLevel[0]]
	last := facts.Commands[topLevel[1]]
	if first.PipelineID != 0 || !first.ControlFlowUncertain ||
		last.PipelineID != 0 || !last.ControlFlowUncertain ||
		last.Kind != CommandKindProcess || last.Effect != EffectExecute ||
		last.Program != "true" || !last.ArgvComplete || len(last.Argv) != 1 ||
		len(last.Wrappers) != 0 || len(last.Redirects) != 0 ||
		!staticArguments(last.Arguments) {
		return false
	}
	// The parser marks both sides of &&/|| uncertain. The first side is always
	// attempted for either operator; accepting it is safe only when the entire
	// top-level suffix is the literal no-op above.
	projected := facts
	projected.Commands = append([]CommandFact(nil), facts.Commands...)
	projected.Commands[topLevel[0]].ControlFlowUncertain = false
	return exactPOSIXSystemLogDestructionWithoutSuppression(projected)
}

func exactPOSIXSystemLogDestructionWithoutSuppression(facts Facts) bool {
	for _, command := range facts.Commands {
		if !exactPOSIXSystemLogDestructionCommand(command) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if len(command.Wrappers) != 1 || command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID == command.ParentCommandID {
				parent.ControlFlowUncertain = false
			}
			if parent.ID != command.ParentCommandID ||
				parent.ControlFlowUncertain || parent.ParentCommandID != 0 ||
				parent.PipelineID != 0 || parent.Kind != CommandKindProcess ||
				parent.Effect != EffectExecute || len(parent.Wrappers) != 0 ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" ||
				len(parent.Argv) != len(command.Argv)+1 ||
				!slices.Equal(parent.Argv[1:], command.Argv) ||
				!onlyDiscardedStderr(parent.Redirects) {
				continue
			}
			return true
		}
	}
	return false
}

func exactRotatedAuditLogUnlockTruncate(facts Facts) bool {
	if len(facts.Commands) != 2 {
		return false
	}
	unlock, truncate := facts.Commands[0], facts.Commands[1]
	const rotatedAuditLog = "/var/log/audit/audit.log.1"
	if unlock.ControlFlowUncertain || unlock.ParentCommandID != 0 ||
		unlock.PipelineID != 0 || unlock.Kind != CommandKindProcess ||
		unlock.Effect != EffectExecute || len(unlock.Wrappers) != 0 ||
		unlock.Program != "chattr" || !unlock.ArgvComplete ||
		len(unlock.Argv) != 3 || unlock.Argv[1] != "-i" ||
		unlock.Argv[2] != rotatedAuditLog ||
		!staticArguments(unlock.Arguments) || !onlyDiscardedStderr(unlock.Redirects) {
		return false
	}
	return !truncate.ControlFlowUncertain && truncate.ParentCommandID == 0 &&
		truncate.PipelineID == 0 && truncate.Kind == CommandKindProcess &&
		truncate.Effect == EffectExecute && len(truncate.Wrappers) == 0 &&
		truncate.Program == "truncate" && truncate.ArgvComplete &&
		len(truncate.Argv) == 4 && truncate.Argv[1] == "-s" &&
		truncate.Argv[2] == "0" && truncate.Argv[3] == rotatedAuditLog &&
		staticArguments(truncate.Arguments) && onlyDiscardedStderr(truncate.Redirects)
}

func exactPOSIXSystemLogShellWrapper(facts Facts, command CommandFact) bool {
	if len(command.Wrappers) != 1 || command.ParentCommandID == 0 {
		return false
	}
	wrapper := command.Wrappers[0]
	if wrapper.Executable != "sh" && wrapper.Executable != "/bin/sh" &&
		wrapper.Executable != "bash" && wrapper.Executable != "/bin/bash" {
		return false
	}
	for _, parent := range facts.Commands {
		if parent.ID != command.ParentCommandID ||
			!exactUnconditionalTopLevelCommand(parent) ||
			(parent.Program != "sh" && parent.Program != "bash") ||
			!parent.ArgvComplete || len(parent.Argv) != 3 ||
			parent.Argv[1] != "-c" || !staticArguments(parent.Arguments) ||
			len(parent.Redirects) != 0 || !slices.Equal(wrapper.Argv, parent.Argv) {
			continue
		}
		return true
	}
	return false
}

func exactJournalWildcardDelete(command CommandFact) bool {
	if command.ControlFlowUncertain || command.ParentCommandID != 0 ||
		command.PipelineID != 0 || command.Kind != CommandKindProcess ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 {
		return false
	}
	arguments := command.Arguments
	if command.Program == "sudo" {
		if len(arguments) != 4 || arguments[0].Value != "sudo" ||
			arguments[1].Value != "rm" || arguments[2].Value != "-f" {
			return false
		}
	} else if command.Program == "rm" {
		if len(arguments) != 3 || arguments[0].Value != "rm" ||
			arguments[1].Value != "-f" {
			return false
		}
	} else {
		return false
	}
	target := arguments[len(arguments)-1]
	return target.Expands && target.Value == "" &&
		target.StaticGlob == "/var/log/journal/*/system.journal"
}

func exactPOSIXSystemLogDestructionCommand(command CommandFact) bool {
	if command.ControlFlowUncertain || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		!command.ArgvComplete {
		return false
	}
	switch command.Program {
	case "cat", "echo":
		if command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
			len(command.Argv) != 2 || len(command.Redirects) != 1 ||
			!staticArguments(command.Arguments) {
			return false
		}
		if command.Program == "cat" &&
			command.Argv[1] != "/dev/null" && command.Argv[1] != "/dev/zero" {
			return false
		}
		if command.Program == "echo" && command.Argv[1] != "" {
			return false
		}
		redirect := command.Redirects[0]
		return !redirect.Expands && redirect.FD == 1 &&
			redirect.Access == PathAccessWrite &&
			exactPOSIXSystemLogPath(redirect.Target)
	case "truncate":
		if !staticArguments(command.Arguments) ||
			!onlyDiscardedStderr(command.Redirects) {
			return false
		}
		var targets []string
		switch {
		case len(command.Argv) >= 4 && command.Argv[1] == "-s" && command.Argv[2] == "0":
			targets = command.Argv[3:]
		case len(command.Argv) >= 3 && command.Argv[1] == "--size=0":
			targets = command.Argv[2:]
		default:
			return false
		}
		for _, target := range targets {
			if !exactPOSIXSystemLogPath(target) {
				return false
			}
		}
		return len(targets) != 0
	case "rm":
		if !onlyDiscardedStderr(command.Redirects) || len(command.Argv) < 3 {
			return false
		}
		if (command.Argv[1] == "-rf" || command.Argv[1] == "-fr") &&
			staticArguments(command.Arguments) {
			for _, target := range command.Argv[2:] {
				if !exactPOSIXSystemLogPath(target) {
					return false
				}
			}
			return true
		}
		return len(command.Argv) == 3 && command.Argv[1] == "-f" &&
			command.Argv[2] == "/var/log/journal/*/system.journal"
	case "unlink":
		return command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
			len(command.Redirects) == 0 && len(command.Argv) == 2 &&
			staticArguments(command.Arguments) &&
			exactPOSIXSystemLogPath(command.Argv[1])
	case "journalctl":
		return staticArguments(command.Arguments) &&
			onlyDiscardedStderr(command.Redirects) && len(command.Argv) == 2 &&
			command.Argv[1] == "--vacuum-time=0"
	default:
		return false
	}
}

func onlyDiscardedStderr(redirects []RedirectFact) bool {
	for _, redirect := range redirects {
		if redirect.Expands || redirect.FD != 2 ||
			redirect.Access != PathAccessWrite || redirect.Target != "/dev/null" {
			return false
		}
	}
	return true
}

func exactPOSIXSystemLogPath(value string) bool {
	switch value {
	case "/var/log/messages", "/var/log/security", "/var/log/syslog",
		"/var/log/auth.log", "/var/log/auth.log/current.log", "/var/log/secure",
		"/var/log/audit/audit.log", "/var/log/wtmp":
		return true
	default:
		return false
	}
}

func staticArguments(arguments []ArgumentFact) bool {
	for _, argument := range arguments {
		if argument.Expands || argument.StaticGlob != "" {
			return false
		}
	}
	return true
}
