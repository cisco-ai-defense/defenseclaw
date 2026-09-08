// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

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
// than the exact journalctl sudo form, pipelines, and conditional execution
// are excluded.
func ExactPOSIXSystemLogDestruction(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if !exactPOSIXSystemLogDestructionCommand(command) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if command.Program != "journalctl" || len(command.Wrappers) != 1 ||
			command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" || len(parent.Argv) != 3 ||
				parent.Argv[1] != "journalctl" ||
				parent.Argv[2] != "--vacuum-time=0" ||
				len(parent.Redirects) != 0 {
				continue
			}
			return true
		}
	}
	return false
}

func exactPOSIXSystemLogDestructionCommand(command CommandFact) bool {
	if command.ControlFlowUncertain || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		!command.ArgvComplete || !staticArguments(command.Arguments) {
		return false
	}
	switch command.Program {
	case "cat", "echo":
		if command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
			len(command.Argv) != 2 || len(command.Redirects) != 1 {
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
		if command.ParentCommandID != 0 || len(command.Wrappers) != 0 ||
			len(command.Redirects) != 0 {
			return false
		}
		return len(command.Argv) == 4 && command.Argv[1] == "-s" &&
			command.Argv[2] == "0" && exactPOSIXSystemLogPath(command.Argv[3]) ||
			len(command.Argv) == 3 && command.Argv[1] == "--size=0" &&
				exactPOSIXSystemLogPath(command.Argv[2])
	case "rm":
		return command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
			len(command.Redirects) == 0 && len(command.Argv) == 3 &&
			(command.Argv[1] == "-rf" || command.Argv[1] == "-fr") &&
			exactPOSIXSystemLogPath(command.Argv[2])
	case "unlink":
		return command.ParentCommandID == 0 && len(command.Wrappers) == 0 &&
			len(command.Redirects) == 0 && len(command.Argv) == 2 &&
			exactPOSIXSystemLogPath(command.Argv[1])
	case "journalctl":
		return len(command.Redirects) == 0 && len(command.Argv) == 2 &&
			command.Argv[1] == "--vacuum-time=0"
	default:
		return false
	}
}

func exactPOSIXSystemLogPath(value string) bool {
	switch value {
	case "/var/log/messages", "/var/log/security", "/var/log/syslog",
		"/var/log/auth.log", "/var/log/secure", "/var/log/audit/audit.log":
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
