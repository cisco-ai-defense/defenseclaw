// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "slices"

// classifyLinuxSecurityControl recognizes only closed, literal forms for
// disabling the Linux audit subsystem, switching SELinux enforcement off, or
// stopping one of a closed set of host security services.
// Other administrative forms remain unsupported rather than inheriting these
// security semantics.
func classifyLinuxSecurityControl(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	disabled, restoration, ok := exactLinuxSecurityControlState(command)
	if !ok {
		out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	addOperation(command, OperationConfigChange)
	if disabled {
		addOperation(command, OperationPolicyBypass)
	}
	if restoration {
		return
	}
}

// ExactLinuxSecurityControlDisable proves one direct, unconditional invocation
// of either `auditctl -e 0`, `setenforce 0`, or `systemctl stop` for a closed
// host firewall/audit service set. Sudo is accepted only as a literal wrapper
// around the exact systemctl form. Status queries, restoration, dynamic
// operands, pipelines, redirects, and conditional execution are excluded.
func ExactLinuxSecurityControlDisable(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if !exactLinuxSecurityControlDisableCommand(command) {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if command.Program != "systemctl" || len(command.Wrappers) != 1 ||
			command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" || len(parent.Argv) != 4 ||
				!slices.Equal(parent.Argv[1:], command.Argv) {
				continue
			}
			return true
		}
	}
	return false
}

func exactLinuxSecurityControlDisableCommand(command CommandFact) bool {
	if command.ControlFlowUncertain || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		!command.ArgvComplete || len(command.Redirects) != 0 ||
		!staticArguments(command.Arguments) ||
		!hasFactOperation(command, OperationConfigChange) ||
		!hasFactOperation(command, OperationPolicyBypass) {
		return false
	}
	disabled, _, ok := exactLinuxSecurityControlState(&command)
	return ok && disabled
}

func exactLinuxSecurityControlState(command *CommandFact) (disabled, restoration, ok bool) {
	if command == nil || len(command.Argv) == 0 {
		return false, false, false
	}
	for _, argument := range command.Arguments {
		if argument.Expands || argument.StaticGlob != "" || argument.Quote != QuoteNone {
			return false, false, false
		}
	}
	switch command.Program {
	case "auditctl":
		if len(command.Argv) != 3 || command.Argv[1] != "-e" {
			return false, false, false
		}
		switch command.Argv[2] {
		case "0":
			return true, false, true
		case "1", "2":
			return false, true, true
		}
	case "setenforce":
		if len(command.Argv) != 2 {
			return false, false, false
		}
		switch command.Argv[1] {
		case "0", "Permissive", "permissive":
			return true, false, true
		case "1", "Enforcing", "enforcing":
			return false, true, true
		}
	case "systemctl":
		if len(command.Argv) != 3 || command.Argv[1] != "stop" {
			return false, false, false
		}
		if exactLinuxSecurityService(command.Argv[2]) {
			return true, false, true
		}
	}
	return false, false, false
}

func exactLinuxSecurityService(value string) bool {
	switch value {
	case "auditd", "auditd.service",
		"firewalld", "firewalld.service",
		"systemd-journald", "systemd-journald.service",
		"ufw", "ufw.service":
		return true
	default:
		return false
	}
}
