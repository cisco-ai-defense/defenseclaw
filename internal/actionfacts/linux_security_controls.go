// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"strings"
)

// classifyLinuxSecurityControl recognizes only closed, literal forms for
// disabling the Linux audit subsystem, deleting audit policy, switching
// SELinux enforcement off, or stopping one of a closed set of host security
// services.
// Other administrative forms remain unsupported rather than inheriting these
// security semantics.
func classifyLinuxSecurityControl(out *parseOutput, command *CommandFact) {
	if !requireCommandDialect(out, command, DialectPOSIX, DialectArgv) {
		return
	}
	// The legacy service grammar is shell-owned. Do not infer it from a
	// connector-supplied argv vector, where platform and wrapper semantics are
	// not established by the POSIX parser.
	if command.Program == "service" && out.dialect != DialectPOSIX {
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
// of either `auditctl -e 0`, a closed auditctl rule deletion, `setenforce 0`,
// `systemctl stop` for a closed host firewall/audit service set, or the legacy
// POSIX form `service auditd stop`.
// Sudo is accepted only as a literal wrapper around an exact service-manager
// form. Status queries, restoration, dynamic operands, pipelines, redirects,
// and conditional execution are excluded.
func ExactLinuxSecurityControlDisable(facts Facts) bool {
	if facts.Parse.Dialect != DialectPOSIX && facts.Parse.Dialect != DialectArgv {
		return false
	}
	for _, command := range facts.Commands {
		if !exactLinuxSecurityControlDisableCommand(command) {
			continue
		}
		if command.Program == "service" && facts.Parse.Dialect != DialectPOSIX {
			continue
		}
		if command.ParentCommandID == 0 && len(command.Wrappers) == 0 {
			return true
		}
		if (command.Program != "auditctl" && command.Program != "systemctl" &&
			command.Program != "service") || len(command.Wrappers) != 1 ||
			command.Wrappers[0].Executable != "sudo" {
			continue
		}
		for _, parent := range facts.Commands {
			if parent.ID != command.ParentCommandID ||
				!exactUnconditionalTopLevelCommand(parent) ||
				!parent.ArgvComplete || !staticArguments(parent.Arguments) ||
				parent.Program != "sudo" ||
				len(parent.Argv) != len(command.Argv)+1 ||
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
		if len(command.Argv) == 2 && command.Argv[1] == "-D" {
			return true, false, true
		}
		if exactAuditctlRuleDelete(command.Argv) {
			return true, false, true
		}
		if len(command.Argv) == 3 && command.Argv[1] == "-e" {
			switch command.Argv[2] {
			case "0":
				return true, false, true
			case "1", "2":
				return false, true, true
			}
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
	case "service":
		if len(command.Argv) == 3 && command.Argv[1] == "auditd" &&
			command.Argv[2] == "stop" {
			return true, false, true
		}
	}
	return false, false, false
}

func exactAuditctlRuleDelete(argv []string) bool {
	if len(argv) < 3 || len(argv) > 32 || argv[0] != "auditctl" || argv[1] != "-d" {
		return false
	}
	list, action, ok := strings.Cut(argv[2], ",")
	if !ok || !slices.Contains([]string{
		"task", "exit", "user", "exclude", "filesystem", "io_uring",
	}, list) || !slices.Contains([]string{"never", "always"}, action) {
		return false
	}
	for index := 3; index < len(argv); index++ {
		switch argv[index] {
		case "-F", "-S", "-C", "-k":
			index++
			if index >= len(argv) || argv[index] == "" || strings.HasPrefix(argv[index], "-") {
				return false
			}
		default:
			return false
		}
	}
	return true
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
