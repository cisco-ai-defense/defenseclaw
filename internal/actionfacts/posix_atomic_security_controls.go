// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"path"
	"slices"
	"strings"
)

const (
	posixSecurityStepJournaldStorageNone = "journald-storage-none"
	posixSecurityStepSyslogdStop         = "syslogd-stop"
	posixSecurityStepSyslogdDisable      = "syslogd-disable"
	posixSecurityStepASLRDisable         = "aslr-disable"
	posixSecurityStepPFStop              = "pf-stop"
	posixSecurityStepPFDisable           = "pf-disable"
	posixSecurityStepUFWLoggingOff       = "ufw-logging-off"
)

// classifyPAMPasswordCapture adds security semantics only to the one closed
// stdout-redirect grammar accepted by ExactPAMPasswordCapture. The literal PAM
// line is not retained outside the ordinary, private ActionFacts command.
func classifyPAMPasswordCapture(_ *parseOutput, command *CommandFact) bool {
	if !exactPAMPasswordCaptureGrammar(*command) {
		return false
	}
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

// ExactPAMPasswordCapture proves a single direct echo of a literal PAM session
// entry to one literal file below /etc/pam.d. The entry must enable tty audit
// for every user and log passwords. Pipelines, substitutions, shell wrappers,
// multiple commands, non-stdout redirects, and dynamic paths are excluded.
func ExactPAMPasswordCapture(facts Facts) bool {
	return facts.Authoritative() && len(facts.Commands) == 1 &&
		exactPAMPasswordCaptureCommand(facts.Commands[0]) &&
		hasFactOperation(facts.Commands[0], OperationConfigChange) &&
		hasFactOperation(facts.Commands[0], OperationPolicyBypass)
}

func exactPAMPasswordCaptureCommand(command CommandFact) bool {
	if command.Dialect != DialectPOSIX || command.ControlFlowUncertain ||
		command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		len(command.Wrappers) != 0 {
		return false
	}
	return exactPAMPasswordCaptureGrammar(command)
}

func exactPAMPasswordCaptureGrammar(command CommandFact) bool {
	if command.Dialect != DialectPOSIX ||
		command.Program != "echo" || command.Executable != "echo" ||
		!command.ArgvComplete || len(command.Argv) != 2 ||
		len(command.Arguments) != 2 ||
		len(command.Redirects) != 1 || !staticArguments(command.Arguments) {
		return false
	}
	redirect := command.Redirects[0]
	if redirect.FD != 1 || redirect.Expands ||
		redirect.Access != PathAccessWrite && redirect.Access != PathAccessAppend ||
		!exactPAMConfigurationPath(redirect.Target) {
		return false
	}
	contentArgument := command.Arguments[1]
	if contentArgument.Quote != QuoteSingle && contentArgument.Quote != QuoteDouble {
		return false
	}
	return literalPAMPasswordCaptureEntry(command.Argv[1])
}

func exactPAMConfigurationPath(value string) bool {
	if !staticAbsolutePOSIXPath(value) || path.Clean(value) != value ||
		!strings.HasPrefix(value, "/etc/pam.d/") {
		return false
	}
	name := strings.TrimPrefix(value, "/etc/pam.d/")
	return name != "" && !strings.Contains(name, "/")
}

func literalPAMPasswordCaptureEntry(value string) bool {
	if value == "" || len(value) > 1024 || strings.TrimSpace(value) != value ||
		strings.ContainsAny(value, "\x00\r\n\\#") {
		return false
	}
	fields := strings.Fields(value)
	if len(fields) < 5 || fields[0] != "session" {
		return false
	}
	var module, allUsers, passwordLogging bool
	for _, field := range fields[1:] {
		switch field {
		case "pam_tty_audit.so":
			module = true
		case "enable=*":
			allUsers = true
		case "log_passwd", "log_password":
			passwordLogging = true
		}
	}
	return module && allUsers && passwordLogging
}

// classifyPOSIXLoggingHardeningControl recognizes only the literal command
// steps used by ExactPOSIXLoggingHardeningDisable. Sequence completeness is
// checked by that proof rather than inferred from a nearby product name.
func classifyPOSIXLoggingHardeningControl(_ *parseOutput, command *CommandFact) bool {
	if command == nil || !staticArguments(command.Arguments) {
		return false
	}
	if _, ok := exactPOSIXLoggingHardeningArgvStep(*command); !ok {
		return false
	}
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

// ExactPOSIXLoggingHardeningDisable proves one of five source-supported closed
// operations: journald persistent storage disabled, FreeBSD syslogd stopped and
// disabled, ASLR disabled, pf stopped and disabled, or UFW logging disabled.
// Each top-level step must belong to the selected proof. A literal sudo is the
// only accepted wrapper.
func ExactPOSIXLoggingHardeningDisable(facts Facts) bool {
	if !facts.Authoritative() || len(facts.Commands) == 0 {
		return false
	}
	steps := make([]string, 0, 2)
	for _, command := range facts.Commands {
		if command.ParentCommandID != 0 {
			continue
		}
		step, ok := exactPOSIXLoggingHardeningTopLevelStep(facts, command)
		if !ok {
			return false
		}
		steps = append(steps, step)
	}
	switch {
	case slices.Equal(steps, []string{posixSecurityStepJournaldStorageNone}):
		return true
	case slices.Equal(steps, []string{posixSecurityStepSyslogdStop, posixSecurityStepSyslogdDisable}):
		return true
	case slices.Equal(steps, []string{posixSecurityStepASLRDisable}):
		return true
	case slices.Equal(steps, []string{posixSecurityStepPFStop, posixSecurityStepPFDisable}):
		return true
	case slices.Equal(steps, []string{posixSecurityStepUFWLoggingOff}):
		return true
	default:
		return false
	}
}

func exactPOSIXLoggingHardeningTopLevelStep(facts Facts, command CommandFact) (string, bool) {
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) {
		return "", false
	}
	if command.Program != "sudo" {
		return exactPOSIXLoggingHardeningCommandStep(command)
	}
	if len(command.Argv) < 2 {
		return "", false
	}
	var matched string
	for _, child := range facts.Commands {
		if child.ParentCommandID != command.ID {
			continue
		}
		if matched != "" || len(child.Wrappers) != 1 ||
			child.Wrappers[0].Executable != "sudo" ||
			!slices.Equal(command.Argv[1:], child.Argv) {
			return "", false
		}
		step, ok := exactPOSIXLoggingHardeningCommandStep(child)
		if !ok {
			return "", false
		}
		matched = step
	}
	return matched, matched != ""
}

func exactPOSIXLoggingHardeningCommandStep(command CommandFact) (string, bool) {
	if command.Dialect != DialectPOSIX || command.ControlFlowUncertain ||
		command.PipelineID != 0 || command.Kind != CommandKindProcess ||
		command.Effect != EffectExecute || !command.ArgvComplete ||
		len(command.Redirects) != 0 || !staticArguments(command.Arguments) {
		return "", false
	}
	return exactPOSIXLoggingHardeningArgvStep(command)
}

func exactPOSIXLoggingHardeningArgvStep(command CommandFact) (string, bool) {
	switch command.Program {
	case "sed":
		if slices.Equal(command.Argv, []string{
			"sed", "-i", "s/Storage=auto/Storage=none/", "/etc/systemd/journald.conf",
		}) || slices.Equal(command.Argv, []string{
			"sed", "--in-place", "s/Storage=auto/Storage=none/", "/etc/systemd/journald.conf",
		}) {
			return posixSecurityStepJournaldStorageNone, true
		}
	case "service":
		switch {
		case slices.Equal(command.Argv, []string{"service", "syslogd", "stop"}):
			return posixSecurityStepSyslogdStop, true
		case slices.Equal(command.Argv, []string{"service", "pf", "stop"}):
			return posixSecurityStepPFStop, true
		case slices.Equal(command.Argv, []string{"service", "pf", "disable"}):
			return posixSecurityStepPFDisable, true
		}
	case "sysrc":
		if slices.Equal(command.Argv, []string{"sysrc", "syslogd_enable=NO"}) {
			return posixSecurityStepSyslogdDisable, true
		}
	case "sysctl":
		if slices.Equal(command.Argv, []string{"sysctl", "-w", "kernel.randomize_va_space=0"}) {
			return posixSecurityStepASLRDisable, true
		}
	case "ufw":
		if slices.Equal(command.Argv, []string{"ufw", "logging", "off"}) {
			return posixSecurityStepUFWLoggingOff, true
		}
	}
	return "", false
}
