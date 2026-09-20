// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

// ExactWindowsSecurityControlMutations returns validated, value-free command
// facts. The parser must have proved the complete input authoritative, and the
// individual mutation must come from a direct, unconditional static command.
func ExactWindowsSecurityControlMutations(facts Facts) []WindowsSecurityControlMutationFact {
	if !facts.Authoritative() {
		return nil
	}
	result := make([]WindowsSecurityControlMutationFact, 0, len(facts.WindowsSecurityControlMutations))
	for _, fact := range facts.WindowsSecurityControlMutations {
		if fact.CommandID <= 0 || !fact.Exact || !validWindowsSecurityControlMutation(fact.Operation) {
			continue
		}
		result = append(result, fact)
	}
	return result
}

// ExactWindowsSecurityControlMutation reports whether the authoritative action
// contains one requested mutation from the closed vocabulary.
func ExactWindowsSecurityControlMutation(facts Facts, operation WindowsSecurityControlMutation) bool {
	if !validWindowsSecurityControlMutation(operation) {
		return false
	}
	for _, fact := range ExactWindowsSecurityControlMutations(facts) {
		if fact.Operation == operation {
			return true
		}
	}
	return false
}

func validWindowsSecurityControlMutation(operation WindowsSecurityControlMutation) bool {
	switch operation {
	case WindowsDefenderExecutableExtensionExclusion,
		WindowsDefenderDriveRootExclusion,
		WindowsAuditDetailedTrackingFailureDisable,
		WindowsAuditProcessCreationSuccessDisable,
		WindowsAuditFullPrivilegeDisable:
		return true
	default:
		return false
	}
}

func projectWindowsSecurityControlMutations(facts Facts) []WindowsSecurityControlMutationFact {
	if !facts.Authoritative() {
		return nil
	}
	result := make([]WindowsSecurityControlMutationFact, 0, len(facts.Commands))
	for _, command := range facts.Commands {
		if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
			!staticWindowsSecurityControlArguments(command.Arguments) {
			continue
		}
		operation, ok := exactWindowsSecurityControlMutationCommand(command)
		if !ok {
			continue
		}
		result = append(result, WindowsSecurityControlMutationFact{
			CommandID: command.ID,
			Operation: operation,
			Exact:     true,
		})
	}
	return result
}

// classifyExactWindowsSecurityControlMutation exposes only the generic
// config-change and policy-bypass semantics to CEL. The semantic owner still
// requires the exact closed mutation fact before the CEL candidate may run.
func classifyExactWindowsSecurityControlMutation(command *CommandFact) bool {
	if command == nil || !command.ArgvComplete ||
		!staticWindowsSecurityControlArguments(command.Arguments) {
		return false
	}
	if _, ok := exactWindowsSecurityControlMutationCommand(*command); !ok {
		return false
	}
	addOperation(command, OperationConfigChange)
	addOperation(command, OperationPolicyBypass)
	return true
}

func staticWindowsSecurityControlArguments(arguments []ArgumentFact) bool {
	if !staticArguments(arguments) {
		return false
	}
	for _, argument := range arguments {
		if argument.Quote == QuoteMixed {
			return false
		}
	}
	return true
}

func exactWindowsSecurityControlMutationCommand(command CommandFact) (WindowsSecurityControlMutation, bool) {
	if len(command.Argv) == 0 {
		return "", false
	}
	switch command.Program {
	case "add-mppreference":
		if command.Dialect != DialectPowerShell {
			return "", false
		}
		if exactPowerShellPreferenceValue(command.Argv[1:], "-exclusionextension", ".exe") {
			return WindowsDefenderExecutableExtensionExclusion, true
		}
	case "set-mppreference":
		if command.Dialect != DialectPowerShell {
			return "", false
		}
		value, ok := exactPowerShellPreferenceArgument(command.Argv[1:], "-exclusionpath")
		if ok && exactWindowsDriveRoot(value) {
			return WindowsDefenderDriveRootExclusion, true
		}
	case "auditpol", "auditpol.exe":
		if command.Dialect != DialectCMD && command.Dialect != DialectPowerShell &&
			command.Dialect != DialectArgv {
			return "", false
		}
		return exactWindowsAuditSetMutation(command.Argv[1:])
	}
	return "", false
}

func exactPowerShellPreferenceValue(argv []string, parameter, expected string) bool {
	value, ok := exactPowerShellPreferenceArgument(argv, parameter)
	return ok && strings.EqualFold(value, expected)
}

// exactPowerShellPreferenceArgument accepts exactly one named value and an
// optional -Force switch. Abbreviations, duplicate parameters, positional
// values, arrays, and additional options deliberately abstain.
func exactPowerShellPreferenceArgument(argv []string, parameter string) (string, bool) {
	if len(argv) != 2 && len(argv) != 3 {
		return "", false
	}
	var value string
	seenForce := false
	for index := 0; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		switch option {
		case parameter:
			if value != "" || index+1 >= len(argv) {
				return "", false
			}
			index++
			value = argv[index]
			if value == "" {
				return "", false
			}
		case "-force":
			if seenForce {
				return "", false
			}
			seenForce = true
		default:
			return "", false
		}
	}
	return value, value != ""
}

func exactWindowsDriveRoot(value string) bool {
	return len(value) == 3 &&
		((value[0] >= 'A' && value[0] <= 'Z') || (value[0] >= 'a' && value[0] <= 'z')) &&
		value[1] == ':' && (value[2] == '\\' || value[2] == '/')
}

func exactWindowsAuditSetMutation(argv []string) (WindowsSecurityControlMutation, bool) {
	if len(argv) != 3 || !strings.EqualFold(argv[0], "/set") {
		return "", false
	}
	first := strings.ToLower(argv[1])
	second := strings.ToLower(argv[2])
	if first > second {
		first, second = second, first
	}
	switch {
	case first == "/category:detailed tracking" && second == "/failure:disable":
		return WindowsAuditDetailedTrackingFailureDisable, true
	case first == "/subcategory:{0cce922b-69ae-11d9-bed3-505054503030}" &&
		second == "/success:disable":
		return WindowsAuditProcessCreationSuccessDisable, true
	case first == "/option:fullprivilegeauditing" && second == "/value:disable":
		return WindowsAuditFullPrivilegeDisable, true
	default:
		return "", false
	}
}
