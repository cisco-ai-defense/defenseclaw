// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const windowsIFEORegistryPrefix = "HKLM/SOFTWARE/MICROSOFT/WINDOWS NT/CURRENTVERSION/IMAGE FILE EXECUTION OPTIONS/"

// ProvesWindowsAccessibilityFeatureHijack recognizes only a complete,
// enforcement-eligible mutation that redirects a Windows accessibility
// executable to the system command interpreter. It intentionally excludes
// ownership/ACL preparation, trigger-only actions, backups/restores, and link
// commands whose source/target relationship ActionFacts cannot yet project
// authoritatively.
func ProvesWindowsAccessibilityFeatureHijack(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		(facts.Parse.Dialect != DialectCMD &&
			facts.Parse.Dialect != DialectPowerShell &&
			facts.Parse.Dialect != DialectArgv) ||
		len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if !exactTopLevelWindowsAccessibilityMutation(command) {
		return false
	}
	return exactWindowsAccessibilityDebuggerHijack(command) ||
		exactWindowsAccessibilityBinaryReplacement(command)
}

func exactTopLevelWindowsAccessibilityMutation(command CommandFact) bool {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || !command.ArgvComplete ||
		command.Effect != EffectExecute || !staticArguments(command.Arguments) ||
		len(command.Argv) != len(command.Arguments) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return false
		}
	}
	return true
}

func exactWindowsAccessibilityDebuggerHijack(command CommandFact) bool {
	mutation, ok := exactWindowsAtomicRegistryMutation(command)
	if !ok || mutation.name != "DEBUGGER" ||
		mutation.valueType != "REG_SZ" && mutation.valueType != "STRING" &&
			mutation.valueType != "" ||
		!strings.HasPrefix(mutation.path, windowsIFEORegistryPrefix) {
		return false
	}
	target := mutation.path[len(windowsIFEORegistryPrefix):]
	return !strings.Contains(target, "/") &&
		exactWindowsAccessibilityExecutable(target) &&
		exactWindowsSystemCommandInterpreter(mutation.value)
}

// powerShellCopyOperands reads the arguments of a Copy-Item call by parameter
// name: positional words fill -Path then -Destination; -Force is the only
// other word allowed. It returns the source and destination.
func powerShellCopyOperands(args []string) ([]string, bool) {
	var source, destination string
	positional := []*string{&source, &destination}
	for index := 0; index < len(args); index++ {
		word := args[index]
		lower := strings.ToLower(word)
		switch {
		case lower == "-force":
		case len(lower) >= 2 && strings.HasPrefix("-path", lower) || lower == "-literalpath":
			if index+1 >= len(args) || source != "" {
				return nil, false
			}
			index++
			source = args[index]
		case len(lower) >= 4 && strings.HasPrefix("-destination", lower):
			if index+1 >= len(args) || destination != "" {
				return nil, false
			}
			index++
			destination = args[index]
		case strings.HasPrefix(word, "-"):
			return nil, false
		default:
			if len(positional) == 0 {
				return nil, false
			}
			for len(positional) > 0 && *positional[0] != "" {
				positional = positional[1:]
			}
			if len(positional) == 0 {
				return nil, false
			}
			*positional[0] = word
			positional = positional[1:]
		}
	}
	if source == "" || destination == "" {
		return nil, false
	}
	return []string{source, destination}, true
}

func exactWindowsAccessibilityBinaryReplacement(command CommandFact) bool {
	if !hasFactOperation(command, OperationCopy) {
		return false
	}
	argv := command.Argv
	switch {
	case command.Dialect == DialectCMD && command.Program == "copy":
		if len(argv) == 4 {
			if !strings.EqualFold(argv[1], "/y") {
				return false
			}
			argv = append(argv[:1:1], argv[2:]...)
		}
	case command.Dialect == DialectPowerShell &&
		(command.Program == "copy-item" || command.Program == "copy" || command.Program == "cp"):
		// The PowerShell spelling of the same replacement: Copy-Item SRC DST,
		// optionally -Force, with the source and destination positional or
		// named (-Path, -Destination) in any order. (cmd's copy /Y is not a
		// Copy-Item parameter.)
		named, ok := powerShellCopyOperands(argv[1:])
		if !ok {
			return false
		}
		argv = append(argv[:1:1], named...)
	default:
		return false
	}
	if len(argv) != 3 {
		return false
	}
	return exactWindowsSystemCommandInterpreter(argv[1]) &&
		exactWindowsProtectedAccessibilityPath(argv[2])
}

func exactWindowsAccessibilityExecutable(value string) bool {
	switch strings.ToLower(value) {
	case "osk.exe", "sethc.exe", "utilman.exe", "magnify.exe",
		"narrator.exe", "displayswitch.exe", "atbroker.exe":
		return true
	default:
		return false
	}
}

func exactWindowsProtectedAccessibilityPath(value string) bool {
	canonical, ok := windowsCanonicalPathFactValue(value)
	if !ok {
		return false
	}
	parsed := parseWindowsPath(canonical)
	if !parsed.absolute || parsed.unresolved {
		return false
	}
	parts := strings.Split(strings.ReplaceAll(canonical, `\`, "/"), "/")
	return len(parts) == 4 && len(parts[0]) == 2 && parts[0][1] == ':' &&
		strings.EqualFold(parts[1], "windows") &&
		strings.EqualFold(parts[2], "system32") &&
		exactWindowsAccessibilityExecutable(parts[3])
}

func exactWindowsSystemCommandInterpreter(value string) bool {
	canonical, ok := windowsCanonicalPathFactValue(value)
	if !ok {
		return false
	}
	parsed := parseWindowsPath(canonical)
	if !parsed.absolute || parsed.unresolved {
		return false
	}
	parts := strings.Split(strings.ReplaceAll(canonical, `\`, "/"), "/")
	return len(parts) == 4 && len(parts[0]) == 2 && parts[0][1] == ':' &&
		strings.EqualFold(parts[1], "windows") &&
		strings.EqualFold(parts[2], "system32") &&
		strings.EqualFold(parts[3], "cmd.exe")
}
