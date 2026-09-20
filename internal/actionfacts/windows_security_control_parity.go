// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const (
	windowsDefenderDefinitionToolPath = `C:\Program Files\Windows Defender\MpCmdRun.exe`
	windowsUACPolicyRegistryPath      = `HKLM/SOFTWARE/MICROSOFT/WINDOWS/CURRENTVERSION/POLICIES/SYSTEM`
)

var windowsDefenderScheduledTasks = map[string]struct{}{
	`\microsoft\windows\windows defender\windows defender cache maintenance`: {},
	`\microsoft\windows\windows defender\windows defender cleanup`:           {},
	`\microsoft\windows\windows defender\windows defender scheduled scan`:    {},
	`\microsoft\windows\windows defender\windows defender verification`:      {},
}

// ProvesWindowsDefenderDisablement recognizes a closed set of complete,
// unconditional Defender-disabling operations. It deliberately excludes
// generic service, feature, task, DNS, and registry mutations.
func ProvesWindowsDefenderDisablement(facts Facts) bool {
	if !windowsSecurityControlParityFactsEligible(facts) {
		return false
	}
	for _, command := range facts.Commands {
		if !windowsSecurityControlParityCommandEligible(command) {
			continue
		}
		program := command.Program
		if program == "" {
			program = command.Executable
		}
		switch program {
		case "mpcmdrun", "mpcmdrun.exe":
			if exactWindowsDefenderDefinitionsRemoval(command) {
				return true
			}
		case "dism", "dism.exe":
			if exactWindowsDefenderDISMRemoval(command) {
				return true
			}
		case "disable-windowsoptionalfeature":
			if exactWindowsDefenderOptionalFeatureDisable(command) {
				return true
			}
		case "remove-windowsfeature", "uninstall-windowsfeature":
			if exactWindowsDefenderFeatureRemoval(command) {
				return true
			}
		case "schtasks", "schtasks.exe":
			if exactWindowsDefenderScheduledTaskDelete(command) {
				return true
			}
		case "add-dnsclientnrptrule":
			if exactWindowsDefenderNRPTSinkhole(command) {
				return true
			}
		}
	}
	return false
}

// ProvesWindowsUACPolicySuppression recognizes PowerShell registry writes that
// set one exact machine-wide UAC protection to its closed disabling DWORD
// value. Restoration values, provider coercion, and dynamic operands abstain.
func ProvesWindowsUACPolicySuppression(facts Facts) bool {
	if !windowsSecurityControlParityFactsEligible(facts) ||
		facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for _, command := range facts.Commands {
		if !windowsSecurityControlParityCommandEligible(command) ||
			command.Program != "set-itemproperty" &&
				command.Program != "new-itemproperty" {
			continue
		}
		path, name, value, ok := exactWindowsSetItemPropertyValue(command.Argv)
		if !ok || !windowsPowerShellExactDWORDForce(command.Argv) {
			continue
		}
		canonical, ok := canonicalRegistryPath(path)
		if !ok || !strings.EqualFold(canonical, windowsUACPolicyRegistryPath) ||
			value != "0" {
			continue
		}
		switch strings.ToUpper(name) {
		case "ENABLELUA", "CONSENTPROMPTBEHAVIORADMIN", "PROMPTONSECUREDESKTOP":
			return true
		}
	}
	return false
}

func windowsSecurityControlParityFactsEligible(facts Facts) bool {
	return facts.Authoritative() && facts.EnforcementEligible() &&
		(facts.Parse.Dialect == DialectCMD || facts.Parse.Dialect == DialectPowerShell)
}

func windowsSecurityControlParityCommandEligible(command CommandFact) bool {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || command.Kind != "" &&
		command.Kind != CommandKindProcess || command.Effect != EffectExecute ||
		!command.ArgvComplete || len(command.Argv) == 0 ||
		len(command.Argv) != len(command.Arguments) ||
		len(command.Wrappers) != 0 || len(command.Redirects) != 0 {
		return false
	}
	for index, argument := range command.Arguments {
		if argument.Expands || argument.Value != command.Argv[index] ||
			argument.Quote == QuoteMixed || argument.Value == "" ||
			strings.Contains(argument.Value, "#{") ||
			strings.ContainsAny(argument.Value, "*?") {
			return false
		}
	}
	return true
}

func exactWindowsDefenderDefinitionsRemoval(command CommandFact) bool {
	return command.Dialect == DialectCMD && len(command.Argv) == 3 &&
		windowsEqualPath(command.Argv[0], windowsDefenderDefinitionToolPath) &&
		strings.EqualFold(command.Argv[1], "-RemoveDefinitions") &&
		strings.EqualFold(command.Argv[2], "-All")
}

func exactWindowsDefenderDISMRemoval(command CommandFact) bool {
	if command.Dialect != DialectCMD || len(command.Argv) != 7 {
		return false
	}
	want := map[string]struct{}{
		"/online":                       {},
		"/disable-feature":              {},
		"/featurename:windows-defender": {},
		"/remove":                       {},
		"/norestart":                    {},
		"/quiet":                        {},
	}
	return exactWindowsUnorderedArguments(command.Argv[1:], want)
}

func exactWindowsDefenderOptionalFeatureDisable(command CommandFact) bool {
	if command.Dialect != DialectPowerShell {
		return false
	}
	seen := make(map[string]struct{}, 4)
	feature := ""
	for index := 1; index < len(command.Argv); index++ {
		option := strings.ToLower(command.Argv[index])
		if _, duplicate := seen[option]; duplicate {
			return false
		}
		seen[option] = struct{}{}
		switch option {
		case "-online", "-norestart":
		case "-featurename":
			index++
			if index >= len(command.Argv) || feature != "" {
				return false
			}
			feature = command.Argv[index]
		case "-erroraction":
			index++
			if index >= len(command.Argv) ||
				!strings.EqualFold(command.Argv[index], "Ignore") {
				return false
			}
		default:
			return false
		}
	}
	_, online := seen["-online"]
	_, noRestart := seen["-norestart"]
	return online && noRestart && strings.EqualFold(feature, "Windows-Defender")
}

func exactWindowsDefenderFeatureRemoval(command CommandFact) bool {
	if command.Dialect != DialectPowerShell {
		return false
	}
	if len(command.Argv) == 2 {
		return strings.EqualFold(command.Argv[1], "Windows-Defender")
	}
	return len(command.Argv) == 3 &&
		strings.EqualFold(command.Argv[1], "-Name") &&
		strings.EqualFold(command.Argv[2], "Windows-Defender")
}

func exactWindowsDefenderScheduledTaskDelete(command CommandFact) bool {
	if command.Dialect != DialectCMD || len(command.Argv) != 5 {
		return false
	}
	deleteSeen := false
	forceSeen := false
	task := ""
	for index := 1; index < len(command.Argv); index++ {
		switch strings.ToLower(command.Argv[index]) {
		case "/delete":
			if deleteSeen {
				return false
			}
			deleteSeen = true
		case "/f":
			if forceSeen {
				return false
			}
			forceSeen = true
		case "/tn":
			index++
			if index >= len(command.Argv) || task != "" {
				return false
			}
			task = strings.ToLower(strings.ReplaceAll(command.Argv[index], "/", `\`))
		default:
			return false
		}
	}
	_, exactTask := windowsDefenderScheduledTasks[task]
	return deleteSeen && forceSeen && exactTask
}

func exactWindowsDefenderNRPTSinkhole(command CommandFact) bool {
	if command.Dialect != DialectPowerShell {
		return false
	}
	seen := make(map[string]struct{}, 3)
	values := make(map[string]string, 3)
	for index := 1; index < len(command.Argv); index++ {
		option := strings.ToLower(command.Argv[index])
		if option != "-namespace" && option != "-nameservers" && option != "-comment" {
			return false
		}
		if _, duplicate := seen[option]; duplicate {
			return false
		}
		seen[option] = struct{}{}
		index++
		if index >= len(command.Argv) {
			return false
		}
		values[option] = command.Argv[index]
	}
	namespace := strings.TrimPrefix(strings.ToLower(values["-namespace"]), ".")
	if namespace != "endpoint.security.microsoft.com" ||
		values["-nameservers"] != "127.0.0.1" {
		return false
	}
	comment := values["-comment"]
	return comment == "" || comment == "Silenced by Name Resolution Policy Table"
}

func windowsPowerShellExactDWORDForce(argv []string) bool {
	seenType := false
	seenForce := false
	for index := 1; index < len(argv); index++ {
		switch strings.ToLower(argv[index]) {
		case "-type", "-propertytype":
			index++
			if index >= len(argv) || seenType || !strings.EqualFold(argv[index], "DWord") {
				return false
			}
			seenType = true
		case "-force":
			if seenForce {
				return false
			}
			seenForce = true
		}
	}
	return seenType && seenForce
}

func exactWindowsUnorderedArguments(arguments []string, want map[string]struct{}) bool {
	if len(arguments) != len(want) {
		return false
	}
	seen := make(map[string]struct{}, len(arguments))
	for _, argument := range arguments {
		argument = strings.ToLower(argument)
		if _, ok := want[argument]; !ok {
			return false
		}
		if _, duplicate := seen[argument]; duplicate {
			return false
		}
		seen[argument] = struct{}{}
	}
	return true
}

func windowsEqualPath(left, right string) bool {
	left = strings.TrimSuffix(strings.ReplaceAll(left, "/", `\`), `\`)
	right = strings.TrimSuffix(strings.ReplaceAll(right, "/", `\`), `\`)
	return strings.EqualFold(left, right)
}
