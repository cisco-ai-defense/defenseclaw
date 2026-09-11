// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const exactPowerShellAMSIReflection = "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"

type windowsAtomicRegistryMutation struct {
	path      string
	name      string
	value     string
	valueType string
}

// parseExactPowerShellAMSIReflection owns one closed PowerShell expression.
// The general PowerShell parser intentionally treats arbitrary member-access
// expressions as opaque. Recognizing this exact no-argument-variation form
// keeps the normal parser closed while still producing an authoritative fact.
func parseExactPowerShellAMSIReflection(
	source string,
	startID int64,
) (parseOutput, bool) {
	if strings.TrimSpace(source) != exactPowerShellAMSIReflection {
		return parseOutput{}, false
	}
	out := newParseOutput(DialectPowerShell, startID)
	command := CommandFact{
		ID:           startID,
		Dialect:      DialectPowerShell,
		Effect:       EffectExecute,
		Executable:   "powershell-amsi-reflection",
		Program:      "powershell-amsi-reflection",
		Argv:         []string{exactPowerShellAMSIReflection},
		Arguments:    []ArgumentFact{{Value: exactPowerShellAMSIReflection, Quote: QuoteNone}},
		ArgvComplete: true,
		Operations: []OperationKind{
			OperationExecute,
			OperationConfigChange,
			OperationPolicyBypass,
		},
	}
	out.appendCommand(command)
	return out, true
}

func exactWindowsAtomicRegistryMutation(
	command CommandFact,
) (windowsAtomicRegistryMutation, bool) {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || !command.ArgvComplete ||
		command.Effect != EffectExecute || !staticArguments(command.Arguments) {
		return windowsAtomicRegistryMutation{}, false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return windowsAtomicRegistryMutation{}, false
		}
	}

	var mutation windowsAtomicRegistryMutation
	var ok bool
	switch command.Program {
	case "reg", "reg.exe":
		mutation, ok = exactWindowsAtomicRegAdd(command.Argv)
	case "set-itemproperty", "new-itemproperty":
		mutation, ok = exactWindowsAtomicItemProperty(command.Argv)
	default:
		return windowsAtomicRegistryMutation{}, false
	}
	if !ok {
		return windowsAtomicRegistryMutation{}, false
	}
	canonical, canonicalOK := canonicalRegistryPath(mutation.path)
	if !canonicalOK {
		return windowsAtomicRegistryMutation{}, false
	}
	mutation.path = strings.ToUpper(canonical)
	mutation.name = strings.ToUpper(mutation.name)
	mutation.valueType = strings.ToUpper(mutation.valueType)
	return mutation, true
}

func exactWindowsAtomicRegAdd(argv []string) (windowsAtomicRegistryMutation, bool) {
	if len(argv) < 9 || len(argv) > 10 || !strings.EqualFold(argv[1], "add") ||
		argv[2] == "" {
		return windowsAtomicRegistryMutation{}, false
	}
	values := make(map[string]string, 3)
	seen := make(map[string]struct{}, 4)
	for index := 3; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if _, duplicate := seen[option]; duplicate {
			return windowsAtomicRegistryMutation{}, false
		}
		seen[option] = struct{}{}
		switch option {
		case "/v", "/t", "/d":
			index++
			if index >= len(argv) || argv[index] == "" {
				return windowsAtomicRegistryMutation{}, false
			}
			values[option] = argv[index]
		case "/f":
		default:
			return windowsAtomicRegistryMutation{}, false
		}
	}
	if values["/v"] == "" || values["/t"] == "" || values["/d"] == "" {
		return windowsAtomicRegistryMutation{}, false
	}
	return windowsAtomicRegistryMutation{
		path:      argv[2],
		name:      values["/v"],
		value:     values["/d"],
		valueType: values["/t"],
	}, true
}

func exactWindowsAtomicItemProperty(argv []string) (windowsAtomicRegistryMutation, bool) {
	if len(argv) < 6 {
		return windowsAtomicRegistryMutation{}, false
	}
	mutation := windowsAtomicRegistryMutation{}
	seen := make(map[string]struct{}, 7)
	for index := 1; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if index == 1 && !strings.HasPrefix(option, "-") {
			mutation.path = argv[index]
			continue
		}
		if _, duplicate := seen[option]; duplicate {
			return windowsAtomicRegistryMutation{}, false
		}
		seen[option] = struct{}{}
		switch option {
		case "-path", "-literalpath", "-name", "-value", "-type", "-propertytype", "-erroraction":
			index++
			if index >= len(argv) || argv[index] == "" {
				return windowsAtomicRegistryMutation{}, false
			}
			switch option {
			case "-path", "-literalpath":
				if mutation.path != "" {
					return windowsAtomicRegistryMutation{}, false
				}
				mutation.path = argv[index]
			case "-name":
				mutation.name = argv[index]
			case "-value":
				mutation.value = argv[index]
			case "-type", "-propertytype":
				if mutation.valueType != "" {
					return windowsAtomicRegistryMutation{}, false
				}
				mutation.valueType = argv[index]
			case "-erroraction":
				if !exactPowerShellErrorAction(argv[index]) {
					return windowsAtomicRegistryMutation{}, false
				}
			}
		case "-force":
		default:
			return windowsAtomicRegistryMutation{}, false
		}
	}
	if mutation.path == "" || mutation.name == "" || mutation.value == "" {
		return windowsAtomicRegistryMutation{}, false
	}
	return mutation, true
}

func exactPowerShellErrorAction(value string) bool {
	switch strings.ToLower(value) {
	case "ignore", "silentlycontinue", "stop", "continue":
		return true
	default:
		return false
	}
}

func exactWindowsTelemetryMutation(command CommandFact) bool {
	mutation, ok := exactWindowsAtomicRegistryMutation(command)
	if !ok || mutation.value != "0" {
		return false
	}
	switch {
	case mutation.name == "COMPLUS_ETWENABLED" &&
		(mutation.path == "HKCU/ENVIRONMENT" ||
			mutation.path == "HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/SESSION MANAGER/ENVIRONMENT"):
		return mutation.valueType == "REG_SZ" || mutation.valueType == "STRING"
	case mutation.name == "ETWENABLED" &&
		mutation.path == "HKLM/SOFTWARE/MICROSOFT/.NETFRAMEWORK":
		return mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD"
	case mutation.name == "ENABLED" &&
		mutation.path == "HKLM/SOFTWARE/MICROSOFT/WINDOWS/CURRENTVERSION/WINEVT/CHANNELS/MICROSOFT-WINDOWS-WINDOWS DEFENDER/OPERATIONAL":
		return mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD"
	case mutation.name == "START" &&
		mutation.path == "HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/WMI/AUTOLOGGER/EVENTLOG-APPLICATION":
		return mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD"
	default:
		return false
	}
}

func exactWindowsCredentialProtectionMutation(
	command CommandFact,
) (identity, step string, ok bool) {
	mutation, ok := exactWindowsAtomicRegistryMutation(command)
	if !ok {
		return "", "", false
	}
	if mutation.path == "HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/SECURITYPROVIDERS/WDIGEST" &&
		mutation.name == "USELOGONCREDENTIAL" && mutation.value == "1" &&
		(mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD" || mutation.valueType == "") {
		return "wdigest", "weaken", true
	}
	if mutation.path == "HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/LSA" &&
		mutation.name == "RUNASPPL" && mutation.value == "0" &&
		(mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD") {
		return "lsa", "weaken", true
	}
	const winlogon = "HKLM/SOFTWARE/POLICIES/MICROSOFT/WINDOWS NT/CURRENTVERSION/WINLOGON"
	if mutation.path != winlogon {
		return "", "", false
	}
	switch mutation.name {
	case "AUTOADMINLOGON":
		if mutation.value == "1" &&
			(mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD") {
			return winlogon, "enable", true
		}
	case "DEFAULTPASSWORD":
		if strings.TrimSpace(mutation.value) != "" &&
			!strings.ContainsAny(mutation.value, "%$") &&
			(mutation.valueType == "REG_SZ" || mutation.valueType == "STRING" || mutation.valueType == "") {
			return winlogon, "password", true
		}
	}
	return "", "", false
}

func exactWindowsAMSIRegistryDisable(command CommandFact) bool {
	mutation, ok := exactWindowsAtomicRegistryMutation(command)
	return ok && mutation.path == "HKCU/SOFTWARE/MICROSOFT/WINDOWS SCRIPT/SETTINGS" &&
		mutation.name == "AMSIENABLE" && mutation.value == "0" &&
		(mutation.valueType == "REG_DWORD" || mutation.valueType == "DWORD")
}

func exactWindowsAMSIProviderRemoval(command CommandFact) bool {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || !command.ArgvComplete ||
		command.Effect != EffectExecute || command.Program != "remove-item" ||
		len(command.Argv) != 4 || !staticArguments(command.Arguments) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return false
		}
	}
	var registryPath string
	if (strings.EqualFold(command.Argv[1], "-path") ||
		strings.EqualFold(command.Argv[1], "-literalpath")) &&
		strings.EqualFold(command.Argv[3], "-recurse") {
		registryPath = command.Argv[2]
	} else if strings.EqualFold(command.Argv[1], "-recurse") &&
		(strings.EqualFold(command.Argv[2], "-path") ||
			strings.EqualFold(command.Argv[2], "-literalpath")) {
		return false
	} else {
		return false
	}
	canonical, ok := canonicalRegistryPath(registryPath)
	if !ok {
		return false
	}
	const prefix = "HKLM/SOFTWARE/MICROSOFT/AMSI/PROVIDERS/"
	upper := strings.ToUpper(canonical)
	return strings.HasPrefix(upper, prefix) &&
		isExactWindowsGUID(upper[len(prefix):])
}

func isExactWindowsGUID(value string) bool {
	if len(value) != 38 || value[0] != '{' || value[37] != '}' {
		return false
	}
	for index := 1; index < 37; index++ {
		switch index {
		case 9, 14, 19, 24:
			if value[index] != '-' {
				return false
			}
		default:
			character := value[index]
			digit := character >= '0' && character <= '9'
			hexLetter := character >= 'A' && character <= 'F'
			if !digit && !hexLetter {
				return false
			}
		}
	}
	return true
}

// ExactWindowsTelemetryDisable accepts one direct, closed registry mutation.
func ExactWindowsTelemetryDisable(facts Facts) bool {
	return facts.Authoritative() &&
		(facts.Parse.Dialect == DialectCMD || facts.Parse.Dialect == DialectPowerShell) &&
		len(facts.Commands) == 1 &&
		exactWindowsTelemetryMutation(facts.Commands[0])
}

// ExactWindowsCredentialProtectionWeakening accepts either one exact WDigest
// or LSA weakening, or exactly the two literal Winlogon auto-logon mutations.
func ExactWindowsCredentialProtectionWeakening(facts Facts) bool {
	if !facts.Authoritative() ||
		facts.Parse.Dialect != DialectCMD && facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	if len(facts.Commands) == 1 {
		_, step, ok := exactWindowsCredentialProtectionMutation(facts.Commands[0])
		return ok && step == "weaken"
	}
	if len(facts.Commands) != 2 {
		return false
	}
	identity, first, ok := exactWindowsCredentialProtectionMutation(facts.Commands[0])
	if !ok {
		return false
	}
	otherIdentity, second, otherOK := exactWindowsCredentialProtectionMutation(facts.Commands[1])
	return otherOK && identity == otherIdentity &&
		(first == "enable" && second == "password" ||
			first == "password" && second == "enable")
}

// ExactWindowsAMSIDisable accepts one exact registry disable, reflection
// bypass, or recursive deletion of one literal AMSI provider GUID subtree.
func ExactWindowsAMSIDisable(facts Facts) bool {
	if !facts.Authoritative() || facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	return exactWindowsAMSIRegistryDisable(command) ||
		exactWindowsAMSIProviderRemoval(command) ||
		command.ParentCommandID == 0 && command.PipelineID == 0 &&
			!command.ControlFlowUncertain && len(command.Wrappers) == 0 &&
			len(command.Redirects) == 0 && command.ArgvComplete &&
			command.Effect == EffectExecute &&
			command.Program == "powershell-amsi-reflection" &&
			hasFactOperation(command, OperationConfigChange) &&
			hasFactOperation(command, OperationPolicyBypass)
}
