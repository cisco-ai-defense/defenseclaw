// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const windowsSecurityControlPairWindow = 4

func windowsClassifyBCDEdit(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	_, _, disabled, ok := exactWindowsBCDRecoverySetting(args)
	if !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationConfigChange)
	if disabled {
		windowsAddOperation(command, OperationPolicyBypass)
	}
}

// exactWindowsBCDRecoverySetting recognizes only recovery controls with known
// disable and restoration values. It returns a normalized boot identifier and
// key so a bounded pair cannot be assembled across different boot entries.
func exactWindowsBCDRecoverySetting(args []windowsWord) (string, string, bool, bool) {
	if len(args) != 4 {
		return "", "", false, false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote != QuoteNone {
			return "", "", false, false
		}
	}
	if !strings.EqualFold(args[0].value, "/set") {
		return "", "", false, false
	}
	identifier := strings.ToLower(args[1].value)
	if len(identifier) < 3 || identifier[0] != '{' ||
		identifier[len(identifier)-1] != '}' ||
		strings.ContainsAny(identifier[1:len(identifier)-1], "{} 	\r\n") {
		return "", "", false, false
	}
	key := strings.ToLower(args[2].value)
	value := strings.ToLower(args[3].value)
	switch key {
	case "bootstatuspolicy":
		switch value {
		case "ignoreallfailures":
			return identifier, key, true, true
		case "displayallfailures":
			return identifier, key, false, true
		}
	case "recoveryenabled":
		switch value {
		case "no":
			return identifier, key, true, true
		case "yes":
			return identifier, key, false, true
		}
	}
	return "", "", false, false
}

func windowsClassifyAuditPol(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if _, ok := exactWindowsAuditPolicyWipeStep(args); !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationConfigChange)
	windowsAddOperation(command, OperationPolicyBypass)
}

func exactWindowsAuditPolicyWipeStep(args []windowsWord) (string, bool) {
	if len(args) != 2 {
		return "", false
	}
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote != QuoteNone {
			return "", false
		}
	}
	if strings.EqualFold(args[0].value, "/clear") &&
		strings.EqualFold(args[1].value, "/y") {
		return "clear", true
	}
	if strings.EqualFold(args[0].value, "/remove") &&
		strings.EqualFold(args[1].value, "/allusers") {
		return "remove-all-users", true
	}
	return "", false
}

func windowsClassifyRecoveryStore(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	if !exactWindowsRecoveryStoreDestruction(command.Program, args) {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationDelete)
	windowsAddOperation(command, OperationConfigChange)
}

func exactWindowsRecoveryStoreDestruction(program string, args []windowsWord) bool {
	for _, arg := range args {
		if arg.expands || arg.wildcard || arg.nativeArgvUncertain ||
			arg.quote != QuoteNone {
			return false
		}
	}
	switch program {
	case "wbadmin", "wbadmin.exe":
		if len(args) != 3 || !strings.EqualFold(args[0].value, "delete") {
			return false
		}
		return strings.EqualFold(args[1].value, "systemstatebackup") &&
			strings.EqualFold(args[2].value, "-keepversions:0") ||
			strings.EqualFold(args[1].value, "catalog") &&
				strings.EqualFold(args[2].value, "-quiet")
	case "wmic", "wmic.exe":
		return len(args) == 2 &&
			strings.EqualFold(args[0].value, "shadowcopy") &&
			strings.EqualFold(args[1].value, "delete")
	default:
		return false
	}
}

func windowsClassifySetMPPreference(
	command *CommandFact,
	args []windowsWord,
	builder *windowsFactBuilder,
) {
	_, disabled, ok := exactWindowsDefenderDisableSetting(args)
	if !ok {
		builder.out.markPartial(IssueUnknownOperandGrammar)
		return
	}
	windowsAddOperation(command, OperationConfigChange)
	if disabled {
		windowsAddOperation(command, OperationPolicyBypass)
	}
}

func exactWindowsDefenderDisableSetting(args []windowsWord) (string, bool, bool) {
	if len(args) != 2 || args[0].expands || args[0].wildcard ||
		args[0].nativeArgvUncertain || args[0].quote != QuoteNone ||
		args[1].wildcard || args[1].nativeArgvUncertain ||
		args[1].quote != QuoteNone {
		return "", false, false
	}
	setting := strings.ToLower(args[0].value)
	switch setting {
	case "-disablerealtimemonitoring", "-drtm":
		setting = "real-time-monitoring"
	case "-disablebehaviormonitoring", "-dbm":
		setting = "behavior-monitoring"
	case "-disablescriptscanning", "-dscrptsc":
		setting = "script-scanning"
	case "-disableblockatfirstseen", "-dbaf":
		setting = "block-at-first-seen"
	default:
		return "", false, false
	}
	value := strings.ToLower(args[1].value)
	switch value {
	case "1", "true", "$true":
		// $true is a closed PowerShell automatic boolean constant. Other
		// expanding values remain unsupported.
		if args[1].expands && value != "$true" {
			return "", false, false
		}
		return setting, true, true
	case "0", "false", "$false":
		if args[1].expands && value != "$false" {
			return "", false, false
		}
		return setting, false, true
	default:
		return "", false, false
	}
}

// ExactWindowsDefenderMultiControlDisable requires at least three distinct
// Defender protections to be disabled by unconditional Set-MpPreference
// commands inside a four-command window. Single-control maintenance remains
// outside this deterministic proof.
func ExactWindowsDefenderMultiControlDisable(facts Facts) bool {
	if facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for start := range facts.Commands {
		settings := make(map[string]struct{}, windowsSecurityControlPairWindow)
		limit := start + windowsSecurityControlPairWindow
		if limit > len(facts.Commands) {
			limit = len(facts.Commands)
		}
		for index := start; index < limit; index++ {
			command := facts.Commands[index]
			if command.ParentCommandID != 0 || command.PipelineID != 0 ||
				command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
				len(command.Redirects) != 0 || !command.ArgvComplete ||
				command.Program != "set-mppreference" ||
				!hasFactOperation(command, OperationPolicyBypass) ||
				len(command.Arguments) != 3 {
				continue
			}
			setting, disabled, ok := exactWindowsDefenderDisableSetting(
				windowsWordsFromArguments(command.Arguments[1:]),
			)
			if ok && disabled {
				settings[setting] = struct{}{}
			}
		}
		if len(settings) >= 3 {
			return true
		}
	}
	return false
}

// ExactWindowsRegistrySecurityControlDisable recognizes either one exact
// Windows Firewall profile disable, one closed critical registry weakening, or
// at least three distinct Defender control disables in a six-command window.
// Critical single-write proofs require the complete input to contain only that
// command. Requiring a conjunction for all other Defender settings keeps
// ordinary one-setting administration outside the proof.
func ExactWindowsRegistrySecurityControlDisable(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD && facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for start := range facts.Commands {
		family, setting, disabled, ok := exactTopLevelWindowsRegistrySecuritySetting(
			facts.Commands[start],
		)
		if !ok || !disabled {
			continue
		}
		if family == "firewall" || family == "critical-single" && len(facts.Commands) == 1 {
			return true
		}
		if family != "defender" {
			continue
		}
		settings := map[string]struct{}{setting: {}}
		limit := start + 6
		if limit > len(facts.Commands) {
			limit = len(facts.Commands)
		}
		for index := start + 1; index < limit; index++ {
			otherFamily, otherSetting, otherDisabled, otherOK :=
				exactTopLevelWindowsRegistrySecuritySetting(facts.Commands[index])
			if otherOK && otherDisabled && otherFamily == "defender" {
				settings[otherSetting] = struct{}{}
			}
		}
		if len(settings) >= 3 {
			return true
		}
	}
	return false
}

func exactTopLevelWindowsRegistrySecuritySetting(
	command CommandFact,
) (family, setting string, disabled, ok bool) {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		!command.ArgvComplete || command.Effect != EffectExecute ||
		!hasFactOperation(command, OperationConfigChange) ||
		!hasFactOperation(command, OperationPolicyBypass) ||
		!windowsSecurityNullRedirectsOnly(command.Redirects) {
		return "", "", false, false
	}
	return exactWindowsRegistrySecuritySetting(command)
}

func windowsSecurityNullRedirectsOnly(redirects []RedirectFact) bool {
	for _, redirect := range redirects {
		if redirect.Expands ||
			!strings.EqualFold(strings.TrimSpace(redirect.Target), "nul") ||
			redirect.Access != PathAccessWrite && redirect.Access != PathAccessAppend {
			return false
		}
	}
	return true
}

func exactWindowsRegistrySecuritySetting(
	command CommandFact,
) (family, setting string, disabled, ok bool) {
	var registryPath, valueName, value string
	switch command.Program {
	case "reg", "reg.exe":
		registryPath, valueName, value, ok = exactWindowsRegAddValue(command.Argv)
	case "set-itemproperty", "new-itemproperty":
		registryPath, valueName, value, ok = exactWindowsSetItemPropertyValue(command.Argv)
	default:
		return "", "", false, false
	}
	if !ok {
		return "", "", false, false
	}
	canonical, canonicalOK := canonicalRegistryPath(registryPath)
	if !canonicalOK {
		return "", "", false, false
	}
	upperPath := strings.ToUpper(canonical)
	upperName := strings.ToUpper(valueName)
	if upperName == "ENABLEFIREWALL" && value == "0" &&
		(strings.HasPrefix(upperPath,
			"HKLM/SYSTEM/CURRENTCONTROLSET/SERVICES/SHAREDACCESS/PARAMETERS/FIREWALLPOLICY/") ||
			strings.HasPrefix(upperPath,
				"HKLM/SOFTWARE/POLICIES/MICROSOFT/WINDOWSFIREWALL/")) {
		profile := upperPath[strings.LastIndex(upperPath, "/")+1:]
		switch profile {
		case "DOMAINPROFILE", "PUBLICPROFILE", "STANDARDPROFILE", "PRIVATEPROFILE":
			return "firewall", strings.ToLower(profile), true, true
		}
	}
	// These exact key/value/data triples disable or materially weaken a closed
	// Windows security boundary. They are accepted only through reg.exe's
	// literal REG_DWORD grammar; PowerShell registry forms intentionally abstain
	// because their coercion and provider semantics are broader.
	if command.Program == "reg" || command.Program == "reg.exe" {
		criticalWeakening := map[string]map[string]string{
			"HKLM/SOFTWARE/MICROSOFT/WINDOWS/CURRENTVERSION/POLICIES/SYSTEM": {
				"ENABLELUA":                  "0",
				"CONSENTPROMPTBEHAVIORADMIN": "0",
			},
			"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/DEVICEGUARD/SCENARIOS/HYPERVISORENFORCEDCODEINTEGRITY": {
				"ENABLED": "0",
			},
			"HKLM/SOFTWARE/MICROSOFT/WINDOWS DEFENDER/FEATURES": {
				"TAMPERPROTECTION": "0",
			},
			"HKLM/SOFTWARE/MICROSOFT/WINDOWS/CURRENTVERSION/POLICIES/SYSTEM/CREDSSP/PARAMETERS": {
				"ALLOWENCRYPTIONORACLE": "2",
			},
			"HKLM/SYSTEM/CURRENTCONTROLSET/CONTROL/TERMINAL SERVER/WINSTATIONS/RDP-TCP": {
				"SECURITYLAYER":      "0",
				"USERAUTHENTICATION": "0",
			},
		}
		if values, knownPath := criticalWeakening[upperPath]; knownPath {
			if weakeningValue, knownName := values[upperName]; knownName {
				return "critical-single", strings.ToLower(upperName), value == weakeningValue, true
			}
		}
	}
	if !strings.Contains(upperPath, "/MICROSOFT/WINDOWS DEFENDER") {
		return "", "", false, false
	}
	disableWithOne := map[string]struct{}{
		"DISABLEANTISPYWARE":               {},
		"DISABLEANTIVIRUS":                 {},
		"DISABLEBEHAVIORMONITORING":        {},
		"DISABLEINTRUSIONPREVENTIONSYSTEM": {},
		"DISABLEIOAVPROTECTION":            {},
		"DISABLEONACCESSPROTECTION":        {},
		"DISABLEREALTIMEMONITORING":        {},
		"DISABLEROUTINELYTAKINGACTION":     {},
		"DISABLESCANONREALTIMEENABLE":      {},
		"DISABLESCRIPTSCANNING":            {},
		"DISABLEBLOCKATFIRSTSEEN":          {},
	}
	if _, known := disableWithOne[upperName]; known {
		return "defender", strings.ToLower(upperName), value == "1", true
	}
	disableWithZero := map[string]struct{}{
		"TAMPERPROTECTION":                  {},
		"DISALLOWEXPLOITPROTECTIONOVERRIDE": {},
		"MPENABLEPUS":                       {},
		"PUAPROTECTION":                     {},
	}
	if _, known := disableWithZero[upperName]; known {
		return "defender", strings.ToLower(upperName), value == "0", true
	}
	return "", "", false, false
}

func exactWindowsRegAddValue(argv []string) (registryPath, name, value string, ok bool) {
	if len(argv) < 9 || !strings.EqualFold(argv[1], "add") || argv[2] == "" {
		return "", "", "", false
	}
	seen := make(map[string]struct{}, 4)
	values := make(map[string]string, 3)
	for index := 3; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if _, duplicate := seen[option]; duplicate {
			return "", "", "", false
		}
		seen[option] = struct{}{}
		switch option {
		case "/v", "/t", "/d":
			index++
			if index >= len(argv) || argv[index] == "" {
				return "", "", "", false
			}
			values[option] = argv[index]
		case "/f":
		default:
			return "", "", "", false
		}
	}
	if _, forced := seen["/f"]; !forced ||
		!strings.EqualFold(values["/t"], "REG_DWORD") ||
		values["/v"] == "" || values["/d"] == "" {
		return "", "", "", false
	}
	return argv[2], values["/v"], strings.Trim(values["/d"], `"`), true
}

func exactWindowsSetItemPropertyValue(argv []string) (registryPath, name, value string, ok bool) {
	if len(argv) < 6 {
		return "", "", "", false
	}
	seen := make(map[string]struct{}, 5)
	values := make(map[string]string, 4)
	for index := 1; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if index == 1 && !strings.HasPrefix(option, "-") {
			registryPath = argv[index]
			continue
		}
		if option == "-force" {
			if _, duplicate := seen[option]; duplicate {
				return "", "", "", false
			}
			seen[option] = struct{}{}
			continue
		}
		if option != "-path" && option != "-literalpath" && option != "-name" &&
			option != "-value" && option != "-type" && option != "-propertytype" {
			return "", "", "", false
		}
		if _, duplicate := seen[option]; duplicate {
			return "", "", "", false
		}
		seen[option] = struct{}{}
		index++
		if index >= len(argv) || argv[index] == "" {
			return "", "", "", false
		}
		values[option] = argv[index]
	}
	if registryPath == "" {
		registryPath = values["-path"]
		if registryPath == "" {
			registryPath = values["-literalpath"]
		}
	}
	propertyType := values["-type"]
	if propertyType == "" {
		propertyType = values["-propertytype"]
	}
	if registryPath == "" || values["-name"] == "" || values["-value"] == "" ||
		propertyType != "" && !strings.EqualFold(propertyType, "DWord") {
		return "", "", "", false
	}
	return registryPath, values["-name"], strings.Trim(values["-value"], `"`), true
}

// ExactWindowsRecoveryStoreDestruction requires one complete, unconditional
// command in the closed destructive wbadmin or WMIC grammar. Backup creation,
// inventory, scoped retention, and interactive catalog deletion abstain.
func ExactWindowsRecoveryStoreDestruction(facts Facts) bool {
	if facts.Parse.Dialect != DialectCMD && facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Commands) != 1 {
		return false
	}
	command := facts.Commands[0]
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || !command.ArgvComplete ||
		!hasFactOperation(command, OperationDelete) ||
		!hasFactOperation(command, OperationConfigChange) ||
		len(command.Arguments) < 2 {
		return false
	}
	return exactWindowsRecoveryStoreDestruction(
		command.Program,
		windowsWordsFromArguments(command.Arguments[1:]),
	)
}

// ExactWindowsRecoveryDisablePair requires both recovery controls to be
// disabled for the same static boot identifier in a four-command window.
func ExactWindowsRecoveryDisablePair(facts Facts) bool {
	return exactWindowsSecurityPair(facts, func(command CommandFact) (string, string, bool) {
		if command.Program != "bcdedit" && command.Program != "bcdedit.exe" ||
			len(command.Arguments) != 5 {
			return "", "", false
		}
		args := windowsWordsFromArguments(command.Arguments[1:])
		identifier, key, disabled, ok := exactWindowsBCDRecoverySetting(args)
		return identifier, key, ok && disabled
	}, "bootstatuspolicy", "recoveryenabled")
}

// ExactWindowsAuditPolicyWipePair requires both the global policy clear and
// all-user policy removal steps in a four-command window.
func ExactWindowsAuditPolicyWipePair(facts Facts) bool {
	return exactWindowsSecurityPair(facts, func(command CommandFact) (string, string, bool) {
		if command.Program != "auditpol" && command.Program != "auditpol.exe" ||
			len(command.Arguments) != 3 {
			return "", "", false
		}
		step, ok := exactWindowsAuditPolicyWipeStep(
			windowsWordsFromArguments(command.Arguments[1:]),
		)
		return "audit-policy", step, ok
	}, "clear", "remove-all-users")
}

type windowsSecurityPairStep func(CommandFact) (identity, step string, ok bool)

func exactWindowsSecurityPair(
	facts Facts,
	classify windowsSecurityPairStep,
	firstStep, secondStep string,
) bool {
	if facts.Parse.Dialect != DialectCMD &&
		facts.Parse.Dialect != DialectPowerShell {
		return false
	}
	for firstIndex, command := range facts.Commands {
		identity, step, ok := exactTopLevelWindowsSecurityStep(command, classify)
		if !ok {
			continue
		}
		limit := firstIndex + windowsSecurityControlPairWindow
		if limit > len(facts.Commands) {
			limit = len(facts.Commands)
		}
		for secondIndex := firstIndex + 1; secondIndex < limit; secondIndex++ {
			otherIdentity, otherStep, otherOK := exactTopLevelWindowsSecurityStep(
				facts.Commands[secondIndex],
				classify,
			)
			if otherOK && identity == otherIdentity &&
				(step == firstStep && otherStep == secondStep ||
					step == secondStep && otherStep == firstStep) {
				return true
			}
		}
	}
	return false
}

func exactTopLevelWindowsSecurityStep(
	command CommandFact,
	classify windowsSecurityPairStep,
) (string, string, bool) {
	if command.ParentCommandID != 0 || command.PipelineID != 0 ||
		command.ControlFlowUncertain || len(command.Wrappers) != 0 ||
		len(command.Redirects) != 0 || !command.ArgvComplete ||
		!hasFactOperation(command, OperationConfigChange) ||
		!hasFactOperation(command, OperationPolicyBypass) {
		return "", "", false
	}
	return classify(command)
}

func windowsWordsFromArguments(arguments []ArgumentFact) []windowsWord {
	out := make([]windowsWord, 0, len(arguments))
	for _, argument := range arguments {
		out = append(out, windowsWord{
			value:    argument.Value,
			quote:    argument.Quote,
			expands:  argument.Expands,
			wildcard: strings.ContainsAny(argument.Value, "*?"),
		})
	}
	return out
}
