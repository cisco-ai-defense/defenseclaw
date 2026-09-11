// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "strings"

const (
	windowsUACMSCFileHandler    = "HKCU/SOFTWARE/CLASSES/MSCFILE/SHELL/OPEN/COMMAND"
	windowsUACMSSettingsHandler = "HKCU/SOFTWARE/CLASSES/MS-SETTINGS/SHELL/OPEN/COMMAND"
	windowsUACFolderHandler     = "HKCU/SOFTWARE/CLASSES/FOLDER/SHELL/OPEN/COMMAND"
)

type windowsUACRegistryWrite struct {
	path      string
	name      string
	value     string
	valueSet  bool
	valueType string
}

// ProvesWindowsUACAutoElevationHijack recognizes a complete same-action proof:
// a literal per-user class handler is replaced with a non-empty static command,
// any required empty DelegateExecute value is installed, and the exact matching
// auto-elevated Windows component is then started from System32.
//
// The proof deliberately excludes nearby registry activity, trigger-only calls,
// cleanup/restore commands, placeholders, dynamic values, wrappers, pipelines,
// conditional execution, and unresolved trigger paths. It is enforcement-grade
// only because every accepted command belongs to an authoritative,
// enforcement-eligible Facts projection.
func ProvesWindowsUACAutoElevationHijack(facts Facts) bool {
	if !facts.Authoritative() || !facts.EnforcementEligible() ||
		facts.Parse.Dialect != DialectPowerShell ||
		len(facts.Commands) < 2 || len(facts.Commands) > 4 {
		return false
	}

	var (
		handlerPath  string
		triggerName  string
		defaultSeen  bool
		delegateSeen bool
		setupSeen    bool
	)
	for index, command := range facts.Commands {
		if !exactWindowsUACTopLevelCommand(command) {
			return false
		}

		if trigger, ok := exactWindowsUACTrigger(command); ok {
			if triggerName != "" || index != len(facts.Commands)-1 {
				return false
			}
			triggerName = trigger
			continue
		}

		if path, ok := exactWindowsUACHandlerSetup(command); ok {
			if setupSeen || defaultSeen || delegateSeen || triggerName != "" ||
				!sameWindowsUACHandler(&handlerPath, path) {
				return false
			}
			setupSeen = true
			continue
		}

		write, ok := exactWindowsUACRegistryWrite(command)
		if !ok || triggerName != "" ||
			!sameWindowsUACHandler(&handlerPath, write.path) {
			return false
		}
		switch write.name {
		case "(DEFAULT)":
			if defaultSeen || !write.valueSet ||
				!exactWindowsUACHandlerPayload(write.value) ||
				!exactWindowsUACStringType(write.valueType) {
				return false
			}
			defaultSeen = true
		case "DELEGATEEXECUTE":
			if delegateSeen || write.valueSet && write.value != "" ||
				!exactWindowsUACStringType(write.valueType) {
				return false
			}
			delegateSeen = true
		default:
			return false
		}
	}

	if !defaultSeen || triggerName == "" {
		return false
	}
	switch handlerPath {
	case windowsUACMSCFileHandler:
		return !delegateSeen && triggerName == "eventvwr.msc"
	case windowsUACMSSettingsHandler:
		return delegateSeen && triggerName == "fodhelper.exe"
	case windowsUACFolderHandler:
		return delegateSeen && triggerName == "sdclt.exe"
	default:
		return false
	}
}

func exactWindowsUACTopLevelCommand(command CommandFact) bool {
	if !exactUnconditionalTopLevelCommand(command) || !command.ArgvComplete ||
		!staticArguments(command.Arguments) ||
		len(command.Argv) == 0 || len(command.Argv) != len(command.Arguments) {
		return false
	}
	for _, argument := range command.Arguments {
		if argument.Quote == QuoteMixed {
			return false
		}
	}
	return true
}

func sameWindowsUACHandler(current *string, candidate string) bool {
	if !exactWindowsUACHandlerPath(candidate) {
		return false
	}
	if *current == "" {
		*current = candidate
		return true
	}
	return *current == candidate
}

func exactWindowsUACHandlerPath(value string) bool {
	switch value {
	case windowsUACMSCFileHandler, windowsUACMSSettingsHandler,
		windowsUACFolderHandler:
		return true
	default:
		return false
	}
}

func exactWindowsUACRegistryWrite(
	command CommandFact,
) (windowsUACRegistryWrite, bool) {
	if !hasFactOperation(command, OperationConfigChange) {
		return windowsUACRegistryWrite{}, false
	}
	switch command.Program {
	case "reg", "reg.exe":
		return exactWindowsUACRegAdd(command.Argv)
	case "set-itemproperty", "new-itemproperty":
		return exactWindowsUACItemProperty(command.Argv)
	default:
		return windowsUACRegistryWrite{}, false
	}
}

func exactWindowsUACRegAdd(argv []string) (windowsUACRegistryWrite, bool) {
	if len(argv) < 5 || !strings.EqualFold(argv[1], "add") {
		return windowsUACRegistryWrite{}, false
	}
	canonical, ok := canonicalRegistryPath(argv[2])
	if !ok {
		return windowsUACRegistryWrite{}, false
	}
	write := windowsUACRegistryWrite{path: strings.ToUpper(canonical)}
	seen := make(map[string]struct{}, 5)
	force := false
	for index := 3; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if _, duplicate := seen[option]; duplicate {
			return windowsUACRegistryWrite{}, false
		}
		seen[option] = struct{}{}
		switch option {
		case "/ve":
			if write.name != "" {
				return windowsUACRegistryWrite{}, false
			}
			write.name = "(DEFAULT)"
		case "/v":
			index++
			if index >= len(argv) || argv[index] == "" || write.name != "" {
				return windowsUACRegistryWrite{}, false
			}
			write.name = strings.ToUpper(argv[index])
		case "/d":
			index++
			if index >= len(argv) || write.valueSet {
				return windowsUACRegistryWrite{}, false
			}
			write.value = argv[index]
			write.valueSet = true
		case "/t":
			index++
			if index >= len(argv) || argv[index] == "" || write.valueType != "" {
				return windowsUACRegistryWrite{}, false
			}
			write.valueType = strings.ToUpper(argv[index])
		case "/f":
			force = true
		default:
			return windowsUACRegistryWrite{}, false
		}
	}
	if !force || write.name == "" {
		return windowsUACRegistryWrite{}, false
	}
	return write, true
}

func exactWindowsUACItemProperty(
	argv []string,
) (windowsUACRegistryWrite, bool) {
	if len(argv) < 7 {
		return windowsUACRegistryWrite{}, false
	}
	write := windowsUACRegistryWrite{}
	seen := make(map[string]struct{}, 7)
	force := false
	for index := 1; index < len(argv); index++ {
		option := strings.ToLower(argv[index])
		if index == 1 && !strings.HasPrefix(option, "-") {
			write.path = argv[index]
			continue
		}
		if _, duplicate := seen[option]; duplicate {
			return windowsUACRegistryWrite{}, false
		}
		seen[option] = struct{}{}
		switch option {
		case "-path", "-literalpath", "-name", "-value",
			"-type", "-propertytype", "-erroraction":
			index++
			if index >= len(argv) {
				return windowsUACRegistryWrite{}, false
			}
			value := argv[index]
			switch option {
			case "-path", "-literalpath":
				if value == "" || write.path != "" {
					return windowsUACRegistryWrite{}, false
				}
				write.path = value
			case "-name":
				if value == "" || write.name != "" {
					return windowsUACRegistryWrite{}, false
				}
				write.name = strings.ToUpper(value)
			case "-value":
				if write.valueSet {
					return windowsUACRegistryWrite{}, false
				}
				write.value = value
				write.valueSet = true
			case "-type", "-propertytype":
				if value == "" || write.valueType != "" {
					return windowsUACRegistryWrite{}, false
				}
				write.valueType = strings.ToUpper(value)
			case "-erroraction":
				if !exactPowerShellErrorAction(value) {
					return windowsUACRegistryWrite{}, false
				}
			}
		case "-force":
			force = true
		default:
			return windowsUACRegistryWrite{}, false
		}
	}
	canonical, ok := canonicalRegistryPath(write.path)
	if !ok || !force || write.name == "" || !write.valueSet {
		return windowsUACRegistryWrite{}, false
	}
	write.path = strings.ToUpper(canonical)
	return write, true
}

func exactWindowsUACHandlerSetup(command CommandFact) (string, bool) {
	if command.Program != "new-item" ||
		!hasFactOperation(command, OperationWrite) || len(command.Argv) < 3 {
		return "", false
	}
	pathValue := ""
	force := false
	for index := 1; index < len(command.Argv); index++ {
		value := command.Argv[index]
		switch strings.ToLower(value) {
		case "-path":
			index++
			if index >= len(command.Argv) || command.Argv[index] == "" ||
				pathValue != "" {
				return "", false
			}
			pathValue = command.Argv[index]
		case "-force":
			if force {
				return "", false
			}
			force = true
		default:
			if strings.HasPrefix(value, "-") || pathValue != "" {
				return "", false
			}
			pathValue = value
		}
	}
	canonical, ok := canonicalRegistryPath(pathValue)
	if !ok || !force {
		return "", false
	}
	canonical = strings.ToUpper(canonical)
	return canonical, exactWindowsUACHandlerPath(canonical)
}

func exactWindowsUACTrigger(command CommandFact) (string, bool) {
	if command.Program != "start-process" ||
		!hasFactOperation(command, OperationExecute) {
		return "", false
	}
	var target string
	switch len(command.Argv) {
	case 2:
		target = command.Argv[1]
	case 3:
		if !strings.EqualFold(command.Argv[1], "-FilePath") {
			return "", false
		}
		target = command.Argv[2]
	default:
		return "", false
	}
	canonical, ok := windowsCanonicalPathFactValue(target)
	if !ok {
		return "", false
	}
	parsed := parseWindowsPath(canonical)
	if !parsed.absolute || parsed.unresolved {
		return "", false
	}
	switch {
	case strings.EqualFold(parsed.normalized, "C:/Windows/System32/eventvwr.msc"):
		return "eventvwr.msc", true
	case strings.EqualFold(parsed.normalized, "C:/Windows/System32/fodhelper.exe"):
		return "fodhelper.exe", true
	case strings.EqualFold(parsed.normalized, "C:/Windows/System32/sdclt.exe"):
		return "sdclt.exe", true
	default:
		return "", false
	}
}

func exactWindowsUACStringType(value string) bool {
	switch value {
	case "", "REG_SZ", "REG_EXPAND_SZ", "STRING", "EXPANDSTRING":
		return true
	default:
		return false
	}
}

func exactWindowsUACHandlerPayload(value string) bool {
	if value == "" || strings.TrimSpace(value) != value {
		return false
	}
	lower := strings.ToLower(value)
	return !strings.ContainsAny(value, "`*?[]{}<>%!$") &&
		!strings.Contains(value, "${") && !strings.Contains(value, "$(") &&
		!strings.Contains(value, "#{") && !strings.Contains(value, "%{") &&
		!strings.Contains(value, "{{") && !strings.Contains(value, "}}") &&
		!strings.Contains(lower, "placeholder")
}
