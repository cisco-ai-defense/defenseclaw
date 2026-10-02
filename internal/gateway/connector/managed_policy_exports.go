// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// ManagedHookGroup is one vendor hook registration DefenseClaw publishes
// through machine policy: the event, its matcher (empty when the vendor
// event has none), the timeout in seconds, and whether it runs async.
type ManagedHookGroup struct {
	Event   string
	Matcher string
	Timeout int
	Async   bool
}

// ManagedHookGroupsForOS returns the hook registrations for connector's
// contract on goos, resolved from agentVersion ("" selects the connector's
// default contract). It exposes the same event matrices the per-user and
// Secure Client installers render, so standalone machine policy never
// drifts from the certified contracts. Only connectors with a machine
// policy route are supported.
func ManagedHookGroupsForOS(connectorName, agentVersion, goos string) ([]ManagedHookGroup, error) {
	name := normalizeConnectorName(connectorName)
	if name == "codex" && strings.TrimSpace(agentVersion) == "" {
		// A machine-wide requirements file serves every client version on
		// the host. Without a pinned version, publish the exact ten-group
		// matrix the Windows machine-requirements installer certifies,
		// which every supported Codex release accepts.
		out := make([]ManagedHookGroup, 0, len(codexHookGroups))
		for _, group := range codexHookGroups {
			out = append(out, ManagedHookGroup{Event: group.eventType, Matcher: group.matcher, Timeout: group.timeout})
		}
		return out, nil
	}
	resolution := resolveHookContractForOS(name, agentVersion, goos)
	contract := resolution.Contract
	if contract.ContractID == "" {
		return nil, fmt.Errorf("%s version %q does not resolve to a supported hook contract on %s", name, strings.TrimSpace(agentVersion), goos)
	}
	switch name {
	case "codex":
		registry := make(map[string]codexHookGroup, len(codexHookGroups)+1)
		for _, group := range codexHookGroups {
			registry[group.eventType] = group
		}
		registry[codexSessionEndHookGroup.eventType] = codexSessionEndHookGroup
		out := make([]ManagedHookGroup, 0, len(contract.Events))
		for _, event := range contract.Events {
			group, ok := registry[event]
			if !ok {
				return nil, fmt.Errorf("codex hook contract %s contains unregistered event %s", contract.ContractID, event)
			}
			if event == "SessionStart" &&
				(contract.ContractID == "codex-hooks-v3" ||
					contract.ContractID == "codex-hooks-v3-generic" ||
					contract.ContractID == "codex-hooks-v4") {
				group.matcher = "startup|resume|clear|compact"
			}
			out = append(out, ManagedHookGroup{Event: group.eventType, Matcher: group.matcher, Timeout: group.timeout})
		}
		return out, nil
	case "claudecode":
		registry := make(map[string]claudeCodeHookGroup, len(claudeCodeAllHookGroups))
		for _, group := range claudeCodeAllHookGroups {
			registry[group.eventType] = group
		}
		out := make([]ManagedHookGroup, 0, len(contract.Events))
		for _, event := range contract.Events {
			group, ok := registry[event]
			if !ok {
				return nil, fmt.Errorf("claudecode hook contract %s contains unregistered event %s", contract.ContractID, event)
			}
			out = append(out, ManagedHookGroup{Event: group.eventType, Matcher: group.matcher, Timeout: group.timeout, Async: group.async})
		}
		return out, nil
	case "cursor":
		out := make([]ManagedHookGroup, 0, len(cursorHookEvents))
		for _, event := range cursorHookEvents {
			out = append(out, ManagedHookGroup{Event: event, Timeout: windowsCursorEnterpriseHookTimeoutSeconds})
		}
		return out, nil
	case "copilot":
		events := contract.Events
		if len(events) == 0 {
			events = copilotCurrentHookEvents
		}
		out := make([]ManagedHookGroup, 0, len(events))
		for _, event := range events {
			if !ValidCopilotHookEvent(event) {
				return nil, fmt.Errorf("copilot hook contract %s contains unsupported event %s", contract.ContractID, event)
			}
			out = append(out, ManagedHookGroup{Event: event, Timeout: 30})
		}
		return out, nil
	default:
		return nil, fmt.Errorf("connector %s has no machine policy hook matrix", name)
	}
}

// WindowsCodexManagedHookCommand renders the exact Codex machine-requirements
// command the Windows Secure Client installer certifies for hookBinary. The
// standalone profile reuses it so both profiles launch the GUI-subsystem
// hook through the same exit-code-preserving PowerShell boundary.
func WindowsCodexManagedHookCommand(hookBinary string) string {
	return windowsCodexManagedHookCommand(hookBinary)
}

// WindowsCodexStandaloneManagedHookCommand renders the standalone profile's
// Codex machine-requirements command for one event: it binds the event and
// hookContract the hook requires and waits for the GUI-subsystem launcher,
// exactly as the standalone requirements writer publishes it.
func WindowsCodexStandaloneManagedHookCommand(hookBinary, event, hookContract string) string {
	return windowsCodexBoundManagedHookCommand(hookBinary, event, hookContract)
}

// CopilotVSCodeLocalManagedHookCommand renders the command DefenseClaw's
// VS Code Local harness hook file and agent plugin register for event: the
// administrator-owned hookBinary bound to the Local dialect. On Windows it
// is the exit-code-preserving PowerShell boundary, which runs the same from
// any shell VS Code or the Copilot CLI starts it in; elsewhere a POSIX
// command line. The foreign-hook guard recognizes exactly these strings.
func CopilotVSCodeLocalManagedHookCommand(goos, hookBinary, event string) string {
	if goos == "windows" {
		return windowsNativePowerShellHookCommandForBoundEvent("copilot", event, "", hookBinary,
			"--enterprise-managed", "--hook-surface", CopilotHookSurfaceVSCodeLocal)
	}
	return shellSingleQuote(hookBinary) + " hook --connector copilot --enterprise-managed --event " +
		shellSingleQuote(event) + " --hook-surface " + CopilotHookSurfaceVSCodeLocal
}

// WindowsAwaitedHookStatements returns the PowerShell statements that start
// the GUI-subsystem hook launcher, wait for it and exit with its status,
// keeping the process handle from the start so a launcher that exits at once
// still returns its status (see windowsAwaitedHookStatements).
func WindowsAwaitedHookStatements(hookBinary string, arguments []string) []string {
	return windowsAwaitedHookStatements(hookBinary, arguments)
}

// PowerShellQuoteLiteral returns one inert single-quoted PowerShell literal.
func PowerShellQuoteLiteral(value string) string {
	return powershellQuoteLiteral(value)
}

// PerUserOwnedHookCommands returns the exact hook command strings the
// per-user installer writes into connectorName's agent config for dataDir
// on this host, plus the Windows exec-form executable. The standalone
// foreign-hook guard treats exactly these as DefenseClaw's registrations;
// the guardian repairs the scripts they name when they drift.
func PerUserOwnedHookCommands(connectorName, dataDir string) []string {
	name := normalizeConnectorName(connectorName)
	conn, ok := NewDefaultRegistry().Get(name)
	if !ok || strings.TrimSpace(dataDir) == "" {
		return nil
	}
	opts := SetupOpts{DataDir: dataDir}
	commands := []string{}
	for _, needle := range ownedHookCommandNeedlesFor(runtime.GOOS, opts, conn) {
		commands = append(commands, needle)
		if runtime.GOOS != "windows" {
			commands = append(commands, shellWord(needle))
		}
	}
	if runtime.GOOS == "windows" {
		if owner, ok := conn.(HookScriptOwner); ok {
			for _, script := range owner.HookScriptNames(opts) {
				commands = append(commands, hookInvocationCommandFor("windows", name, filepath.Join(dataDir, "hooks", script)))
			}
		}
		commands = append(commands, defenseclawHookBinary())
	}
	return uniqueNonEmptyStrings(commands)
}
