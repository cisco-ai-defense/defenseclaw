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
	"path"
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
		return windowsGuardedPowerShellHookCommand(CopilotRemovedDeploymentGuardPowerShell(hookBinary),
			"copilot", event, hookBinary, "--enterprise-managed", "--hook-surface", CopilotHookSurfaceVSCodeLocal)
	}
	return CopilotRemovedDeploymentGuardPOSIX(hookBinary) + shellSingleQuote(hookBinary) +
		" hook --connector copilot --enterprise-managed --event " + shellSingleQuote(event) +
		" --hook-surface " + CopilotHookSurfaceVSCodeLocal
}

// CopilotVSCodeLocalPriorReleaseHookCommand is the command DefenseClaw 1.0.0
// rendered for event in the VS Code Local hook file and the Copilot plugin:
// CopilotVSCodeLocalManagedHookCommand without the removed-deployment guard
// (GAP-0999, GAP-1043). Each enrolled user of a managed 1.0.0 install that
// upgrades holds it until the hook guardian's next pass rewrites the files,
// so it stays DefenseClaw's own: ensure replaces it, uninstall and the
// orphan cleanup remove it, and the foreign-hook guard never denies it
// (GAP-1232). Supported upgrade path: 1.0.0 to any later 1.x release; keep
// it while 1.0.0 is a supported upgrade source.
func CopilotVSCodeLocalPriorReleaseHookCommand(goos, hookBinary, event string) string {
	if goos == "windows" {
		return windowsNativePowerShellHookCommandForBoundEvent("copilot", event, "", hookBinary,
			"--enterprise-managed", "--hook-surface", CopilotHookSurfaceVSCodeLocal)
	}
	return shellSingleQuote(hookBinary) + " hook --connector copilot --enterprise-managed --event " +
		shellSingleQuote(event) + " --hook-surface " + CopilotHookSurfaceVSCodeLocal
}

// managedDeploymentMarker is the file whose presence says the managed
// deployment that owns hookBinary is still installed: the gateway binary in
// the same administrator-owned folder. Uninstall and package removal take
// both away; an antivirus that quarantines the hook binary leaves the
// gateway binary in place.
func managedDeploymentMarker(goos, hookBinary string) string {
	if goos == "windows" {
		dir := ""
		if i := strings.LastIndexAny(hookBinary, `\/`); i >= 0 {
			dir = hookBinary[:i]
		}
		return dir + `\` + windowsGatewayBinaryName
	}
	return path.Join(path.Dir(hookBinary), "defenseclaw-gateway")
}

// CopilotRemovedDeploymentGuardPOSIX is the start of a POSIX Copilot hook
// command: once the managed deployment is removed (neither the hook binary
// nor the gateway binary beside it exists), the command exits 0, so the
// registration a running Copilot process or a signed-out account keeps is
// inert. Copilot denies every call whose hook fails, so a dangling command
// made that session unusable (GAP-0999, GAP-1043). With the deployment
// still installed and only the hook binary missing, the command still runs
// it and fails, and Copilot denies: a quarantined hook never fails open
// (GAP-0935).
func CopilotRemovedDeploymentGuardPOSIX(hookBinary string) string {
	return "[ -e " + shellSingleQuote(hookBinary) + " ] || [ -e " +
		shellSingleQuote(managedDeploymentMarker("linux", hookBinary)) + " ] || exit 0; exec "
}

// CopilotRemovedDeploymentGuardPowerShell is CopilotRemovedDeploymentGuardPOSIX
// as one PowerShell statement for the Windows Copilot commands. Constrained
// Language mode refuses the .NET call, so it uses Test-Path there.
func CopilotRemovedDeploymentGuardPowerShell(hookBinary string) string {
	hook := powershellQuoteLiteral(hookBinary)
	marker := powershellQuoteLiteral(managedDeploymentMarker("windows", hookBinary))
	return "if ($ExecutionContext.SessionState.LanguageMode -ne 'FullLanguage') { " +
		"if (-not (Microsoft.PowerShell.Management\\Test-Path -LiteralPath " + hook + ") -and " +
		"-not (Microsoft.PowerShell.Management\\Test-Path -LiteralPath " + marker + ")) { exit 0 } } " +
		"elseif (-not [System.IO.File]::Exists(" + hook + ") -and -not [System.IO.File]::Exists(" + marker + ")) { exit 0 }"
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
	return perUserOwnedHookCommands(connectorName, dataDir, "")
}

// PerUserOwnedHookCommandsForBinary adds, on Windows, the commands the
// per-user installer renders for the administrator's hookBinary. A hook
// process runs the launcher rather than the installed gateway, so the
// launcher it resolves for itself is not the one the guardian registered.
func PerUserOwnedHookCommandsForBinary(connectorName, dataDir, hookBinary string) []string {
	return perUserOwnedHookCommands(connectorName, dataDir, hookBinary)
}

func perUserOwnedHookCommands(connectorName, dataDir, hookBinary string) []string {
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
		binaries := []string{defenseclawHookBinary()}
		if published := strings.TrimSpace(hookBinary); published != "" && !strings.EqualFold(published, binaries[0]) {
			binaries = append(binaries, published)
		}
		for _, binary := range binaries {
			resolve := func() string { return binary }
			if owner, ok := conn.(HookScriptOwner); ok {
				for _, script := range owner.HookScriptNames(opts) {
					commands = append(commands, hookInvocationCommandWith("windows", name, filepath.Join(dataDir, "hooks", script), resolve))
				}
			}
			if name == "antigravity" {
				for _, event := range antigravityLifecycleEvents {
					commands = append(commands, windowsNativePowerShellHookCommandForEvent(name, event, binary))
				}
			}
			commands = append(commands, binary)
		}
	}
	return uniqueNonEmptyStrings(commands)
}
