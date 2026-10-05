// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// windowsStandalonePerUserConnectors are the hook connectors the Windows
// standalone profile manages through an impersonated per-user footprint.
// They have no vendor machine policy that can carry DefenseClaw by itself, so
// the guardian registers the administrator-owned hook binary in each enrolled
// user's own agent configuration and repairs it.
//
// The value records whether the connector's runtime executes the DefenseClaw
// hook binary (true) or is only an in-agent plugin that calls the gateway
// itself (false). Only hook-binary connectors get a protected runtime
// generation and a per-user machine enrollment: a plugin that never executes
// defenseclaw-hook.exe cannot consume one. OpenCode counts as a hook-binary
// connector: on the machine policy route its managed plugin runs the hook
// binary for every event, so every OpenCode row publishes a generation.
//
// The Secure Client profile never manages these connectors.
var windowsStandalonePerUserConnectors = map[string]bool{
	"copilot":     true,
	"antigravity": true,
	"devin":       true,
	"hermes":      true,
	"kiro":        true,
	"opencode":    true,
	"amp":         false,
}

// windowsStandaloneInAgentPluginConnector reports whether the connector's
// per-user registration is an in-agent plugin file (Amp, OpenCode) rendered
// with the standalone install marker.
func windowsStandaloneInAgentPluginConnector(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "amp", "opencode":
		return true
	default:
		return false
	}
}

// windowsStandaloneRuntimeOnlyConnectors are per-user connectors whose hook
// registration is vendor machine policy on Windows (GitHub Copilot loads
// %ProgramData%\GitHub\Copilot\policy.d before every other source), so the
// guardian writes only their per-user DefenseClaw runtime and never the
// user's own agent configuration. A second, user-level registration would
// run the hook twice. OpenCode joins them while its machine policy is in
// force (windowsStandaloneRuntimeOnlyInstall); its removal stays on the
// per-user path, which also removes a plugin left from the per-user route.
var windowsStandaloneRuntimeOnlyConnectors = map[string]bool{
	"copilot": true,
}

func windowsStandaloneRuntimeOnlyConnector(name string) bool {
	return windowsStandaloneRuntimeOnlyConnectors[strings.ToLower(strings.TrimSpace(name))]
}

// windowsEnterpriseRefusedConnectors names connectors native Windows
// enterprise management refuses outright, with the reason shown to the
// administrator.
var windowsEnterpriseRefusedConnectors = map[string]string{
	"openhands": "OpenHands CLI requires WSL on Windows; DefenseClaw has no WSL connector path",
	"omnigent":  "OmniGent enforces through an in-process policy API with no hook boundary a standard user cannot remove; it is not managed on Windows",
	"openclaw":  "OpenClaw requires the guardrail proxy, which the Windows enterprise profile does not host",
	"zeptoclaw": "ZeptoClaw requires the guardrail proxy, which the Windows enterprise profile does not host",
}

// windowsStandalonePerUserConnector reports whether name is a standalone
// per-user connector and whether its runtime is the hook binary.
func windowsStandalonePerUserConnector(name string) (hookBinary, ok bool) {
	hookBinary, ok = windowsStandalonePerUserConnectors[strings.ToLower(strings.TrimSpace(name))]
	return hookBinary, ok
}

// WindowsStandalonePerUserConnectorNames returns the per-user connector names
// in a stable order.
func WindowsStandalonePerUserConnectorNames() []string {
	return []string{"amp", "antigravity", "copilot", "devin", "hermes", "kiro", "opencode"}
}

// WindowsEnterpriseRefusedConnectorReason returns the administrator-facing
// reason a connector is refused by Windows enterprise management, or "".
func WindowsEnterpriseRefusedConnectorReason(name string) string {
	return windowsEnterpriseRefusedConnectors[strings.ToLower(strings.TrimSpace(name))]
}

// isWindowsStandalonePerUserBuiltin is the concrete-type check for the
// per-user connectors: a plugin can claim a built-in name while running
// arbitrary code from Setup or Teardown.
func isWindowsStandalonePerUserBuiltin(name string, conn connector.Connector) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "amp":
		return connector.IsBuiltinAMPConnector(conn)
	case "copilot", "antigravity", "devin", "hermes", "opencode":
		return connector.IsBuiltinHookOnlyConnector(conn, strings.ToLower(strings.TrimSpace(name)))
	case "kiro":
		_, ok := conn.(*connector.KiroConnector)
		return ok
	default:
		return false
	}
}
