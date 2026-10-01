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

import "strings"

// An agent reaches DefenseClaw through one of several host surfaces: its
// terminal CLI, a desktop app, or an editor extension. Each surface embeds
// an agent engine (the component that runs the vendor hooks) inside a host
// product with its own version. Only the engine version can select a hook
// contract: a host version (the Codex extension's 26.5908.31748, an IDE
// launcher's version) says nothing about the hook payloads the engine sends,
// yet it would satisfy an open-ended contract range such as
// codex-hooks-v4 (>=0.145.0).
//
// Vendor sources for the surface model:
//   - Claude Code reads managed settings in the terminal, the VS Code and
//     JetBrains extensions, the desktop app's Code tab and the Agent SDK
//     (https://code.claude.com/docs/en/managed-settings); the VS Code
//     extension bundles its own CLI at the extension's version
//     (https://code.claude.com/docs/en/vs-code).
//   - Codex runs hooks in the CLI, the IDE extension, the desktop app and
//     app-server (https://learn.chatgpt.com/docs/hooks).
//   - Antigravity's IDE, 2.0 and CLI share one hook file
//     (https://antigravity.google/docs/hooks).

// Host surfaces.
const (
	HostSurfaceCLI       = "cli"
	HostSurfaceDesktop   = "desktop"
	HostSurfaceExtension = "extension"
)

// Unverified-version policies (enterprise.enrollment.unverified_versions).
const (
	// UnverifiedVersionsReport admits a surface whose engine version
	// resolves a hook contract even when that surface has not been
	// live-verified, and reports it. The default: unknown but compatible
	// versions are supported.
	UnverifiedVersionsReport = "report"
	// UnverifiedVersionsRefuse admits only live-verified surfaces.
	UnverifiedVersionsRefuse = "refuse"
)

// AgentSurface is one install of an agent on one host surface.
type AgentSurface struct {
	Surface string `json:"surface"`
	// Host names the host product ("vscode", "cursor", "claude-desktop").
	Host string `json:"host,omitempty"`
	// EngineVersion is the embedded engine's version, or empty when no
	// static or safe source for it exists.
	EngineVersion string `json:"engine_version,omitempty"`
	// HostVersion is the host product's own version. It never selects a
	// hook contract.
	HostVersion string `json:"host_version,omitempty"`
	Path        string `json:"path,omitempty"`
}

// SurfaceResolution is how one surface maps to a hook contract.
type SurfaceResolution struct {
	HookContractResolution
	Surface string
	// Verified: DefenseClaw hooks were live-verified on this surface.
	Verified bool
}

// liveVerifiedSurfaces lists, per connector, the non-CLI surfaces whose
// hook delivery has been verified live. Cursor's hooks are the desktop
// app's own, and its contracts are ranges of the app version.
var liveVerifiedSurfaces = map[string]map[string]bool{
	"cursor": {HostSurfaceDesktop: true},
}

// SurfaceLiveVerified reports whether surface is live-verified for
// connectorName. The CLI surface always is.
func SurfaceLiveVerified(connectorName, surface string) bool {
	surface = strings.ToLower(strings.TrimSpace(surface))
	if surface == "" || surface == HostSurfaceCLI {
		return true
	}
	return liveVerifiedSurfaces[normalizeConnectorName(connectorName)][surface]
}

// ResolveSurfaceHookContract resolves the hook contract of one surface
// from its engine version. For the CLI surface it is ResolveHookContract.
// A non-CLI surface without an engine version resolves to unknown: the
// connector's default contract for an unversioned CLI is never assumed
// for an app or extension, and a host version is never consulted.
func ResolveSurfaceHookContract(connectorName, surface, engineVersion string) SurfaceResolution {
	surface = strings.ToLower(strings.TrimSpace(surface))
	if surface == "" {
		surface = HostSurfaceCLI
	}
	out := SurfaceResolution{Surface: surface, Verified: SurfaceLiveVerified(connectorName, surface)}
	if surface != HostSurfaceCLI && strings.TrimSpace(engineVersion) == "" {
		out.HookContractResolution = HookContractResolution{
			Connector: normalizeConnectorName(connectorName),
			Status:    HookCompatibilityUnknown,
			Reason:    "no engine version for this surface; a host version never selects a hook contract",
		}
		return out
	}
	out.HookContractResolution = ResolveHookContract(connectorName, engineVersion)
	return out
}

// Admitted reports whether the surface may be enrolled under policy
// (UnverifiedVersionsReport or UnverifiedVersionsRefuse), and why not.
func (r SurfaceResolution) Admitted(policy string) (bool, string) {
	switch r.Status {
	case HookCompatibilityKnown, HookCompatibilityNotGated:
	default:
		return false, r.Reason
	}
	if r.Verified || !strings.EqualFold(strings.TrimSpace(policy), UnverifiedVersionsRefuse) {
		return true, ""
	}
	return false, "hook delivery on the " + r.Surface + " surface is not live-verified, and enterprise.enrollment.unverified_versions is refuse"
}

// A hook call names the surface it comes from (hookexec.AgentSurfaceHeader)
// so the gateway can refuse an unverified app or extension of a user who is
// enrolled through the agent's CLI: every surface of a machine-policy agent
// runs the same hook command, so the command itself cannot tell them apart.
// The hook classifies its caller from two signals, in this order:
//   - the executable of the agent engine that runs the hook (the kernel's
//     record of the process): an engine an editor extension bundles lives
//     in that extension's folder, wherever the extensions folder is
//     (VSCODE_EXTENSIONS and --extensions-dir included), and a desktop
//     app's engine lives in the app's bundle or data folder;
//   - the surface variable the vendor sets in the engine's environment
//     (Claude Code's CLAUDE_CODE_ENTRYPOINT, the originator the Codex IDE
//     extension and app set for their app-server). Neither variable is
//     documented as an interface; their values are a live check.
//
// Both signals are the user's to influence: the classification enforces an
// administrator's surface policy for honest callers, it is not an identity.
// A caller neither signal names is unclassified ("") and never refused on
// its surface.

// agentSurfaceMarkers are lower-case, slash-separated path fragments of an
// agent engine's executable, per connector and surface.
var agentSurfaceMarkers = map[string]map[string][]string{
	"claudecode": {
		HostSurfaceExtension: {"/anthropic.claude-code-", "/jetbrains/"},
		HostSurfaceDesktop: {
			"/claude/claude-code/", "/claude.app/", "/windowsapps/claude_",
			"/packages/claude_",
		},
	},
	"codex": {
		HostSurfaceExtension: {"/openai.chatgpt-", "/jetbrains/"},
		HostSurfaceDesktop:   {"/codex.app/", "/windowsapps/openai.codex_", "/opt/chatgpt/", "/chatgpt.app/"},
	},
	"antigravity": {
		HostSurfaceDesktop: {"/antigravity.app/", "/usr/share/antigravity/", "/opt/antigravity/", "/programs/antigravity/"},
	},
	"cursor": {
		HostSurfaceDesktop: {"/cursor.app/", "/usr/share/cursor/", "/opt/cursor/", "/programs/cursor/"},
	},
}

// agentSurfaceCLINames are engine executables that are always the CLI
// surface, even where a desktop app's bundle carries them.
var agentSurfaceCLINames = map[string]map[string]bool{
	"antigravity": {"agy": true, "agy.exe": true},
	"cursor":      {"cursor-agent": true, "cursor-agent.exe": true},
}

// agentSurfaceVariables maps a vendor surface variable's value (lower
// case) to a surface, per connector.
var agentSurfaceVariables = map[string]struct {
	name   string
	values map[string]string
}{
	"claudecode": {"CLAUDE_CODE_ENTRYPOINT", map[string]string{
		"cli": HostSurfaceCLI, "claude-vscode": HostSurfaceExtension, "claude-desktop": HostSurfaceDesktop,
	}},
	"codex": {"CODEX_INTERNAL_ORIGINATOR_OVERRIDE", map[string]string{
		"codex_cli_rs": HostSurfaceCLI, "codex_vscode": HostSurfaceExtension, "codex desktop": HostSurfaceDesktop,
		"codex_desktop": HostSurfaceDesktop,
	}},
}

// ClassifyAgentSurface names the surface (HostSurfaceCLI, ...Desktop or
// ...Extension) of a hook call of connectorName whose agent engine runs
// executable with the environment getenv reads, or "" when neither names
// one.
func ClassifyAgentSurface(connectorName, executable string, getenv func(string) string) string {
	name := normalizeConnectorName(connectorName)
	if path := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(executable), `\`, "/")); path != "" {
		if agentSurfaceCLINames[name][path[strings.LastIndex(path, "/")+1:]] {
			return HostSurfaceCLI
		}
		for _, surface := range []string{HostSurfaceExtension, HostSurfaceDesktop} {
			for _, marker := range agentSurfaceMarkers[name][surface] {
				if strings.Contains(path, marker) {
					return surface
				}
			}
		}
	}
	if variable, ok := agentSurfaceVariables[name]; ok && getenv != nil {
		if surface, ok := variable.values[strings.ToLower(strings.TrimSpace(getenv(variable.name)))]; ok {
			return surface
		}
	}
	return ""
}

// ValidHostSurface returns surface when it names a host surface, else "".
func ValidHostSurface(surface string) string {
	switch surface = strings.ToLower(strings.TrimSpace(surface)); surface {
	case HostSurfaceCLI, HostSurfaceDesktop, HostSurfaceExtension:
		return surface
	}
	return ""
}

// SurfaceRefused reports whether a hook call of connectorName from surface
// is refused under policy: unverified_versions: refuse admits only
// live-verified surfaces. An unclassified or CLI call never is.
func SurfaceRefused(connectorName, surface, policy string) bool {
	surface = ValidHostSurface(surface)
	if surface == "" || surface == HostSurfaceCLI || !strings.EqualFold(strings.TrimSpace(policy), UnverifiedVersionsRefuse) {
		return false
	}
	return !SurfaceLiveVerified(connectorName, surface)
}

// CompareAgentVersions orders two agent versions by their normalized
// major.minor.patch.
func CompareAgentVersions(a, b string) int { return compareVersion(a, b) }
