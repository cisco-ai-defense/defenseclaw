//go:build windows

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
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Windows app and extension discovery is static, like
// standaloneWindowsAgentVersionExplain: the LocalSystem enumerator reads
// folder names and package metadata under the profile, refuses reparse
// chains, bounds every read, and executes nothing. Reading as the profile
// owner (impersonation) is not done yet. Layouts vendors do not document
// are marked "live check".

// windowsExtensionRoots are the VS Code-family extensions folders under a
// profile (https://code.visualstudio.com/docs/configure/extensions/extension-marketplace).
var windowsExtensionRoots = []struct{ host, dir string }{
	{"vscode", `.vscode\extensions`},
	{"vscode-insiders", `.vscode-insiders\extensions`},
	{"vscodium", `.vscode-oss\extensions`},
	{"cursor", `.cursor\extensions`},
	{"windsurf", `.windsurf\extensions`},
	{"kiro", `.kiro\extensions`},
	{"antigravity", `.antigravity\extensions`}, // live check
}

// windowsSurfaceExtensions maps a connector to its extension id and whether
// the extension version is its engine version (Claude Code bundles its CLI
// at the extension's version, https://code.claude.com/docs/en/vs-code; the
// Codex extension's engine version has no static source).
var windowsSurfaceExtensions = map[string]struct {
	id             string
	engineIsHost   bool
	desktopProbers []func(profileHome string) (connector.AgentSurface, bool)
}{
	"claudecode": {id: "anthropic.claude-code", engineIsHost: true, desktopProbers: []func(string) (connector.AgentSurface, bool){discoverWindowsClaudeDesktop}},
	"codex":      {id: "openai.chatgpt", desktopProbers: []func(string) (connector.AgentSurface, bool){discoverWindowsCodexApp}},
}

const windowsSurfaceMaxEntries = 4096

// DiscoverWindowsAgentSurfaces lists connectorName's app and extension
// installs under profileHome.
func DiscoverWindowsAgentSurfaces(profileHome, connectorName string) []connector.AgentSurface {
	profileHome = strings.TrimSpace(profileHome)
	probe, ok := windowsSurfaceExtensions[strings.ToLower(strings.TrimSpace(connectorName))]
	if !ok || !filepath.IsAbs(profileHome) {
		return nil
	}
	profileHome = filepath.Clean(profileHome)
	var out []connector.AgentSurface
	for _, root := range windowsExtensionRoots {
		dir, version := newestWindowsExtensionDir(filepath.Join(profileHome, root.dir), probe.id)
		if dir == "" {
			continue
		}
		surface := connector.AgentSurface{Surface: connector.HostSurfaceExtension, Host: root.host, Path: dir, HostVersion: version}
		if packageVersion, ok := readWindowsAgentVersionCandidate(filepath.Join(dir, "package.json")); ok {
			surface.HostVersion = packageVersion
		}
		if probe.engineIsHost {
			surface.EngineVersion = surface.HostVersion
		}
		out = append(out, surface)
	}
	for _, prober := range probe.desktopProbers {
		if surface, ok := prober(profileHome); ok {
			out = append(out, surface)
		}
	}
	return out
}

// discoverWindowsClaudeDesktop finds the Claude Code build Claude Desktop
// runs, kept as claude-code\<version> under its roaming data folder; the
// MSIX package keeps it in the package's LocalCache (live check).
func discoverWindowsClaudeDesktop(profileHome string) (connector.AgentSurface, bool) {
	dirs := []string{filepath.Join(profileHome, "AppData", "Roaming", "Claude", "claude-code")}
	if packages, _ := filepath.Glob(filepath.Join(profileHome, "AppData", "Local", "Packages", "Claude_*")); len(packages) != 0 {
		sort.Strings(packages)
		for _, pkg := range packages[:min(len(packages), 4)] {
			dirs = append(dirs, filepath.Join(pkg, "LocalCache", "Roaming", "Claude", "claude-code"))
		}
	}
	for _, dir := range dirs {
		if version := newestWindowsVersionDir(dir); version != "" {
			return connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", EngineVersion: version, Path: dir}, true
		}
	}
	return connector.AgentSurface{}, false
}

// discoverWindowsCodexApp reports the Codex app's MSIX package data folder.
// Its engine version has no static source (live check), so it is reported
// and never enrolled on its own; the host version comes from the package
// folder name under WindowsApps when LocalSystem can list it.
func discoverWindowsCodexApp(profileHome string) (connector.AgentSurface, bool) {
	packages, _ := filepath.Glob(filepath.Join(profileHome, "AppData", "Local", "Packages", "OpenAI.Codex_*"))
	for _, pkg := range packages {
		if winpath.RejectReparseChain(pkg) != nil {
			continue
		}
		if info, err := os.Lstat(pkg); err != nil || !info.IsDir() {
			continue
		}
		surface := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "codex-app", Path: pkg}
		if programFiles, err := winpath.TrustedProgramFiles(); err == nil {
			surface.HostVersion = newestWindowsPackageVersion(filepath.Join(programFiles, "WindowsApps"), "OpenAI.Codex_")
		}
		return surface, true
	}
	return connector.AgentSurface{}, false
}

// newestWindowsExtensionDir returns the newest "<id>-<version>[-<platform>]"
// folder of extension id under root and its version, leaving out folders
// the editor marked obsolete (.obsolete format is a live check).
func newestWindowsExtensionDir(root, id string) (string, string) {
	entries := readWindowsDirBounded(root)
	obsolete := map[string]bool{}
	if data, err := readBoundedWindowsAgentPackageJSON(filepath.Join(root, ".obsolete")); err == nil {
		_ = json.Unmarshal(data, &obsolete)
	}
	prefix := strings.ToLower(id) + "-"
	best, bestVersion := "", ""
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(strings.ToLower(name), prefix) || obsolete[name] {
			continue
		}
		version := name[len(prefix):]
		if i := strings.IndexByte(version, '-'); i >= 0 {
			version = version[:i]
		}
		if !windowsNativeClaudeVersionName(version) {
			continue
		}
		if best == "" || compareWindowsEnterpriseVersion(version, bestVersion) > 0 {
			best, bestVersion = filepath.Join(root, name), version
		}
	}
	return best, bestVersion
}

// newestWindowsVersionDir returns the highest dotted-numeric folder name
// under dir.
func newestWindowsVersionDir(dir string) string {
	best := ""
	for _, entry := range readWindowsDirBounded(dir) {
		name := entry.Name()
		if entry.IsDir() && windowsNativeClaudeVersionName(name) && (best == "" || compareWindowsEnterpriseVersion(name, best) > 0) {
			best = name
		}
	}
	return best
}

// newestWindowsPackageVersion reads "<prefix><version>_<arch>__<publisher>"
// package folder names.
func newestWindowsPackageVersion(dir, prefix string) string {
	best := ""
	for _, entry := range readWindowsDirBounded(dir) {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		version, _, _ := strings.Cut(name[len(prefix):], "_")
		if windowsNativeClaudeVersionName(version) && (best == "" || compareWindowsEnterpriseVersion(version, best) > 0) {
			best = version
		}
	}
	return best
}

func readWindowsDirBounded(dir string) []os.DirEntry {
	if winpath.RejectReparseChain(dir) != nil {
		return nil
	}
	file, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer file.Close()
	entries, _ := file.ReadDir(windowsSurfaceMaxEntries)
	return entries
}

// windowsStandaloneSurfaceVersion is the row version of a profile with no
// agent CLI: the oldest engine version among its admitted app and extension
// surfaces, or "". Rejected surfaces are reported.
func windowsStandaloneSurfaceVersion(row *ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext) string {
	name := strings.ToLower(strings.TrimSpace(row.Connector))
	admission := admitSurfaces(name, UnverifiedVersionsFor(name), DiscoverWindowsAgentSurfaces(row.UserHome, name))
	enrolled := len(admission.admitted) != 0
	for _, rejected := range admission.rejected {
		consequence, refusal := "", RefusalMissing
		switch {
		case enrolled && !rejected.refused:
			continue
		case enrolled:
			consequence = "the user's admitted " + name + " install shares its hooks and its hook calls do not name their surface, so nothing refuses it"
		case windowsStandaloneMachinePolicyConnector(name):
			consequence, refusal = "its machine-policy hooks refuse this user's tool calls until it is enrolled", RefusalEnforced
		default:
			consequence = "it runs without DefenseClaw hooks"
		}
		if rowContext.report != nil {
			rowContext.report(rejected.unprotected(rowContext.user, canonicalManifestTargetSID(row.SID), nil, name, consequence, refusal))
		}
	}
	version := admission.rowVersion("")
	if version != "" {
		logfSafely(logf, row.SID, "(SID, "+name+") no agent CLI; enrolling at "+version+", the oldest admitted "+admission.surface+" engine version")
	}
	return version
}
