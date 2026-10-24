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
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows/registry"
)

// Windows app and extension discovery is static, like
// standaloneWindowsAgentVersionExplain: it reads folder names and package
// metadata, refuses reparse chains, bounds every read, and executes
// nothing. Every read of a user-writable location (the profile's extension
// folders, app data and package folders, and a relocated VSCODE_EXTENSIONS
// folder) runs under the profile owner's active-session token
// (windowsSurfaceReadAs), so it can reach nothing the user could not; only
// administrator-protected sources (WindowsApps) are read as LocalSystem. A
// signed-out user has no token, so their surfaces are discovered after
// they sign in. Layouts vendors do not document are marked "live check".

// windowsSurfaceReadAs runs fn under the token of the profile owner sid
// (replaceable in tests).
var windowsSurfaceReadAs = func(sid, profileHome string, fn func() error) error {
	return runAsTarget(TargetCredentials{UserHome: profileHome, SID: sid}, fn)
}

// windowsUserEnvironment reads a value of the user's persistent
// environment (HKU\<sid>\Environment), "" when unset (replaceable in
// tests). The hive is loaded while the user is signed in.
var windowsUserEnvironment = func(sid, name string) string {
	key, err := registry.OpenKey(registry.USERS, sid+`\Environment`, registry.QUERY_VALUE)
	if err != nil {
		return ""
	}
	defer key.Close()
	value, _, err := key.GetStringValue(name)
	if err != nil {
		return ""
	}
	return value
}

var windowsSurfaceTrustedProgramFiles = winpath.TrustedProgramFiles

// windowsRelocatedExtensionsRoot is the VS Code extensions folder the
// user's persistent VSCODE_EXTENSIONS names, or "". %USERPROFILE%,
// %APPDATA% and %LOCALAPPDATA% are expanded to the profile's folders; any
// other variable leaves it unresolved. A folder set only for one launch
// (--extensions-dir, or a variable set in one shell) has no persistent
// source; the hook still names such an extension's calls by the engine's
// path (connector.ClassifyAgentSurface).
func windowsRelocatedExtensionsRoot(sid, profileHome string) string {
	value := strings.TrimSpace(windowsUserEnvironment(sid, "VSCODE_EXTENSIONS"))
	if value == "" {
		return ""
	}
	for variable, dir := range map[string]string{
		"%USERPROFILE%":  profileHome,
		"%APPDATA%":      filepath.Join(profileHome, "AppData", "Roaming"),
		"%LOCALAPPDATA%": filepath.Join(profileHome, "AppData", "Local"),
	} {
		if len(value) >= len(variable) && strings.EqualFold(value[:len(variable)], variable) {
			value = dir + value[len(variable):]
		}
	}
	if strings.Contains(value, "%") || !filepath.IsAbs(value) {
		return ""
	}
	return filepath.Clean(value)
}

// windowsExtensionRoots are the VS Code-family extensions folders under a
// profile (https://code.visualstudio.com/docs/configure/extensions/extension-marketplace).
var windowsExtensionRoots = []struct{ host, dir string }{
	{"vscode", `.vscode\extensions`},
	{"vscode-insiders", `.vscode-insiders\extensions`},
	{"vscodium", `.vscode-oss\extensions`},
	{"cursor", `.cursor\extensions`},
	{legacyconnector.VendorToken, legacyconnector.InventoryDotDirs[0] + `\extensions`}, // Devin Desktop, pre-rename folder; live check
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
	desktopProbers []func(profileHome string) (connector.AgentSurface, bool, error)
}{
	"claudecode": {id: "anthropic.claude-code", engineIsHost: true, desktopProbers: []func(string) (connector.AgentSurface, bool, error){discoverWindowsClaudeDesktop}},
	"codex":      {id: "openai.chatgpt", desktopProbers: []func(string) (connector.AgentSurface, bool, error){discoverWindowsCodexApp}},
	// Devin Desktop has no extension (surface_probes_devin.go).
	"devin": {desktopProbers: []func(string) (connector.AgentSurface, bool, error){discoverWindowsDevinDesktop}},
}

const windowsSurfaceMaxEntries = 4096

// discoverWindowsAgentSurfaces distinguishes complete extension roots from
// overflowing app and extension roots. An overflowing root supplies observed
// warnings but cannot select a row version because a newer build may be beyond
// its bound.
func discoverWindowsAgentSurfaces(sid, profileHome, connectorName string) ([]connector.AgentSurface, []connector.AgentSurface, error) {
	profileHome = strings.TrimSpace(profileHome)
	probe, ok := windowsSurfaceExtensions[strings.ToLower(strings.TrimSpace(connectorName))]
	if !ok || !filepath.IsAbs(profileHome) {
		return nil, nil, nil
	}
	profileHome = filepath.Clean(profileHome)
	roots := make([]struct{ host, dir string }, 0, len(windowsExtensionRoots)+1)
	for _, root := range windowsExtensionRoots {
		if probe.id == "" {
			break
		}
		roots = append(roots, struct{ host, dir string }{root.host, filepath.Join(profileHome, root.dir)})
	}
	if relocated := windowsRelocatedExtensionsRoot(sid, profileHome); probe.id != "" && relocated != "" {
		roots = append(roots, struct{ host, dir string }{"vscode", relocated})
	}
	var out []connector.AgentSurface
	var completeIndexes []int
	incompleteIndexes := map[int]bool{}
	var scanErr error
	readErr := windowsSurfaceReadAs(sid, profileHome, func() error {
		seen := map[string]bool{}
		for _, root := range roots {
			dir, version, err := newestWindowsExtensionDir(root.dir, probe.id)
			if err != nil {
				scanErr = errors.Join(scanErr, err)
			}
			if dir == "" || seen[strings.ToLower(dir)] {
				continue
			}
			seen[strings.ToLower(dir)] = true
			surface := connector.AgentSurface{Surface: connector.HostSurfaceExtension, Host: root.host, Path: dir, HostVersion: version}
			if packageVersion, ok := readWindowsAgentVersionCandidate(filepath.Join(dir, "package.json")); ok {
				surface.HostVersion = packageVersion
			}
			if probe.engineIsHost {
				surface.EngineVersion = surface.HostVersion
			}
			out = append(out, surface)
			if err == nil {
				completeIndexes = append(completeIndexes, len(out)-1)
			}
		}
		for _, prober := range probe.desktopProbers {
			surface, ok, err := prober(profileHome)
			scanErr = errors.Join(scanErr, err)
			if ok {
				out = append(out, surface)
				if err == nil {
					completeIndexes = append(completeIndexes, len(out)-1)
				}
			}
		}
		return nil
	})
	// Administrator-protected package folders are read as LocalSystem.
	for i := range out {
		if out[i].Host == "codex-app" {
			if programFiles, err := windowsSurfaceTrustedProgramFiles(); err == nil {
				version, versionErr := newestWindowsPackageVersion(filepath.Join(programFiles, "WindowsApps"), "OpenAI.Codex_")
				out[i].HostVersion = version
				if versionErr != nil {
					scanErr = errors.Join(scanErr, versionErr)
					incompleteIndexes[i] = true
				}
			}
		}
	}
	var complete []connector.AgentSurface
	if readErr == nil {
		for _, i := range completeIndexes {
			if !incompleteIndexes[i] {
				complete = append(complete, out[i])
			}
		}
	}
	return out, complete, errors.Join(scanErr, readErr)
}

// discoverWindowsClaudeDesktop finds the Claude Code build Claude Desktop
// runs, kept as claude-code\<version> under its roaming data folder; the
// MSIX package keeps it in the package's LocalCache (live check).
func discoverWindowsClaudeDesktop(profileHome string) (connector.AgentSurface, bool, error) {
	dirs := []string{filepath.Join(profileHome, "AppData", "Roaming", "Claude", "claude-code")}
	if packages, _ := filepath.Glob(filepath.Join(profileHome, "AppData", "Local", "Packages", "Claude_*")); len(packages) != 0 {
		sort.Strings(packages)
		for _, pkg := range packages[:min(len(packages), 4)] {
			dirs = append(dirs, filepath.Join(pkg, "LocalCache", "Roaming", "Claude", "claude-code"))
		}
	}
	var scanErr error
	var best connector.AgentSurface
	for _, dir := range dirs {
		version, err := newestWindowsVersionDir(dir)
		scanErr = errors.Join(scanErr, err)
		if version != "" && (best.EngineVersion == "" || compareWindowsEnterpriseVersion(version, best.EngineVersion) > 0) {
			best = connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", EngineVersion: version, Path: dir}
		}
	}
	return best, best.EngineVersion != "", scanErr
}

// discoverWindowsCodexApp reports the Codex app's MSIX package data folder.
// Its engine version has no static source (live check), so it is reported
// and never enrolled on its own; discovery takes the
// host version from the package folder name under WindowsApps.
func discoverWindowsCodexApp(profileHome string) (connector.AgentSurface, bool, error) {
	packages, _ := filepath.Glob(filepath.Join(profileHome, "AppData", "Local", "Packages", "OpenAI.Codex_*"))
	for _, pkg := range packages {
		if winpath.RejectReparseChain(pkg) != nil {
			continue
		}
		if info, err := os.Lstat(pkg); err != nil || !info.IsDir() {
			continue
		}
		return connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "codex-app", Path: pkg}, true, nil
	}
	return connector.AgentSurface{}, false, nil
}

// discoverWindowsDevinDesktop finds Devin Desktop's per-user install
// (%LOCALAPPDATA%\Programs\Devin) or machine install (%ProgramFiles%\Devin)
// and reads the engine version from the man page of the Devin CLI it
// bundles.
func discoverWindowsDevinDesktop(profileHome string) (connector.AgentSurface, bool, error) {
	dirs := []string{filepath.Join(profileHome, "AppData", "Local", "Programs", "Devin")}
	if programFiles, err := winpath.TrustedProgramFiles(); err == nil {
		dirs = append(dirs, filepath.Join(programFiles, "Devin"))
	}
	for _, dir := range dirs {
		if winpath.RejectReparseChain(dir) != nil {
			continue
		}
		if info, err := os.Lstat(filepath.Join(dir, "Devin.exe")); err != nil || !info.Mode().IsRegular() {
			continue
		}
		surface := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "devin-desktop", Path: dir}
		if data, err := readBoundedWindowsAgentPackageJSON(devinDesktopManPage(filepath.Join(dir, "resources", "app"))); err == nil {
			if version := parseDevinManPageVersion(data); isValidWindowsAgentVersion(version) {
				surface.EngineVersion = version
			}
		}
		return surface, true, nil
	}
	return connector.AgentSurface{}, false, nil
}

// newestWindowsExtensionDir returns the newest "<id>-<version>[-<platform>]"
// folder of extension id under root and its version, leaving out folders
// the editor marked obsolete (.obsolete format is a live check).
func newestWindowsExtensionDir(root, id string) (string, string, error) {
	entries, overflow := readWindowsDirBounded(root)
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
	if overflow {
		return best, bestVersion, fmt.Errorf("extension folder %s has more than %d entries", root, windowsSurfaceMaxEntries)
	}
	return best, bestVersion, nil
}

// newestWindowsVersionDir returns the highest dotted-numeric folder name
// under dir.
func newestWindowsVersionDir(dir string) (string, error) {
	best := ""
	entries, overflow := readWindowsDirBounded(dir)
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() && windowsNativeClaudeVersionName(name) && (best == "" || compareWindowsEnterpriseVersion(name, best) > 0) {
			best = name
		}
	}
	if overflow {
		return best, fmt.Errorf("version folder %s has more than %d entries", dir, windowsSurfaceMaxEntries)
	}
	return best, nil
}

// newestWindowsPackageVersion reads "<prefix><version>_<arch>__<publisher>"
// package folder names.
func newestWindowsPackageVersion(dir, prefix string) (string, error) {
	best := ""
	entries, overflow := readWindowsDirBounded(dir)
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(name, prefix) {
			continue
		}
		version, _, _ := strings.Cut(name[len(prefix):], "_")
		if windowsNativeClaudeVersionName(version) && (best == "" || compareWindowsEnterpriseVersion(version, best) > 0) {
			best = version
		}
	}
	if overflow {
		return best, fmt.Errorf("package folder %s has more than %d entries", dir, windowsSurfaceMaxEntries)
	}
	return best, nil
}

func readWindowsDirBounded(dir string) ([]os.DirEntry, bool) {
	if winpath.RejectReparseChain(dir) != nil {
		return nil, false
	}
	file, err := os.Open(dir)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	entries, _ := file.ReadDir(windowsSurfaceMaxEntries + 1)
	if len(entries) > windowsSurfaceMaxEntries {
		return entries[:windowsSurfaceMaxEntries], true
	}
	return entries, false
}

// windowsStandaloneSurfaces is the admission of the profile's app and
// extension surfaces, or false while the owner is signed out (discovery
// needs the owner's token; the sign-in cycle discovers them).
func windowsStandaloneSurfaces(row *ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext) (surfaceAdmission, bool) {
	name := strings.ToLower(strings.TrimSpace(row.Connector))
	if _, ok := windowsSurfaceExtensions[name]; !ok {
		return surfaceAdmission{}, false
	}
	if !rowContext.sessionActive {
		logfSafely(logf, row.SID, "(SID, "+name+") app and extension discovery waits until the user signs in")
		return surfaceAdmission{}, false
	}
	surfaces, complete, err := discoverWindowsAgentSurfaces(canonicalManifestTargetSID(row.SID), row.UserHome, name)
	if err != nil {
		logfSafely(logf, row.SID, "(SID, "+name+") app and extension discovery failed: "+err.Error())
		if rowContext.report != nil {
			rowContext.report(UnprotectedAgent{User: rowContext.user, SID: row.SID, Connector: name,
				Code: UnprotectedCodeInstallScanIncomplete, Reason: "app and extension inventory is incomplete: " + err.Error()})
		}
	}
	if len(surfaces) == 0 && err != nil {
		return surfaceAdmission{}, false
	}
	policy := UnverifiedVersionsFor(name)
	admission := admitSurfaces(name, policy, complete)
	if err != nil {
		// Retain refused observations from incomplete roots alongside the
		// coverage warning, without enrolling from those roots.
		admission.rejected = admitSurfaces(name, policy, surfaces).rejected
	}
	return admission, true
}

// windowsStandaloneSurfaceVersion is the row version of a profile whose
// agent CLI is at cliVersion ("" when there is none): the older of the CLI
// version and the oldest engine version among its admitted app and
// extension surfaces, or "". While the owner is signed out it is
// cliVersion. Refused and explicitly below-contract surfaces are reported
// beside a CLI; an unversioned surface beside a CLI remains a known limit.
func windowsStandaloneSurfaceVersion(row *ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext, cliVersion string) string {
	if cliVersion != "" && !rowContext.sessionActive {
		// The CLI enrolls the row; its surfaces are read in the owner's
		// next signed-in cycle.
		return cliVersion
	}
	name := strings.ToLower(strings.TrimSpace(row.Connector))
	admission, ok := windowsStandaloneSurfaces(row, logf, rowContext)
	if !ok {
		return cliVersion
	}
	enrolled := cliVersion != "" || len(admission.admitted) != 0
	for _, rejected := range admission.rejected {
		consequence, refusal := "", RefusalMissing
		switch {
		case enrolled && !rejected.refused && !rejected.belowMinimum:
			continue
		case enrolled && !rejected.refused:
			consequence = "its engine is below the first known hook contract, so the enrolled CLI's hooks cannot be assumed to protect it"
		case enrolled:
			consequence, refusal = surfaceRefusalConsequence(name, rejected)
		case windowsStandaloneMachinePolicyConnector(name):
			consequence, refusal = "its machine-policy hooks refuse this user's tool calls until it is enrolled", RefusalEnforced
		default:
			consequence = "it runs without DefenseClaw hooks"
		}
		if rowContext.report != nil {
			rowContext.report(rejected.unprotected(rowContext.user, canonicalManifestTargetSID(row.SID), nil, name, consequence, refusal))
		}
	}
	version := admission.rowVersion(cliVersion)
	if version != cliVersion {
		logfSafely(logf, row.SID, "(SID, "+name+") follows its "+admission.surface+" surface at engine version "+version)
	}
	return version
}
