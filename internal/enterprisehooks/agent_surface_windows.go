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
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
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
// folder) runs under the token of the profile owner's session, active or
// disconnected (windowsSurfaceReadAs), so it can reach nothing the user
// could not; only administrator-protected sources (WindowsApps) are read as
// LocalSystem. A signed-out user has no token, so their surfaces are
// discovered after they sign in. Layouts vendors do not document are marked "live check".

// windowsSurfaceReadAs runs fn under the token of the profile owner sid
// (replaceable in tests).
var windowsSurfaceReadAs = func(sid, profileHome string, fn func() error) error {
	return runAsTarget(TargetCredentials{UserHome: profileHome, SID: sid, AllowDisconnected: true}, fn)
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
	desktopProbers []windowsDesktopProber
}{
	"claudecode": {id: "anthropic.claude-code", engineIsHost: true, desktopProbers: []windowsDesktopProber{discoverWindowsClaudeDesktop}},
	"codex":      {id: "openai.chatgpt", desktopProbers: []windowsDesktopProber{windowsSingleDesktop(discoverWindowsCodexApp)}},
	// Devin Desktop has no extension (surface_probes_devin.go).
	"devin": {desktopProbers: []windowsDesktopProber{windowsSingleDesktop(discoverWindowsDevinDesktop)}},
}

// windowsDesktopSurface is one surface a desktop prober found; complete is
// false when it comes from a folder that was not read in full, so it may
// warn but not select a row version.
type windowsDesktopSurface struct {
	surface  connector.AgentSurface
	complete bool
}

// windowsDesktopProber lists a desktop app's surfaces in a profile.
type windowsDesktopProber func(profileHome string) ([]windowsDesktopSurface, error)

// windowsSingleDesktop adapts a prober of one app install, whose surface is
// complete when it was read without an error.
func windowsSingleDesktop(probe func(string) (connector.AgentSurface, bool, error)) windowsDesktopProber {
	return func(profileHome string) ([]windowsDesktopSurface, error) {
		surface, ok, err := probe(profileHome)
		if !ok {
			return nil, err
		}
		return []windowsDesktopSurface{{surface: surface, complete: err == nil}}, err
	}
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
			found, err := prober(profileHome)
			scanErr = errors.Join(scanErr, err)
			for _, desktop := range found {
				out = append(out, desktop.surface)
				if desktop.complete {
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

// windowsClaudeDesktopCandidatesMax bounds the version folders of one data
// folder that are checked, newest first, for a build that verifies.
const windowsClaudeDesktopCandidatesMax = 4

// discoverWindowsClaudeDesktop finds the Claude Code builds Claude Desktop
// runs, kept as claude-code\<version> under each of its data folders
// (internal/claudedesktop: %APPDATA%\Claude, the MSIX package's
// %LOCALAPPDATA%\Claude-Data\claude_<id>, and %LOCALAPPDATA%\Claude-3p on
// third-party inference; measured on Claude Desktop 4.16336.0). Each data
// folder is a surface of its own with its newest build whose Authenticode
// signature names Anthropic (the folder is the user's own), and, as another
// surface with EngineUnverified, the folder's newest build when that one is
// not signed: a newer unsigned or half-written folder never hides a genuine
// build, and admitSurfaces sees every folder's build, so the row follows
// the oldest admitted one. A surface is incomplete when its folder was not
// read in full, when the data folder glob left folders out, or when the
// newest candidates all failed and older ones were not checked; the scan
// error then reports the coverage as incomplete.
func discoverWindowsClaudeDesktop(profileHome string) ([]windowsDesktopSurface, error) {
	var scanErr error
	dirs, overflow := claudedesktop.EngineDirs("windows", claudedesktop.FoldersForHome("windows", profileHome))
	if overflow {
		scanErr = fmt.Errorf("more Claude Desktop data folders match than the %d read in %s", claudedesktop.MaxGlobMatches, profileHome)
	}
	var out []windowsDesktopSurface
	for _, engineDir := range dirs {
		dir := engineDir.Path
		versions, err := windowsEngineVersionDirs(dir)
		scanErr = errors.Join(scanErr, err)
		complete := err == nil && !engineDir.Overflow
		var newestRejected *connector.AgentSurface
		var chosen []windowsDesktopSurface
		for i, version := range versions {
			if i == windowsClaudeDesktopCandidatesMax {
				complete = false
				scanErr = errors.Join(scanErr, fmt.Errorf("no signed Claude Desktop engine among the %d newest builds in %s", i, dir))
				break
			}
			reason := windowsClaudeDesktopBuildCheck(filepath.Join(dir, version))
			if reason == "" {
				chosen = []windowsDesktopSurface{{surface: connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", EngineVersion: version, Path: dir}}}
				break
			}
			if newestRejected == nil {
				newestRejected = &connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "claude-desktop", Path: dir,
					EngineUnverified: boundEngineUnverifiedReason("Claude Desktop engine " + version + ": " + reason)}
			}
		}
		if newestRejected != nil {
			chosen = append(chosen, windowsDesktopSurface{surface: *newestRejected})
		}
		for i := range chosen {
			chosen[i].complete = complete
		}
		out = append(out, chosen...)
	}
	return out, scanErr
}

// windowsClaudeDesktopBuildCheck is verifyWindowsClaudeDesktopBuild; tests
// replace it.
var windowsClaudeDesktopBuildCheck = verifyWindowsClaudeDesktopBuild

// windowsSignedVersionIs reports whether a signed file version (a.b.c.d)
// is folder's major.minor.patch.
func windowsSignedVersionIs(fileVersion, folder string) bool {
	file := strings.Split(strings.TrimSpace(fileVersion), ".")
	want := strings.Split(strings.TrimSpace(folder), ".")
	if len(file) < 3 || len(want) != 3 {
		return false
	}
	for i := range want {
		if strings.TrimLeft(file[i], "0") != strings.TrimLeft(want[i], "0") {
			return false
		}
	}
	for _, rest := range file[3:] {
		if strings.Trim(rest, "0") != "" {
			return false
		}
	}
	return true
}

// windowsClaudeDesktopPublishers are the Authenticode signers a Claude
// Desktop engine build may carry: the names DefenseClaw's Windows installer
// accepts for Claude Code.
var windowsClaudeDesktopPublishers = codesig.AnthropicPublishers

// verifyWindowsClaudeDesktopEngine checks one engine executable; tests
// replace it.
var verifyWindowsClaudeDesktopEngine = codesig.VerifyAuthenticode

// verifyWindowsClaudeDesktopEngineDigest is verifyWindowsClaudeDesktopEngine
// that also hashes the file through the handle it verified; tests replace
// it.
var verifyWindowsClaudeDesktopEngineDigest = codesig.VerifyAuthenticodeWithSHA256

// windowsClaudeDesktopEnginesMax bounds the executables one version folder
// is searched for.
const windowsClaudeDesktopEnginesMax = 4

// verifyWindowsClaudeDesktopBuild returns why the engine build in
// versionDir is not identified, or "" when a claude.exe in it (the folder
// itself or one level below, live check) has a valid Authenticode
// signature from windowsClaudeDesktopPublishers. It runs under the user's
// token, executes nothing and refuses reparse points.
func verifyWindowsClaudeDesktopBuild(versionDir string) string {
	_, _, reason := verifiedWindowsClaudeDesktopBuild(versionDir, verifyWindowsClaudeDesktopEngine)
	return reason
}

// verifiedWindowsClaudeDesktopBuild is verifyWindowsClaudeDesktopBuild,
// checking each claude.exe with verify, that also returns the claude.exe
// that verified and the sha256 verify reported for it ("" with the reason
// otherwise).
func verifiedWindowsClaudeDesktopBuild(versionDir string, verify func(string, []string) codesig.Result) (executable, digest, reason string) {
	candidates, _ := filepath.Glob(filepath.Join(versionDir, "*", "claude.exe"))
	sort.Strings(candidates)
	candidates = append([]string{filepath.Join(versionDir, "claude.exe")}, candidates...)
	folder := filepath.Base(versionDir)
	checked := 0
	for _, candidate := range candidates {
		if info, err := os.Lstat(candidate); err != nil || !info.Mode().IsRegular() {
			continue
		}
		if checked++; checked > windowsClaudeDesktopEnginesMax {
			break
		}
		result := verify(candidate, windowsClaudeDesktopPublishers)
		switch {
		case !result.Verified:
			reason = result.Reason
		case result.Version == "":
			reason = candidate + " is signed but has no file version to compare with its " + folder + " folder"
		case !windowsSignedVersionIs(result.Version, folder):
			// An older signed build copied into a newer folder must not
			// select the newer hook contract.
			reason = candidate + " is signed as version " + result.Version + ", not " + folder
		default:
			return candidate, result.SHA256, ""
		}
	}
	if reason == "" {
		return "", "", "no claude.exe in " + versionDir
	}
	return "", "", reason
}

// discoverWindowsCodexApp reports the Codex app's MSIX package data folder.
// Its engine version has no static source (live check), so it is reported
// and never enrolled on its own; discovery takes the
// host version from the package folder name under WindowsApps.
func discoverWindowsCodexApp(profileHome string) (connector.AgentSurface, bool, error) {
	packages, _ := filepath.Glob(filepath.Join(profileHome, "AppData", "Local", "Packages", "OpenAI.Codex_*"))
	var scanErr error
	for _, pkg := range packages {
		if err := winpath.RejectReparseChain(pkg); err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf("the Codex app folder %s was not inspected: %w", pkg, err))
			continue
		}
		if info, err := os.Lstat(pkg); err != nil || !info.IsDir() {
			continue
		}
		return connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: "codex-app", Path: pkg}, true, scanErr
	}
	return connector.AgentSurface{}, false, scanErr
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
	var scanErr error
	for _, dir := range dirs {
		if err := winpath.RejectReparseChain(dir); err != nil {
			scanErr = errors.Join(scanErr, fmt.Errorf("the Devin Desktop folder %s was not inspected: %w", dir, err))
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
		return surface, true, scanErr
	}
	return connector.AgentSurface{}, false, scanErr
}

// newestWindowsExtensionDir returns the newest "<id>-<version>[-<platform>]"
// folder of extension id under root and its version, leaving out folders
// the editor marked obsolete (.obsolete format is a live check).
func newestWindowsExtensionDir(root, id string) (string, string, error) {
	entries, overflow, err := readWindowsDirBounded(root)
	if err != nil {
		return "", "", err
	}
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

// windowsEngineVersionDirs returns the dotted-numeric folder names under dir,
// newest first.
func windowsEngineVersionDirs(dir string) ([]string, error) {
	entries, overflow, err := readWindowsDirBounded(dir)
	if err != nil {
		return nil, err
	}
	var versions []string
	for _, entry := range entries {
		if name := entry.Name(); entry.IsDir() && windowsNativeClaudeVersionName(name) {
			versions = append(versions, name)
		}
	}
	sort.SliceStable(versions, func(i, j int) bool { return compareWindowsEnterpriseVersion(versions[i], versions[j]) > 0 })
	if overflow {
		return versions, fmt.Errorf("version folder %s has more than %d entries", dir, windowsSurfaceMaxEntries)
	}
	return versions, nil
}

// newestWindowsPackageVersion reads "<prefix><version>_<arch>__<publisher>"
// package folder names.
func newestWindowsPackageVersion(dir, prefix string) (string, error) {
	best := ""
	entries, overflow, err := readWindowsDirBounded(dir)
	if err != nil {
		return "", err
	}
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

// readWindowsDirBounded lists at most windowsSurfaceMaxEntries entries of
// dir; overflow reports more. An absent dir is an empty listing. A dir that
// exists but was not listed (a reparse point on its path, a refused or
// failed open or listing) is an error, so the inventory is reported
// incomplete instead of silently empty (GAP-1390).
func readWindowsDirBounded(dir string) ([]os.DirEntry, bool, error) {
	if err := winpath.RejectReparseChain(dir); err != nil {
		return nil, false, fmt.Errorf("folder %s was not inspected: %w", dir, err)
	}
	file, err := os.Open(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, false, nil
	}
	if err != nil {
		return nil, false, fmt.Errorf("folder %s could not be opened: %w", dir, err)
	}
	defer file.Close()
	entries, err := file.ReadDir(windowsSurfaceMaxEntries + 1)
	if err != nil && !errors.Is(err, io.EOF) {
		return nil, false, fmt.Errorf("folder %s could not be listed: %w", dir, err)
	}
	if len(entries) > windowsSurfaceMaxEntries {
		return entries[:windowsSurfaceMaxEntries], true, nil
	}
	return entries, false, nil
}

// windowsStandaloneSurfaces is the admission of the profile's app and
// extension surfaces, or false while the owner is signed out (discovery
// needs the token of the owner's session, active or disconnected; the
// sign-in cycle discovers them).
func windowsStandaloneSurfaces(row *ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext) (surfaceAdmission, bool) {
	name := strings.ToLower(strings.TrimSpace(row.Connector))
	if _, ok := windowsSurfaceExtensions[name]; !ok {
		return surfaceAdmission{}, false
	}
	if !rowContext.surfacesReadable() {
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
// In a disconnected session the surfaces are read and reported only: the
// result is cliVersion, so a row follows or is enrolled from a surface
// only in an active session.
func windowsStandaloneSurfaceVersion(row *ManifestTarget, logf EnumerationLogger, rowContext windowsStandaloneRowContext, cliVersion string) string {
	if cliVersion != "" && !rowContext.surfacesReadable() {
		// The CLI enrolls the row; its surfaces are read in the owner's
		// next signed-in cycle.
		return cliVersion
	}
	name := strings.ToLower(strings.TrimSpace(row.Connector))
	admission, ok := windowsStandaloneSurfaces(row, logf, rowContext)
	if !ok {
		return cliVersion
	}
	enrolled := cliVersion != "" || (rowContext.sessionActive && len(admission.admitted) != 0)
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
	if !rowContext.sessionActive {
		return cliVersion
	}
	version := admission.rowVersion(cliVersion)
	if version != cliVersion {
		logfSafely(logf, row.SID, "(SID, "+name+") follows its "+admission.surface+" surface at engine version "+version)
	}
	return version
}
