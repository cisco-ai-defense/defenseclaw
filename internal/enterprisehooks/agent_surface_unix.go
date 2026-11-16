//go:build !windows

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
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/claudedesktop"
	"github.com/defenseclaw/defenseclaw/internal/codesig"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/lazyregexp"
	"github.com/defenseclaw/defenseclaw/internal/legacyconnector"
)

// Unix app and extension discovery runs in the per-user worker, with the
// target user's credentials, like DiscoverUnixAgentVersion. It reads
// package metadata only. No host app (an IDE, a desktop app, a launcher)
// is ever executed. With allowExec it may run an engine CLI bundled in an
// extension or app with --version, as the user, bounded, and only when
// unixDiscoveryCandidateTrusted admits the binary.
//
// Layouts that vendors do not document and that need a live check are
// marked "live check" below.

// unixExtensionRoot is a VS Code-family extensions folder under the home.
// VS Code documents ~/.vscode/extensions and its relocation with
// VSCODE_EXTENSIONS or --extensions-dir, which discovery does not follow
// (https://code.visualstudio.com/docs/configure/extensions/extension-marketplace).
type unixExtensionRoot struct{ host, dir string }

var unixExtensionRoots = []unixExtensionRoot{
	{"vscode", ".vscode/extensions"},
	{"vscode-insiders", ".vscode-insiders/extensions"},
	{"vscode-server", ".vscode-server/extensions"},
	{"vscode-server-insiders", ".vscode-server-insiders/extensions"},
	{"vscodium", ".vscode-oss/extensions"},
	{"cursor", ".cursor/extensions"},
	{legacyconnector.VendorToken, legacyconnector.InventoryDotDirs[0] + "/extensions"}, // Devin Desktop, pre-rename folder; live check
	{"kiro", ".kiro/extensions"},
	{"antigravity", ".antigravity/extensions"}, // live check
}

// unixSurfaceProbe lists where one connector's apps and extensions live.
type unixSurfaceProbe struct {
	// extension is the marketplace id ("publisher.name") of the agent's
	// VS Code extension.
	extension string
	// extensionEngineIsHost: the extension's version is its engine version
	// (Claude Code: "the extension bundles its own CLI at the extension's
	// version", https://code.claude.com/docs/en/vs-code).
	extensionEngineIsHost bool
	// extensionEngines are extension-relative globs of a bundled engine CLI
	// that may be run with --version (live check).
	extensionEngines []string
	// desktop lists the connector's desktop apps.
	desktop []unixDesktopProbe
}

// unixDesktopProbe is one desktop app. Paths starting with "~/" are under
// the home; others are absolute. goos limits it to "darwin" or "linux".
type unixDesktopProbe struct {
	goos, host string
	// claudeDesktopEngines: the app keeps the Claude Code builds it runs as
	// claude-code/<version>/... in each of its data folders
	// (internal/claudedesktop), and each data folder is reported as a
	// surface of its own (discoverUnixClaudeDesktopEngines).
	claudeDesktopEngines bool
	// bundles are macOS app bundles; the host version is their
	// CFBundleShortVersionString.
	bundles []string
	// packageJSON: the app's package.json version is the engine version
	// (Cursor's hook contracts are ranges of the app version).
	packageJSON []string
	// launchers are host launchers whose presence is reported. They are
	// never executed.
	launchers []string
	// appDirs are Linux install folders (a package's /usr/share/<app>, an
	// unpacked tarball). Like bundles they show the install, and manPages
	// and engines are relative to them.
	appDirs []string
	// manPages are bundle- or appDir-relative man pages of an engine CLI
	// the app bundles; the .TH header names the engine version and is read
	// without running anything.
	manPages []string
	// engines are bundle- or appDir-relative engine CLIs that may be run
	// with --version (live check).
	engines []string
	// engineSigner, on macOS, is the signer every Claude Desktop engine
	// build must carry: the folder is the user's own, so its version is
	// taken only from a build whose code signature verifies
	// (verifyUnixDesktopEngine). Linux builds carry none and need an
	// executable engine instead (claudedesktop.LinuxEngineExecutable).
	engineSigner *codesig.Darwin
}

var unixSurfaceProbes = map[string]unixSurfaceProbe{
	"claudecode": {
		extension:             "anthropic.claude-code",
		extensionEngineIsHost: true,
		desktop: []unixDesktopProbe{
			// Claude Desktop keeps the Claude Code build it runs for Cowork and
			// the Code tab as claude-code/<version>/<build>/claude.app under
			// its data folder, one per deployment (Claude, and Claude-3p on
			// third-party inference: internal/claudedesktop), signed by
			// Anthropic (measured on Claude Desktop 4.16336.0, engine 2.1.317).
			{goos: "darwin", host: "claude-desktop", claudeDesktopEngines: true, bundles: []string{"/Applications/Claude.app", "~/Applications/Claude.app"},
				engineSigner: &codesig.ClaudeCodeDarwin},
			// Linux Claude Desktop (Ubuntu 22.04+, Debian 12+, Cowork included,
			// https://code.claude.com/docs/en/desktop-linux). The folders are
			// the app's data folders (~/.config/Claude, ~/.config/Claude-3p)
			// plus claude-code, as on macOS and Windows; live check. Linux
			// builds carry no vendor signature: a build counts when its
			// folder holds an executable engine, and its folder name is the
			// version, as before.
			{goos: "linux", host: "claude-desktop", claudeDesktopEngines: true},
		},
	},
	"codex": {
		extension:        "openai.chatgpt",
		extensionEngines: []string{"bin/*/codex"},
		desktop: []unixDesktopProbe{
			// The macOS bundle name and its bundled engine are live checks.
			{goos: "darwin", host: "codex-app", bundles: []string{"/Applications/Codex.app", "~/Applications/Codex.app"}, engines: []string{"Contents/Resources/codex"}},
			// The Linux app is the chatgpt package
			// (https://learn.chatgpt.com/docs/linux/linux-app); its install
			// path is a live check.
			{goos: "linux", host: "chatgpt", launchers: []string{"/usr/bin/chatgpt", "/opt/ChatGPT/chatgpt"}},
		},
	},
	"cursor": {
		desktop: []unixDesktopProbe{
			{goos: "darwin", host: "cursor", packageJSON: []string{"/Applications/Cursor.app/Contents/Resources/app/package.json", "~/Applications/Cursor.app/Contents/Resources/app/package.json"}},
			// Linux .deb/.rpm install paths; live check.
			{goos: "linux", host: "cursor", packageJSON: []string{"/usr/share/cursor/resources/app/package.json", "/opt/Cursor/resources/app/package.json"}},
		},
	},
	"devin": {
		// Devin Desktop runs the Devin CLI it bundles (surface_probes_devin.go).
		desktop: []unixDesktopProbe{
			{goos: "darwin", host: "devin-desktop", bundles: []string{"/Applications/Devin.app", "~/Applications/Devin.app"},
				manPages: []string{devinDesktopManPage("Contents/Resources/app")}, engines: []string{devinDesktopCLI("Contents/Resources/app", "devin")}},
			{goos: "linux", host: "devin-desktop", appDirs: []string{"/usr/share/devin-desktop", "/opt/Devin", "~/Devin"},
				manPages: []string{devinDesktopManPage("resources/app")}, engines: []string{devinDesktopCLI("resources/app", "devin")}},
		},
	},
	"antigravity": {
		// The IDE shares the CLI's hook file
		// (https://antigravity.google/docs/hooks) but has no engine
		// version source: it is reported, never enrolled on its own.
		desktop: []unixDesktopProbe{
			{goos: "darwin", host: "antigravity-ide", bundles: []string{"/Applications/Antigravity.app", "~/Applications/Antigravity.app"}},
			{goos: "linux", host: "antigravity-ide", launchers: []string{"/usr/bin/antigravity", "/usr/share/antigravity/antigravity", "~/.local/bin/antigravity"}},
		},
	},
}

// unixSurfaceGOOS selects the desktop probes; tests set it.
var unixSurfaceGOOS = unixAgentAppBundleGOOS

// unixExtensionMaxEntries bounds one extensions folder listing.
const unixExtensionMaxEntries = 4096

// DiscoverUnixAgentSurfaces lists connectorName's app and extension
// installs for home. complete is false when an extensions folder holds more
// entries than the scan reads or could not be read: an extension the
// listing missed must leave coverage incomplete, never clean (GAP-1077).
func DiscoverUnixAgentSurfaces(ctx context.Context, home, connectorName string, allowExec bool) (surfaces []connector.AgentSurface, complete bool) {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	probe, ok := unixSurfaceProbes[connectorName]
	if !ok {
		return nil, true
	}
	home = filepath.Clean(home)
	var out []connector.AgentSurface
	complete = true
	if probe.extension != "" {
		for _, root := range unixExtensionRoots {
			dir, listed := newestUnixExtensionDir(filepath.Join(home, filepath.FromSlash(root.dir)), probe.extension)
			complete = complete && listed
			if dir == "" {
				continue
			}
			surface := connector.AgentSurface{Surface: connector.HostSurfaceExtension, Host: root.host, Path: dir}
			pkg := filepath.Join(dir, "package.json")
			if !unixDiscoveryCandidateTrusted(home, pkg) {
				continue
			}
			if version, ok := readUnixPackageVersion(pkg, "", false); ok {
				surface.HostVersion = version
				if probe.extensionEngineIsHost {
					surface.EngineVersion = version
				}
			}
			if surface.EngineVersion == "" && allowExec {
				surface.EngineVersion = runUnixBundledEngine(ctx, home, dir, probe.extensionEngines)
			}
			out = append(out, surface)
		}
	}
	for _, desktop := range probe.desktop {
		if desktop.goos != unixSurfaceGOOS {
			continue
		}
		surfaces, listed := discoverUnixDesktop(ctx, home, desktop, allowExec)
		complete = complete && listed
		out = append(out, surfaces...)
	}
	return out, complete
}

func unixHomePath(home, path string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, filepath.FromSlash(path[2:]))
	}
	return filepath.FromSlash(path)
}

// discoverUnixDesktop reports one desktop app's surfaces: one per Claude
// Desktop data folder that holds an engine build, else one for the app.
// complete is false when an engine folder was not read in full.
func discoverUnixDesktop(ctx context.Context, home string, probe unixDesktopProbe, allowExec bool) ([]connector.AgentSurface, bool) {
	surface := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: probe.host}
	found, complete := false, true
	var engines []connector.AgentSurface
	if probe.claudeDesktopEngines {
		engines, complete = discoverUnixClaudeDesktopEngines(ctx, home, probe)
	}
	for _, path := range probe.packageJSON {
		path = unixHomePath(home, path)
		if !unixDiscoveryCandidateTrusted(home, path) {
			continue
		}
		if version, ok := readUnixPackageVersion(path, "", false); ok {
			surface.EngineVersion, surface.HostVersion, surface.Path, found = version, version, path, true
			break
		}
	}
	for index, root := range append(append([]string{}, probe.bundles...), probe.appDirs...) {
		root = unixHomePath(home, root)
		if info, err := os.Lstat(root); err != nil || !info.IsDir() {
			continue
		}
		found = true
		if surface.Path == "" {
			surface.Path = root
		}
		if unixDiscoveryCandidateTrusted(home, root) {
			if index < len(probe.bundles) {
				surface.HostVersion = readUnixBundleVersion(filepath.Join(root, "Contents", "Info.plist"))
			}
			if surface.EngineVersion == "" {
				surface.EngineVersion = readUnixManPageVersion(home, root, probe.manPages)
			}
			if surface.EngineVersion == "" && allowExec {
				surface.EngineVersion = runUnixBundledEngine(ctx, home, root, probe.engines)
			}
		}
		break
	}
	for _, launcher := range probe.launchers {
		launcher = unixHomePath(home, launcher)
		if unixAgentExecutablePresent(launcher) {
			found = true
			if surface.Path == "" {
				surface.Path = launcher
			}
			break
		}
	}
	if len(engines) != 0 {
		for i := range engines {
			engines[i].HostVersion = surface.HostVersion
		}
		return engines, complete
	}
	if !found {
		return nil, complete
	}
	return []connector.AgentSurface{surface}, complete
}

// unixDesktopEngineCandidatesMax bounds the version folders of one data
// folder that are checked, newest first, for a build that verifies.
const unixDesktopEngineCandidatesMax = 4

// discoverUnixClaudeDesktopEngines reports Claude Desktop's engine builds
// under home, one surface per data folder (internal/claudedesktop; the
// default folders of the account, as a service would read them): the
// newest build there that verifies (macOS: its code signature; Linux: an
// executable engine, which is never a signature), and, as a surface of its
// own with EngineUnverified, the folder's newest build when that one does
// not verify. A newer unsigned or half-written version folder therefore
// never hides a genuine build of the same or another data folder, and
// admitSurfaces sees the build of every folder, so the row follows the
// oldest admitted one. complete is false when an engine folder holds more
// entries than are read, or when its newest candidates all fail and older
// ones were not checked.
func discoverUnixClaudeDesktopEngines(ctx context.Context, home string, probe unixDesktopProbe) ([]connector.AgentSurface, bool) {
	// macOS and Linux roots hold no "*", so the data folder list itself
	// does not overflow.
	dirs, overflow := claudedesktop.EngineDirs(probe.goos, claudedesktop.FoldersForHome(probe.goos, home))
	complete := !overflow
	var out []connector.AgentSurface
	for _, dir := range dirs {
		if !unixDiscoveryCandidateTrusted(home, dir.Path) {
			continue
		}
		versions, listed := unixVersionDirs(dir.Path)
		complete = complete && listed
		var newestRejected *connector.AgentSurface
		for i, version := range versions {
			if i == unixDesktopEngineCandidatesMax {
				complete = false
				break
			}
			reason := unixDesktopEngineCheck(ctx, filepath.Join(dir.Path, version), version, probe)
			if reason == "" {
				out = append(out, connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: probe.host, EngineVersion: version, Path: dir.Path})
				break
			}
			if newestRejected == nil {
				newestRejected = &connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: probe.host, Path: dir.Path,
					EngineUnverified: boundEngineUnverifiedReason("Claude Desktop engine " + version + ": " + reason)}
			}
		}
		if newestRejected != nil {
			out = append(out, *newestRejected)
		}
	}
	return out, complete
}

// unixDesktopEngineCheck returns why the Claude Desktop engine build in
// versionDir is not identified, or "".
func unixDesktopEngineCheck(ctx context.Context, versionDir, version string, probe unixDesktopProbe) string {
	if probe.engineSigner != nil {
		return verifyUnixDesktopEngine(ctx, versionDir, version, *probe.engineSigner)
	}
	if claudedesktop.LinuxEngineExecutable(versionDir) == "" {
		return "no executable claude engine in " + versionDir
	}
	return ""
}

// newestUnixExtensionDir returns the newest "<id>-<version>[-<platform>]"
// folder of extension id under root, leaving out folders the editor has
// marked obsolete (removed, pending deletion). complete is false when root
// holds more entries than the bound or could not be read for another
// reason than being absent or out of the account's reach.
func newestUnixExtensionDir(root, id string) (dir string, complete bool) {
	entries, err := readUnixDirBounded(root, unixExtensionMaxEntries)
	if err != nil {
		return "", unixEntryAbsent(err)
	}
	complete = len(entries) <= unixExtensionMaxEntries
	obsolete := readUnixObsoleteExtensions(filepath.Join(root, ".obsolete"))
	prefix := strings.ToLower(id) + "-"
	best, bestVersion := "", ""
	for _, entry := range entries {
		name := entry.Name()
		if !entry.IsDir() || !strings.HasPrefix(strings.ToLower(name), prefix) || obsolete[name] {
			continue
		}
		version := name[len(prefix):]
		// Marketplace versions are major.minor.patch; what follows a dash
		// is the platform ("-darwin-arm64").
		if i := strings.IndexByte(version, '-'); i >= 0 {
			version = version[:i]
		}
		if !validUnixAgentVersion(version) {
			continue
		}
		if best == "" || compareUnixVersions(version, bestVersion) > 0 {
			best, bestVersion = filepath.Join(root, name), version
		}
	}
	return best, complete
}

// readUnixDirBounded lists at most limit+1 entries of dir, so a caller can
// tell a folder over the bound from one at it.
func readUnixDirBounded(dir string, limit int) ([]os.DirEntry, error) {
	file, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(limit + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })
	return entries, nil
}

// readUnixObsoleteExtensions reads an extensions folder's .obsolete record,
// a JSON object whose keys are removed extension folders (format is a live
// check; an unreadable record hides nothing).
func readUnixObsoleteExtensions(path string) map[string]bool {
	data, ok := readUnixSmallRegularFile(path)
	if !ok {
		return nil
	}
	var record map[string]bool
	if json.Unmarshal(data, &record) != nil {
		return nil
	}
	return record
}

// readUnixSmallRegularFile reads a regular file of at most
// unixAgentVersionMaxBytes without following a link or blocking on a FIFO.
func readUnixSmallRegularFile(path string) ([]byte, bool) {
	if info, err := os.Lstat(path); err != nil || !info.Mode().IsRegular() {
		return nil, false
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return nil, false
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, unixAgentVersionMaxBytes+1))
	if err != nil || len(data) > unixAgentVersionMaxBytes {
		return nil, false
	}
	return data, true
}

var unixPlistShortVersion = lazyregexp.New(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,128})</string>`)

// readUnixBundleVersion returns an XML Info.plist's
// CFBundleShortVersionString, or "" (a binary plist is not parsed).
func readUnixBundleVersion(path string) string {
	data, ok := readUnixSmallRegularFile(path)
	if !ok {
		return ""
	}
	match := unixPlistShortVersion.FindSubmatch(data)
	if match == nil {
		return ""
	}
	if version := strings.TrimSpace(string(match[1])); validUnixAgentVersion(version) {
		return version
	}
	return ""
}

// readUnixManPageVersion reads the engine version from the first trusted
// man page under dir.
func readUnixManPageVersion(home, dir string, pages []string) string {
	for _, page := range pages {
		path := filepath.Join(dir, page)
		if !unixDiscoveryCandidateTrusted(home, path) {
			continue
		}
		if data, ok := readUnixSmallRegularFile(path); ok {
			if version := parseDevinManPageVersion(data); validUnixAgentVersion(version) {
				return version
			}
		}
	}
	return ""
}

// runUnixBundledEngine runs the first trusted engine CLI matching one of
// patterns under dir with --version, as the calling user.
func runUnixBundledEngine(ctx context.Context, home, dir string, patterns []string) string {
	for _, pattern := range patterns {
		matches, err := filepath.Glob(filepath.Join(dir, filepath.FromSlash(pattern)))
		if err != nil {
			continue
		}
		if len(matches) > 4 {
			matches = matches[:4]
		}
		for _, candidate := range matches {
			if !unixDiscoveryCandidateTrusted(home, candidate) {
				continue
			}
			if version := execUnixAgentVersion(ctx, candidate, home, ""); version != "" {
				return version
			}
		}
	}
	return ""
}

// verifyUnixDesktopBundle checks one engine bundle's code signature; tests
// replace it.
var verifyUnixDesktopBundle = codesig.VerifyDarwin

// unixDesktopEngineBundlesMax bounds the bundles one version folder is
// searched for.
const unixDesktopEngineBundlesMax = 4

// verifyUnixDesktopEngine returns why the engine build in versionDir is not
// identified, or "" when one claude.app in it (<versionDir>/<build>/ or
// <versionDir>/ itself) has a code signature of signer that verifies and a
// sealed Info.plist that names version. It runs in the per-user worker, as
// the user, and executes nothing from the folder.
func verifyUnixDesktopEngine(ctx context.Context, versionDir, version string, signer codesig.Darwin) string {
	bundles, _ := filepath.Glob(filepath.Join(versionDir, "*", "claude.app"))
	sort.Strings(bundles)
	bundles = append([]string{filepath.Join(versionDir, "claude.app")}, bundles...)
	reason, checked := "", 0
	for _, bundle := range bundles {
		if info, err := os.Lstat(bundle); err != nil || !info.IsDir() {
			continue
		}
		if checked++; checked > unixDesktopEngineBundlesMax {
			break
		}
		plist := filepath.Join(bundle, "Contents", "Info.plist")
		if named := readUnixBundleVersion(plist); named != version {
			reason = "the build " + bundle + " runs from the " + version + " folder, but its Info.plist names " + strconv.Quote(named)
			continue
		}
		result := verifyUnixDesktopBundle(ctx, bundle, signer,
			codesig.DarwinOptions{Pin: []string{filepath.Join(bundle, "Contents", "MacOS", "claude"), plist}})
		if result.Verified {
			return ""
		}
		reason = result.Reason
	}
	if reason == "" {
		return "no claude.app engine bundle in " + versionDir
	}
	return reason
}

// UnixAgentSurfacesMax bounds the surfaces the parent accepts per connector
// from a per-user discovery worker.
const UnixAgentSurfacesMax = 16

var unixAgentSurfaceHost = lazyregexp.New(`^[a-z0-9-]{1,32}$`)

// ValidUnixAgentSurface checks a surface a per-user worker reported: the
// worker runs as the user, so the parent keeps only well-formed values.
func ValidUnixAgentSurface(surface connector.AgentSurface) (connector.AgentSurface, bool) {
	if surface.Surface != connector.HostSurfaceDesktop && surface.Surface != connector.HostSurfaceExtension {
		return connector.AgentSurface{}, false
	}
	if !unixAgentSurfaceHost.MatchString(surface.Host) {
		return connector.AgentSurface{}, false
	}
	for _, version := range []string{surface.EngineVersion, surface.HostVersion} {
		if version != "" && !ValidUnixAgentVersion(version) {
			return connector.AgentSurface{}, false
		}
	}
	if surface.Path != "" && (!filepath.IsAbs(surface.Path) || len(surface.Path) > 4096) {
		return connector.AgentSurface{}, false
	}
	if surface.EngineUnverified != "" && (surface.EngineVersion != "" || !ValidEngineUnverifiedReason(surface.EngineUnverified)) {
		return connector.AgentSurface{}, false
	}
	return surface, true
}
