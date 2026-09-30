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
	"regexp"
	"sort"
	"strings"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
	// engineDirs hold version-named engine builds (Claude Desktop keeps
	// the Claude Code build it runs as <dir>/<version>).
	engineDirs []string
	// bundles are macOS app bundles; the host version is their
	// CFBundleShortVersionString.
	bundles []string
	// packageJSON: the app's package.json version is the engine version
	// (Cursor's hook contracts are ranges of the app version).
	packageJSON []string
	// launchers are host launchers whose presence is reported. They are
	// never executed.
	launchers []string
	// engines are bundle-relative engine CLIs that may be run with
	// --version (live check).
	engines []string
}

var unixSurfaceProbes = map[string]unixSurfaceProbe{
	"claudecode": {
		extension:             "anthropic.claude-code",
		extensionEngineIsHost: true,
		desktop: []unixDesktopProbe{
			{goos: "darwin", host: "claude-desktop", engineDirs: []string{"~/Library/Application Support/Claude/claude-code"}, bundles: []string{"/Applications/Claude.app", "~/Applications/Claude.app"}},
			// Linux Claude Desktop (Ubuntu 22.04+, Debian 12+,
			// https://code.claude.com/docs/en/desktop-linux); live check.
			{goos: "linux", host: "claude-desktop", engineDirs: []string{"~/.config/Claude/claude-code"}},
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
// installs for home.
func DiscoverUnixAgentSurfaces(ctx context.Context, home, connectorName string, allowExec bool) []connector.AgentSurface {
	connectorName = strings.ToLower(strings.TrimSpace(connectorName))
	probe, ok := unixSurfaceProbes[connectorName]
	if !ok {
		return nil
	}
	home = filepath.Clean(home)
	var out []connector.AgentSurface
	if probe.extension != "" {
		for _, root := range unixExtensionRoots {
			dir := newestUnixExtensionDir(filepath.Join(home, filepath.FromSlash(root.dir)), probe.extension)
			if dir == "" {
				continue
			}
			surface := connector.AgentSurface{Surface: connector.HostSurfaceExtension, Host: root.host, Path: dir}
			if version, ok := readUnixPackageVersion(filepath.Join(dir, "package.json"), "", false); ok {
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
		if surface, ok := discoverUnixDesktop(ctx, home, desktop, allowExec); ok {
			out = append(out, surface)
		}
	}
	return out
}

func unixHomePath(home, path string) string {
	if strings.HasPrefix(path, "~/") {
		return filepath.Join(home, filepath.FromSlash(path[2:]))
	}
	return filepath.FromSlash(path)
}

func discoverUnixDesktop(ctx context.Context, home string, probe unixDesktopProbe, allowExec bool) (connector.AgentSurface, bool) {
	surface := connector.AgentSurface{Surface: connector.HostSurfaceDesktop, Host: probe.host}
	found := false
	for _, dir := range probe.engineDirs {
		path := unixHomePath(home, dir)
		if version := newestVersionDir(path); version != "" && unixDiscoveryCandidateTrusted(home, path) {
			surface.EngineVersion, surface.Path, found = version, path, true
			break
		}
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
	for _, bundle := range probe.bundles {
		bundle = unixHomePath(home, bundle)
		if info, err := os.Lstat(bundle); err != nil || !info.IsDir() {
			continue
		}
		found = true
		if surface.Path == "" {
			surface.Path = bundle
		}
		if unixDiscoveryCandidateTrusted(home, bundle) {
			surface.HostVersion = readUnixBundleVersion(filepath.Join(bundle, "Contents", "Info.plist"))
			if surface.EngineVersion == "" && allowExec {
				surface.EngineVersion = runUnixBundledEngine(ctx, home, bundle, probe.engines)
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
	return surface, found
}

// newestUnixExtensionDir returns the newest "<id>-<version>[-<platform>]"
// folder of extension id under root, leaving out folders the editor has
// marked obsolete (removed, pending deletion).
func newestUnixExtensionDir(root, id string) string {
	entries, err := readUnixDirBounded(root, unixExtensionMaxEntries)
	if err != nil {
		return ""
	}
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
	return best
}

func readUnixDirBounded(dir string, limit int) ([]os.DirEntry, error) {
	file, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	entries, err := file.ReadDir(limit)
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

var unixPlistShortVersion = regexp.MustCompile(`<key>CFBundleShortVersionString</key>\s*<string>([^<]{1,128})</string>`)

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

// UnixAgentSurfacesMax bounds the surfaces the parent accepts per connector
// from a per-user discovery worker.
const UnixAgentSurfacesMax = 16

var unixAgentSurfaceHost = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)

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
	return surface, true
}
