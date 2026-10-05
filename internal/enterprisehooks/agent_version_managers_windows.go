// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// Standalone discovery also finds npm-distributed agent CLIs installed
// through the Node version managers and package managers users run on
// Windows: nvm-windows, fnm, Volta, pnpm and the npm prefix the user's
// .npmrc names. Every read is the same static, bounded, reparse-refusing
// package.json read as the fixed probes; nothing is executed. The version
// only selects a hook contract; a per-user connector whose guardian-managed
// image is not the canonical one is then refused and reported as
// unprotected, so the install is visible either way. The Secure Client
// profile keeps its fixed probe list.

// windowsStandaloneNPMPackages names each npm-distributed connector's
// package(s).
var windowsStandaloneNPMPackages = map[string][]string{
	"claudecode": {filepath.Join("@anthropic-ai", "claude-code")},
	"codex":      {filepath.Join("@openai", "codex")},
	"copilot":    {filepath.Join("@github", "copilot")},
	"opencode":   {"opencode-ai"},
	"amp":        {filepath.Join("@ampcode", "cli"), filepath.Join("@sourcegraph", "amp")},
}

const (
	// windowsVersionManagerMaxEntries bounds each version directory walk.
	windowsVersionManagerMaxEntries = 64
	// windowsVersionManagerMaxVersions bounds the Node versions searched
	// per version manager, newest first.
	windowsVersionManagerMaxVersions = 16
)

var (
	windowsNodeVersionDirectoryName = regexp.MustCompile(`^v?\d+\.\d+\.\d+$`)
	windowsPNPMLayoutDirectoryName  = regexp.MustCompile(`^\d+$`)
)

// windowsStandaloneNodeModulesRoots lists the node_modules directories the
// version managers keep under profileHome, for package names that are not
// known in advance (the Volta image is per package; see the caller).
func windowsStandaloneNodeModulesRoots(profileHome string) []string {
	roaming := filepath.Join(profileHome, "AppData", "Roaming")
	local := filepath.Join(profileHome, "AppData", "Local")
	var roots []string
	if prefix := windowsUserNPMRCPrefix(profileHome); prefix != "" {
		roots = append(roots, filepath.Join(prefix, "node_modules"))
	}
	// nvm-windows keeps each Node under NVM_HOME\v<version>, whose
	// node_modules holds that Node's global packages.
	for _, nvmHome := range []string{filepath.Join(roaming, "nvm"), filepath.Join(local, "nvm")} {
		for _, dir := range newestWindowsVersionDirs(nvmHome, windowsNodeVersionDirectoryName) {
			roots = append(roots, filepath.Join(dir, "node_modules"))
		}
	}
	// fnm: FNM_DIR\node-versions\v<version>\installation.
	for _, fnmHome := range []string{filepath.Join(roaming, "fnm"), filepath.Join(local, "fnm")} {
		for _, dir := range newestWindowsVersionDirs(filepath.Join(fnmHome, "node-versions"), windowsNodeVersionDirectoryName) {
			roots = append(roots, filepath.Join(dir, "installation", "node_modules"))
		}
	}
	// pnpm: PNPM_HOME\global\<layout version>\node_modules.
	for _, dir := range newestWindowsVersionDirs(filepath.Join(local, "pnpm", "global"), windowsPNPMLayoutDirectoryName) {
		roots = append(roots, filepath.Join(dir, "node_modules"))
	}
	return roots
}

// discoverWindowsStandaloneVersionManagerAgentVersion reads the connector's
// package.json from the version-manager install locations.
func discoverWindowsStandaloneVersionManagerAgentVersion(profileHome, connectorName string) string {
	packages := windowsStandaloneNPMPackages[connectorName]
	if len(packages) == 0 {
		return ""
	}
	var candidates []string
	// Volta installs each global package into its own image:
	// %LOCALAPPDATA%\Volta\tools\image\packages\<package>\node_modules\<package>.
	for _, name := range packages {
		candidates = append(candidates, filepath.Join(profileHome, "AppData", "Local", "Volta", "tools", "image", "packages", name, "node_modules", name, "package.json"))
	}
	for _, root := range windowsStandaloneNodeModulesRoots(profileHome) {
		for _, name := range packages {
			candidates = append(candidates, filepath.Join(root, name, "package.json"))
		}
	}
	for _, candidate := range candidates {
		if version, ok := readWindowsAgentVersionCandidate(candidate); ok {
			return version
		}
	}
	return ""
}

// newestWindowsVersionDirs lists the plain subdirectories of parent whose
// names match pattern, newest version first, bounded.
func newestWindowsVersionDirs(parent string, pattern *regexp.Regexp) []string {
	if err := winpath.RejectReparseChain(parent); err != nil {
		return nil
	}
	entries, err := os.ReadDir(parent)
	if err != nil {
		return nil
	}
	var names []string
	for index, entry := range entries {
		if index >= windowsVersionManagerMaxEntries {
			break
		}
		if !entry.IsDir() || entry.Type()&os.ModeSymlink != 0 || !pattern.MatchString(entry.Name()) {
			continue
		}
		names = append(names, entry.Name())
	}
	sort.SliceStable(names, func(i, j int) bool {
		return compareWindowsEnterpriseVersion(strings.TrimPrefix(names[i], "v"), strings.TrimPrefix(names[j], "v")) > 0
	})
	if len(names) > windowsVersionManagerMaxVersions {
		names = names[:windowsVersionManagerMaxVersions]
	}
	dirs := make([]string, 0, len(names))
	for _, name := range names {
		dirs = append(dirs, filepath.Join(parent, name))
	}
	return dirs
}

// windowsUserNPMRCPrefix returns the npm global prefix %USERPROFILE%\.npmrc
// sets, when it lies inside the profile (a prefix elsewhere is not the
// user's own install and is not read), or "".
func windowsUserNPMRCPrefix(profileHome string) string {
	path := filepath.Join(profileHome, ".npmrc")
	if err := winpath.RejectReparseChain(path); err != nil {
		return ""
	}
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return ""
	}
	file, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, windowsAgentVersionMaxBytes+1))
	if err != nil || int64(len(data)) > windowsAgentVersionMaxBytes {
		return ""
	}
	prefix := ""
	for _, line := range strings.Split(string(data), "\n") {
		key, value, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok || strings.TrimSpace(key) != "prefix" {
			continue
		}
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		for _, home := range []string{"${USERPROFILE}", "%USERPROFILE%", "~"} {
			if strings.HasPrefix(value, home) {
				value = profileHome + strings.TrimPrefix(value, home)
				break
			}
		}
		prefix = value // the last assignment wins, as in npm
	}
	prefix = filepath.Clean(strings.ReplaceAll(prefix, "/", `\`))
	if prefix == "." || !filepath.IsAbs(prefix) || strings.ContainsAny(prefix, "\x00") || !pathInside(profileHome, prefix) {
		return ""
	}
	return prefix
}
