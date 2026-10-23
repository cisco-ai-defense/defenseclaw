// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"io"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func privateInstallContractReason(name, version string) string {
	if minimum := windowsEnterpriseStandaloneAgentMinimum(name); minimum != "" &&
		compareWindowsEnterpriseVersion(connector.NormalizeAgentVersion(name, version), minimum) < 0 {
		return "version " + version + " is below the lowest supported hook contract " + minimum
	}
	if result := connector.ResolveHookContract(name, version); result.Status != connector.HookCompatibilityKnown {
		return "version " + version + " is not verified against a known hook contract"
	}
	return ""
}

// DiscoverWindowsPrivateAgentInstalls checks the fixed npm roots and one
// directory below a profile, where npm --prefix leaves a runnable local
// copy. It performs bounded static reads and refuses reparse chains while
// the enumerator runs as LocalSystem.
func DiscoverWindowsPrivateAgentInstalls(home string, names []string) []PrivateAgentInstall {
	relevant := ""
	for _, name := range names {
		if name == "claudecode" || name == "codex" || name == "copilot" {
			relevant = name
			break
		}
	}
	if relevant == "" {
		return nil
	}
	home = filepath.Clean(home)
	if winpath.RejectReparseChain(home) != nil {
		return []PrivateAgentInstall{{Connector: relevant, Incomplete: true}}
	}
	f, err := os.Open(home)
	if err != nil {
		return []PrivateAgentInstall{{Connector: relevant, Incomplete: true}}
	}
	entries, err := f.Readdirnames(privateAgentInstallMaxEntries + 1)
	_ = f.Close()
	if err != nil && err != io.EOF || len(entries) > privateAgentInstallMaxEntries {
		return []PrivateAgentInstall{{Connector: relevant, Incomplete: true}}
	}
	roots := []string{home, filepath.Join(home, ".claude", "local"), filepath.Join(home, "AppData", "Roaming", "npm"),
		filepath.Join(home, ".bun", "install", "global"),
		filepath.Join(home, "AppData", "Local", "Yarn", "Data", "global")}
	for _, modules := range windowsStandaloneNodeModulesRoots(home) {
		roots = append(roots, filepath.Dir(modules))
	}
	for _, entry := range entries {
		child := filepath.Join(home, entry)
		if winpath.RejectReparseChain(child) != nil {
			continue
		}
		if info, err := os.Lstat(child); err == nil && info.IsDir() {
			roots = append(roots, child)
		}
	}
	seen := map[string]bool{}
	var found []PrivateAgentInstall
	incomplete := false
	for _, name := range names {
		packages := windowsStandaloneNPMPackages[name]
		if name != "claudecode" && name != "copilot" && name != "codex" {
			continue
		}
		packageRoots := append([]string(nil), roots...)
		for _, packageName := range packages {
			// Volta gives each package an image below AppData\Local, outside
			// the profile's immediate children and the npm prefix roots.
			packageRoots = append(packageRoots, filepath.Join(home, "AppData", "Local", "Volta", "tools", "image", "packages", packageName))
		}
		for _, root := range packageRoots {
			for _, packageName := range packages {
				for _, modules := range []string{"node_modules", filepath.Join("lib", "node_modules")} {
					packageDir := filepath.Join(root, modules, packageName)
					if seen[packageDir] {
						continue
					}
					if winpath.RejectReparseChain(packageDir) != nil {
						incomplete = true
						continue
					}
					seen[packageDir] = true
					if name == "claudecode" {
						if info, err := os.Lstat(filepath.Join(packageDir, "cli.js")); err != nil || !info.Mode().IsRegular() {
							continue
						}
					}
					path := filepath.Join(packageDir, "package.json")
					if info, err := os.Lstat(path); (err != nil || !info.Mode().IsRegular()) && name != "claudecode" {
						continue
					}
					version, ok := readWindowsAgentVersionCandidate(path)
					if ok && privateInstallReason(name, version) == "" {
						continue
					}
					found = append(found, PrivateAgentInstall{Connector: name, Version: version, Path: packageDir})
					if len(found) >= privateAgentInstallMaxFindings {
						return append(found, PrivateAgentInstall{Connector: relevant, Incomplete: true})
					}
				}
			}
		}
	}
	if containsPrivateConnector(names, "claudecode") {
		local := filepath.Join(home, ".claude", "local")
		entry := filepath.Join(local, "node_modules", "@anthropic-ai", "claude-code", "cli.js")
		if _, err := os.Lstat(entry); os.IsNotExist(err) {
			for _, base := range []string{"claude", "claude.cmd", "claude.exe"} {
				wrapper := filepath.Join(local, base)
				if info, err := os.Lstat(wrapper); err == nil {
					if winpath.RejectReparseChain(wrapper) != nil {
						incomplete = true
					} else if info.Mode().IsRegular() {
						found = append(found, PrivateAgentInstall{Connector: "claudecode", Path: wrapper})
					}
				} else if !os.IsNotExist(err) {
					incomplete = true
				}
			}
		} else if err != nil {
			incomplete = true
		}
	}
	if containsPrivateConnector(names, "claudecode") {
		versionsDir := filepath.Join(home, ".local", "share", "claude", "versions")
		if winpath.RejectReparseChain(versionsDir) != nil {
			return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
		}
		f, err := os.Open(versionsDir)
		if err == nil {
			versions, listErr := f.Readdirnames(privateAgentInstallMaxFindings + 1)
			_ = f.Close()
			if listErr != nil && listErr != io.EOF || len(versions) > privateAgentInstallMaxFindings {
				return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
			}
			for _, version := range versions {
				path := filepath.Join(versionsDir, version)
				if winpath.RejectReparseChain(path) != nil {
					incomplete = true
					continue
				}
				if info, err := os.Lstat(path); err == nil && info.Mode().IsRegular() {
					if !windowsNativeClaudeVersionName(version) {
						version = ""
					}
					if privateInstallReason("claudecode", version) == "" {
						continue
					}
					found = append(found, PrivateAgentInstall{Connector: "claudecode", Version: version, Path: path})
				}
				if len(found) >= privateAgentInstallMaxFindings {
					return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
				}
			}
		} else if !os.IsNotExist(err) {
			return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
		}
	}
	if incomplete {
		found = append(found, PrivateAgentInstall{Connector: relevant, Incomplete: true})
	}
	return found
}

func containsPrivateConnector(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
