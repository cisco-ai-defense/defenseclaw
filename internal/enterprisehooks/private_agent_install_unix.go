// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var errPrivateInstallLimit = errors.New("private agent install scan exceeded its entry limit")

var privateUnixNPMPackages = map[string]string{
	"claudecode": "@anthropic-ai/claude-code",
	"copilot":    "@github/copilot",
	"codex":      "@openai/codex",
}

func privateInstallContractReason(connector, version string) string {
	return unixNewRowVersionRefused(connector, version)
}

// DiscoverUnixPrivateAgentInstalls runs in the enrolled user's discovery
// worker. Besides known npm roots, it checks one directory below the home:
// npm install --prefix "$HOME/private" puts a runnable copy there. It reads
// metadata only; no user executable runs in the root enumerator.
func DiscoverUnixPrivateAgentInstalls(home string, connectors []string) []PrivateAgentInstall {
	relevant := ""
	for _, name := range connectors {
		if privateUnixNPMPackages[name] != "" {
			relevant = name
			break
		}
	}
	if relevant == "" {
		return nil
	}
	home = filepath.Clean(home)
	roots := []string{home}
	if connectorListed(connectors, "claudecode") {
		// The vendor's local installer keeps a runnable copy two levels
		// below the home; the one-child prefix scan cannot reach it.
		roots = append(roots, filepath.Join(home, ".claude", "local"))
	}
	for _, root := range userNodePrefixes(home) {
		if rel, err := filepath.Rel(home, root); err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			roots = append(roots, root)
		}
	}
	entries, err := boundedPrivateHomeDirs(home)
	if err != nil {
		return []PrivateAgentInstall{{Connector: relevant, Incomplete: true}}
	}
	for _, name := range entries {
		roots = append(roots, filepath.Join(home, name))
	}
	seen := map[string]bool{}
	var found []PrivateAgentInstall
	for _, connector := range connectors {
		pkg := privateUnixNPMPackages[connector]
		if pkg == "" {
			continue
		}
		connectorRoots := append([]string{}, roots...)
		// Volta stores each package in its own image, rather than directly
		// under tools/image. A supported selected image can hide an old one.
		connectorRoots = append(connectorRoots, filepath.Join(home, ".volta", "tools", "image", "packages", filepath.FromSlash(pkg)))
		for _, root := range connectorRoots {
			for _, path := range nodeModulesPackage(root, pkg) {
				if seen[path] || !unixDiscoveryCandidateTrusted(home, path) {
					continue
				}
				seen[path] = true
				// A package record by itself may be a leftover cache. Claude
				// Code's cli.js is the runnable npm entry point.
				if connector == "claudecode" {
					entry := filepath.Join(filepath.Dir(path), "cli.js")
					if !unixDiscoveryCandidateTrusted(home, entry) {
						return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
					}
					if info, err := os.Stat(entry); err != nil || !info.Mode().IsRegular() {
						continue
					}
				}
				if _, err := os.Lstat(path); err != nil && connector != "claudecode" {
					continue
				}
				version, ok := readUnixPackageVersion(path, pkg, false)
				if ok && privateInstallReason(connector, version) == "" {
					continue
				}
				found = append(found, PrivateAgentInstall{Connector: connector, Version: version, Path: filepath.Dir(path)})
				if len(found) >= privateAgentInstallMaxFindings {
					return append(found, PrivateAgentInstall{Connector: relevant, Incomplete: true})
				}
			}
		}
	}
	if connectorListed(connectors, "claudecode") {
		local := filepath.Join(home, ".claude", "local")
		entry := filepath.Join(local, "node_modules", "@anthropic-ai", "claude-code", "cli.js")
		info, err := os.Stat(entry)
		if (err != nil || !info.Mode().IsRegular()) && unixAgentExecutablePresent(filepath.Join(local, "claude")) {
			found = append(found, PrivateAgentInstall{Connector: "claudecode", Path: filepath.Join(local, "claude")})
		}
	}
	if connectorListed(connectors, "claudecode") {
		versionsDir := filepath.Join(home, ".local", "share", "claude", "versions")
		f, err := os.Open(versionsDir)
		if err == nil {
			versions, listErr := f.Readdirnames(privateAgentInstallMaxFindings + 1)
			_ = f.Close()
			if listErr != nil && listErr != io.EOF || len(versions) > privateAgentInstallMaxFindings {
				return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
			}
			for _, version := range versions {
				path := filepath.Join(versionsDir, version)
				if !unixAgentExecutablePresent(path) {
					continue
				}
				if !validUnixAgentVersion(version) {
					version = ""
				}
				if privateInstallReason("claudecode", version) == "" {
					continue
				}
				found = append(found, PrivateAgentInstall{Connector: "claudecode", Version: version, Path: path})
				if len(found) >= privateAgentInstallMaxFindings {
					return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
				}
			}
		} else if !os.IsNotExist(err) {
			return append(found, PrivateAgentInstall{Connector: "claudecode", Incomplete: true})
		}
	}
	return found
}

func boundedPrivateHomeDirs(home string) ([]string, error) {
	f, err := os.Open(home)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	names, err := f.Readdirnames(privateAgentInstallMaxEntries + 1)
	if err != nil && err != io.EOF {
		return nil, err
	}
	if len(names) > privateAgentInstallMaxEntries {
		return nil, errPrivateInstallLimit
	}
	var out []string
	for _, name := range names {
		info, err := os.Stat(filepath.Join(home, name))
		if err == nil && info.IsDir() {
			out = append(out, name)
		}
	}
	return out, nil
}
