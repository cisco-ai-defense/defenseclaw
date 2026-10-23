// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"io"
	"os"
	"path/filepath"
	"strings"

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

// windowsPrivateInstallMachineRoots are machine npm prefixes every account
// can run a copy from: Node's own folder, where npm puts global packages
// when the prefix is the Node installation. Tests replace it.
var windowsPrivateInstallMachineRoots = func() []string {
	programFiles := strings.TrimSpace(os.Getenv("ProgramFiles"))
	if programFiles == "" || !filepath.IsAbs(programFiles) {
		programFiles = `C:\Program Files`
	}
	return []string{filepath.Join(programFiles, "nodejs")}
}

// DiscoverWindowsPrivateAgentInstalls checks the fixed npm roots, every
// installed Node of the version managers (not only the newest few), the
// Volta package images, the vendor's local install, the native installer's
// versions, the machine npm prefix and one directory below a profile,
// where npm --prefix leaves a runnable local copy. It performs bounded
// static reads and refuses reparse chains while the enumerator runs as
// LocalSystem; a part it cannot read or that exceeds its bound is reported
// incomplete with the reason.
func DiscoverWindowsPrivateAgentInstalls(home string, names []string) []PrivateAgentInstall {
	wanted := privateInstallConnectors(names, func(name string) bool { return name == "claudecode" || name == "codex" || name == "copilot" })
	if len(wanted) == 0 {
		return nil
	}
	home = filepath.Clean(home)
	scan := newPrivateInstallScan()
	if winpath.RejectReparseChain(home) != nil {
		scan.skipAll(wanted, PrivateInstallSkippedLocation)
		return scan.result()
	}
	roots := []string{home, filepath.Join(home, ".claude", "local"), filepath.Join(home, "AppData", "Roaming", "npm"),
		filepath.Join(home, ".bun", "install", "global"),
		filepath.Join(home, "AppData", "Local", "Yarn", "Data", "global")}
	modulesRoots, truncated := windowsStandaloneNodeModulesRootsBounded(home, privateAgentInstallMaxVersionDirs)
	if truncated {
		scan.skipAll(wanted, PrivateInstallSkippedVersionManagers)
	}
	for _, modules := range modulesRoots {
		roots = append(roots, filepath.Dir(modules))
	}
	f, err := os.Open(home)
	var entries []string
	if err == nil {
		entries, err = f.Readdirnames(privateAgentInstallMaxEntries + 1)
		_ = f.Close()
		if err == io.EOF {
			err = nil
		}
	}
	if err != nil || len(entries) > privateAgentInstallMaxEntries {
		scan.skipAll(wanted, PrivateInstallSkippedHome)
		entries = nil
	}
	for _, entry := range entries {
		child := filepath.Join(home, entry)
		if winpath.RejectReparseChain(child) != nil {
			continue // the profile's compatibility junctions name folders scanned through their own roots
		}
		if info, err := os.Lstat(child); err == nil && info.IsDir() {
			roots = append(roots, child)
		}
	}
	for _, machine := range windowsPrivateInstallMachineRoots() {
		info, err := os.Lstat(machine)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || winpath.RejectReparseChain(machine) != nil {
			// Absent, or nvm-windows' link to the active version under one
			// profile's nvm root, which that profile's scan reads.
			continue
		}
		roots = append(roots, machine)
	}
	for _, name := range wanted {
		packages := windowsStandaloneNPMPackages[name]
		packageRoots := append([]string(nil), roots...)
		for _, packageName := range packages {
			// Volta gives each package an image below AppData\Local, outside
			// the profile's immediate children and the npm prefix roots.
			packageRoots = append(packageRoots, filepath.Join(home, "AppData", "Local", "Volta", "tools", "image", "packages", packageName))
		}
		for _, root := range packageRoots {
			for _, packageName := range packages {
				for _, modules := range []string{"node_modules", filepath.Join("lib", "node_modules")} {
					scanWindowsNPMPackage(scan, name, filepath.Join(root, modules, packageName))
				}
			}
		}
	}
	if containsPrivateConnector(wanted, "claudecode") {
		local := filepath.Join(home, ".claude", "local")
		packageDir := filepath.Join(local, "node_modules", "@anthropic-ai", "claude-code")
		if runnable, readable := windowsClaudePackageRunnable(packageDir); !readable {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
		} else if !runnable {
			for _, base := range []string{"claude", "claude.cmd", "claude.exe"} {
				wrapper := filepath.Join(local, base)
				info, err := os.Lstat(wrapper)
				switch {
				case err == nil && winpath.RejectReparseChain(wrapper) != nil:
					scan.skip("claudecode", PrivateInstallSkippedLocation)
				case err == nil && info.Mode().IsRegular():
					if scan.judge(windowsCopyIdentity(wrapper)) {
						scan.add(PrivateAgentInstall{Connector: "claudecode", Path: wrapper})
					}
				case err != nil && !os.IsNotExist(err):
					scan.skip("claudecode", PrivateInstallSkippedLocation)
				}
			}
		}
		scanWindowsClaudeVersions(scan, filepath.Join(home, ".local", "share", "claude", "versions"))
	}
	return scan.result()
}

// windowsCopyIdentity names one copy: the scan refuses reparse points, so
// the cleaned path, case-folded as NTFS compares names, is the copy.
func windowsCopyIdentity(path string) string {
	return strings.ToLower(filepath.Clean(path))
}

// windowsClaudePackageRunnable reports whether a Claude Code npm package
// holds an entry point: cli.js up to 2.1.112, the native bin\claude.exe
// from 2.1.113. readable is false when a reparse point or an error leaves
// the answer unknown.
func windowsClaudePackageRunnable(dir string) (runnable, readable bool) {
	for _, entry := range []string{"cli.js", filepath.Join("bin", "claude.exe")} {
		path := filepath.Join(dir, entry)
		info, err := os.Lstat(path)
		if err != nil {
			if !os.IsNotExist(err) {
				return false, false
			}
			continue
		}
		if winpath.RejectReparseChain(path) != nil {
			return false, false
		}
		if info.Mode().IsRegular() {
			return true, true
		}
	}
	return false, true
}

func scanWindowsNPMPackage(scan *privateInstallScan, name, packageDir string) {
	identity := windowsCopyIdentity(packageDir)
	if scan.seen[identity] {
		return
	}
	if winpath.RejectReparseChain(packageDir) != nil {
		scan.skip(name, PrivateInstallSkippedLocation)
		return
	}
	if info, err := os.Lstat(packageDir); err != nil || !info.IsDir() {
		return
	}
	scan.judge(identity)
	if name == "claudecode" {
		runnable, readable := windowsClaudePackageRunnable(packageDir)
		if !readable {
			scan.skip(name, PrivateInstallSkippedLocation)
			return
		}
		if !runnable {
			return
		}
	}
	path := filepath.Join(packageDir, "package.json")
	if info, err := os.Lstat(path); (err != nil || !info.Mode().IsRegular()) && name != "claudecode" {
		return
	}
	version, ok := readWindowsAgentVersionCandidate(path)
	if ok && privateInstallReason(name, version) == "" {
		return
	}
	scan.add(PrivateAgentInstall{Connector: name, Version: version, Path: packageDir})
}

func scanWindowsClaudeVersions(scan *privateInstallScan, versionsDir string) {
	if winpath.RejectReparseChain(versionsDir) != nil {
		scan.skip("claudecode", PrivateInstallSkippedLocation)
		return
	}
	f, err := os.Open(versionsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
		}
		return
	}
	versions, listErr := f.Readdirnames(privateAgentInstallMaxVersionDirs + 1)
	_ = f.Close()
	if listErr != nil && listErr != io.EOF {
		scan.skip("claudecode", PrivateInstallSkippedLocation)
		return
	}
	if len(versions) > privateAgentInstallMaxVersionDirs {
		scan.skip("claudecode", PrivateInstallSkippedNativeVersions)
	}
	for _, version := range versions {
		path := filepath.Join(versionsDir, version)
		if winpath.RejectReparseChain(path) != nil {
			scan.skip("claudecode", PrivateInstallSkippedLocation)
			continue
		}
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() || !scan.judge(windowsCopyIdentity(path)) {
			continue
		}
		if !windowsNativeClaudeVersionName(version) {
			version = ""
		}
		if privateInstallReason("claudecode", version) == "" {
			continue
		}
		scan.add(PrivateAgentInstall{Connector: "claudecode", Version: version, Path: path})
	}
}

func containsPrivateConnector(names []string, name string) bool {
	for _, candidate := range names {
		if candidate == name {
			return true
		}
	}
	return false
}
