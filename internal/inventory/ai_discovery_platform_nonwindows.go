// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

func platformDiscoveryHomeDir() (string, error) {
	return os.UserHomeDir()
}

func platformDiscoveryVariable(name, _ string) (string, bool) {
	return os.LookupEnv(name)
}

func platformInstalledApplicationNames(home string) []string {
	var roots []string
	var suffix string
	switch runtime.GOOS {
	case "darwin":
		roots = append(roots, "/Applications", "/System/Applications")
		if home != "" {
			roots = append(roots, filepath.Join(home, "Applications"))
		}
		suffix = ".app"
	case "linux":
		roots = append(roots, "/usr/share/applications")
		if home != "" {
			roots = append(roots, filepath.Join(home, ".local", "share", "applications"))
		}
		suffix = ".desktop"
	default:
		return nil
	}

	seen := map[string]bool{}
	var out []string
	for _, root := range roots {
		children, err := os.ReadDir(root)
		if err != nil {
			continue
		}
		for _, child := range children {
			name := strings.ToLower(strings.TrimSpace(child.Name()))
			if name == "" || !strings.HasSuffix(name, suffix) || seen[name] {
				continue
			}
			seen[name] = true
			out = append(out, name)
		}
	}
	return out
}

func platformEditorExtensionRoots(string) []string {
	// POSIX editor roots are already the portable baseline in
	// detectEditorExtensions; this hook adds AppData-only Windows roots.
	return nil
}

func platformShellHistoryPaths(string) []string {
	// POSIX shell histories are already the portable baseline in
	// detectShellHistory; this hook adds PSReadLine-only Windows paths.
	return nil
}

func platformModelScanRoots(string) []modelScanRoot {
	// Portable and macOS model stores are assembled in modelFileScanRoots;
	// this hook adds Windows products whose stores live under Known Folders.
	return nil
}
