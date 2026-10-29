// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// standaloneScannerRuntime reports whether this process is the standalone
// managed-enterprise gateway (its service units set both variables), the
// only deployment whose package installs a scanner runtime. Per-user
// installs keep their scanner commands.
func standaloneScannerRuntime() bool {
	return managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) &&
		managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv))
}

// installedScannerRuntime is the package's defenseclaw-scanners launcher
// when it and its Python tree are installed and trusted (GAP-1527);
// managed.ErrNoScannerRuntime when the packages installed none. Tests
// replace it.
var installedScannerRuntime = func() (string, error) {
	launcher, _, err := managed.InstalledUnixScannerRuntime()
	return launcher, err
}

// resolveScannerRuntime binds a bare default scanner command of the
// standalone managed gateway to the scanner runtime its package installed.
// An explicit scanner path in config stays authoritative; a host without
// the runtime (a payload install) keeps binary.
func resolveScannerRuntime(binary string, defaults ...string) string {
	if !standaloneScannerRuntime() || !isDefaultScanner(binary, defaults) {
		return binary
	}
	if path, err := installedScannerRuntime(); err == nil {
		return path
	}
	return binary
}

// scannerRuntimePreflight refuses a scan through an installed runtime that
// is no longer trusted (changed modes or owners, a link put in the tree),
// before a default command could be resolved through PATH instead. A host
// without the runtime keeps its earlier answer.
func scannerRuntimePreflight(binary string, defaults ...string) error {
	if !standaloneScannerRuntime() {
		return nil
	}
	managedBinary := isDefaultScanner(binary, defaults)
	if launcher, err := managed.StandaloneUnixScannerRuntimeLauncher(); err == nil && filepath.Clean(strings.TrimSpace(binary)) == launcher {
		managedBinary = true
	}
	if !managedBinary {
		return nil
	}
	if _, err := installedScannerRuntime(); err != nil && !errors.Is(err, managed.ErrNoScannerRuntime) {
		return fmt.Errorf("scanner: %w: it cannot be run (%v); reinstall the defenseclaw-enterprise package to restore it",
			ErrScannerRuntimeUnavailable, err)
	}
	return nil
}

func isDefaultScanner(binary string, defaults []string) bool {
	candidate := strings.TrimSpace(binary)
	for _, name := range defaults {
		if candidate == name {
			return true
		}
	}
	return false
}

// fileInfoIsReparsePoint: links are os.ModeSymlink on these platforms.
func fileInfoIsReparsePoint(os.FileInfo) bool { return false }
