//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package policy

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// Windows Enterprise Setup installs a pinned Python/PyYAML environment in its
// protected scanner runtime. The admission record is bound to the scanner
// executable; the installed Python resides beneath the same protected root.
func installedPythonInterpreter() (string, error) {
	root, err := windowsScannerRuntimeRoot()
	if err != nil {
		return "", fmt.Errorf("resolve managed policy Python runtime: %w", err)
	}
	scanner := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	if err := managed.CheckScannerRuntimeAdmitted(root, scanner); err != nil {
		return "", fmt.Errorf("policy Python runtime is not admitted; repair the Enterprise Setup installation: %w", err)
	}
	python := filepath.Join(root, "python", "python.exe")
	info, err := os.Stat(python)
	if err != nil || !info.Mode().IsRegular() {
		return "", fmt.Errorf("managed policy Python interpreter unavailable at %s; repair the Enterprise Setup installation", python)
	}
	// The service runs it by its path: it, the runtime folder and every
	// folder above them must be beyond a standard user's reach, or one could
	// swap the interpreter between this check and the run (review loop
	// round 4).
	if err := managed.ValidateTrustedRuntimeImage(root, python, "policy Python runtime"); err != nil {
		return "", fmt.Errorf("policy Python runtime cannot be trusted; repair the Enterprise Setup installation: %w", err)
	}
	if err := managed.ValidateTrustedRuntimeCodeTree(root, "policy Python runtime"); err != nil {
		return "", fmt.Errorf("policy Python imports cannot be trusted; repair the Enterprise Setup installation: %w", err)
	}
	return python, nil
}

// windowsScannerRuntimeRoot resolves the scanner runtime root; a seam for
// tests.
var windowsScannerRuntimeRoot = managed.StandaloneWindowsScannerRuntimeDir
