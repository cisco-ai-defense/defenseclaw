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
	root, err := managed.StandaloneWindowsScannerRuntimeDir()
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
	return python, nil
}
