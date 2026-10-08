// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package scanner

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// scannerRuntimePath is the installed scanner runtime, or "" when this host
// has none or it cannot be used; tests replace it.
var scannerRuntimePath = func() string {
	path, err := installedScannerRuntime()
	if err != nil {
		return ""
	}
	return path
}

// scannerRuntimeProblem says why the scanner runtime of a host that has one
// (its root folder exists: the standalone Windows enterprise install) cannot
// be run; nil when it can or the host has none. Tests replace it.
var scannerRuntimeProblem = func() error {
	_, err := installedScannerRuntime()
	if errors.Is(err, errNoScannerRuntime) {
		return nil
	}
	return err
}

var errNoScannerRuntime = errors.New("this host has no scanner runtime")

func installedScannerRuntime() (string, error) {
	root, err := managed.StandaloneWindowsScannerRuntimeDir()
	if err != nil {
		return "", errNoScannerRuntime
	}
	if _, err := os.Lstat(root); err != nil {
		return "", errNoScannerRuntime
	}
	path := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
	info, err := os.Lstat(path)
	if err != nil {
		return "", fmt.Errorf("%s is missing", path)
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 {
		return "", fmt.Errorf("%s is not a regular file", path)
	}
	// Only an administrator-owned runtime that no standard user can
	// replace is run.
	if err := managed.ValidateTrustedFilePath(path, "scanner runtime"); err != nil {
		return "", err
	}
	return path, nil
}

// resolveScannerRuntime binds a bare default scanner command to the scanner
// runtime the standalone Windows enterprise lifecycle installs. An explicit
// scanner path in config stays authoritative, and every other install
// (per-user, Secure Client) has no scanner runtime and keeps binary.
func resolveScannerRuntime(binary string, defaults ...string) string {
	for _, name := range defaults {
		if strings.EqualFold(strings.TrimSpace(binary), name) {
			if path := scannerRuntimePath(); path != "" {
				return path
			}
			return binary
		}
	}
	return binary
}
