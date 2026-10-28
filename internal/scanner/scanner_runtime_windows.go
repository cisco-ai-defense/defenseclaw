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
	"sync"
	"syscall"

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

// scannerRuntimeProblem says why the scanner runtime of the standalone
// Windows enterprise install cannot be run; nil when it can or this process
// is not that install. Tests replace it.
var scannerRuntimeProblem = func() error {
	_, err := installedScannerRuntime()
	if errors.Is(err, errNoScannerRuntime) {
		return nil
	}
	return err
}

var errNoScannerRuntime = errors.New("this host has no scanner runtime")

// scannerRuntimeRoot resolves the machine-wide scanner runtime root; tests
// replace it.
var scannerRuntimeRoot = managed.StandaloneWindowsScannerRuntimeDir

// standaloneScannerRuntime reports whether this process runs the standalone
// Windows enterprise deployment, the only one that has a scanner runtime.
// Per-user and Secure Client installs keep their scanner commands even when
// a machine-wide runtime root is left behind, for example by a standalone
// uninstall that could not remove it (GAP-1436).
func standaloneScannerRuntime() bool {
	return managed.IsManagedEnterprise(os.Getenv(managed.DeploymentModeEnv)) &&
		managed.IsStandaloneProfile(os.Getenv(managed.EnterpriseProfileEnv))
}

func installedScannerRuntime() (string, error) {
	if !standaloneScannerRuntime() {
		return "", errNoScannerRuntime
	}
	root, err := scannerRuntimeRoot()
	if err != nil {
		return "", errNoScannerRuntime
	}
	if _, err := os.Lstat(root); err != nil {
		// A standalone managed service requires this runtime even when its
		// whole folder has been removed.
		return "", fmt.Errorf("scanner runtime folder %s is unavailable: %w", root, err)
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
	// replace is run: not the folder, not a file beside the executable,
	// and not through a folder above them, ProgramData\Cisco included
	// (review loop round 4).
	if err := managed.ValidateTrustedRuntimeImage(root, path, "scanner runtime"); err != nil {
		return "", err
	}
	if err := managed.ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
		return "", err
	}
	// And only the executable the lifecycle admitted by the payload trust
	// policy: one replaced in place by an administrator, or by a process
	// running as one, fails every scan closed (GAP-0311).
	if err := admittedScannerRuntime(root, path, info); err != nil {
		return "", err
	}
	return path, nil
}

// admittedRuntime caches the last admitted executable, so a scan hashes the
// runtime (hundreds of MB) again only after the file or its record changes.
var admittedRuntime struct {
	sync.Mutex
	info   os.FileInfo
	digest string
}

func admittedScannerRuntime(root, path string, info os.FileInfo) error {
	recorded, err := managed.ReadScannerRuntimeAdmission(root)
	if err != nil {
		return err
	}
	admittedRuntime.Lock()
	defer admittedRuntime.Unlock()
	if cached := admittedRuntime.info; cached != nil && recorded != "" && recorded == admittedRuntime.digest &&
		os.SameFile(cached, info) && cached.Size() == info.Size() && cached.ModTime().Equal(info.ModTime()) {
		return nil
	}
	admittedRuntime.info, admittedRuntime.digest = nil, ""
	digest, err := managed.CheckScannerRuntimeAdmittedDigest(root, path)
	if err != nil {
		return err
	}
	admittedRuntime.info, admittedRuntime.digest = info, digest
	return nil
}

// resolveScannerRuntime binds a bare default scanner command to the scanner
// runtime the standalone Windows enterprise lifecycle installs. An explicit
// scanner path in config stays authoritative, and every other install
// (per-user, Secure Client) has no scanner runtime and keeps binary.
func resolveScannerRuntime(binary string, defaults ...string) string {
	if !standaloneScannerRuntime() {
		return binary
	}
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

// scannerRuntimePreflight refuses an unusable managed runtime before a default
// command can be resolved through PATH. Recheck an already-resolved installed
// runtime too: its admission can change after scanner construction.
func scannerRuntimePreflight(binary string, defaults ...string) error {
	if !standaloneScannerRuntime() {
		return nil
	}
	candidate := strings.TrimSpace(binary)
	managedBinary := false
	for _, name := range defaults {
		if strings.EqualFold(candidate, name) {
			managedBinary = true
			break
		}
	}
	if root, err := scannerRuntimeRoot(); err == nil {
		installed := filepath.Join(root, managed.StandaloneWindowsScannerRuntimeName)
		if strings.EqualFold(filepath.Clean(candidate), installed) {
			managedBinary = true
		}
	}
	if !managedBinary {
		return nil
	}
	if problem := scannerRuntimeProblem(); problem != nil {
		// ErrScannerRuntimeUnavailable lets the rescan loop retry soon: Setup
		// starts the gateway before it has prepared the runtime (GAP-0975).
		return fmt.Errorf("scanner: %w: it cannot be run (%v); scans run again once Setup has prepared it, "+
			"and the DefenseClaw Setup with /repair prepares it again", ErrScannerRuntimeUnavailable, problem)
	}
	return nil
}

// fileInfoIsReparsePoint reports a reparse point Lstat names neither a
// symlink nor irregular, such as a junction under an older GODEBUG.
func fileInfoIsReparsePoint(info os.FileInfo) bool {
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&syscall.FILE_ATTRIBUTE_REPARSE_POINT != 0
}
