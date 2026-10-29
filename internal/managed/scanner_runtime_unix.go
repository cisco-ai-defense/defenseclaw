// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package managed

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"syscall"
)

// The managed-enterprise Linux and macOS packages install the scanner
// runtime (GAP-1527): the Python tree at <install root>/scanner-runtime,
// which the package manager writes root-owned, and its launcher
// defenseclaw-scanners in the package's bin folder. The payload (tar.gz)
// channel installs neither, so a deployment from it has no scanner runtime.
const (
	StandaloneUnixScannerRuntimeDirName = "scanner-runtime"
	StandaloneUnixScannerRuntimeName    = "defenseclaw-scanners"
)

// StandaloneUnixScannerRuntimeDir is the scanner runtime tree of this
// host's standalone layout: /opt/defenseclaw/scanner-runtime on Linux,
// /opt/cisco/defenseclaw/scanner-runtime on macOS.
func StandaloneUnixScannerRuntimeDir() (string, error) {
	layout, err := StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return "", err
	}
	return path.Join(layout.InstallRoot, StandaloneUnixScannerRuntimeDirName), nil
}

// StandaloneUnixScannerRuntimeLauncher is the installed defenseclaw-scanners.
func StandaloneUnixScannerRuntimeLauncher() (string, error) {
	layout, err := StandaloneLayoutFor(runtime.GOOS)
	if err != nil {
		return "", err
	}
	return path.Join(layout.BinDir, StandaloneUnixScannerRuntimeName), nil
}

// ErrNoScannerRuntime reports a host whose packages installed no scanner
// runtime (absent tree or launcher).
var ErrNoScannerRuntime = errors.New("this installation has no scanner runtime")

// InstalledUnixScannerRuntime returns the launcher and the runtime tree when
// both are installed and trusted. ErrNoScannerRuntime when either is absent;
// any other error names what makes the installed runtime untrusted.
func InstalledUnixScannerRuntime() (launcher, root string, err error) {
	return installedUnixScannerRuntime(true)
}

// InstalledUnixScannerRuntimeInScan is InstalledUnixScannerRuntime for the
// launcher a scan started. The gateway contains a scanner in a user
// namespace of its own (processutil.RunContained) where root is unmapped
// and every root-owned file reads as the overflow owner, so no owner can be
// proven there: the gateway proved them outside the namespace right before
// it started the scan (scanner preflight), and inside only the kinds and
// modes of the entries are checked again. Anywhere else the full check runs.
func InstalledUnixScannerRuntimeInScan() (launcher, root string, err error) {
	return installedUnixScannerRuntime(!InUnmappedRootUserNamespace())
}

func installedUnixScannerRuntime(owners bool) (launcher, root string, err error) {
	launcher, err = StandaloneUnixScannerRuntimeLauncher()
	if err != nil {
		return "", "", ErrNoScannerRuntime
	}
	root, err = StandaloneUnixScannerRuntimeDir()
	if err != nil {
		return "", "", ErrNoScannerRuntime
	}
	_, launcherErr := os.Lstat(launcher)
	_, rootErr := os.Lstat(root)
	if errors.Is(launcherErr, fs.ErrNotExist) || errors.Is(rootErr, fs.ErrNotExist) {
		return "", "", ErrNoScannerRuntime
	}
	if launcherErr != nil {
		return "", "", fmt.Errorf("scanner runtime launcher %s: %w", launcher, launcherErr)
	}
	if rootErr != nil {
		return "", "", fmt.Errorf("scanner runtime folder %s: %w", root, rootErr)
	}
	if !owners {
		if err := validateRuntimeTreeEntries(root, "scanner Python runtime", false); err != nil {
			return "", "", err
		}
		return launcher, root, nil
	}
	if err := ValidateTrustedFilePath(launcher, "scanner runtime launcher"); err != nil {
		return "", "", err
	}
	if err := ValidateTrustedRuntimeCodeTree(root, "scanner Python runtime"); err != nil {
		return "", "", err
	}
	return launcher, root, nil
}

// ValidateTrustedRuntimeCodeTree checks the scanner runtime tree before the
// gateway runs code from it: root and the folders above it cannot be
// replaced by a standard account, and every entry beneath is a plain file or
// folder owned by root that no group or other account can write. A writable
// module, .pth file or folder runs code as the gateway even when the
// interpreter itself is protected; the service account may not own it
// either, or a compromised gateway could keep code it changed.
func ValidateTrustedRuntimeCodeTree(root, label string) error {
	if root == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(root)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if err := ValidateTrustedRuntimeDir(clean, label); err != nil {
		return err
	}
	return validateRuntimeTreeEntries(clean, label, true)
}

// validateRuntimeTreeEntries walks the tree: plain files and folders, none
// group- or other-writable, and with owners, every one owned by root.
func validateRuntimeTreeEntries(clean, label string, owners bool) error {
	const maxEntries = 200000
	entries := 0
	checkACL := !runtimeTreeHasNoACL(clean)
	return filepath.WalkDir(clean, func(cur string, _ fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entries++; entries > maxEntries {
			return fmt.Errorf("%s has more than %d entries", clean, maxEntries)
		}
		info, err := os.Lstat(cur)
		if err != nil {
			return fmt.Errorf("%s: %w", cur, err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s: symlinks are not allowed in %s", cur, label)
		}
		if !info.IsDir() && !info.Mode().IsRegular() {
			return fmt.Errorf("%s: %s holds only files and folders", cur, label)
		}
		if info.Mode().Perm()&0o022 != 0 {
			return fmt.Errorf("%s: group/other writable permissions %04o are not trusted in %s", cur, info.Mode().Perm(), label)
		}
		if !owners {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return fmt.Errorf("%s: cannot inspect file owner", cur)
		}
		if owner := hostOwnerUID(cur, info, st.Uid); owner != 0 {
			return fmt.Errorf("%s: owner uid %d is not root, so it is not trusted in %s", cur, owner, label)
		}
		if !checkACL {
			return nil
		}
		return validateTrustedPathACL(cur)
	})
}
