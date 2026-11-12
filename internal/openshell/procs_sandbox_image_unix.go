//go:build linux || darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package openshell

import (
	"context"
	"os"
	"path/filepath"
	"strconv"
)

// ownSandboxDaemonImage checks the kernel process image for the verified
// listener holder. The doctor's OS override is used by the existing Unix
// path tests; unsupported platforms have no image proof.
func (r *doctorRun) ownSandboxDaemonImage(ctx context.Context, pid int) bool {
	selfPath, err := os.Executable()
	if err != nil {
		return false
	}
	self, err := os.Stat(selfPath)
	if err != nil {
		return false
	}
	var other os.FileInfo
	var path string
	switch r.GOOS {
	case "linux":
		// /proc/<pid>/exe follows the running file even after an upgrade.
		other, err = os.Stat("/proc/" + strconv.Itoa(pid) + "/exe")
	case "darwin":
		// lsof identifies the socket PID; inspect that PID's running image.
		var pathErr error
		path, pathErr = sandboxDaemonProcessPath(ctx, pid)
		if pathErr != nil || !filepath.IsAbs(path) {
			return false
		}
		other, err = os.Stat(path)
	default:
		return false
	}
	if err != nil || other == nil {
		return false
	}
	if os.SameFile(self, other) {
		return true
	}
	// The managed macOS LaunchAgent executes the package's content-addressed
	// gateway copy. It is a different inode from the CLI binary.
	return r.GOOS == "darwin" && installedSandboxDaemonCopy(selfPath, path)
}
