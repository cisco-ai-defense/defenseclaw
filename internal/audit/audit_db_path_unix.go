//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

func openAuditDBFileNoFollow(path string, create, _ bool) (*os.File, error) {
	flags := syscall.O_RDWR | syscall.O_CLOEXEC | syscall.O_NOFOLLOW
	if create {
		flags |= syscall.O_CREAT | syscall.O_EXCL
	}
	fd, err := syscall.Open(path, flags, 0o600)
	if err != nil {
		return nil, err
	}
	file := os.NewFile(uintptr(fd), path)
	if file == nil {
		_ = syscall.Close(fd)
		return nil, errors.New("audit: create file handle")
	}
	return file, nil
}

func auditDBPlatformFileNeedsHardening(*os.File) (bool, error) { return false, nil }

// Preserve the Unix sidecar repair seam: chmod/permission hardening remains
// handle-bound and is intentionally repeated during sidecar discovery.
func auditDBPlatformSidecarNeedsHardening(*os.File) (bool, error) { return true, nil }

func auditDBPlatformHardeningNeedsCapabilityReopen() bool { return false }

func validateAuditDBPlatformTrust(_ string, info os.FileInfo, directory, _ bool) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("audit: database path ownership is unavailable")
	}
	owner := int(stat.Uid)
	effectiveUser := os.Geteuid()
	if owner != effectiveUser && !(directory && owner == 0) {
		return errors.New("audit: database path has an untrusted owner")
	}
	if info.Mode().Perm()&0o022 != 0 {
		if directory && owner == 0 && info.Mode()&os.ModeSticky != 0 {
			return nil
		}
		// In container environments, Kubernetes fsGroup makes emptyDir
		// volumes group-writable. Accept group-writable directories
		// when deployment_mode=container. Mount points are root-owned
		// (owner==0) while user-created subdirs are user-owned.
		if directory && isContainerDeploymentMode() {
			return nil
		}
		kind := "file"
		if directory {
			kind = "directory"
		}
		return fmt.Errorf("audit: database %s is group- or other-writable", kind)
	}
	return nil
}

func isContainerDeploymentMode() bool {
	return strings.EqualFold(strings.TrimSpace(os.Getenv("DEFENSECLAW_DEPLOYMENT_MODE")), "container")
}

// macOS and some Unix installations expose a root-level system directory as a
// root-owned symlink (for example /tmp -> /private/tmp). Permit only that
// narrow system alias; operator-controlled symlinks at any lower level fail.
func trustedAuditDBSystemDirectoryAlias(path string, info os.FileInfo) bool {
	if filepath.Dir(path) != string(os.PathSeparator) {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil || filepath.Clean(resolved) == filepath.Clean(path) {
		return false
	}
	target, err := os.Stat(resolved)
	return err == nil && target.IsDir() && validateAuditDBPlatformTrust(resolved, target, true, false) == nil
}

func secureAuditDBPlatformPath(string, bool) error { return nil }

func secureAuditDBPlatformFile(*os.File, bool) error { return nil }

func auditDBModeMatches(info os.FileInfo, want os.FileMode) bool {
	return info.Mode().Perm() == want.Perm()
}

func auditDBImmediateDirectoryModeTrusted(info os.FileInfo) bool {
	if info.Mode().Perm()&0o022 == 0 {
		return true
	}
	return isContainerDeploymentMode()
}
