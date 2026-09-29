//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"github.com/defenseclaw/defenseclaw/internal/managed"
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

// validateAuditDBPlatformTrust judges the ownership + permission posture of an
// audit-DB path element.
//
// The fourth parameter (strict) toggles the AIFW-34262 advisory downgrade for
// ancestor permission verdicts. When strict is false, the caller is walking
// an ANCESTOR (not the leaf) — a permission-shaped 0o022 verdict on a path
// under managed.PlatformInstallerOwnedPath (e.g. /opt/cisco, /Library/Logs/Cisco)
// is downgraded to a managed_trust_ancestor_advisory warning and swallowed.
// That mirrors the softening that internal/managed/trust_unix.go already does
// for the config and data_dir ancestors; without it, /opt/cisco at 0775
// (group-writable, root-owned) trips this check and fails-closed at gateway
// startup even though PR #884 softened the parallel managed-package walker.
// When strict is true (leaf), every verdict stays fatal. Structural failures
// (untrusted owner, ownership lookup failure) also stay fatal in either mode.
// managed.TrustStrictAncestorsEnv=1 forces every verdict fatal.
func validateAuditDBPlatformTrust(path string, info os.FileInfo, directory, strict bool) error {
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
		kind := "file"
		if directory {
			kind = "directory"
		}
		verdict := managed.NewTrustVerdict("audit: database %s is group- or other-writable", kind)
		advisory := !strict && managed.PlatformInstallerOwnedPath(path)
		label := fmt.Sprintf("audit store database %s", kind)
		return managed.RelaxAncestorTrustVerdict(advisory, path, label, verdict)
	}
	return nil
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
	return info.Mode().Perm()&0o022 == 0
}
