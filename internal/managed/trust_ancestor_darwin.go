//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"os"
	"path/filepath"
	"syscall"
)

// osRootAncestor reports the macOS operating system ancestors of the managed
// install root, `/` and `/opt`. Their owner and mode belong to the OS and to
// whatever tooling the administrator runs (Homebrew and MacPorts commonly take
// `/opt`), so a permission verdict there is advisory, the same as for the
// Cisco Secure Client tree below it. The shell installer already treats them
// that way. A standalone process (StandaloneTrustScope) keeps their verdicts
// fatal, as before.
func osRootAncestor(path string) bool {
	if StandaloneTrustScope() {
		return false
	}
	switch filepath.Clean(path) {
	case "/", "/opt":
		return true
	}
	return false
}

// macOS administrator groups: wheel and admin.
const (
	darwinWheelGID = 0
	darwinAdminGID = 80
)

// administratorWriterGroup reports whether gid is a group whose write bit an
// ancestor of the Secure Client install marker may carry: wheel and admin,
// the principals JudgeDarwinACLOutput already trusts for a write ACL entry.
// A standalone process (StandaloneTrustScope) accepts none.
func administratorWriterGroup(gid uint32) bool {
	if StandaloneTrustScope() {
		return false
	}
	return gid == darwinWheelGID || gid == darwinAdminGID
}

// trustedRootAlias reports whether path is one of Apple's fixed root aliases,
// `/etc`, `/tmp` or `/var`: a root-owned symlink in `/` to the folder of the
// same name in `/private`. A trust walk that meets one as an ancestor accepts
// it silently, because the OS ships it that way and SIP protects it. Any other
// symlink on a managed path stays a structural finding.
func trustedRootAlias(path string) bool {
	clean := filepath.Clean(path)
	switch clean {
	case "/etc", "/tmp", "/var":
	default:
		return false
	}
	info, err := os.Lstat(clean)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		return false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		return false
	}
	target, err := os.Readlink(clean)
	if err != nil {
		return false
	}
	name := filepath.Base(clean)
	return target == "private/"+name || target == "/private/"+name
}
