// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package assetfacts

import (
	"errors"

	"golang.org/x/sys/unix"
)

// A missing POSIX access ACL leaves the mode bits authoritative. Any ACL or
// inability to inspect it makes a managed peer's directory entry unproven.
func directoryAccessACLAbsent(path string) bool {
	_, err := unix.Getxattr(path, "system.posix_acl_access", nil)
	return errors.Is(err, unix.ENODATA)
}
