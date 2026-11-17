// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"errors"

	"golang.org/x/sys/windows"
)

// SymlinkPrivilegeMissing reports whether err is the Windows refusal to
// create a symbolic link for an account without the privilege.
func SymlinkPrivilegeMissing(err error) bool {
	return errors.Is(err, windows.ERROR_PRIVILEGE_NOT_HELD)
}
