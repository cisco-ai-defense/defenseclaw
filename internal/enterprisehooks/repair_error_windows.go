// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"os"
)

// Used only at known per-user runtime file reads, never at profile or machine
// policy checks. Access denied and untrusted path/identity errors are preserved.
func windowsUserRuntimeMissingRepair(err error) error {
	if errors.Is(err, os.ErrNotExist) {
		return windowsUserRuntimeRepairRequired(err)
	}
	return err
}
