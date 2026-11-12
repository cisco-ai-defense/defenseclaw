// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "os"

// unprotectedAgentsRecordTrusted is the protection status requires of the
// record (readWindowsProtectedRecord): the manifest AdminFile contract,
// SYSTEM and Administrators only with a protected DACL.
func unprotectedAgentsRecordTrusted(path string, _ os.FileInfo) error {
	return validateWindowsTargetsManifestObject(path, false)
}
