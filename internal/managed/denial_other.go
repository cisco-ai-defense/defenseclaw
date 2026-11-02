//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

import "os"

// ClassifyDenial sorts a failed file operation on path. Only macOS overloads
// EPERM; elsewhere every permission error is access drift.
func ClassifyDenial(_ string, err error) DenialClass {
	switch {
	case err == nil:
		return DenialNone
	case os.IsPermission(err):
		return DenialAccess
	default:
		return DenialOther
	}
}
