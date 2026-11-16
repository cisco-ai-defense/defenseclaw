//go:build !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package managed

// AcceptTrustedFileDrift is the strict ValidateTrustedFilePath verdict on
// this platform; the trust record's writer repairs drift.
func AcceptTrustedFileDrift(path, label string) error {
	return ValidateTrustedFilePath(path, label)
}
