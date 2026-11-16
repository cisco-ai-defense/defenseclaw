//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package safefile

// ReclaimToDirectoryOwner is a Unix sudo-home repair.
func ReclaimToDirectoryOwner(string) error {
	return nil
}

// PreflightReclaimDirectory is a Unix sudo-home check.
func PreflightReclaimDirectory(string) error {
	return nil
}
