//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "github.com/defenseclaw/defenseclaw/internal/safefile"

// ReclaimWrittenFileToDirectoryOwner is a Unix sudo-home repair.
func ReclaimWrittenFileToDirectoryOwner(path string) error {
	return safefile.ReclaimToDirectoryOwner(path)
}
