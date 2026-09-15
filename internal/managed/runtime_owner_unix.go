//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import "github.com/defenseclaw/defenseclaw/internal/safefile"

// ReclaimWrittenFileToDirectoryOwner gives a root-created runtime file back
// to the operator who owns the already-trusted parent directory.
func ReclaimWrittenFileToDirectoryOwner(path string) error {
	return safefile.ReclaimToDirectoryOwner(path)
}
