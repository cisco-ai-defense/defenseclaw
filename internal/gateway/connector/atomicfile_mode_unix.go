// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func atomicFileProtectionMatches(_ *os.File, info os.FileInfo, perm os.FileMode) bool {
	return info.Mode().Perm() == perm.Perm()
}

func atomicFileValidateStagedProtection(_ *os.File, _ os.FileMode) error { return nil }

func atomicFilePublish(source, destination string, _ os.FileInfo, _ os.FileMode) error {
	return safefile.ReplaceFile(source, destination)
}
