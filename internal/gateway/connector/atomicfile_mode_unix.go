// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

func atomicFileProtectionMatches(_ string, info os.FileInfo, perm os.FileMode) bool {
	return info.Mode().Perm() == perm.Perm()
}

func atomicFilePrepareDestination(_ string, _ os.FileMode) error { return nil }
