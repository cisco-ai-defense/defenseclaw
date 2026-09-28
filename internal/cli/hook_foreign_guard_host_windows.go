//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// platformHookForeignGuardSummaryDirTrusted accepts the standalone hook
// runtime directory only when it exists as a real directory owned by
// Administrators, LocalSystem or TrustedInstaller, grants no other principal
// write access, is not a reparse point, and sits under ancestors a standard
// user cannot replace. The standalone lifecycle creates it that way; a folder
// a standard user creates is owned by that user and fails here. The Lstat
// first keeps the common case (no standalone deployment, so no directory)
// to one file system call.
func platformHookForeignGuardSummaryDirTrusted(dir string) error {
	info, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !info.IsDir() {
		return fmt.Errorf("machine policy summary directory %s is not a directory", dir)
	}
	return managed.ValidateTrustedRuntimeDir(dir, "machine policy summary directory")
}
