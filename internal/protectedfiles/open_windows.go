// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package protectedfiles

import (
	"os"
	"path/filepath"
	"strings"
)

// openNoFollow opens path for reading. digestOf has already refused a
// reparse point (Lstat reports it as a symlink).
func openNoFollow(path string) (*os.File, error) { return os.Open(path) }

// restorableDefault allows a restore only inside this process's own
// profile, so a gateway running as a service account never writes into a
// user's profile, and never through a reparse point in the directory.
func restorableDefault(path string) bool {
	home, err := os.UserHomeDir()
	if err != nil || home == "" {
		return false
	}
	home = filepath.Clean(home)
	clean := filepath.Clean(path)
	if !strings.HasPrefix(strings.ToLower(clean), strings.ToLower(home)+string(filepath.Separator)) {
		return false
	}
	info, err := os.Lstat(filepath.Dir(clean))
	return err == nil && info.IsDir() && info.Mode()&os.ModeSymlink == 0
}
