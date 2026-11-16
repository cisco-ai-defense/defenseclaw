// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package assetfacts

import "os"

// Windows hooks read paths as the local user; there is no Unix managed hook
// peer. Opening the directory checks that user's ACL before following a cd.
func callerCanEnterDirectory(path string, _, _ int) bool {
	f, err := os.Open(path)
	if err != nil {
		return false
	}
	defer f.Close()
	info, err := f.Stat()
	return err == nil && info.IsDir()
}
