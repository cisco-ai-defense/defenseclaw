// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import "os"

// directoryEnterable reports a directory that cd can enter as this
// account. Windows has no search bit: SetCurrentDirectory opens the
// directory, and the traverse right is usually granted to everyone by the
// bypass-traverse privilege, so opening it here is the same test (and the
// stricter one when listing is denied, which only keeps the old reading)
// (rel-1-0-6:GAP-0320 review 5).
func directoryEnterable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || !info.IsDir() {
		return false
	}
	directory, err := os.Open(path)
	if err != nil {
		return false
	}
	_ = directory.Close()
	return true
}
