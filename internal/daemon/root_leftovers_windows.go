// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import "io/fs"

// fileOwnerUID has no meaning on Windows, where RootOwnedStartBlockers
// returns before it is asked.
func fileOwnerUID(fs.FileInfo) (uint32, bool) { return 0, false }

// accountCanUseDir has no meaning on Windows, for the same reason.
func accountCanUseDir(string) bool { return true }
