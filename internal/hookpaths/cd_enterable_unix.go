// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"golang.org/x/sys/unix"
)

// directoryEnterable reports a directory that cd can enter as this
// account: it exists, is a directory, and grants search permission. Stat
// alone succeeds on a mode 0 directory that cd refuses
// (rel-1-0-6:GAP-0320 review 5).
func directoryEnterable(path string) bool {
	info, err := pathStat(path)
	return err == nil && info.IsDir() && unix.Access(path, unix.X_OK) == nil
}
