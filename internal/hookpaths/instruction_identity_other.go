// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

// fileLinkNames reports that POSIX cannot list the names of a file: no call
// maps an inode to its directory entries.
func fileLinkNames(string) (names []string, complete, listed bool) {
	return nil, false, false
}
