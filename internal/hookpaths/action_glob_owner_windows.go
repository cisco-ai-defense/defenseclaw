// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"path/filepath"

	"golang.org/x/sys/windows"
)

// actionProcessProfileDirectory is the profile folder of the user this
// process runs as; a variable so a test can place the home there.
var actionProcessProfileDirectory = func() (string, error) {
	return windows.GetCurrentProcessToken().GetUserProfileDirectory()
}

// actionProcessOwnsHome reports a process that runs as the user of the
// home: its profile folder is the home. Such a process (a per-user gateway,
// the hook client) cannot list a folder the user Git Bash cannot list
// either, such as the legacy junctions of a profile (Application Data,
// Cookies, My Documents ...) that deny listing to everyone, so the shell
// expands nothing there (rel-1-0-6:GAP-0211, as GAP-1739 on Linux). A
// service with another profile keeps such a folder as unproved.
func actionProcessOwnsHome(home string) bool {
	profile, err := actionProcessProfileDirectory()
	if err != nil || profile == "" || home == "" {
		return false
	}
	return samePathName(filepath.Clean(profile), filepath.Clean(home))
}
