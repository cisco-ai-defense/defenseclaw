// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisestatus

import "github.com/defenseclaw/defenseclaw/internal/winpath"

type launchDirIdentity = winpath.LocalFileIdentity

// statLaunchPath identifies a directory a user's process named. Status runs
// elevated, so it never lets Windows follow a link it has not checked: a
// symbolic link or junction to a network share, a device or a mapped drive
// is not resolved (winpath.ErrPathNotLocal) and the launch stays reported.
func statLaunchPath(path string) (launchDirIdentity, error) {
	return winpath.LocalPathIdentity(path)
}

func sameLaunchDirIdentity(a, b launchDirIdentity) bool {
	return a.Directory && b.Directory && a.Volume == b.Volume && a.Index == b.Index
}
