// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisestatus

import "os"

type launchDirIdentity = os.FileInfo

func statLaunchPath(path string) (launchDirIdentity, error) { return os.Stat(path) }

func sameLaunchDirIdentity(a, b launchDirIdentity) bool {
	return a.IsDir() && b.IsDir() && os.SameFile(a, b)
}
