// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package enterprisehooks

// unixPrivacyProtectedHomeFolders is empty: only macOS holds a folder open()
// for a privacy decision.
var unixPrivacyProtectedHomeFolders []string

// unixHomeCaseInsensitive: Linux file systems compare names with case.
// Tests replace it.
var unixHomeCaseInsensitive = func(string) bool { return false }

// unixPrivateWalkPlatformPrunedHomeTrees: the Android SDK where Android
// Studio puts it on Linux (unixPrivateWalkPrunedHomeTrees).
var unixPrivateWalkPlatformPrunedHomeTrees = []string{"Android/Sdk"}

var unixPrivateWalkPlatformCacheRoots []string
