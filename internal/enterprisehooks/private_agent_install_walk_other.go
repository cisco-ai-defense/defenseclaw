// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows && !darwin

package enterprisehooks

// unixPrivacyProtectedHomeFolders is empty: only macOS holds a folder open()
// for a privacy decision.
var unixPrivacyProtectedHomeFolders []string

const unixHomeCaseInsensitive = false

// unixPrivateWalkPlatformPrunedHomeTrees: the Android SDK where Android
// Studio puts it on Linux (unixPrivateWalkPrunedHomeTrees).
var unixPrivateWalkPlatformPrunedHomeTrees = []string{"Android/Sdk"}

var unixPrivateWalkPlatformCacheRoots []string
