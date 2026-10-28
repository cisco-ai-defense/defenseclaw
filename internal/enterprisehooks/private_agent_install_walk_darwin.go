// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

import "golang.org/x/sys/unix"

// unixPrivacyProtectedHomeFolders are the folders below a macOS home whose
// open() waits for a privacy (TCC) decision when the process has no Full
// Disk Access: the user's files folders, app data containers, iCloud and
// file-provider storage, and the personal data stores.
var unixPrivacyProtectedHomeFolders = []string{
	".Trash", "Desktop", "Documents", "Downloads", "Movies", "Music",
	"Pictures/Photos Library.photoslibrary",
	"Library/Containers", "Library/Group Containers", "Library/Daemon Containers",
	"Library/Mobile Documents", "Library/CloudStorage",
	"Library/Mail", "Library/Messages", "Library/Safari", "Library/Calendars",
	"Library/Reminders", "Library/HomeKit", "Library/Suggestions", "Library/Biome",
	"Library/IdentityServices", "Library/Sharing", "Library/Cookies",
	"Library/Application Support/AddressBook", "Library/Application Support/CallHistoryDB",
	"Library/Application Support/CallHistoryTransactions", "Library/Application Support/com.apple.TCC",
	"Library/Application Support/Knowledge", "Library/Metadata/CoreSpotlight",
}

// darwinPathconfCaseSensitive is macOS's _PC_CASE_SENSITIVE pathconf name
// (<sys/unistd.h>): 1 on a case-sensitive volume, 0 on one that compares
// names without case.
const darwinPathconfCaseSensitive = 11

// unixHomeCaseInsensitive reports whether the volume of home compares names
// without case: the default APFS volume does, a case-sensitive APFS or HFS+
// volume does not. Unknown (pathconf fails) is case-sensitive, so the walk
// prunes only the exact names and never a case-distinct tree. Tests replace it.
var unixHomeCaseInsensitive = func(home string) bool {
	sensitive, err := unix.Pathconf(home, darwinPathconfCaseSensitive)
	return err == nil && sensitive == 0
}

// unixPrivateWalkPlatformPrunedHomeTrees are the macOS toolchain trees the
// walk does not list (unixPrivateWalkPrunedHomeTrees): Xcode's derived data,
// simulators and device support, the Android SDK and pnpm's content store.
var unixPrivateWalkPlatformPrunedHomeTrees = []string{"Library/Developer", "Library/Android", "Library/pnpm/store"}

// unixPrivateWalkPlatformCacheRoots: the macOS cache folder.
var unixPrivateWalkPlatformCacheRoots = []string{"Library/Caches"}
