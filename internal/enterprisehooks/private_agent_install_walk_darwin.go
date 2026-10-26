// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package enterprisehooks

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
	// macOS 15.8 also holds these in a managed (AD) account, measured with
	// find(1) as each account on dc-fc-r103-mac: each open() returns EINTR
	// after about 13 s, which os.Open retries, so the walk timed out and
	// every managed account stayed agent_install_scan_incomplete (GAP-1603).
	"Library/Accounts", "Library/AppleMediaServices", "Library/Assistant/SiriVocabulary",
	"Library/Autosave Information", "Library/ContainerManager", "Library/CoreFollowUp",
	"Library/DoNotDisturb", "Library/DuetExpertCenter", "Library/IntelligencePlatform",
	"Library/PersonalizationPortrait", "Library/Photos", "Library/Shortcuts", "Library/StatusKit",
	"Library/Trial", "Library/Weather", "Library/com.apple.aiml.instrumentation",
	"Library/Application Support/DifferentialPrivacy", "Library/Application Support/FaceTime",
	"Library/Application Support/FileProvider", "Library/Application Support/com.apple.sharedfilelist",
	"Library/Caches/CloudKit", "Library/Caches/com.apple.HomeKit", "Library/Caches/com.apple.Safari",
	"Library/Caches/com.apple.ap.adprivacyd", "Library/Caches/com.apple.containermanagerd",
	"Library/Caches/com.apple.homed",
}
