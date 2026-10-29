// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"path/filepath"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// outageAccountHome is this account's profile folder from the Profile known
// folder, never from USERPROFILE or HOME: the folder install.ps1's default
// DEFENSECLAW_HOME (%USERPROFILE%\.defenseclaw) is in. It is "" when the
// lookup fails. A variable for tests.
var outageAccountHome = func() string {
	profile, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
	if err != nil || !filepath.IsAbs(profile) {
		return ""
	}
	return filepath.Clean(profile)
}

// outageInstalledDataRoot is the data root of the installed runtime's
// protected install state (trustedNativeHookHome: install.ps1's
// DEFENSECLAW_HOME, data_root in defenseclaw-hook-state.json). recognized is
// false for a source build; a recognized state that cannot be read gives "".
// A variable for tests.
var outageInstalledDataRoot = trustedNativeHookHome

// outageHomeEnvNames are the home variables whose .defenseclaw
// hookOutageInstallHeld also looks in.
var outageHomeEnvNames = []string{"USERPROFILE", "HOME"}
