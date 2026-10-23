// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// managedHookUserProfileDir is the invoking user's profile from the process
// token. os.UserHomeDir reads the inherited USERPROFILE, which agent runtimes
// can redirect; the managed runtime resolves the account from the token.
func managedHookUserProfileDir() (string, error) {
	return winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
}
