// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func currentUserProfile() (string, error) {
	return winpath.CurrentUserKnownFolderPath(windows.FOLDERID_Profile)
}
