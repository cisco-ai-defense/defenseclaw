// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// CurrentUserKnownFolderPath resolves a Known Folder for the user represented
// by the current process token. An explicit token is required because the
// Token(0) convenience API can consult process-level USERPROFILE and
// LOCALAPPDATA overrides. Agent runtimes legitimately override those variables
// for connector isolation, but they must never redirect Setup ownership or the
// native hook trust boundary.
func CurrentUserKnownFolderPath(folderID *windows.KNOWNFOLDERID) (string, error) {
	var token windows.Token
	if err := windows.OpenProcessToken(
		windows.CurrentProcess(),
		windows.TOKEN_QUERY|windows.TOKEN_IMPERSONATE,
		&token,
	); err != nil {
		return "", fmt.Errorf("open current process token: %w", err)
	}
	path, err := token.KnownFolderPath(folderID, windows.KF_FLAG_DEFAULT)
	closeErr := token.Close()
	if err != nil {
		return "", fmt.Errorf("resolve current user Known Folder: %w", err)
	}
	if closeErr != nil {
		return "", fmt.Errorf("close current process token: %w", closeErr)
	}
	return path, nil
}
