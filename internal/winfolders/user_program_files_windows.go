// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

// Package winfolders resolves Windows Known Folders used as trust roots.
package winfolders

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

type resolver func(*windows.KNOWNFOLDERID, uint32) (string, error)

// UserProgramFiles returns the current user's canonical per-user Programs
// directory without consulting environment variables. DONT_VERIFY is
// intentional: FOLDERID_UserProgramFiles is an optional directory and a fresh
// Windows profile may not have materialized it yet.
//
// Older or stripped-down Windows images can lack the UserProgramFiles Known
// Folder registration. Its documented default is <LocalAppData>\Programs, so
// fall back to the independently resolved LocalAppData Known Folder while
// preserving the same non-environment trust boundary.
//
// The answer belongs to the process token's user and does not change while
// the process runs (a folder redirection applies at the next sign-in), so the
// first successful one is kept: hook ownership checks ask once per hook word
// (GAP-2149). A failure is not kept.
func UserProgramFiles() (string, error) {
	userProgramFilesMu.Lock()
	defer userProgramFilesMu.Unlock()
	if userProgramFilesPath != "" {
		return userProgramFilesPath, nil
	}
	path, err := resolveUserProgramFiles()
	if err == nil {
		userProgramFilesPath = path
	}
	return path, err
}

var (
	resolveUserProgramFiles = func() (string, error) {
		return userProgramFiles(winpath.CurrentUserKnownFolderPathWithFlags)
	}
	userProgramFilesMu   sync.Mutex
	userProgramFilesPath string
)

func userProgramFiles(resolve resolver) (string, error) {
	programs, programsErr := resolve(windows.FOLDERID_UserProgramFiles, windows.KF_FLAG_DONT_VERIFY)
	if programsErr == nil && strings.TrimSpace(programs) != "" {
		return filepath.Clean(programs), nil
	}

	local, localErr := resolve(windows.FOLDERID_LocalAppData, windows.KF_FLAG_DONT_VERIFY)
	if localErr != nil {
		return "", fmt.Errorf(
			"resolve UserProgramFiles Known Folder (%v) and LocalAppData fallback: %w",
			programsErr,
			localErr,
		)
	}
	if strings.TrimSpace(local) == "" {
		return "", fmt.Errorf("UserProgramFiles and LocalAppData Known Folders are empty")
	}
	return filepath.Join(filepath.Clean(local), "Programs"), nil
}
