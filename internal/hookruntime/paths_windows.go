// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// The LocalAppData Known Folder of the process token's user does not change
// while the process runs (a folder redirection applies at the next sign-in),
// but each lookup opens the token and asks the shell. Hook ownership checks
// resolve the launcher once per hook word, which made the Windows removal
// passes take minutes (GAP-2149), so the first successful answer is kept. A
// failed lookup is not kept.
var (
	lookupLocalAppData = func() (string, error) {
		return winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
	}
	localAppDataMu sync.Mutex
	localAppData   string
)

func currentUserLocalAppData() (string, error) {
	localAppDataMu.Lock()
	defer localAppDataMu.Unlock()
	if localAppData != "" {
		return localAppData, nil
	}
	path, err := lookupLocalAppData()
	if err == nil && strings.TrimSpace(path) != "" {
		localAppData = path
	}
	return path, err
}

func CurrentUserPaths() (Paths, error) {
	localAppData, err := currentUserLocalAppData()
	if err != nil {
		return Paths{}, fmt.Errorf("resolve LocalAppData Known Folder: %w", err)
	}
	if strings.TrimSpace(localAppData) == "" {
		return Paths{}, fmt.Errorf("LocalAppData Known Folder is empty")
	}
	root := filepath.Join(localAppData, "DefenseClaw", "HookRuntime")
	return Paths{
		Root:     root,
		Launcher: filepath.Join(root, LauncherName),
		State:    filepath.Join(root, StateName),
	}, nil
}
