// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

func CurrentUserPaths() (Paths, error) {
	localAppData, err := winpath.CurrentUserKnownFolderPath(windows.FOLDERID_LocalAppData)
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
