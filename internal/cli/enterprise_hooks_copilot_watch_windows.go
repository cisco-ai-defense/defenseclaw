//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisepolicy"
)

// enterpriseHookPlatformWatchFiles names the files the Windows guardian
// writes for a target beyond what enterprisehooks.WatchOwnedFiles lists, and
// the folders to watch for them: a Copilot row's VS Code Local hook file. It
// was in no watch list, so a standard user who removed it waited for the
// interval pass while status, which reads the guardian's last pass, said the
// host was security-complete (GAP-0664). Only DefenseClaw writes the file,
// so any event on it starts a pass. A folder that is a link or a mount
// point is not watched.
func enterpriseHookPlatformWatchFiles(connectorName, home string) (dirs, files []string) {
	home = strings.TrimSpace(home)
	if !strings.EqualFold(strings.TrimSpace(connectorName), "copilot") || home == "" {
		return nil, nil
	}
	path := filepath.Clean(enterprisepolicy.CopilotVSCodeLocalHookFilePath(home))
	dir := filepath.Dir(path)
	if info, err := os.Lstat(dir); err == nil && info.IsDir() && info.Mode()&(os.ModeSymlink|os.ModeIrregular) == 0 {
		dirs = []string{dir}
	}
	return dirs, []string{path}
}
