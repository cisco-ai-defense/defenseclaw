//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

func pathForDataDir(dataDir string) string {
	if os.Getenv(managed.WindowsServiceAccountEnv) == "" {
		// Standalone/developer processes do not use the SCM-installed layout.
		return filepath.Join(dataDir, StateDirName, FileName)
	}
	authorizationDir := os.Getenv(managed.HookGuardianAuthorizationDirEnv)
	for _, path := range []string{dataDir, authorizationDir} {
		if path == "" || path != strings.TrimSpace(path) ||
			strings.ContainsAny(path, "\x00\r\n") || !filepath.IsAbs(path) ||
			filepath.Clean(path) != path {
			return ""
		}
	}
	if !strings.EqualFold(filepath.Base(dataDir), "runtime") {
		return ""
	}
	stateRoot := filepath.Dir(dataDir)
	if !strings.EqualFold(authorizationDir, filepath.Join(stateRoot, "hook-guardian-state")) {
		return ""
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(dataDir); err != nil {
		return ""
	}
	statePath := PathForStateRoot(filepath.Join(stateRoot, StateDirName))
	for _, path := range []string{dataDir, authorizationDir, statePath} {
		if err := winpath.RejectReparseChain(path); err != nil {
			return ""
		}
	}
	// Both inputs are pinned in the administrator-owned service Environment.
	// Never fall back to runtime\hook-guardian: the gateway can write runtime,
	// while the actual guardian signal accompanies its protected manifest.
	return statePath
}

func readStatePathTrusted(path string) bool {
	// The signal is replaced atomically during normal Guardian transitions.
	// Check again at each poll so a later reparse replacement stays unknown.
	return os.Getenv(managed.WindowsServiceAccountEnv) == "" ||
		winpath.RejectReparseChain(path) == nil
}
